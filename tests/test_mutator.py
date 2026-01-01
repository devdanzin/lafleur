#!/usr/bin/env python3
"""
Comprehensive test suite for lafleur's mutator.py module.

This test suite covers all mutator classes, helper functions, and the main
ASTMutator orchestrator. It uses unittest and aims for high coverage of all
functionality.
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

# Import from the reorganized mutators package
from lafleur.mutators.engine import ASTMutator
from lafleur.mutators.generic import (
    OperatorSwapper,
    ComparisonSwapper,
    ConstantPerturbator,
    GuardInjector,
    ContainerChanger,
    VariableSwapper,
    StatementDuplicator,
    VariableRenamer,
    ForLoopInjector,
    GuardRemover,
)
from lafleur.mutators.scenarios_types import (
    TypeInstabilityInjector,
    InlineCachePolluter,
    LoadAttrPolluter,
    ManyVarsInjector,
    TypeIntrospectionMutator,
    FunctionPatcher,
)
from lafleur.mutators.scenarios_data import (
    MagicMethodMutator,
    NumericMutator,
    IterableMutator,
    DictPolluter,
)
from lafleur.mutators.scenarios_runtime import (
    GCInjector,
    SideEffectInjector,
    GlobalInvalidator,
    StressPatternInjector,
)
from lafleur.mutators.scenarios_control import (
    TraceBreaker,
    ExitStresser,
    DeepCallMutator,
    GuardExhaustionGenerator,
)
from lafleur.mutators.utils import (
    FuzzerSetupNormalizer,
    EmptyBodySanitizer,
    genLyingEqualityObject,
    genStatefulLenObject,
    genUnstableHashObject,
    genStatefulStrReprObject,
    genStatefulGetitemObject,
    genStatefulGetattrObject,
    genStatefulBoolObject,
    genStatefulIterObject,
    genStatefulIndexObject,
    genSimpleObject,
)
from lafleur.mutators.scenarios_runtime import (
    _create_type_corruption_node,
    _create_uop_attribute_deletion_node,
    _create_method_patch_node,
    _create_dict_swap_node,
    _create_class_reassignment_node,
)
from lafleur.mutators.scenarios_data import (
    _create_len_attack,
    _create_hash_attack,
    _create_pow_attack,
)


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions used by mutators."""

    def test_create_type_corruption_node(self):
        """Test type corruption node generation."""
        nodes = _create_type_corruption_node("test_var")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        self.assertEqual(nodes[0].targets[0].id, "test_var")
        # Value should be one of the corruption values
        self.assertIsInstance(nodes[0].value, ast.Constant)

    def test_create_uop_attribute_deletion_node(self):
        """Test attribute deletion node generation."""
        nodes = _create_uop_attribute_deletion_node("test_obj")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Delete)
        self.assertIsInstance(nodes[0].targets[0], ast.Attribute)
        self.assertEqual(nodes[0].targets[0].value.id, "test_obj")

    def test_create_method_patch_node(self):
        """Test method patching node generation."""
        nodes = _create_method_patch_node("test_obj")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        self.assertIsInstance(nodes[0].value, ast.Lambda)

    def test_create_dict_swap_node(self):
        """Test dict swap node generation."""
        nodes = _create_dict_swap_node("obj1", "obj2")
        self.assertEqual(len(nodes), 1)
        self.assertIsInstance(nodes[0], ast.Assign)
        # Check it's a tuple assignment
        self.assertIsInstance(nodes[0].targets[0], ast.Tuple)
        self.assertEqual(len(nodes[0].targets[0].elts), 2)

    def test_create_class_reassignment_node(self):
        """Test class reassignment node generation."""
        nodes = _create_class_reassignment_node("test_obj")
        self.assertEqual(len(nodes), 2)
        self.assertIsInstance(nodes[0], ast.ClassDef)
        self.assertIsInstance(nodes[1], ast.Assign)

    # NOTE: _is_simple_statement function was removed in codebase refactor
    # def test_is_simple_statement(self):
    #     """Test simple statement detection."""
    #     pass


class TestEvilObjectGenerators(unittest.TestCase):
    """Test evil object generator functions."""

    def test_genLyingEqualityObject(self):
        """Test lying equality object generation."""
        code = genLyingEqualityObject("test_eq")
        self.assertIn("class LyingEquality_test_eq:", code)
        self.assertIn("def __eq__", code)
        self.assertIn("def __ne__", code)
        self.assertIn("test_eq = LyingEquality_test_eq()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulLenObject(self):
        """Test stateful len object generation."""
        code = genStatefulLenObject("test_len")
        self.assertIn("class StatefulLen_test_len:", code)
        self.assertIn("def __len__", code)
        self.assertIn("test_len = StatefulLen_test_len()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genUnstableHashObject(self):
        """Test unstable hash object generation."""
        code = genUnstableHashObject("test_hash")
        self.assertIn("class UnstableHash_test_hash:", code)
        self.assertIn("def __hash__", code)
        self.assertIn("fuzzer_rng.randint", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genSimpleObject(self):
        """Test simple object generation."""
        code = genSimpleObject("test_obj")
        self.assertIn("class C_test_obj:", code)
        self.assertIn("self.x = 1", code)
        self.assertIn("self.y = 'y'", code)
        self.assertIn("def get_value", code)

    def test_genStatefulStrReprObject(self):
        """Test stateful str/repr object generation."""
        code = genStatefulStrReprObject("test_str_repr")
        self.assertIn("class StatefulStrRepr_test_str_repr:", code)
        self.assertIn("def __str__", code)
        self.assertIn("def __repr__", code)
        self.assertIn("return 123", code)  # The TypeError-inducing return
        self.assertIn("test_str_repr = StatefulStrRepr_test_str_repr()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulGetitemObject(self):
        """Test stateful getitem object generation."""
        code = genStatefulGetitemObject("test_getitem")
        self.assertIn("class StatefulGetitem_test_getitem:", code)
        self.assertIn("def __getitem__", code)
        self.assertIn("return 99.9", code)  # Float return
        self.assertIn("return 5", code)  # Int return
        self.assertIn("test_getitem = StatefulGetitem_test_getitem()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulGetattrObject(self):
        """Test stateful getattr object generation."""
        code = genStatefulGetattrObject("test_getattr")
        self.assertIn("class StatefulGetattr_test_getattr:", code)
        self.assertIn("def __getattr__", code)
        self.assertIn("return b'evil_attribute'", code)
        self.assertIn("return 'normal_attribute'", code)
        self.assertIn("test_getattr = StatefulGetattr_test_getattr()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulBoolObject(self):
        """Test stateful bool object generation."""
        code = genStatefulBoolObject("test_bool")
        self.assertIn("class StatefulBool_test_bool:", code)
        self.assertIn("def __bool__", code)
        self.assertIn("return False", code)
        self.assertIn("return True", code)
        self.assertIn("test_bool = StatefulBool_test_bool()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulIterObject(self):
        """Test stateful iter object generation."""
        code = genStatefulIterObject("test_iter")
        self.assertIn("class StatefulIter_test_iter:", code)
        self.assertIn("def __iter__", code)
        self.assertIn("self._iterable = [1, 2, 3]", code)
        self.assertIn("return iter((None,))", code)
        self.assertIn("test_iter = StatefulIter_test_iter()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)

    def test_genStatefulIndexObject(self):
        """Test stateful index object generation."""
        code = genStatefulIndexObject("test_index")
        self.assertIn("class StatefulIndex_test_index:", code)
        self.assertIn("def __index__", code)
        self.assertIn("return 99", code)  # Out-of-bounds index
        self.assertIn("return 0", code)  # Normal index
        self.assertIn("test_index = StatefulIndex_test_index()", code)

        # Test it's valid Python
        tree = ast.parse(code)
        self.assertIsInstance(tree, ast.Module)


class TestBasicMutators(unittest.TestCase):
    """Test basic AST mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_operator_swapper(self):
        """Test OperatorSwapper mutator."""
        code = "result = a + b"
        tree = ast.parse(code)

        # Force mutation by patching random
        with patch("random.random", return_value=0.1):
            mutator = OperatorSwapper()
            mutated = mutator.visit(tree)

        # Check that the operator changed
        binop = mutated.body[0].value
        self.assertIsInstance(binop, ast.BinOp)
        # Should not be Add anymore (with high probability)
        # Note: Due to randomness, we can't guarantee which operator it becomes

    def test_comparison_swapper(self):
        """Test ComparisonSwapper mutator."""
        code = "if a < b: pass"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ComparisonSwapper()
            mutated = mutator.visit(tree)

        compare = mutated.body[0].test
        self.assertIsInstance(compare, ast.Compare)
        # Should have swapped the operator
        self.assertIsInstance(compare.ops[0], ast.GtE)

    def test_constant_perturbator_int(self):
        """Test ConstantPerturbator on integers."""
        code = "x = 42"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value=1):
                mutator = ConstantPerturbator()
                mutated = mutator.visit(tree)

        constant = mutated.body[0].value
        self.assertEqual(constant.value, 43)  # 42 + 1

    def test_constant_perturbator_string(self):
        """Test ConstantPerturbator on strings."""
        code = "x = 'hello'"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.randint", return_value=1):  # Mutate 'e'
                with patch("random.choice", return_value=1):
                    mutator = ConstantPerturbator()
                    mutated = mutator.visit(tree)

        constant = mutated.body[0].value
        self.assertEqual(len(constant.value), 5)
        self.assertNotEqual(constant.value, "hello")

    def test_guard_injector(self):
        """Test GuardInjector mutator."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = GuardInjector()
        mutated = mutator.visit(tree)

        # Should wrap in an If statement
        self.assertIsInstance(mutated.body[0], ast.If)
        # Check the test uses fuzzer_rng
        test = mutated.body[0].test
        self.assertIsInstance(test, ast.Compare)
        self.assertIsInstance(test.left, ast.Call)
        self.assertEqual(test.left.func.value.id, "fuzzer_rng")

    def test_container_changer_list_to_set(self):
        """Test ContainerChanger converting list to set."""
        code = "x = [1, 2, 3]"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ContainerChanger()
            mutated = mutator.visit(tree)

        container = mutated.body[0].value
        self.assertIsInstance(container, ast.Set)

    def test_container_changer_list_comprehension(self):
        """Test ContainerChanger on list comprehension."""
        code = "x = [i for i in range(10)]"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.3):
            mutator = ContainerChanger()
            mutated = mutator.visit(tree)

        comp = mutated.body[0].value
        self.assertIsInstance(comp, ast.SetComp)

    def test_variable_swapper(self):
        """Test VariableSwapper mutator."""
        code = dedent("""
            x = 1
            y = 2
            z = x + y
        """)
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # Check that some swapping occurred
        # Due to randomness, we can't predict exact swaps
        self.assertIsInstance(mutated, ast.Module)

    def test_variable_swapper_protected_names(self):
        """Test VariableSwapper doesn't swap protected names."""
        code = dedent("""
            print(len([1, 2, 3]))
            x = 1
            y = 2
        """)
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # print and len should not be swapped
        call = mutated.body[0].value
        self.assertEqual(call.func.id, "print")
        self.assertEqual(call.args[0].func.id, "len")

    def test_statement_duplicator(self):
        """Test StatementDuplicator mutator."""
        code = "x = 1"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = StatementDuplicator()
            mutated = mutator.visit(tree)

        # Should have duplicated the statement
        self.assertEqual(len(mutated.body), 2)
        self.assertIsInstance(mutated.body[0], ast.Assign)
        self.assertIsInstance(mutated.body[1], ast.Assign)

    def test_variable_renamer(self):
        """Test VariableRenamer mutator."""
        code = "x = 1; y = x + 2"
        tree = ast.parse(code)

        remapping = {"x": "renamed_x", "y": "renamed_y"}
        mutator = VariableRenamer(remapping)
        mutated = mutator.visit(tree)

        # Check variables were renamed
        self.assertEqual(mutated.body[0].targets[0].id, "renamed_x")
        self.assertEqual(mutated.body[1].targets[0].id, "renamed_y")
        self.assertEqual(mutated.body[1].value.left.id, "renamed_x")


class TestStressPatternMutators(unittest.TestCase):
    """Test stress pattern injection mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_stress_pattern_injector(self):
        """Test StressPatternInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                return x + y
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = StressPatternInjector()
                mutated = mutator.visit(tree)

        # Should have injected stress pattern
        func = mutated.body[0]
        self.assertIsInstance(func, ast.FunctionDef)
        # Body should have more statements
        self.assertGreater(len(func.body), 3)

    def test_type_instability_injector(self):
        """Test TypeInstabilityInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                for i in range(100):
                    x = i * 2
                    y = x + 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = TypeInstabilityInjector()
                mutated = mutator.visit(tree)

        # Should have wrapped loop body in try/except
        func = mutated.body[0]
        loop = func.body[0]
        self.assertIsInstance(loop.body[0], ast.Try)

    def test_guard_exhaustion_generator(self):
        """Test GuardExhaustionGenerator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = GuardExhaustionGenerator()
            mutated = mutator.visit(tree)

        # Should have injected isinstance chain
        func = mutated.body[0]
        # Should have poly_list setup and loop
        self.assertGreater(len(func.body), 1)

    def test_inline_cache_polluter(self):
        """Test InlineCachePolluter mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = InlineCachePolluter()
            mutated = mutator.visit(tree)

        # Should have injected polluter classes
        func = mutated.body[0]
        # Check for class definitions
        has_class = any(isinstance(stmt, ast.ClassDef) for stmt in func.body)
        self.assertTrue(has_class)

    def test_side_effect_injector(self):
        """Test SideEffectInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = SideEffectInjector()
                mutated = mutator.visit(tree)

        # Should have injected __del__ side effect
        func = mutated.body[0]
        # Look for FrameModifier class
        has_frame_modifier = any(
            isinstance(stmt, ast.ClassDef) and "FrameModifier" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_frame_modifier)

    def test_for_loop_injector(self):
        """Test ForLoopInjector mutator."""
        code = dedent("""
            x = 1
            y = 2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            with patch("random.choice", return_value="range"):
                with patch("random.randint", return_value=100):
                    mutator = ForLoopInjector()
                    mutated = mutator.visit(tree)

        # First statement should be wrapped in a loop
        self.assertIsInstance(mutated.body[0], ast.For)

    def test_global_invalidator(self):
        """Test GlobalInvalidator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.randint", side_effect=[0, 12345]):
                mutator = GlobalInvalidator()
                mutated = mutator.visit(tree)

        # Should have injected globals() assignment
        func = mutated.body[0]
        # Look for globals() call
        has_globals = any(
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.targets[0], ast.Subscript)
            and isinstance(stmt.targets[0].value, ast.Call)
            and isinstance(stmt.targets[0].value.func, ast.Name)
            and stmt.targets[0].value.func.id == "globals"
            for stmt in func.body
        )
        self.assertTrue(has_globals)

    def test_load_attr_polluter(self):
        """Test LoadAttrPolluter mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = LoadAttrPolluter()
            mutated = mutator.visit(tree)

        # Should have injected LOAD_ATTR pollution scenario
        func = mutated.body[0]
        # Look for ShapeA/B/C/D classes
        class_names = [stmt.name for stmt in func.body if isinstance(stmt, ast.ClassDef)]
        shape_classes = [name for name in class_names if "ShapeA_" in name or "ShapeB_" in name]
        self.assertGreater(len(shape_classes), 0)

        # Should have loop accessing payload attribute
        code_str = ast.unparse(func)
        self.assertIn("payload", code_str)
        self.assertIn("obj.payload", code_str)

    def test_many_vars_injector(self):
        """Test ManyVarsInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.03):
            with patch("random.randint", return_value=1234):
                mutator = ManyVarsInjector()
                mutated = mutator.visit(tree)

        # Should have injected many variables
        func = mutated.body[0]
        # Count variable assignments
        var_assigns = [stmt for stmt in func.body if isinstance(stmt, ast.Assign)]
        # Should have at least 260 new variables plus the original
        self.assertGreater(len(var_assigns), 260)

        # Check variable naming pattern
        code_str = ast.unparse(func)
        self.assertIn("mv_1234_0", code_str)
        self.assertIn("mv_1234_259", code_str)

    def test_type_introspection_mutator(self):
        """Test TypeIntrospectionMutator mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                if isinstance(x, int):
                    y = 2
                if hasattr(x, 'foo'):
                    z = 3
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", side_effect=lambda x: x[0] if isinstance(x, list) else x):
                mutator = TypeIntrospectionMutator()
                mutated = mutator.visit(tree)

        # Should have injected attack scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should contain either isinstance or hasattr attack
        has_isinstance_attack = "isinstance attack" in code_str or "poly_isinstance" in code_str
        has_hasattr_attack = "hasattr" in code_str and "fuzzer_attr" in code_str
        self.assertTrue(has_isinstance_attack or has_hasattr_attack)

    def test_exit_stresser(self):
        """Test ExitStresser mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch(
                "random.randint", side_effect=[4567, 7]
            ):  # prefix and num_branches
                mutator = ExitStresser()
                mutated = mutator.visit(tree)

        # Should have injected exit stress scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)

        # Should contain the exit stress pattern
        self.assertIn("exit stress scenario", code_str)
        self.assertIn("res_es_4567", code_str)
        # Should have if/elif chain
        self.assertIn("if i %", code_str)
        self.assertIn("elif i %", code_str)


class TestAdvancedMutators(unittest.TestCase):
    """Test advanced mutator classes."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_gc_injector(self):
        """Test GCInjector mutator."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choices", return_value=[1]):
                mutator = GCInjector()
                mutated = mutator.visit(tree)

        # Should have injected import gc and gc.set_threshold
        func = mutated.body[0]
        self.assertIsInstance(func.body[0], ast.Import)
        self.assertEqual(func.body[0].names[0].name, "gc")
        self.assertIsInstance(func.body[1], ast.Expr)

    def test_dict_polluter_global(self):
        """Test DictPolluter with global pollution."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.05, 0.3]):
            mutator = DictPolluter()
            mutated = mutator.visit(tree)

        # Should have injected global dict pollution
        func = mutated.body[0]
        self.assertGreater(len(func.body), 1)

    def test_function_patcher(self):
        """Test FunctionPatcher mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = FunctionPatcher()
                mutated = mutator.visit(tree)

        # Should have injected function patching scenario
        func = mutated.body[0]
        # Look for victim_func definition
        has_victim_func = any(
            isinstance(stmt, ast.FunctionDef) and "victim_func" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_victim_func)

    def test_trace_breaker(self):
        """Test TraceBreaker mutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", side_effect=lambda x: x[0]):
                mutator = TraceBreaker()
                mutated = mutator.visit(tree)

        # Should have injected trace-breaking scenario
        func = mutated.body[0]
        self.assertGreater(len(func.body), 1)

    def test_deep_call_mutator(self):
        """Test DeepCallMutator."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=10):
                with patch("random.randint", return_value=1234):  # Add prefix mock
                    mutator = DeepCallMutator()
                    mutated = mutator.visit(tree)

        # Should have injected deep call chain
        func = mutated.body[0]
        # Check the string representation contains function definitions
        code_str = ast.unparse(func)
        # The newlines are escaped in the string, check for function pattern
        self.assertIn("f_0_dc_1234", code_str)
        self.assertIn("f_9_dc_1234", code_str)

    def test_guard_remover(self):
        """Test GuardRemover mutator."""
        code = dedent("""
            if fuzzer_rng.random() < 0.1:
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = GuardRemover()
            mutated = mutator.visit(tree)

        # Should have removed the guard
        self.assertIsInstance(mutated.body[0], ast.Assign)
        self.assertEqual(mutated.body[0].targets[0].id, "x")


class TestMagicMethodMutators(unittest.TestCase):
    """Test magic method and numeric mutators."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_magic_method_mutator_len_attack(self):
        """Test MagicMethodMutator with len attack."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choice", return_value=_create_len_attack):
                mutator = MagicMethodMutator()
                mutated = mutator.visit(tree)

        # Should have injected len attack
        func = mutated.body[0]
        # Look for StatefulLen class
        has_stateful_len = any(
            isinstance(stmt, ast.ClassDef) and "StatefulLen" in stmt.name for stmt in func.body
        )
        self.assertTrue(has_stateful_len)

    def test_numeric_mutator_pow_args(self):
        """Test NumericMutator mutating pow arguments."""
        code = "result = pow(2, 3)"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=(10, -2)):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        # Check pow arguments were changed
        call = mutated.body[0].value
        self.assertEqual(call.args[0].value, 10)
        self.assertEqual(call.args[1].value, -2)

    def test_numeric_mutator_chr_args(self):
        """Test NumericMutator mutating chr arguments."""
        code = "c = chr(65)"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=-1):
                mutator = NumericMutator()
                mutated = mutator.visit(tree)

        # Check chr argument was changed
        call = mutated.body[0].value
        self.assertEqual(call.args[0].value, -1)

    def test_iterable_mutator_tuple_attack(self):
        """Test IterableMutator with tuple attack."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            # Make it choose _create_tuple_attack
            def mock_choice(choices):
                for choice in choices:
                    if hasattr(choice, "__name__") and "tuple" in choice.__name__:
                        return choice
                return choices[0]

            with patch("random.choice", side_effect=mock_choice):
                mutator = IterableMutator()
                mutated = mutator.visit(tree)

        # Should have injected tuple attack scenario
        func = mutated.body[0]
        code_str = ast.unparse(func)
        self.assertIn("tuple", code_str)


class TestUtilityTransformers(unittest.TestCase):
    """Test utility transformer classes."""

    def test_fuzzer_setup_normalizer_import(self):
        """Test FuzzerSetupNormalizer removing imports."""
        code = dedent("""
            import gc
            import random
            import os
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed gc and random imports
        self.assertEqual(len(mutated.body), 1)
        self.assertEqual(mutated.body[0].names[0].name, "os")

    def test_fuzzer_setup_normalizer_assign(self):
        """Test FuzzerSetupNormalizer removing fuzzer_rng assignment."""
        code = dedent("""
            fuzzer_rng = random.Random(42)
            x = 1
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed fuzzer_rng assignment
        self.assertEqual(len(mutated.body), 1)
        self.assertEqual(mutated.body[0].targets[0].id, "x")

    def test_fuzzer_setup_normalizer_gc_call(self):
        """Test FuzzerSetupNormalizer removing gc.set_threshold."""
        code = dedent("""
            gc.set_threshold(1)
            print("hello")
        """)
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)

        # Should have removed gc.set_threshold call
        self.assertEqual(len(mutated.body), 1)
        self.assertIsInstance(mutated.body[0].value, ast.Call)
        self.assertEqual(mutated.body[0].value.func.id, "print")

    def test_fuzzer_setup_normalizer_random_call(self):
        """Test FuzzerSetupNormalizer converting random() to fuzzer_rng.random()."""
        code = "x = random()"
        tree = ast.parse(code)

        normalizer = FuzzerSetupNormalizer()
        mutated = normalizer.visit(tree)
        print(ast.unparse(mutated))

        # Should have converted to fuzzer_rng.random()
        call = mutated.body[0].value
        self.assertIsInstance(call.func, ast.Attribute)
        self.assertEqual(call.func.value.id, "fuzzer_rng")
        self.assertEqual(call.func.attr, "random")

    def test_empty_body_sanitizer_if(self):
        """Test EmptyBodySanitizer adding pass to empty if."""
        code = "if True: pass"
        tree = ast.parse(code)
        # Manually remove the pass to create empty body
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)

    def test_empty_body_sanitizer_function(self):
        """Test EmptyBodySanitizer adding pass to empty function."""
        code = "def f(): pass"
        tree = ast.parse(code)
        # Manually remove the pass
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)

    def test_empty_body_sanitizer_for(self):
        """Test EmptyBodySanitizer adding pass to empty for loop."""
        code = "for i in range(10): pass"
        tree = ast.parse(code)
        # Manually remove the pass
        tree.body[0].body = []

        sanitizer = EmptyBodySanitizer()
        mutated = sanitizer.visit(tree)

        # Should have added pass
        self.assertEqual(len(mutated.body[0].body), 1)
        self.assertIsInstance(mutated.body[0].body[0], ast.Pass)


class TestASTMutator(unittest.TestCase):
    """Test the main ASTMutator orchestrator class."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_mutate_simple_code(self):
        """Test mutating simple code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                return x + y
        """)

        mutator = ASTMutator()
        mutated_code = mutator.mutate(code, seed=42)

        # Should return valid Python code
        self.assertIsInstance(mutated_code, str)
        # Should be parseable
        tree = ast.parse(mutated_code)
        self.assertIsInstance(tree, ast.Module)

    def test_mutate_ast_directly(self):
        """Test mutating AST directly."""
        code = "x = 1 + 2"
        tree = ast.parse(code)

        mutator = ASTMutator()
        mutated_tree, transformers = mutator.mutate_ast(tree, seed=42)

        # Should return mutated AST and list of transformers
        self.assertIsInstance(mutated_tree, ast.Module)
        self.assertIsInstance(transformers, list)
        self.assertGreater(len(transformers), 0)

        # Should be unparseable
        mutated_code = ast.unparse(mutated_tree)
        self.assertIsInstance(mutated_code, str)

    def test_mutate_with_specific_count(self):
        """Test mutating with specific mutation count."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = ASTMutator()
        _, transformers = mutator.mutate_ast(tree, seed=42, mutations=5)

        # Should apply exactly 5 mutations
        self.assertEqual(len(transformers), 5)

    def test_mutate_with_seed(self):
        """Test that same seed produces same mutations."""
        code = dedent("""
            def uop_harness_test():
                x = 1 + 2
                y = x * 3
                for i in range(10):
                    z = i + y
        """)

        mutator = ASTMutator()
        result1 = mutator.mutate(code, seed=123)
        result2 = mutator.mutate(code, seed=123)

        # Same seed should produce same result
        self.assertEqual(result1, result2)

        # Different seed should produce different result (with high probability)
        result3 = mutator.mutate(code, seed=456)
        # If they're still the same, try more seeds
        if result1 == result3:
            result3 = mutator.mutate(code, seed=789)
        self.assertNotEqual(result1, result3)

    def test_mutate_invalid_syntax(self):
        """Test mutating code with invalid syntax."""
        code = "this is not valid python"

        mutator = ASTMutator()
        result = mutator.mutate(code)

        # Should return error comment
        self.assertIn("# Original code failed to parse:", result)

    def test_mutate_list_as_tree(self):
        """Test mutating when tree is a list."""
        statements = [
            ast.Assign(targets=[ast.Name(id="x", ctx=ast.Store())], value=ast.Constant(value=1)),
            ast.Assign(targets=[ast.Name(id="y", ctx=ast.Store())], value=ast.Constant(value=2)),
        ]

        mutator = ASTMutator()
        mutated_tree, _ = mutator.mutate_ast(statements, seed=42)

        # Should wrap in Module
        self.assertIsInstance(mutated_tree, ast.Module)
        self.assertGreaterEqual(len(mutated_tree.body), 2)

    def test_all_mutators_available(self):
        """Test that all mutators are available in ASTMutator."""
        mutator = ASTMutator()

        # Check some key mutators are present
        mutator_names = [m.__name__ for m in mutator.transformers]

        self.assertIn("OperatorSwapper", mutator_names)
        self.assertIn("GCInjector", mutator_names)
        self.assertIn("TypeInstabilityInjector", mutator_names)
        self.assertIn("GuardRemover", mutator_names)

        # Should have many mutators
        self.assertGreater(len(mutator.transformers), 20)


class TestAttackFunctions(unittest.TestCase):
    """Test attack generation functions."""

    def test_create_len_attack(self):
        """Test len attack generation."""
        nodes = _create_len_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain StatefulLen class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("StatefulLen", code)
        self.assertIn("for i_len", code)

    def test_create_hash_attack(self):
        """Test hash attack generation."""
        nodes = _create_hash_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain UnstableHash class
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("UnstableHash", code)
        self.assertIn("d = {}", code)

    def test_create_pow_attack(self):
        """Test pow attack generation."""
        nodes = _create_pow_attack("test_prefix")

        # Should generate valid AST nodes
        self.assertIsInstance(nodes, list)
        self.assertGreater(len(nodes), 0)

        # Should contain pow calls
        code = ast.unparse(ast.Module(body=nodes))
        self.assertIn("pow(10, -2)", code)
        self.assertIn("pow(-10, 0.5)", code)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_guard_injector_with_none_node(self):
        """Test GuardInjector when child visitor returns None."""

        # Create a custom node that will be removed
        class RemovingTransformer(ast.NodeTransformer):
            def visit_Assign(self, node):
                return None  # Remove assignments

        code = "x = 1"
        tree = ast.parse(code)

        # First apply removing transformer
        remover = RemovingTransformer()
        tree = remover.visit(tree)

        # Then apply GuardInjector
        injector = GuardInjector()
        result = injector.visit(tree)

        # Should handle None gracefully
        self.assertIsInstance(result, ast.Module)

    def test_type_instability_with_no_loop_var(self):
        """Test TypeInstabilityInjector with tuple target."""
        code = dedent("""
            def uop_harness_test():
                for a, b in [(1, 2)]:
                    x = a + b
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = TypeInstabilityInjector()
            mutated = mutator.visit(tree)

        # Should not crash, should return unchanged
        self.assertIsInstance(mutated, ast.Module)

    def test_stress_pattern_injector_no_vars(self):
        """Test StressPatternInjector with no local variables."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            mutator = StressPatternInjector()
            mutated = mutator.visit(tree)

        # Should handle gracefully
        self.assertIsInstance(mutated, ast.Module)

    def test_variable_swapper_single_var(self):
        """Test VariableSwapper with only one variable."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = VariableSwapper()
        mutated = mutator.visit(tree)

        # Should handle gracefully without swapping
        self.assertIsInstance(mutated, ast.Module)
        self.assertEqual(mutated.body[0].targets[0].id, "x")

    def test_for_loop_injector_with_del(self):
        """Test ForLoopInjector doesn't wrap del statements."""
        code = "del x"
        tree = ast.parse(code)

        with patch("random.random", return_value=0.01):
            mutator = ForLoopInjector()
            mutated = mutator.visit(tree)

        # Should not wrap del in loop
        self.assertIsInstance(mutated.body[0], ast.Delete)

    def test_mutator_with_complex_ast(self):
        """Test mutator with complex nested AST."""
        code = dedent("""
            def uop_harness_test():
                class Inner:
                    def method(self):
                        for i in range(10):
                            if i > 5:
                                try:
                                    x = 1 / i
                                except ZeroDivisionError:
                                    pass
                                finally:
                                    y = 2
                return Inner()
        """)

        mutator = ASTMutator()
        mutated_code = mutator.mutate(code, seed=42)

        # Should handle complex nested structure
        self.assertIsInstance(mutated_code, str)
        tree = ast.parse(mutated_code)
        self.assertIsInstance(tree, ast.Module)

    def test_many_vars_with_existing_vars(self):
        """Test ManyVarsInjector with existing variables."""
        code = dedent("""
            def uop_harness_test():
                existing_var_1 = 10
                existing_var_2 = 20
                return existing_var_1 + existing_var_2
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.03):
            mutator = ManyVarsInjector()
            mutated = mutator.visit(tree)

        # Should preserve existing variables and add new ones
        func = mutated.body[0]
        # First assignments should be the many new variables
        # Last statements should be the original code
        self.assertEqual(func.body[-2].targets[0].id, "existing_var_2")
        self.assertIsInstance(func.body[-1], ast.Return)


class TestIntegration(unittest.TestCase):
    """Integration tests for the mutation system."""

    def test_multiple_mutations_pipeline(self):
        """Test applying multiple mutations in sequence."""
        code = dedent("""
            def uop_harness_test():
                x = 1
                y = 2
                for i in range(10):
                    result = x + y * i
                return result
        """)

        mutator = ASTMutator()

        # Apply mutations multiple times
        mutated = code
        for i in range(3):
            mutated = mutator.mutate(mutated, seed=i)
            # Each iteration should produce valid code
            tree = ast.parse(mutated)
            self.assertIsInstance(tree, ast.Module)

    def test_normalizer_then_mutate(self):
        """Test normalizing then mutating."""
        code = dedent("""
            import gc
            import random

            fuzzer_rng = random.Random(42)
            gc.set_threshold(1)

            def uop_harness_test():
                if random() > 10:
                    return x
        """)

        # First parse
        tree = ast.parse(code)

        # Apply normalizer
        normalizer = FuzzerSetupNormalizer()
        normalized = normalizer.visit(tree)

        # Check normalization worked
        normalized_code = ast.unparse(normalized)
        self.assertIn("fuzzer_rng.random()", normalized_code)

        # Then mutate with a seed that won't apply GCInjector
        mutator = ASTMutator()
        with patch("random.seed"):
            with patch("random.randint", return_value=1):
                with patch("random.choices", return_value=[OperatorSwapper]):
                    mutated, _ = mutator.mutate_ast(normalized, seed=42)

        final_code = ast.unparse(mutated)
        # Should still have the normalized random call
        self.assertIn("fuzzer_rng.random", final_code)

    def test_empty_body_after_mutation(self):
        """Test sanitizing empty bodies after mutation."""
        # Create a scenario where mutation might create empty body
        code = dedent("""
            def f():
                if True:
                    x = 1
        """)

        tree = ast.parse(code)

        # Simulate a mutation that removes the assignment
        tree.body[0].body[0].body = []

        # Apply sanitizer
        sanitizer = EmptyBodySanitizer()
        sanitized = sanitizer.visit(tree)

        # Should have added pass
        if_body = sanitized.body[0].body[0].body
        self.assertEqual(len(if_body), 1)
        self.assertIsInstance(if_body[0], ast.Pass)

    def test_type_introspection_with_normalizer(self):
        """Test TypeIntrospectionMutator with FuzzerSetupNormalizer."""
        code = dedent("""
            import random

            def uop_harness_test():
                if random() > 0.1:
                    if isinstance(x, float):
                        return True
        """)

        # First normalize
        tree = ast.parse(code)
        normalizer = FuzzerSetupNormalizer()
        normalized = normalizer.visit(tree)

        # Verify normalization
        code_before_mutation = ast.unparse(normalized)
        self.assertIn("fuzzer_rng.random()", code_before_mutation)

        # The test was checking for fuzzer_rng.random after mutation,
        # but the mutator prepends attack code. The original normalized
        # code is still there, just later in the function.
        with patch("random.random", return_value=0.1):
            mutator = TypeIntrospectionMutator()
            mutated = mutator.visit(normalized)

        code_str = ast.unparse(mutated)
        # The normalized call is still there, just after the attack
        self.assertIn("fuzzer_rng.random()", code_str)

    def test_complex_evil_object_scenario(self):
        """Test combining multiple evil object generators."""
        # Generate a scenario using multiple evil objects
        code = dedent(f"""
            {genStatefulBoolObject("bool_obj")}
            {genStatefulIndexObject("idx_obj")}

            def uop_harness_test():
                data = [1, 2, 3, 4, 5]
                if bool_obj:
                    result = data[idx_obj]
                return result
        """)

        # Parse and mutate
        mutator = ASTMutator()
        mutated = mutator.mutate(code, seed=42)

        # Should produce valid code
        tree = ast.parse(mutated)
        self.assertIsInstance(tree, ast.Module)


class TestMutatorOutput(unittest.TestCase):
    """Test the output quality of mutators."""

    def test_gc_injector_output(self):
        """Test GCInjector produces correct code."""
        code = dedent("""
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.1):
            with patch("random.choices", return_value=[10]):
                mutator = GCInjector()
                mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        self.assertIn("import gc", output)
        self.assertIn("gc.set_threshold(10)", output)

    def test_guard_injector_output(self):
        """Test GuardInjector produces correct code."""
        code = "x = 1"
        tree = ast.parse(code)

        mutator = GuardInjector()
        mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        self.assertIn("if fuzzer_rng.random() < 0.1:", output)
        self.assertIn("x = 1", output)

    def test_deep_call_output(self):
        """Test DeepCallMutator produces valid call chain."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch("random.choice", return_value=5):
                with patch("random.randint", return_value=2824):
                    mutator = DeepCallMutator()
                    mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # The function definitions are in a string that gets parsed
        # Check that the attack was injected
        self.assertIn("Running deep call scenario", output)
        self.assertIn("f_4_dc_2824", output)  # Top function call

    def test_exit_stresser_output_format(self):
        """Test ExitStresser produces correctly formatted if/elif chains."""
        code = dedent("""
            def uop_harness_test():
                pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            with patch(
                "random.randint", side_effect=[9999, 3]
            ):  # prefix and 3 branches
                mutator = ExitStresser()
                mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # Should have exactly 3 branches
        self.assertIn("if i % 3 == 0:", output)
        self.assertIn("elif i % 3 == 1:", output)
        self.assertIn("elif i % 3 == 2:", output)
        self.assertIn("res_es_9999", output)

    def test_type_introspection_polymorphic_output(self):
        """Test TypeIntrospectionMutator polymorphic attack output."""
        code = dedent("""
            def uop_harness_test():
                if isinstance(x, str):
                    pass
        """)
        tree = ast.parse(code)

        with patch("random.random", side_effect=[0.1, 0.3]):  # Force polymorphic attack
            mutator = TypeIntrospectionMutator()
            mutated = mutator.visit(tree)

        output = ast.unparse(mutated)
        # Should contain polymorphic list and isinstance with str
        self.assertIn("_poly_list = [1, 'a', 3.0, [], (), {}, True, b'bytes']", output)
        self.assertIn("isinstance(poly_variable, str)", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
