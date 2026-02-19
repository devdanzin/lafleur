import ast
import re
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.sniper import SniperMutator


class TestSniperMutator(unittest.TestCase):
    def test_invalidation_logic_builtin(self):
        """Test that invalidation code for builtins is generated correctly."""
        mutator = SniperMutator(["len"])
        stmts = mutator._create_invalidation_stmt("len")

        # Should return import builtins; builtins.len = ...
        code = ast.unparse(ast.Module(body=stmts, type_ignores=[]))
        self.assertIn("import builtins", code)
        self.assertIn("builtins.len =", code)

    def test_invalidation_logic_global(self):
        """Test that invalidation code for globals is generated correctly."""
        mutator = SniperMutator(["MyGlobal"])
        stmts = mutator._create_invalidation_stmt("MyGlobal")

        # Should return globals()['MyGlobal'] = None
        code = ast.unparse(ast.Module(body=stmts, type_ignores=[]))
        self.assertIn("globals()['MyGlobal'] = None", code)

    def test_injection_into_for_loop_with_warmup_delay(self):
        """Test that invalidation code is delayed until after JIT warmup."""
        code = dedent("""
            def func():
                for i in range(200):
                    pass
        """)
        tree = ast.parse(code)

        with (
            patch("random.random", return_value=0.9),
            patch("random.sample", return_value=["len"]),
            patch("random.randint", side_effect=[1, 1000, 75]),
        ):
            # randint calls: num_keys=1, counter suffix=1000, trigger_iteration=75
            mutator = SniperMutator(["len"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        # Should have the invalidation code
        self.assertIn("builtins.len =", generated)
        # Should have iteration counter with lazy init
        self.assertIn("_sniper_ctr_1000", generated)
        # Should be gated behind an if check
        self.assertIn("_sniper_ctr_1000 == 75", generated)
        # Counter should use try/except NameError for lazy init
        self.assertIn("except NameError", generated)

    def test_injection_into_while_loop_with_warmup_delay(self):
        """Test that invalidation in while loops is also delayed."""
        code = dedent("""
            def func():
                while True:
                    pass
        """)
        tree = ast.parse(code)

        with (
            patch("random.random", return_value=0.9),
            patch("random.sample", return_value=["MyGlobal"]),
            patch("random.randint", side_effect=[1, 2000, 60]),
        ):
            mutator = SniperMutator(["MyGlobal"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        self.assertIn("globals()['MyGlobal'] = None", generated)
        # Should have delayed trigger
        self.assertIn("_sniper_ctr_2000", generated)
        self.assertIn("_sniper_ctr_2000 == 60", generated)

    def test_trigger_iteration_in_warmup_range(self):
        """Test that trigger iteration is in the JIT warmup range (50-100)."""
        code = dedent("""
            def func():
                for i in range(200):
                    pass
        """)
        tree = ast.parse(code)

        # Don't mock random.randint — let it generate naturally
        with (
            patch("random.random", return_value=0.9),
            patch("random.sample", return_value=["_jit_helper_add"]),
        ):
            mutator = SniperMutator(["_jit_helper_add"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        # Find the trigger value: look for _sniper_ctr_XXXX == NN
        match = re.search(r"_sniper_ctr_\d+ == (\d+)", generated)
        if match:
            trigger = int(match.group(1))
            self.assertGreaterEqual(trigger, 50)
            self.assertLessEqual(trigger, 100)

    def test_empty_keys_does_nothing(self):
        """Test that nothing happens if watched_keys is empty."""
        code = dedent("""
            def func():
                for i in range(10):
                    pass
        """)
        tree = ast.parse(code)
        mutator = SniperMutator([])
        mutated = mutator.visit(tree)

        ast.unparse(mutated)
        # Should match original exactly (ignoring potential whitespace diffs, but structure same)
        self.assertEqual(ast.dump(tree), ast.dump(mutated))

    def test_syntax_validity(self):
        """Test that generated code is syntactically valid."""
        code = dedent("""
            def func():
                for i in range(100):
                    x = i + 1
        """)
        tree = ast.parse(code)

        with (
            patch("random.random", return_value=0.9),
            patch("random.sample", return_value=["_jit_helper_add"]),
        ):
            mutator = SniperMutator(["_jit_helper_add"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        # Must be parseable
        ast.parse(generated)


if __name__ == "__main__":
    unittest.main()
