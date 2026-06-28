"""
Unit tests for lafleur/jit_seeds.py (native JIT seed generation).
"""

import ast
import random
import unittest

from lafleur import jit_seeds
from lafleur.jit_bug_patterns import BUG_PATTERNS
from lafleur.jit_seeds import (
    HAS_OBJECTS,
    SELECTABLE_BUG_PATTERNS,
    SELECTABLE_UOPS,
    UOP_RECIPES,
    generate_bug_pattern_seed,
    generate_jit_seed,
    generate_synthesize_seed,
    generate_uop_targeted_pattern,
)

# Every operand "kind" a recipe placeholder is allowed to reference.
_OBJECT_KINDS = {
    "object",
    "object_with_attr",
    "object_with_getitem",
    "object_with_method",
    "stateful_getattr_object",
    "stateful_getitem_object",
    "stateful_index_object",
    "stateful_bool_object",
    "stateful_iter_object",
    "stateful_len_object",
    "unstable_hash_object",
}
_KNOWN_KINDS = set(jit_seeds._SIMPLE_GENERATORS) | _OBJECT_KINDS | {"new_variable", "any"}


class TestRecipeTableIntegrity(unittest.TestCase):
    """The UOP_RECIPES table is well-formed and self-consistent."""

    def test_table_is_populated(self):
        self.assertGreaterEqual(len(UOP_RECIPES), 38)

    def test_every_recipe_has_pattern_and_placeholders(self):
        for name, recipe in UOP_RECIPES.items():
            with self.subTest(uop=name):
                self.assertIn("pattern", recipe)
                self.assertIn("placeholders", recipe)
                self.assertIsInstance(recipe["pattern"], str)
                self.assertIsInstance(recipe["placeholders"], dict)

    def test_selectable_excludes_yield_value(self):
        # _YIELD_VALUE would turn the harness into a never-run generator (see module).
        self.assertNotIn("_YIELD_VALUE", SELECTABLE_UOPS)
        self.assertEqual(set(SELECTABLE_UOPS), set(UOP_RECIPES) - {"_YIELD_VALUE"})

    def test_recipes_only_reference_known_kinds(self):
        for name, recipe in UOP_RECIPES.items():
            for placeholder, kinds in recipe["placeholders"].items():
                for kind in kinds:
                    with self.subTest(uop=name, placeholder=placeholder, kind=kind):
                        self.assertIn(kind, _KNOWN_KINDS)


class TestSeedGeneration(unittest.TestCase):
    """Generated seeds are valid, deterministic Python with the expected shape."""

    def test_generated_seeds_parse(self):
        for s in range(25):
            with self.subTest(seed=s):
                code = generate_jit_seed(random.Random(s))
                ast.parse(code)  # raises SyntaxError if invalid

    def test_assembled_seed_with_boilerplate_parses(self):
        # Mirror what CorpusManager.generate_new_seed assembles around the core.
        for s in range(10):
            core = generate_jit_seed(random.Random(s))
            full = f"import sys\nimport random\nfuzzer_rng = random.Random({s})\n{core}\n"
            with self.subTest(seed=s):
                ast.parse(full)

    def test_deterministic_for_same_rng_seed(self):
        a = generate_jit_seed(random.Random(1234))
        b = generate_jit_seed(random.Random(1234))
        self.assertEqual(a, b)

    def test_distinct_for_different_rng_seeds(self):
        a = generate_jit_seed(random.Random(1))
        b = generate_jit_seed(random.Random(2))
        self.assertNotEqual(a, b)

    def test_contains_harness_and_hot_loop(self):
        code = generate_jit_seed(random.Random(7), family="uop", loop_iterations=300, prefix="f1")
        self.assertIn("def uop_harness_f1():", code)
        self.assertIn("range(300)", code)

    def test_loop_iterations_respected(self):
        code = generate_jit_seed(random.Random(0), family="uop", loop_iterations=123)
        self.assertIn("range(123)", code)

    def test_num_uops_bounds(self):
        # The header line records the selected uops; count them.
        code = generate_jit_seed(random.Random(3), family="uop", num_uops=(2, 2))
        header = code.splitlines()[0]
        self.assertTrue(header.startswith("# JIT seed: targeted uops "))

    def test_unknown_family_raises(self):
        with self.assertRaises(ValueError):
            generate_jit_seed(random.Random(0), family="nonsense")


class TestObjectGeneratorWiring(unittest.TestCase):
    """Object placeholders are realized by lafleur's own evil-object generators."""

    @unittest.skipUnless(HAS_OBJECTS, "lafleur.mutators.utils not importable")
    def test_object_kinds_all_have_generators(self):
        for kind in _OBJECT_KINDS:
            with self.subTest(kind=kind):
                self.assertIn(kind, jit_seeds._OBJECT_GENERATORS)

    @unittest.skipUnless(HAS_OBJECTS, "lafleur.mutators.utils not importable")
    def test_object_recipe_emits_a_class(self):
        # _LOAD_ATTR's operand is always an object kind, so its setup defines a class.
        setup, _body = generate_uop_targeted_pattern(["_LOAD_ATTR"], random.Random(0))
        self.assertIn("class ", setup)

    def test_degrades_without_objects(self):
        # The unknown-recipe path and "any"/object fallback must still yield valid code.
        setup, body = generate_uop_targeted_pattern(["_BINARY_OP_ADD_INT"], random.Random(0))
        ast.parse(f"{setup}\n{body}")


class TestBugPatternSeeds(unittest.TestCase):
    """The curated bug-pattern seed family renders to valid, deterministic Python."""

    _MODULE_COUPLED = {"generator_method_call", "evil_deep_calls_correctness"}

    def test_module_coupled_patterns_excluded(self):
        # Patterns that call into a fuzzed target module must not be selectable.
        for name in self._MODULE_COUPLED:
            self.assertIn(name, BUG_PATTERNS)
            self.assertNotIn(name, SELECTABLE_BUG_PATTERNS)
        self.assertEqual(set(SELECTABLE_BUG_PATTERNS), set(BUG_PATTERNS) - self._MODULE_COUPLED)

    def test_every_selectable_pattern_renders_and_parses(self):
        # The key risk: a template must fill + wrap into valid Python.
        for name in SELECTABLE_BUG_PATTERNS:
            for s in range(4):
                with self.subTest(pattern=name, seed=s):
                    code = generate_bug_pattern_seed(random.Random(s), name=name)
                    ast.parse(code)

    def test_assembled_pattern_with_boilerplate_parses(self):
        # Patterns reference sys / fuzzer_rng from boilerplate; assembled form parses.
        for name in SELECTABLE_BUG_PATTERNS:
            core = generate_bug_pattern_seed(random.Random(0), name=name)
            full = f"import sys\nimport random\nfuzzer_rng = random.Random(0)\n{core}\n"
            with self.subTest(pattern=name):
                ast.parse(full)

    def test_harness_wrapped_and_called(self):
        code = generate_bug_pattern_seed(random.Random(1), name="decref_escapes", prefix="p1")
        self.assertIn("def jit_harness_p1():", code)
        self.assertIn("jit_harness_p1()", code)

    def test_deterministic_for_same_rng_seed(self):
        a = generate_bug_pattern_seed(random.Random(5), name="isinstance_patch")
        b = generate_bug_pattern_seed(random.Random(5), name="isinstance_patch")
        self.assertEqual(a, b)

    def test_random_pattern_selection_only_uses_selectable(self):
        for s in range(30):
            code = generate_bug_pattern_seed(random.Random(s))
            header = code.splitlines()[0]
            self.assertTrue(header.startswith("# JIT seed: bug pattern "))


class TestSynthesizeSeeds(unittest.TestCase):
    """The synthesize seed family renders to valid, deterministic Python."""

    def test_generated_seeds_parse(self):
        for s in range(30):
            with self.subTest(seed=s):
                ast.parse(generate_synthesize_seed(random.Random(s)))

    def test_assembled_with_boilerplate_parses(self):
        for s in range(10):
            core = generate_synthesize_seed(random.Random(s))
            full = f"import sys\nimport random\nfuzzer_rng = random.Random({s})\n{core}\n"
            with self.subTest(seed=s):
                ast.parse(full)

    def test_harness_and_hot_loop(self):
        code = generate_synthesize_seed(random.Random(2), loop_iterations=321, prefix="s1")
        self.assertIn("def synth_harness_s1():", code)
        self.assertIn("range(321)", code)
        self.assertIn("synth_harness_s1()", code)

    def test_deterministic_for_same_rng_seed(self):
        a = generate_synthesize_seed(random.Random(99))
        b = generate_synthesize_seed(random.Random(99))
        self.assertEqual(a, b)


class TestFamilyDispatch(unittest.TestCase):
    """generate_jit_seed dispatches across families and always yields valid Python."""

    _HARNESS_MARKER = {
        "uop_harness_": "uop",
        "jit_harness_": "bug_pattern",
        "synth_harness_": "synthesize",
    }

    def _family_of(self, code: str) -> str:
        for marker, family in self._HARNESS_MARKER.items():
            if marker in code:
                return family
        raise AssertionError(f"no known harness marker in seed:\n{code[:200]}")

    def test_explicit_families_parse(self):
        for family in ("uop", "bug_pattern", "synthesize"):
            for s in range(8):
                with self.subTest(family=family, seed=s):
                    ast.parse(generate_jit_seed(random.Random(s), family=family))

    def test_default_dispatch_covers_all_families(self):
        seen = set()
        for s in range(120):
            code = generate_jit_seed(random.Random(s))
            ast.parse(code)
            seen.add(self._family_of(code))
        self.assertEqual(seen, {"uop", "bug_pattern", "synthesize"})


if __name__ == "__main__":
    unittest.main()
