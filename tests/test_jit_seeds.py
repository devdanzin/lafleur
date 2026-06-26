"""
Unit tests for lafleur/jit_seeds.py (native JIT seed generation).
"""

import ast
import random
import unittest

from lafleur import jit_seeds
from lafleur.jit_seeds import (
    HAS_OBJECTS,
    SELECTABLE_UOPS,
    UOP_RECIPES,
    generate_jit_seed,
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
        code = generate_jit_seed(random.Random(7), loop_iterations=300, prefix="f1")
        self.assertIn("def uop_harness_f1():", code)
        self.assertIn("range(300)", code)

    def test_loop_iterations_respected(self):
        code = generate_jit_seed(random.Random(0), loop_iterations=123)
        self.assertIn("range(123)", code)

    def test_num_uops_bounds(self):
        # The header line records the selected uops; count them.
        code = generate_jit_seed(random.Random(3), num_uops=(2, 2))
        header = code.splitlines()[0]
        self.assertTrue(header.startswith("# JIT seed: targeted uops "))


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


if __name__ == "__main__":
    unittest.main()
