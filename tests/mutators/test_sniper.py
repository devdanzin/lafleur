import ast
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

    def test_injection_into_for_loop(self):
        """Test that invalidation code is injected into a for loop."""
        code = dedent("""
            def func():
                for i in range(10):
                    pass
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.9), patch("random.sample", return_value=["len"]):
            mutator = SniperMutator(["len"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        self.assertIn("builtins.len =", generated)
        self.assertIn("for i in range(10):", generated)

    def test_injection_into_while_loop(self):
        """Test that invalidation code is injected into a while loop."""
        code = dedent("""
            def func():
                while True:
                    pass
        """)
        tree = ast.parse(code)

        with (
            patch("random.random", return_value=0.9),
            patch("random.sample", return_value=["MyGlobal"]),
        ):
            mutator = SniperMutator(["MyGlobal"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        self.assertIn("globals()['MyGlobal'] = None", generated)

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

        generated = ast.unparse(mutated)
        # Should match original exactly (ignoring potential whitespace diffs, but structure same)
        self.assertEqual(ast.dump(tree), ast.dump(mutated))

    def test_syntax_validity(self):
        """Test that generated code is syntactically valid."""
        code = dedent("""
            def func():
                for i in range(10):
                    x = 1
        """)
        tree = ast.parse(code)

        with patch("random.random", return_value=0.9):
            mutator = SniperMutator(["len", "MyGlobal"])
            mutated = mutator.visit(tree)

        generated = ast.unparse(mutated)
        try:
            ast.parse(generated)
        except SyntaxError:
            self.fail("Generated code has syntax error")


if __name__ == "__main__":
    unittest.main()
