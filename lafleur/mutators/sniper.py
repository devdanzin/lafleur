import ast
import random
from textwrap import dedent

class SniperMutator(ast.NodeTransformer):
    """
    A mutator that targets specific global variables or builtins that the JIT is "watching".
    It injects invalidation logic into hot loops to trigger deoptimizations or state corruption.
    """

    KNOWN_BUILTINS = {
        "len", "range", "isinstance", "print", "list", "dict", "set", "tuple",
        "int", "str", "float", "bool", "type", "object", "id", "hash", "iter",
        "next", "min", "max", "sum", "any", "all", "sorted", "reversed", "enumerate",
        "zip", "map", "filter", "open", "getattr", "setattr", "delattr", "hasattr",
        "isinstance", "issubclass", "callable", "chr", "ord", "hex", "oct", "bin"
    }

    def __init__(self, watched_keys: list[str]):
        self.watched_keys = watched_keys

    def _create_invalidation_stmt(self, key: str) -> ast.stmt:
        """Generates an AST statement to invalidate the given key."""
        if key in self.KNOWN_BUILTINS:
            # import builtins; builtins.{key} = lambda *a, **k: None
            source = dedent(f"""
                import builtins
                builtins.{key} = lambda *a, **k: None
            """).strip()
        else:
            # globals()['{key}'] = None
            source = f"globals()['{key}'] = None"
        
        try:
            return ast.parse(source).body
        except SyntaxError:
            # Fallback for weird keys
            return []

    def visit_For(self, node: ast.For) -> ast.For:
        self.generic_visit(node)
        return self._snipe_loop(node)

    def visit_While(self, node: ast.While) -> ast.While:
        self.generic_visit(node)
        return self._snipe_loop(node)

    def _snipe_loop(self, node: ast.AST) -> ast.AST:
        """Injects invalidation logic into the loop body."""
        if not self.watched_keys:
            return node
            
        # Probabilistic application (50%)
        if random.random() < 0.5:
            return node

        # Pick 1-3 keys to invalidate
        num_keys = random.randint(1, min(3, len(self.watched_keys)))
        targets = random.sample(self.watched_keys, num_keys)
        
        invalidation_code = []
        for key in targets:
            stmts = self._create_invalidation_stmt(key)
            invalidation_code.extend(stmts)
            
        if invalidation_code:
            # Insert at the start of the loop body
            node.body = invalidation_code + node.body
            ast.fix_missing_locations(node)
            
        return node
