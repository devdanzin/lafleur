---
name: new-mutator
description: Scaffold a new AST mutator class with tests and register it in the engine
argument-hint: <MutatorName> [scenario-module]
disable-model-invocation: true
user-invocable: true
---

# New Mutator Scaffold

Create a new AST mutator named `$ARGUMENTS`.

## Step 1: Choose the module

Pick the correct scenario module based on the mutator's purpose:

| Module | Purpose |
|--------|---------|
| `lafleur/mutators/generic.py` | General-purpose structural mutations (operator swap, constant perturbation, loop injection) |
| `lafleur/mutators/scenarios_types.py` | Type system and caching attacks (type instability, inline cache, MRO) |
| `lafleur/mutators/scenarios_control.py` | Control flow stress testing (deep calls, recursion, exception mazes, coroutines) |
| `lafleur/mutators/scenarios_data.py` | Data structure manipulation (dict pollution, comprehension bombs, magic methods) |
| `lafleur/mutators/scenarios_runtime.py` | Runtime state corruption (frame manipulation, GC stress, eval frame hooks) |

If the user specified a module as the second argument, use that. Otherwise, infer from the mutator name and purpose.

## Step 2: Implement the mutator class

Read the chosen module first to understand existing patterns. Then add the new class following one of these patterns:

### Pattern 1: Scenario Injection (preferred for complex mutations)

```python
class MyMutator(ast.NodeTransformer):
    """One-line description of what this mutator does."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if not node.name.startswith("uop_harness"):
            return node
        if random.random() < 0.1:  # Probabilistic application
            scenario = ast.parse(textwrap.dedent("""\
                # injected code here
            """)).body
            node.body = scenario + node.body
            ast.fix_missing_locations(node)
        return node
```

### Pattern 2: In-Place Modification (for simple transformations)

```python
class MyMutator(ast.NodeTransformer):
    """One-line description of what this mutator does."""

    def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
        if random.random() < 0.3:
            node.op = ast.Sub()
        return node
```

### Requirements

- Class must inherit from `ast.NodeTransformer`
- Must have a one-line docstring
- Must gate mutations with `random.random() < threshold` (typically 0.05-0.15)
- For `visit_FunctionDef`: check `node.name.startswith("uop_harness")` and skip non-harness functions
- Call `ast.fix_missing_locations(node)` after modifying node bodies
- Handle edge cases: empty function bodies, no variables available
- Use `textwrap.dedent()` for multi-line injected code

## Step 3: Register in engine.py

1. Add the import to `lafleur/mutators/engine.py` in the appropriate import block (sorted alphabetically within the block for the source module)
2. Add the class to the `self.transformers` list in `ASTMutator.__init__()`, placed near related mutators

## Step 4: Write tests

Add tests to the matching test file under `tests/mutators/`:

| Source module | Test file |
|--------------|-----------|
| `generic.py` | `tests/mutators/test_generic.py` |
| `scenarios_types.py` | `tests/mutators/test_scenarios_types.py` |
| `scenarios_control.py` | `tests/mutators/test_scenarios_control.py` |
| `scenarios_data.py` | `tests/mutators/test_scenarios_data.py` |
| `scenarios_runtime.py` | `tests/mutators/test_scenarios_runtime.py` |

Read the target test file first to follow the existing test class pattern. Every mutator test class needs:

1. **test_basic_mutation**: Apply the mutator with `random.random` patched low (e.g. 0.05), verify the AST is modified
2. **test_skipped_at_high_probability**: Patch `random.random` to return 0.99, verify no mutation applied
3. **test_produces_valid_code**: `ast.unparse(mutated_tree)` succeeds and `compile()` succeeds
4. **test_skips_non_harness_functions**: Functions not named `uop_harness*` are left unchanged
5. **test_handles_empty_body**: Empty function body doesn't crash the mutator

```python
class TestMyMutator(unittest.TestCase):
    def test_basic_mutation(self):
        code = textwrap.dedent("""\
            def uop_harness_test():
                x = 1
                y = x + 2
        """)
        tree = ast.parse(code)
        with patch("random.random", return_value=0.05):
            mutated = MyMutator().visit(tree)
        result = ast.unparse(mutated)
        # Assert mutation was applied...

    def test_skipped_at_high_probability(self):
        code = textwrap.dedent("""\
            def uop_harness_test():
                x = 1
        """)
        tree = ast.parse(code)
        original = ast.dump(tree)
        with patch("random.random", return_value=0.99):
            mutated = MyMutator().visit(tree)
        self.assertEqual(ast.dump(mutated), original)
```

## Step 5: Verify

Run these commands:

```bash
ruff format lafleur/mutators/<module>.py tests/mutators/<test_file>.py lafleur/mutators/engine.py
ruff check lafleur/mutators/<module>.py tests/mutators/<test_file>.py lafleur/mutators/engine.py
~/venvs/jit_cpython_venv/bin/python -m pytest tests/mutators/<test_file>.py -v -k TestMyMutator
~/venvs/jit_cpython_venv/bin/python -m pytest tests/ -v
```
