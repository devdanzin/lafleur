# Lafleur Developer Documentation: 07. Extending Lafleur

### Introduction

`lafleur` was designed with modularity in mind, making it straightforward for developers to contribute new ideas and enhance its bug-finding capabilities. The two primary ways to extend the fuzzer are by adding new mutation strategies or by improving its coverage signal with new rare event definitions.

This document provides a practical guide for both of these processes. For the contribution workflow, code formatting, and quality checks, see [CONTRIBUTING.md](../../CONTRIBUTING.md).

-----

### How to Add a New Mutator

The most impactful way to contribute to `lafleur` is to create a new mutator. The entire mutation engine is built on Python's `ast.NodeTransformer` class, making it easy to add new, targeted transformations.

#### **Step 1: Create the Transformer Class**

Mutator classes are organized by category in the `lafleur/mutators/` package:

* **Generic mutations** go in `lafleur/mutators/generic.py`.
* **Control flow attacks** go in `lafleur/mutators/scenarios_control.py`.
* **Data model attacks** go in `lafleur/mutators/scenarios_data.py`.
* **Runtime/State attacks** go in `lafleur/mutators/scenarios_runtime.py`.
* **Type system attacks** go in `lafleur/mutators/scenarios_types.py`.

Choose the appropriate file (or create a new one) and define your class inheriting from `ast.NodeTransformer`.

```python
# In lafleur/mutators/scenarios_data.py (or the appropriate category)

import ast
import random
import sys

class MyNewMutator(ast.NodeTransformer):
    """A clear, one-line docstring explaining the JIT weakness being targeted."""

    # ... implementation goes here ...
```

#### **Step 2: Implement a Visitor Method**

The core logic of your mutator goes into one or more `visit_*` methods. The name of the method determines which type of AST node it will operate on.

There are two main patterns for creating mutators in `lafleur`:

**Pattern 1: Scenario Injection (Preferred)**

This is the preferred pattern for complex JIT attack mutations. The mutator operates on `visit_FunctionDef`, scopes itself to the harness function, and injects a new, self-contained block of code. This is robust and guaranteed not to create invalid syntax.

```python
def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
    # IMPORTANT: Always visit children first so nested functions are processed.
    self.generic_visit(node)

    # CRITICAL: Only mutate the harness function. Without this guard,
    # your mutator will inject code into every function in the file —
    # including helper functions, nested functions, and setup code.
    # This was the #1 source of bugs found during code review.
    if not node.name.startswith("uop_harness"):
        return node

    if not node.body:
        return node

    # Probabilistically decide whether to apply the mutation.
    # Typical rates: 5-10% for heavy/invasive mutations, 15-25% for lighter ones.
    if random.random() < 0.15:
        # Use a unique prefix to avoid variable name collisions when
        # multiple mutators inject into the same function.
        prefix = f"myattack_{random.randint(1000, 9999)}"

        print(
            f"    -> Injecting my attack into '{node.name}'",
            file=sys.stderr,
        )

        # 1. Create your new code as a string
        scenario_code = f"""
warmup_{prefix} = 0
for _i_{prefix} in range(200):
    warmup_{prefix} += _i_{prefix}
# ... your JIT attack logic here ...
"""
        # 2. Parse it into AST nodes
        new_nodes = ast.parse(scenario_code).body
        # 3. Inject the nodes into the function body
        node.body = new_nodes + node.body
        # 4. Fix line numbers — required or the AST won't compile.
        ast.fix_missing_locations(node)

    return node
```

**Pattern 2: In-Place Modification**

For simpler mutations, you can directly modify the attributes of an AST node. This is used by mutators like `OperatorSwapper` or `BoundaryValuesMutator`. This is powerful but requires care to ensure the modification is always syntactically valid.

```python
def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
    # Modify the node directly
    if isinstance(node.op, ast.Add):
        node.op = ast.Sub()
    return node
```

> **Note:** In-place mutators that operate on general nodes (like `visit_BinOp`) will modify all matching nodes in the entire AST, not just those inside the harness. This is usually acceptable for simple, low-risk transformations. For anything that injects new code or restructures control flow, always use Pattern 1 with the harness scoping guard.

#### **Step 3: Register the New Mutator**

Make the fuzzer aware of your new mutator. Open `lafleur/mutators/engine.py` and add your new class to the `self.transformers` list in `ASTMutator.__init__`. You will also need to import your class at the top of the file.

```python
# In lafleur/mutators/engine.py

from lafleur.mutators.scenarios_data import MyNewMutator  # Import your class

class ASTMutator:
    def __init__(self):
        self.transformers = [
            # ... (existing mutators) ...
            MyNewMutator,  # Add your new class here
        ]
```

Your new mutator will now be automatically picked up and used by the fuzzer's "Havoc" and "Spam" strategies.

#### **Step 4: Write Tests**

Every new mutator must have corresponding tests. The test suite is documented in detail in [08. Testing](./08_testing_lafleur.md). At minimum, your tests should verify:

1. **Syntax validity**: The mutated code must parse without errors.
2. **Harness scoping**: The mutation only applies inside `uop_harness` functions.
3. **Determinism**: Tests must use `unittest.mock.patch` on `random` so results are reproducible.

Here's a minimal test template:

```python
# In tests/mutators/test_scenarios_data.py

import ast
import unittest
from unittest.mock import patch

from lafleur.mutators.scenarios_data import MyNewMutator


class TestMyNewMutator(unittest.TestCase):
    HARNESS_CODE = """
def uop_harness_test(x):
    y = x + 1
    return y
"""

    NON_HARNESS_CODE = """
def helper_func(x):
    y = x + 1
    return y
"""

    @patch("random.random", return_value=0.05)  # Force mutation to trigger
    def test_produces_valid_code(self, mock_random):
        tree = ast.parse(self.HARNESS_CODE)
        mutated = MyNewMutator().visit(tree)
        # Must not raise SyntaxError
        ast.parse(ast.unparse(mutated))

    @patch("random.random", return_value=0.05)
    def test_only_mutates_harness(self, mock_random):
        tree = ast.parse(self.NON_HARNESS_CODE)
        mutated = MyNewMutator().visit(tree)
        result = ast.unparse(mutated)
        # Should be unchanged — not a harness function
        self.assertNotIn("myattack_", result)
```

-----

### Common Pitfalls

These are the most frequent issues found during code review of existing mutators. Avoid them in your contributions.

**1. Missing harness scoping guard**

Without `if not node.name.startswith("uop_harness"): return node`, your `visit_FunctionDef` will inject code into every function in the file. This was the single most common bug class found during code review — 3 of 4 scenario modules had this issue.

**2. Forgetting `self.generic_visit(node)`**

If your `visit_FunctionDef` doesn't call `self.generic_visit(node)` before its logic, nested functions won't be visited by any other visitor methods in your transformer. Always call it first.

**3. Forgetting `ast.fix_missing_locations(node)`**

AST nodes created by `ast.parse()` have line/column numbers, but nodes you create manually (e.g., `ast.Assign(...)`) don't. `ast.fix_missing_locations(node)` copies the parent's location info to all children that lack it. Without it, `compile()` will raise a `TypeError` about missing line numbers.

**4. Variable name collisions**

If two mutators both inject a variable called `result` into the same function, the second will overwrite the first. Always use unique prefixes: `f"myprefix_{random.randint(1000, 9999)}"`.

**5. Not gating with a probability check**

A mutator that fires on every function it visits will dominate the mutation pipeline and bloat the output. Always wrap your logic in `if random.random() < rate:` with a rate between 0.05 and 0.25.

-----

### How to Add New Rare Events

Improving the fuzzer's feedback signal is another easy and high-impact way to contribute. If you discover a new JIT log message that indicates a bailout, failure, or other interesting event, you can teach the fuzzer to recognize it.

#### Finding New Events

New rare events can be discovered by:

* Reading CPython's JIT source code (`Python/optimizer.c`, `Python/optimizer_analysis.c`, `Python/ceval.c`) and searching for error messages, bailout strings, or `RARE_EVENT` macros.
* Analyzing verbose JIT logs (`PYTHON_LLTRACE=2 PYTHON_OPT_DEBUG=4`) from fuzzing runs and looking for messages that aren't already captured.
* Monitoring CPython's commit log for new JIT warning/bailout messages.

#### Adding the Event

1.  **Open `lafleur/coverage.py`.**

2.  **Find the `RARE_EVENT_REGEX` constant.**

3.  **Add your new string** to the regex using the `|` (OR) operator:

```python
# In lafleur/coverage.py

RARE_EVENT_REGEX = re.compile(
    r"(_DEOPT|_GUARD_FAIL"
    r"|... (existing events) ..."
    r"|Confidence too low"
    r"|JIT optimization failed)"  # <-- Add your new event here
)
```

The coverage parser will now recognize and record this new event, adding it to the fuzzer's feedback signal.

#### Verifying the Event

After adding the event, you can verify it's being triggered by running a fuzzing session and checking the coverage state:

```bash
# Run a short fuzzing session
lafleur --fusil-path /path/to/fusil/... --min-corpus-files 5

# Inspect the coverage state for your new event
python -m lafleur.state_tool dump coverage/coverage_state.pkl | grep "your_event_string"
```