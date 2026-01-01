# Lafleur Developer Documentation: 07. Extending Lafleur

### Introduction

`lafleur` was designed with modularity in mind, making it straightforward for developers to contribute new ideas and enhance its bug-finding capabilities. The two primary ways to extend the fuzzer are by adding new mutation strategies or by improving its coverage signal with new rare event definitions.

This document provides a practical guide for both of these processes.

-----

### How to Add a New Mutator

The most impactful way to contribute to `lafleur` is to create a new mutator. The entire mutation engine is built on Python's `ast.NodeTransformer` class, making it easy to add new, targeted transformations.

The process involves three simple steps.

#### **Step 1: Create the Transformer Class**

Mutator classes are now organized by category in the `lafleur/mutators/` package.
* **Generic mutations** go in `lafleur/mutators/generic.py`.
* **Control flow attacks** go in `lafleur/mutators/scenarios_control.py`.
* **Data model attacks** go in `lafleur/mutators/scenarios_data.py`.
* **Runtime/State attacks** go in `lafleur/mutators/scenarios_runtime.py`.
* **Type system attacks** go in `lafleur/mutators/scenarios_types.py`.

Choose the appropriate file (or create a new one) and define your class inheriting from `ast.NodeTransformer`.

```python
# In lafleur/mutators/your_module.py

import ast
import random

class MyNewMutator(ast.NodeTransformer):
    """A clear, one-line docstring explaining the mutator's purpose."""

    # ... implementation goes here ...

```

#### **Step 2: Implement a Visitor Method**

The core logic of your mutator goes into one or more `visit_*` methods. The name of the method determines which type of AST node it will operate on.

There are two main patterns for creating mutators in `lafleur`:

1. **Scenario Injection (Safest):** This is the preferred pattern for complex mutations. The mutator operates on a `visit_FunctionDef` and injects a new, self-contained block of code into the function's body. This is robust and guaranteed not to create invalid syntax.

```python
def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
    # Probabilistically decide whether to apply the mutation
    if random.random() < 0.1:
        # 1. Create your new code as a string
        scenario_code = "print('New scenario injected!')"
        # 2. Parse it into AST nodes
        new_nodes = ast.parse(scenario_code).body
        # 3. Inject the nodes into the function
        node.body = new_nodes + node.body
        ast.fix_missing_locations(node)
    return node

```

2. **In-Place Modification:** For simpler mutations, you can directly modify the attributes of an AST node. This is used by mutators like `OperatorSwapper` or our `NumericMutator`. This is powerful but requires care to ensure the modification is always syntactically valid.

```python
def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
    # Modify the node directly
    if isinstance(node.op, ast.Add):
        node.op = ast.Sub()
    return node

```

#### **Step 3: Register the New Mutator**

The final step is to make the fuzzer aware of your new mutator. Open `lafleur/mutators/engine.py` and add your new class to the `self.transformers` list in `ASTMutator.__init__`. You will also need to import your class at the top of the file.

```python
# In lafleur/mutators/engine.py

from lafleur.mutators.your_module import MyNewMutator  # Import your class

class ASTMutator:
    def __init__(self):
        self.transformers = [
            # ... (existing mutators) ...
            MyNewMutator, # Add your new class here
        ]

```

Your new mutator will now be automatically picked up and used by the fuzzer's "Havoc" and "Spam" strategies.

-----

### How to Add New Rare Events

Improving the fuzzer's feedback signal is another easy and high-impact way to contribute. If you discover a new JIT log message that indicates a bailout, failure, or other interesting event, you can teach the fuzzer to recognize it.

1.  **Open `lafleur/coverage.py`.**

2.  **Find the `RARE_EVENT_REGEX` constant.**

3.  **Add your new string** to the regex using the `|` (OR) operator. For example, to add an event for the string "JIT optimization failed", you would change the regex like this:

```python
# In lafleur/coverage.py

RARE_EVENT_REGEX = re.compile(
    r"(_DEOPT|_GUARD_FAIL"
    r"|... (existing events) ..."
    r"|Confidence too low"
    r"|JIT optimization failed)" # <-- Add your new event here
)
```

The coverage parser will now recognize and record this new event, adding it to the fuzzer's feedback signal.

-----

### Code Style & Contributions

  * The project follows **PEP 8** for code style.
  * Please add **docstrings** to any new modules, classes, or functions you create, following the style established in the existing codebase.
  * The preferred contribution workflow is to fork the main repository **`https://github.com/devdanzin/lafleur`**, create a new branch for your feature, and submit a pull request with your changes.
