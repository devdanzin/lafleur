# Lafleur Developer Documentation: 04. The Mutation Engine

### Introduction

The `lafleur/mutator.py` module is the heart of the fuzzer's creative process. Unlike fuzzers that work on raw text or bytes, `lafleur` operates on the structural representation of Python code, the **Abstract Syntax Tree (AST)**. This allows for intelligent, syntactically correct, and highly complex transformations.

The engine is orchestrated by the `ASTMutator` class. This class manages a library of `ast.NodeTransformer` subclasses, each of which implements a specific, self-contained mutation strategy. When a parent test case is selected for mutation, the orchestrator passes its AST to the `ASTMutator`, which applies a random pipeline of these transformers to generate a new and unique child.

---

### Generic Mutators

This is a suite of simple, general-purpose mutators that provide basic structural changes to the code.

* **`OperatorSwapper`**: Swaps binary arithmetic and bitwise operators (e.g., `+` becomes `-`, `&` becomes `|`).
* **`ComparisonSwapper`**: Swaps comparison operators (e.g., `<` becomes `>=`, `==` becomes `!=`).
* **`ConstantPerturbator`**: Slightly modifies numeric and string constants (e.g., `100` becomes `101`, `"abc"` becomes `"abd"`).
* **`ContainerChanger`**: Changes container literal types (e.g., a `list` `[...]` becomes a `tuple` `(...)` or a `set` `{...}`).
* **`VariableSwapper`**: Swaps all occurrences of two variable names within a scope.
* **`ForLoopInjector`**: Finds a simple statement and wraps it in a `for` loop to make the operation "hot" for the JIT.

---

### JIT-Specific Mutators

This is a library of advanced mutators specifically designed to generate patterns that attack common JIT compiler optimizations and assumptions.

* **`StressPatternInjector`**: Injects a hand-crafted "evil snippet" into a function's body, such as one that corrupts a variable's type or deletes an attribute.
* **`TypeInstabilityInjector`**: Attacks **type speculation**. It finds a variable in a hot loop and injects a trigger that changes the variable's type mid-loop (e.g., from `int` to `str`), forcing a deoptimization.
* **`GuardExhaustionGenerator`**: Attacks **JIT guard tables**. It injects a loop over a polymorphic list of objects and a long `if/elif` chain of `isinstance` checks, forcing the JIT to emit numerous guards.
* **`InlineCachePolluter`**: Attacks **inline caches (ICs)** for method calls. It injects a scenario with several classes that share a method name, then calls that method on instances of each class inside a hot loop, creating a "megamorphic" call site.
* **`SideEffectInjector`**: Attacks **state stability assumptions**. It injects a `FrameModifier` class whose `__del__` method can maliciously alter a function's local state. It then triggers this `__del__` method from within a hot loop to test the JIT's deoptimization pathways.
* **`GlobalInvalidator`**: Attacks **global versioning caches**. It injects a statement that directly modifies the `globals()` dictionary, forcing an invalidation of JIT caches that depend on it.
* **`LoadAttrPolluter`**: Attacks **`LOAD_ATTR` caches**. It injects several classes that define the same attribute name in different ways (data, property, slot) and then accesses that attribute in a hot loop.
* **`ManyVarsInjector`**: Attacks **`EXTENDED_ARG` handling**. It injects a large number (>256) of local variable declarations into a function to stress the interpreter's and JIT's handling of large stack frames.
* **`TypeIntrospectionMutator`**: Attacks optimizations for built-ins like `isinstance` and `hasattr` by injecting scenarios that violate the JIT's assumptions about type stability.
* **`MagicMethodMutator`**: Attacks the JIT's data model assumptions by injecting scenarios that use objects with misbehaving magic methods (e.g., `__len__`, `__hash__`, `__iter__`).
* **`NumericMutator`**: Attacks JIT optimizations for numeric built-ins (`pow`, `chr`, `abs`, etc.) by providing them with tricky arguments that test edge cases and error handling paths.
* **`IterableMutator`**: Attacks the JIT's understanding of the iterator protocol by injecting scenarios that use misbehaving iterators with built-ins like `tuple()`, `all()`, and `min()`.

---

### The Library of "Evil Objects"

To support the advanced JIT-specific mutators, `mutator.py` also contains a suite of functions that generate the source code for "evil" classes. The core concept is that these classes have stateful "magic" methods that intentionally violate Python's data model contracts to trick the JIT.

Key examples include:
* **`genStatefulLenObject`**: Generates a class whose `__len__` method returns different values on subsequent calls.
* **`genUnstableHashObject`**: Generates a class whose `__hash__` method is not constant, violating a core requirement for dictionary keys.
* **`genStatefulIterObject`**: Generates a class whose `__iter__` method can return different kinds of iterators, for example, one that changes the type of the items it yields mid-iteration.
