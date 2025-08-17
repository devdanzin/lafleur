# Lafleur Developer Documentation: 04. The Mutation Engine

### Introduction

The `lafleur/mutator.py` module is the heart of the fuzzer's creative process. Unlike fuzzers that work on raw text or bytes, `lafleur` operates on the structural representation of Python code, the **Abstract Syntax Tree (AST)**. This allows for intelligent, syntactically correct, and highly complex transformations.

The engine is orchestrated by the `ASTMutator` class, which manages a library of `ast.NodeTransformer` subclasses. When a parent test case is selected for mutation, the orchestrator passes its AST to the `ASTMutator`, which applies a randomized pipeline of these transformers to generate a new and unique child.

### Adaptive Mutation Strategy

The selection of mutation strategies is not static. `lafleur` uses an adaptive, learning-based approach to focus its efforts on the mutators that are proving most effective. This entire system is managed by the `MutatorScoreTracker` in `lafleur/learning.py`.

* **`MutatorScoreTracker`**: This class is the core of the learning engine. It tracks the historical success of every mutator and high-level strategy (like "havoc" or "spam").

* **Decaying Scores**: When a mutation leads to a new discovery (new coverage or a crash), the scores of the mutators involved are increased. After every success, all scores in the system are multiplied by a **decay factor** (e.g., 0.995). This algorithm ensures that the system rewards mutators that have been successful *recently*, allowing the fuzzer's strategy to adapt as it explores different areas of the JIT's state space.

* **Epsilon-Greedy Selection**: To balance exploration and exploitation, the fuzzer uses an epsilon-greedy selection strategy. Most of the time, it **exploits** its knowledge by choosing a mutator from the top performers, weighted by their current score. However, with a small probability (epsilon), it **explores** by choosing a mutator completely at random from the entire pool. This guarantees that new or currently "cold" mutators still get a chance to run and prove their effectiveness.

### Code Normalization and Sanitization

Before mutations are applied, the parent's AST is first run through a series of pre-processing transformers to ensure consistency and prevent the accumulation of fuzzer-injected code.

* **`FuzzerSetupNormalizer`**: This transformer scans the AST and removes any fuzzer-injected setup code from previous generations, such as `import gc`, `gc.set_threshold(...)`, and the `fuzzer_rng` initialization. This keeps the corpus clean and prevents redundant setup code from bloating test cases.
* **`EmptyBodySanitizer`**: After all mutations are complete, this final pass is run on the AST. It finds any control flow statements (like `if` or `for`) that may have had their contents removed by other mutators and inserts a `pass` statement into their body. This is a critical step that guarantees the final generated code is always syntactically valid and prevents `IndentationError` crashes.

### Generic Mutators

This is a suite of simple, general-purpose mutators that provide basic structural changes to the code.

* **`OperatorSwapper`**: Swaps binary arithmetic and bitwise operators (e.g., `+` becomes `-`, `&` becomes `|`).
* **`ComparisonSwapper`**: Swaps comparison operators (e.g., `<` becomes `>=`, `==` becomes `!=`).
* **`ConstantPerturbator`**: Slightly modifies numeric and string constants (e.g., `100` becomes `101`, `"abc"` becomes `"abd"`).
* **`ContainerChanger`**: Changes container literal types (e.g., a `list` `[...]` becomes a `tuple` `(...)` or a `set` `{...}`).
* **`VariableSwapper`**: Swaps all occurrences of two variable names within a scope.
* **`ForLoopInjector`**: Finds a simple statement and wraps it in a `for` loop to make the operation "hot" for the JIT.
* **`GuardRemover`**: The opposite of `GuardInjector`, this mutator finds `if fuzzer_rng.random() < ...:` blocks and replaces them with their body, simplifying the control flow.

### JIT-Specific Mutators

This is a library of advanced mutators specifically designed to generate patterns that attack common JIT compiler optimizations and assumptions.

* **`StressPatternInjector`**: Injects a hand-crafted "evil snippet" into a function's body, such as one that corrupts a variable's type or deletes an attribute.
* **`GCInjector`**: Injects a call to `gc.set_threshold()` with a randomized, low value to increase garbage collection pressure on the JIT's memory management.
* **`DictPolluter`**: Attacks JIT dictionary caches (`dk_version`) by injecting loops that repeatedly add and delete keys from `globals()` or a local dictionary.
* **`FunctionPatcher`**: Attacks JIT function versioning. It injects a scenario that defines a simple nested function, calls it in a hot loop, and then redefines the function object or its `__defaults__` to invalidate the JIT's assumptions.
* **`TraceBreaker`**: Attacks the JIT's ability to form long, linear "superblocks" by injecting code known to be "trace-unfriendly," such as dynamic calls or complex exception handling.
* **`ExitStresser`**: Attacks the JIT's side-exit mechanism by injecting a loop with many frequently-taken `if/elif` branches, forcing the JIT to manage multiple deoptimization points for a single trace.
* **`DeepCallMutator`**: Attacks the JIT's trace stack limit by injecting a chain of deeply nested function calls with a precisely targeted depth based on the `TRACE_STACK_SIZE` constant found in CPython's source code.
* **`TypeInstabilityInjector`**: Attacks **type speculation**. It finds a variable in a hot loop and injects a trigger that changes the variable's type mid-loop (e.g., from `int` to `str`), forcing a deoptimization.
* **`SideEffectInjector`**: Attacks **state stability assumptions**. It injects a `FrameModifier` class whose `__del__` method can maliciously alter a function's local state to test deoptimization pathways.
* **`GuardExhaustionGenerator`**: Attacks **JIT guard tables**. It injects a loop over a polymorphic list and a long `if/elif` chain of `isinstance` checks to force the JIT to emit numerous guards.
* **`InlineCachePolluter`**: Attacks **inline caches (ICs)** for method calls by creating "megamorphic" call sites.
* **`LoadAttrPolluter`**: Attacks **`LOAD_ATTR` caches** by creating polymorphic access sites for attributes with the same name but different kinds (data, property, slot).
* **`ManyVarsInjector`**: Attacks **`EXTENDED_ARG` handling** by injecting a large number (>256) of local variables into a function.
* **`TypeIntrospectionMutator`**: Attacks optimizations for `isinstance` and `hasattr` by injecting scenarios that violate the JIT's assumptions about type stability.
* **`MagicMethodMutator`**: Attacks the JIT's data model assumptions by using "evil objects" with misbehaving magic methods (e.g., `__len__`, `__hash__`).
* **`NumericMutator`**: Attacks JIT optimizations for numeric built-ins (`pow`, `chr`, etc.) by providing them with tricky arguments that test edge cases and error handling paths.
* **`IterableMutator`**: Attacks the JIT's understanding of the iterator protocol by injecting scenarios with misbehaving iterators.
