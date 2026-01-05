# Lafleur Developer Documentation: 04. The Mutation Engine

### Introduction

The `lafleur/mutators/` package is the heart of the fuzzer's creative process. Unlike fuzzers that work on raw text or bytes, `lafleur` operates on the structural representation of Python code, the **Abstract Syntax Tree (AST)**. This allows for intelligent, syntactically correct, and highly complex transformations.

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

### Slicing Strategy for Large Files

To improve performance when mutating very large test cases, `lafleur` employs a meta-mutation strategy called slicing. When the orchestrator detects that a function's body has grown beyond a certain threshold (e.g., >100 statements), it can opt to apply a mutation pipeline to only a small, random slice of the AST instead of visiting the entire tree.

This process works as follows:
1. A random slice of the function's body is selected (e.g., 25 statements).
2. A temporary, minimal AST is created containing only this slice.
3. The normal mutation pipeline (e.g., "havoc" or "spam") is applied to this small, temporary AST.
4. The full function body is then reconstructed with the mutated slice placed back in its original position.

This strategy significantly speeds up the mutation of large files by avoiding a full, slow traversal of a huge AST, while still ensuring that different parts of the large test case are mutated over time.

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
* **`BuiltinNamespaceCorruptor`**: Attacks assumptions about built-in functions by replacing them (e.g., `len`, `isinstance`) with malicious proxies in the `builtins` namespace.
* **`ComprehensionBomb`**: Attacks nested iterator handling by running a list comprehension over a stateful iterator that changes behavior during iteration.
* **`CoroutineStateCorruptor`**: Attacks `async`/`await` state management by creating a coroutine that corrupts a local variable while suspended.
* **`ExceptionHandlerMaze`**: Attacks exception handling and trace generation by injecting deeply nested `try/except` blocks with a stateful metaclass that influences `isinstance` checks.
* **`FrameManipulator`**: Attacks stack frame integrity by injecting a function that uses `sys._getframe()` to modify a local variable in its caller's frame.
* **`WeakRefCallbackChaos`**: Attacks garbage collection reentrancy by registering a weakref callback that violates a variable's type assumption when triggered.
* **`DescriptorChaosGenerator`**: Attacks attribute access optimizations by injecting a class with a stateful descriptor that changes the type of the returned value on subsequent accesses.
* **`MROShuffler`**: Attacks method resolution order caches by injecting a scenario that changes a class's `__bases__` at runtime.
* **`SuperResolutionAttacker`**: Attacks `super()` call caching by mutating the class hierarchy during a hot loop of `super()` calls.
* **`CodeObjectSwapper`**: Attacks function execution by hot-swapping the `__code__` object of a function with that of another, incompatible function.
* **`SysMonitoringMutator`**: Attacks the `sys.monitoring` interactions by registering and unregistering tool IDs during execution.
* **`AsyncConstructMutator`**: Attacks async-specific UOPs by generating complex `async for` and `async with` patterns.
* **`GlobalOptimizationInvalidator`**: Attacks **"Global-to-Constant Promotion"**. It targets the JIT's optimization that treats globals (like `range`) as constants. It injects a hot loop that uses a global, then swaps that global for an incompatible object (e.g., a dummy callable) mid-execution, forcing a complex deoptimization or a crash if the guard fails.
* **`CodeObjectHotSwapper`**: Attacks the **`_RETURN_GENERATOR`** opcode. It compiles a generator function, then hot-swaps the function's `__code__` object with one from a different generator, and calls it again. This tests if the JIT holds onto stale `CodeObject` pointers or cached creation paths.
* **`TypeShadowingMutator`**: Attacks **`_GUARD_TYPE_VERSION`**. It tricks the JIT into optimizing a variable as one type (e.g., `float`), then uses `sys._getframe().f_locals` to overwrite that variable with an incompatible type (e.g., `str`) behind the JIT's back, immediately followed by an operation that requires the original type.
* **`ZombieTraceMutator`**: Attacks the **Executor Lifecycle** and memory management (`pending_deletion`). It rapidly creates and destroys closures (and their associated JIT traces) in a loop to stress the garbage collector and the JIT's linked list of executors, aiming to trigger Use-After-Free bugs or race conditions.

---

### The Library of "Evil Objects"

To support the advanced JIT-specific mutators, `mutator.py` also contains a suite of functions that generate the source code for "evil" classes. The core concept is that these classes have stateful "magic" methods that intentionally violate Python's data model contracts to trick the JIT.

Key examples include:
* **`genStatefulLenObject`**: Generates a class whose `__len__` method returns different values on subsequent calls.
* **`genUnstableHashObject`**: Generates a class whose `__hash__` method is not constant, violating a core requirement for dictionary keys.
* **`genStatefulIterObject`**: Generates a class whose `__iter__` method can return different kinds of iterators, for example, one that changes the type of the items it yields mid-iteration.