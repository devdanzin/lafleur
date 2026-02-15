# Lafleur Developer Documentation: 04. The Mutation Engine

### Introduction

The `lafleur/mutators/` package is the heart of the fuzzer's creative process. Unlike fuzzers that work on raw text or bytes, `lafleur` operates on the structural representation of Python code, the **Abstract Syntax Tree (AST)**. This allows for intelligent, syntactically correct, and highly complex transformations.

The engine is orchestrated by the `ASTMutator` class in `lafleur/mutators/engine.py`, which manages a pool of `ast.NodeTransformer` subclasses. When a parent test case is selected for mutation, the `MutationController` (in `lafleur/mutation_controller.py`) selects a strategy, passes the parent's AST through a randomized pipeline of these transformers, and produces a new child.

For a step-by-step guide on adding your own mutator, see [07. Extending Lafleur](./07_extending_lafleur.md).

-----

### Mutation Strategies

The `MutationController` selects one of five mutation strategies for each session. Strategy selection is itself adaptive — the learning engine tracks which strategies produce discoveries and weights future selection accordingly.

* **Deterministic**: Applies a small, seed-controlled pipeline of 1–3 randomly chosen transformers. Provides reproducible mutations for a given seed.

* **Havoc**: Applies a large stack of 15–50 transformers, each chosen independently by weighted random selection from the full pool. This is the primary exploration strategy, producing highly diverse mutations.

* **Spam**: Selects a single transformer and applies it 20–50 times repeatedly. This deeply exercises one attack pattern, useful for saturating a specific JIT subsystem.

* **Sniper**: A targeted strategy that uses JIT introspection data. When the Bloom filter probing system (see [03. Coverage and Feedback](./03_coverage_and_feedback.md)) detects which globals and builtins the JIT is watching, the `SniperMutator` surgically invalidates those specific watched variables during execution.

* **Helper+Sniper**: A combined strategy that first injects `_jit_helper_*` functions using the `HelperFunctionInjector`, then attacks those helpers with the `SniperMutator`. This solves a bootstrapping problem: the combined strategy gets credit for discoveries, allowing both the injection and attack mutators to co-evolve.

When a test case's function body exceeds 100 statements, the controller automatically applies the **slicing** optimization (described below) instead of traversing the full AST.

-----

### Adaptive Mutation Strategy

The selection of mutation strategies and individual transformers is guided by an adaptive, learning-based approach managed by the `MutatorScoreTracker` in `lafleur/learning.py`.

* **Reward on Success**: When a mutation leads to a new discovery (new coverage or a crash), the scores of the responsible strategy and transformers are incremented by a fixed reward.

* **Decay on Attempts**: Every 50 attempts (the `DECAY_INTERVAL`), all scores in the system are multiplied by a decay factor (default 0.995). Because decay is driven by attempts rather than successes, the system naturally favors mutators that succeed *relative to how often they are tried* — a mutator that succeeds once every 10 attempts will maintain a higher score than one that succeeds once every 100 attempts, even if the latter has more total successes.

* **Epsilon-Greedy Selection**: To balance exploration and exploitation, the fuzzer uses an epsilon-greedy strategy at both the strategy level and the individual transformer level. With probability epsilon (default 0.1), it **explores** by returning uniform weights across all candidates. Otherwise, it **exploits** by weighting selection toward high-scoring candidates.

* **Grace Period**: Candidates with fewer than `min_attempts` (default 10) receive a neutral weight of 1.0 regardless of their score. This prevents premature penalization of new or rarely-used mutators before enough data has been collected.

* **Weight Floor**: Even the lowest-scoring candidates maintain a minimum weight (0.05), ensuring that no mutator is ever completely starved of selection opportunities.

-----

### Code Normalization and Sanitization

Before mutations are applied, the parent's AST is run through pre-processing transformers to ensure consistency and prevent accumulation of fuzzer-injected code.

* **`FuzzerSetupNormalizer`** (in `lafleur/mutators/utils.py`): Scans the AST and removes any fuzzer-injected setup code from previous generations, such as `import gc`, `gc.set_threshold(...)`, and the `fuzzer_rng` initialization. This keeps the corpus clean and prevents redundant setup code from bloating test cases.

* **`EmptyBodySanitizer`** (in `lafleur/mutators/utils.py`): After all mutations are complete, this final pass finds any control flow statements (like `if` or `for`) that may have had their contents removed by other mutators and inserts a `pass` statement into their body. This guarantees the final generated code is always syntactically valid.

-----

### Slicing Strategy for Large Files

When a function's body grows beyond 100 statements, `lafleur` applies mutations to only a small, random slice of the AST instead of the entire tree. The `SlicingMutator` (in `lafleur/mutators/engine.py`) handles this:

1. A random slice of 25 statements is selected from the function's body.
2. A temporary, minimal AST module is created containing only this slice.
3. The normal mutation pipeline is applied to this small, temporary AST.
4. The full function body is reconstructed with the mutated slice placed back in its original position.

This significantly speeds up mutation of large files while ensuring that different parts of the test case are mutated over time.

-----

### The Mutator Pool

The `ASTMutator` maintains a pool of 76 transformer classes, organized across several source modules. Rather than listing every mutator individually (the pool grows with every release), this section describes each category, its attack philosophy, and representative examples.

> **Note**: The `SniperMutator` and `HelperFunctionInjector` are not in the main pool — they are applied through dedicated strategy stages by the `MutationController`.

#### Generic Mutators (`lafleur/mutators/generic.py`)

**~25 transformers** providing general-purpose AST transformations. These mutators don't target specific JIT subsystems but create structural diversity that can expose optimization bugs indirectly.

Attack patterns include:

* **Operator and comparison mutations**: `OperatorSwapper`, `ComparisonSwapper`, `ComparisonChainerMutator` — swap or extend arithmetic, bitwise, and comparison operators.
* **Constant and literal mutations**: `ConstantPerturbator`, `BoundaryValuesMutator`, `LiteralTypeSwapMutator` — perturb numeric constants, inject boundary values (MAX_INT, NaN, etc.), or swap literal types to stress type specialization guards.
* **Control flow restructuring**: `ForLoopInjector`, `BlockTransposerMutator`, `GuardInjector`, `GuardRemover` — wrap statements in loops, move code blocks, or inject/remove conditional guards.
* **Container and variable mutations**: `ContainerChanger`, `VariableSwapper`, `UnpackingMutator`, `NewUnpackingMutator` — change container types, swap variable names, or transform assignments into unpacking operations.
* **Code pattern generators**: `PatternMatchingMutator`, `SliceMutator`, `DecoratorMutator`, `RecursionWrappingMutator`, `StringInterpolationMutator`, `ArithmeticSpamMutator` — inject specific code patterns that target particular UOP families.
* **Specialized UOP targeting**: `AsyncConstructMutator`, `ExceptionGroupMutator`, `SysMonitoringMutator`, `ImportChaosMutator` — generate patterns that exercise specific, less commonly tested UOP categories.
* **Corpus hygiene**: `RedundantStatementSanitizer` — probabilistically removes consecutive identical statements to control bloat from mutators like `StatementDuplicator`.

#### Type System Attacks (`lafleur/mutators/scenarios_types.py`)

**~14 transformers** targeting the JIT's type speculation, inline caches, and class hierarchy assumptions.

Representative mutators:

* **`TypeInstabilityInjector`**: Finds a variable in a hot loop and injects a trigger that changes its type mid-loop (e.g., from `int` to `str`), forcing deoptimization.
* **`InlineCachePolluter`**: Creates megamorphic call sites to overwhelm the JIT's inline caches for method calls.
* **`MROShuffler`** / **`BasesRewriteMutator`**: Modify class `__bases__` at runtime to invalidate method resolution order caches, targeting the `set_bases` rare event.
* **`DynamicClassSwapper`**: Swaps objects between incompatible classes (different `__slots__`, MRO depths, etc.) to stress `_GUARD_TYPE_VERSION` guards, targeting the `set_class` rare event.
* **`TypeVersionInvalidator`**: Modifies class attributes at runtime (method injection, replacement, dict modification) to invalidate JIT type version caches.
* **`ComprehensiveFunctionMutator`**: Systematically attacks all function modification rare events (code swapping, defaults modification, closure manipulation).

Also includes: `LoadAttrPolluter`, `ManyVarsInjector`, `TypeIntrospectionMutator`, `FunctionPatcher`, `SuperResolutionAttacker`, `DescriptorChaosGenerator`, `CodeObjectSwapper`.

#### Data Model and Cache Attacks (`lafleur/mutators/scenarios_data.py`)

**~17 transformers** targeting the JIT's data structures, memory management, and internal caches.

Representative mutators:

* **`BloomFilterSaturator`**: Exploits the JIT's global variable tracking by saturating its Bloom filter (~4096 mutations) and then modifying watched globals to trigger stale-cache bugs.
* **`LatticeSurfingMutator`**: Injects objects that dynamically flip their `__class__` to stress the JIT's Abstract Interpretation Lattice and `_GUARD_TYPE_VERSION` guards.
* **`StackCacheThrasher`**: Creates deeply nested right-associative expressions that force stack depth beyond the JIT's 3-item cache limit, triggering `_SPILL` and `_RELOAD` instructions.
* **`AbstractInterpreterConfusionMutator`**: Wraps subscript indices with a `_ChameleonInt` (an `int` subclass that can raise exceptions during `__index__()`) to stress specialized micro-ops like `_BINARY_OP_SUBSCR_LIST_INT`.
* **`ZombieTraceMutator`**: Rapidly creates and destroys closures to stress the JIT's executor lifecycle and `pending_deletion` linked list.
* **`MagicMethodMutator`**: Uses "evil objects" with misbehaving magic methods (`__len__`, `__hash__`, `__iter__`) that violate the data model contracts the JIT relies on.

Also includes: `DictPolluter`, `GlobalOptimizationInvalidator`, `CodeObjectHotSwapper`, `TypeShadowingMutator`, `NumericMutator`, `IterableMutator`, `BuiltinNamespaceCorruptor`, `ComprehensionBomb`, `ReentrantSideEffectMutator`, `BoundaryComparisonMutator`, `UnpackingChaosMutator`.

#### Control Flow and Execution Path Attacks (`lafleur/mutators/scenarios_control.py`)

**~11 transformers** targeting the JIT's trace formation, side-exit handling, and exception processing.

Representative mutators:

* **`DeepCallMutator`**: Injects deeply nested function call chains targeting the JIT's trace stack limit (`TRACE_STACK_SIZE`).
* **`ExitStresser`**: Injects loops with many frequently-taken branches to force the JIT to manage numerous deoptimization points per trace.
* **`TraceBreaker`**: Injects "trace-unfriendly" code (dynamic calls, complex exception handling) that prevents the JIT from forming long superblocks.
* **`PatternMatchingChaosMutator`**: Converts `isinstance` checks and for-loop unpacking into structural pattern matching to stress `MATCH_MAPPING`, `MATCH_SEQUENCE`, and `MATCH_CLASS` opcodes.
* **`ExceptionHandlerMaze`**: Injects deeply nested `try/except` blocks with a stateful metaclass to stress exception handling and trace generation.

Also includes: `GuardExhaustionGenerator`, `MaxOperandMutator`, `RecursionWrappingMutator`, `ContextManagerInjector`, `YieldFromInjector`, `CoroutineStateCorruptor`.

#### Runtime State and Environment Attacks (`lafleur/mutators/scenarios_runtime.py`)

**~9 transformers** targeting the JIT's assumptions about the execution environment, frame state, and global runtime.

Representative mutators:

* **`EvalFrameHookMutator`**: Installs and removes custom eval frame hooks mid-execution, targeting the `set_eval_frame_func` rare event.
* **`RareEventStressTester`**: A meta-mutator that chains multiple JIT rare events (`set_class`, `set_bases`, `set_eval_frame_func`, `builtin_dict`, `func_modification`) in sequence to stress the JIT's ability to handle multiple simultaneous invalidations.
* **`FrameManipulator`**: Uses `sys._getframe()` to maliciously modify local variables in the caller's frame, attacking JIT assumptions about local state stability.
* **`SideEffectInjector`**: Injects a class whose `__del__` method alters a function's local state, testing deoptimization pathways through side effects.
* **`WeakRefCallbackChaos`**: Registers weakref callbacks that violate type assumptions when triggered by garbage collection.

Also includes: `StressPatternInjector`, `GCInjector`, `GlobalInvalidator`, `ClosureStompMutator`.

-----

### The Library of "Evil Objects"

To support the advanced JIT-specific mutators, `lafleur/mutators/utils.py` contains a suite of helper functions that generate source code for "evil" classes. The core concept is that these classes have stateful magic methods that intentionally violate Python's data model contracts to trick the JIT.

Key generators include:

* **`genStatefulLenObject`**: Generates a class whose `__len__` method returns different values on subsequent calls.
* **`genUnstableHashObject`**: Generates a class whose `__hash__` method is not constant, violating a core requirement for dictionary keys.
* **`genStatefulIterObject`**: Generates a class whose `__iter__` method returns iterators that change the type of yielded items mid-iteration.
* **`genStatefulBoolObject`**: Generates a class whose `__bool__` method alternates between `True` and `False`.
* **`genStatefulIndexObject`**: Generates a class whose `__index__` method returns different integers on each call.

These generators are used by mutators like `MagicMethodMutator` and `IterableMutator` to create objects that appear normal during the JIT's tracing phase but misbehave once optimized code runs.