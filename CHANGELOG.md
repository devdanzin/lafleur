# Changelog

All notable changes to this project should be documented in this file.

## [0.1.x] - Unreleased

### Added

- GitHub Actions CI/CD workflow with lint, format, and JIT test jobs, by @devdanzin.
- An `UnpackingChaosMutator` that attacks JIT optimizations for `UNPACK_SEQUENCE` and `UNPACK_EX` by wrapping iterables in a chaotic iterator that lies about its length and changes behavior (grow, shrink, type_switch) after JIT warmup to trigger deoptimization bugs, by @devdanzin.
- A `PatternMatchingChaosMutator` that attacks JIT optimizations for structural pattern matching (`MATCH_MAPPING`, `MATCH_SEQUENCE`, `MATCH_CLASS`) by injecting classes with dynamic `__match_args__`, guards with side effects, type-switching subjects, walrus operators in guards, and converting `isinstance` checks and for-loop unpacking to match statements, by @devdanzin.
- A `ClosureStompMutator` that attacks JIT closure optimizations by injecting helper functions to randomly corrupt `func.__closure__[i].cell_contents`, invalidating type/value assumptions for nested functions, by @devdanzin.
- An `EvalFrameHookMutator` that targets the `set_eval_frame_func` rare event by installing/removing custom eval frame hooks mid-execution, by @devdanzin.
- A `ComprehensiveFunctionMutator` that systematically attacks all function modification rare events, by @devdanzin.

### Enhanced


### Fixed

- Filter SyntaxError/IndentationError crashes from invalid mutations, by @devdanzin.


## [0.1.0] - 2026-01-11

### Added

- A `bump_version.py` script to automate version update, by @smiyashaji.
- A `--timeout` CLI option for configurable script running timeouts, by @ShrayJP.
- A coverage hash to handle duplicated files with non-deterministic results, by @devdanzin.
- A `--runs` CLI option to determine how many times each test case is run, by @devdanzin.
- A `--dynamic-runs` CLI option to calculate number of runs based on parent score, by @devdanzin.
- A `GCInjector` mutator to lower GC thresholds inside the harness function, by @devdanzin.
- A way to prepend code lowering the GC thresholds to the test case, by @devdanzin.
- A `DictPolluter` mutator to attack global or local dict caches (dk_version), by @devdanzin.
- A `FunctionPatcher` mutator to attack function versioning and inlining caches, by @devdanzin.
- A `TraceBreaker` mutator to attack the JIT's ability to form superblocks using trace-unfriendly code, by @devdanzin.
- An `ExitStresser` mutator to attack the JIT's side-exit mechanism with loops containing many frequently taken branches, by @devdanzin.
- A `DeepCallMutator` to attack the JIT's trace stack limit by adding a chain of nested function calls, by @devdanzin.
- A `GuardRemover` mutator as a counterpoint to `GuardInjector`, by @devdanzin.
- Tests for mutators.py, by @devdanzin.
- A depth-first way of mutating code samples, by @devdanzin.
- A `--keep-temp-logs` CLI option to keep temporary log files, by @devdanzin.
- A `SlicingMutator` to only visit part of the AST of very big files, by @devdanzin.
- Pruning (`--prune-corpus -f`) of the corpus by removing files that are subsumed by others, by @devdanzin.
- A `BoundaryValuesMutator` that replaces numeric constants with interesting/boundary values, by @devdanzin.
- A `BlockTransposerMutator` that moves code blocks within a function body, by @devdanzin.
- An `UnpackingMutator` that transforms simple assignments into complex unpacking ones, by @devdanzin.
- A `DecoratorMutator` that wraps functions inside our harness with simple decorators, by @devdanzin.
- A `RecursionWrappingMutator` that wraps blocks of code in self-recursive functions, by @devdanzin.
- Support to fuzzing Python builds with `ASAN` enabled, by @devdanzin.
- A `DescriptorChaosGenerator` that injects a class with a stateful descriptor, by @devdanzin.
- A `MROShuffler`that injects a scenario which changes MRO after a while, by @devdanzin.
- A `FrameManipulator` that injects a function that modifies a local variable up the call stack, by @devdanzin.
- A `ComprehensionBomb` that runs a list comprehension over a stateful iterator, by @devdanzin.
- A `SuperResolutionAttacker` to stress the caches that the JIT uses for super() calls, by @devdanzin.
- A `CoroutineStateCorruptor` to create a coroutine where a local variable is corrupted, by @devdanzin.
- A `WeakRefCallbackChaos` to use a weakref callback that violates a variable's type assumption, by @devdanzin.
- An `ExceptionHandlerMaze` to add an exception with a metaclass to make except blocks stateful, by @devdanzin.
- A `BuiltinNamespaceCorruptor` to replace built-in functions with malicious versions, by @devdanzin.
- A `CodeObjectSwapper` to swap the code object of a function with that of another, by @devdanzin.
- A timing fuzzing mode to search for code samples where the JIT is slower than no JIT, by @devdanzin.
- An `analyze_uop_coverage.py` script to analyze and report on seen UOPs in our campaigns, by @devdanzin.
- A `SliceMutator` to add slices and slicing operations, by @devdanzin.
- The `--target-python` CLI option to run the fuzzing scripts on a different Python interpreter, by @devdanzin.
- A check that the target Python interpreter outputs the necessary JIT debug messages, by @devdanzin.
- A `PatternMatchingMutator` that injects match/case statements to target pattern matching UOPs, by @devdanzin.
- An `ArithmeticSpamMutator` that injects tight loops with arithmetic operations to target related UOPs, by @devdanzin.
- A `NewUnpackingMutator` targeting unpacking dicts and single element lists, by @devdanzin.
- A `StringInterpolationMutator` targeting string interpolation UOPs, by @devdanzin.
- An `ExceptionGroupMutator` targeting exception group UOPs, by @devdanzin.
- An `AsyncConstructMutator` targeting async construct UOPs, by @devdanzin.
- A `SysMonitoringMutator` targeting sys monitoring UOPs, by @devdanzin.
- A `ReentrantSideEffectMutator` that creates "rug pull" attacks on mutable containers by clearing them during access operations, by @devdanzin.
- A `ComparisonChainerMutator` that extends simple comparisons into chained comparisons to stress JIT stack management, by @devdanzin.
- A `ContextManagerInjector` that wraps code blocks in context managers to stress-test SETUP_WITH and exception propagation, by @devdanzin.
- An `ImportChaosMutator` that injects random standard library imports to alter memory layout and global state, by @devdanzin.
- A `LiteralTypeSwapMutator` that swaps literal constants with different-typed values to stress JIT type specialization and guards, by @devdanzin.
- A `YieldFromInjector` that targets generator suspension, `yield from` delegation, and stack unwinding during cleanup with try/finally blocks, by @devdanzin.
- A `RedundantStatementSanitizer` that removes consecutive identical statements probabilistically to control file size bloat from mutators like StatementDuplicator, by @devdanzin.
- A `LatticeSurfingMutator` that attacks the JIT's Abstract Interpretation Lattice by injecting objects that dynamically flip their `__class__` to stress-test `_GUARD_TYPE_VERSION` guards, by @devdanzin.
- A `BloomFilterSaturator` that exploits the JIT's global variable tracking by saturating the bloom filter (reaching the ~4096 mutation limit) and then modifying watched globals to trigger stale-cache bugs, by @devdanzin.
- A `StackCacheThrasher` that stresses the JIT's Stack Cache and Register Allocator by creating deeply nested right-associative expressions (8 levels) that force stack depth beyond the 3-item cache limit, triggering _SPILL and _RELOAD instructions, by @devdanzin.
- A `BoundaryComparisonMutator` that stresses the JIT's platform-specific assembly optimizers (Tools/jit/_optimizers.py) by generating edge-case comparisons (NaN vs NaN, NaN vs Inf, 0.0 vs -0.0) that force CPU flags into unusual states (like Parity Flag set) to expose incorrect branch inversion logic, by @devdanzin.
- An `AbstractInterpreterConfusionMutator` that stress-tests the JIT's specialized micro-ops (like _BINARY_OP_SUBSCR_LIST_INT) by wrapping subscript indices with _ChameleonInt (an int subclass that can raise exceptions during __index__() or __hash__()), verifying that the JIT correctly handles exceptions from within index conversion and unwinds properly, by @devdanzin.
- A `MaxOperandMutator` that stresses the JIT's Copy-and-Patch encoding by forcing EXTENDED_ARG bytecodes (300 local variables for LOAD_FAST > 255, or 200-statement blocks for jump offsets > 255), by @devdanzin.
- A `SessionFuzzingDriver` (`lafleur/driver.py`) and `--session-fuzz` CLI flag that enables "warm JIT" fuzzing. In this mode, scripts run sequentially in the same process via `exec()`, allowing JIT state (traces, caches, global watchers) to persist. The driver runs a parent script (warmup) followed by the child (attack), by @devdanzin.
- A `GlobalOptimizationInvalidator` that exploits the JIT's "Global-to-Constant Promotion" by training the JIT to trust a global variable (`range`), then swapping it for an `_EvilGlobal` callable class mid-loop (at iteration 1000 of 2000) to force complex deoptimization, by @devdanzin.
- A `CodeObjectHotSwapper` that targets `_RETURN_GENERATOR` opcode by training the JIT on `_gen_A()` generators (1000 warmup iterations), then swapping `_gen_A.__code__ = _gen_B.__code__` to force deoptimization when the JIT's cached metadata becomes stale, by @devdanzin.
- A `TypeShadowingMutator` that attacks `_GUARD_TYPE_VERSION` by training the JIT on a float variable, then using `sys._getframe().f_locals` to change its type to a string mid-loop (bypassing standard bytecodes), and triggering the type-specialized operation again, by @devdanzin.
- A `ZombieTraceMutator` that stresses the JIT's executor lifecycle management (`pycore_optimizer.h`) by rapidly creating and destroying JIT traces in a loop (50 iterations), defining hot functions that trigger Tier 2 compilation, then letting them go out of scope to test the `pending_deletion` linked list logic for `_PyExecutorObject` cleanup, by @devdanzin.
- **Session Crash Bundles**: Implemented comprehensive crash reporting for session fuzzing. Crashes now save the entire session lineage (warmup, polluters, attack script) and generate a `reproduce.sh` script for easy debugging, by @devdanzin.
- **The Mixer**: Enhanced session fuzzing with a strategy that probabilistically injects random "polluter" scripts from the corpus before the main test case to stress JIT caches and state, by @devdanzin.
- **JIT Introspection (EKG)**: Upgraded `driver.py` to inspect CPython's internal `_PyExecutorObject` using `ctypes`. This allows tracking granular JIT vitals such as zombie traces (`pending_deletion`), trace validity, and warmth, by @devdanzin.
- **Feedback-Driven Scoring**: Updated the orchestrator to parse and score JIT vitals. The fuzzer now actively rewards mutations that provoke high stress on the JIT, such as high side-exit counts (Tachycardia), deep trace chains (Hyper-Extension), and tiny compiled stubs, by @devdanzin.
- **Exit Density Metric**: Introduced a normalized metric (`exit_count / code_size`) to measure instability per instruction, avoiding bias towards large traces, by @devdanzin.
- **Differential Scoring**: Implemented a smart scoring rule where children are only rewarded if their instability (`max_exit_density`) is significantly worse than their parent's, preventing the fuzzer from getting stuck in local optima, by @devdanzin.
- **Dynamic Density Clamping**: Added a mechanism to clamp the saved instability metrics for the next generation, preventing massive outliers from creating impossible targets for future mutations, by @devdanzin.
- **Tier 3 Introspection**: Implemented Bloom Filter probing in `driver.py` to detect which globals and builtins the JIT is optimizing against, by @devdanzin.
- **Sniper Mutator**: A new targeted strategy that uses introspection data to surgically invalidate watched variables during execution, by @devdanzin.
- **Instance Metadata**: `lafleur/metadata.py` now generates `run_metadata.json` capturing hardware stats, build flags, and environment details for every run, by @devdanzin.
- **Runtime Telemetry**: Enhanced orchestrator to track and log system load, RSS memory usage, and disk consumption, by @devdanzin.
- **Lafleur Report**: A new CLI tool (`lafleur-report`) to generate human-readable summaries of individual fuzzing instances, by @devdanzin.
- **Corpus Analysis**: Automated calculation of evolutionary stats (lineage depth, sterile rate, tree topology) saved to `corpus_stats.json`, by @devdanzin.
- **Campaign Aggregator**: A new CLI tool (`lafleur-campaign`) to merge metrics from multiple instances into a fleet-wide dashboard, by @devdanzin.
- **HTML Campaign Reports**: `lafleur-campaign` can now generate self-contained, offline-capable HTML reports with visualizations, by @devdanzin.
- **Crash Registry**: A SQLite-based system (`lafleur/registry.py`) to track crash fingerprints, sightings, and reported issues over time, by @devdanzin.
- **Lafleur Triage**: A comprehensive CLI tool (`lafleur-triage`) for managing the crash registry, supporting interactive triage, issue recording, and import/export, by @devdanzin.
- **Regression Detection**: Campaign reports now integrate with the registry to automatically highlight regressions (fixed bugs that reappeared) and filter known noise, by @devdanzin.
- **Documentation**: Added `docs/TOOLING.md` covering the new analysis and triage workflows, by @devdanzin.


### Enhanced

- Timeout log files will be compressed with zstd if larger than 1MB, by @devdanzin.
- Mutations (`GuardInjector`) will add non-determinism again in a reproducible way, by @devdanzin.
- Give scores to mutators and reward those most successful, by @devdanzin.
- Use trace length and number of side exits in corpus scheduling, by @devdanzin.
- Record JIT state (executing, tracing or optimized) when collecting edges, by @devdanzin.
- Use `FuzzerSetupNormalizer` to make randomness reproducible, by @devdanzin.
- Do not record some known uninteresting crashes, by @devdanzin.
- Allow disabling tweaks when running `jit_tuner.py`, by @devdanzin.
- Store int ids for UOPs, edges, and rare events instead of strings in the coverage file, by @devdanzin.
- Make interestingness more strict based on scores calculated by `InterestingnessScorer`, by @devdanzin.
- Update calling of `fusil` to use `--only-generate` instead of `sudo`.
- Many mutators based on Claude suggestions, by @devdanzin.
- Differential testing mode to use different processes, by @devdanzin.
- Deeper analysis of differences in differential testing mode, by @devdanzin.
- Implemented statistical comparisons in timing fuzzing mode, by @devdanzin.
- Allow timing and differential modes to run together, by @devdanzin.
- Truncate timeout log files if they're too large, by @devdanzin.
- Truncate or compress timeout log files if they're too large, by @devdanzin.
- Record the reason for a crash (return code, signal, or keyword) in the filename, by @devdanzin.
- Break `mutator.py` into multiple modules in the `mutators` package, by @devdanzin.


### Fixed

- Correctly delete all temporary files created by multiple runs, by @devdanzin.
- Avoid adding RNG seeding and GC tuning multiple times, by @devdanzin.
- Avoid double counting crashes, by @devdanzin.
- Avoid IndentationErrors after mutation with `GuardRemover`, by @devdanzin.
- Delete temporary compressed files, by @devdanzin.
- Avoid overwriting new files manually added to the corpus, by @devdanzin.
- Code generation bugs in `FuzzerSetupNormalizer`, `DeepCallMutator` and `ExitStresser`, by @devdanzin.
- Detect interestingness of manually added files to the corpus, by @devdanzin.
- Use `FuzzerSetupNormalizer` to remove extraneous GC and RNG tuning, by @devdanzin.
- Sanitize all blocks that would have an empty block to contain `pass`, by @devdanzin.
- Avoid overwriting crash files by giving them unique names, by @devdanzin.
- UOP are validated against the set of known UOPs to avoid recording cut names, by @devdanzin.
- Wrong concatenation in `_execute_child` using escaped `"\\n"`, by @devdanzin.
- Wrong environment values in `_run_timed_trial` making JIT run mistakenly verbose, by @devdanzin.
- Not passing `reason` when detecting a divergence and then terminating, by @devdanzin.
- Not saving regressions to their separate directory, by @devdanzin.
- Errors trying to serialize objects JSON doesn't know how to encode, by @devdanzin.
- When a crash happens in a timed run, continue to the coverage run to try to record it, by @devdanzin.


## [0.0.1] - 2024-11-20

- Initial release of the `lafleur` evolutionary fuzzer.
- Core components: Orchestrator, Corpus Manager, AST Mutator, and Coverage Parser.
- Suite of JIT-specific mutation strategies.
- Differential testing mode for finding correctness bugs.
