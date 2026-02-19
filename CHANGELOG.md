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
- A `DynamicClassSwapper` that aggressively swaps objects between incompatible classes (built-in type subclasses, classes with/without `__slots__`, different MRO depths, incompatible `__dict__` attributes) to stress JIT type guards and deoptimization logic, targeting the `set_class` rare event, by @devdanzin.
- A `BasesRewriteMutator` that creatively manipulates `__bases__` tuples (removal, builtin injection, inheritance toggling, complete replacement) to attack MRO caching assumptions, targeting the `set_bases` rare event, by @devdanzin.
- A `TypeVersionInvalidator` that targets `_GUARD_TYPE_VERSION` by modifying class attributes at runtime (method injection, method replacement, attribute injection, dict modification) to invalidate JIT type caches, by @devdanzin.
- A `RareEventStressTester` meta-mutator that chains multiple JIT rare events (`set_class`, `set_bases`, `set_eval_frame_func`, `builtin_dict`, `func_modification`) in sequence to stress the JIT's ability to handle multiple invalidations, by @devdanzin.
- A `--no-ekg` CLI flag to disable JIT introspection (`_Py_GetJitEntries`) for CPython builds that lack it, enabling fuzzing on stock or older JIT builds, by @devdanzin.
- A **heartbeat mechanism** for campaign instance status detection using a file-based heartbeat written every 60 seconds, replacing the unreliable timestamp-age heuristic, by @devdanzin.
- A **HealthMonitor** observability system that logs adverse fuzzing events (parse failures, timeout streaks, corpus degradation, ignored crashes) to a structured JSONL log (`health_events.jsonl`) for diagnostic analysis, by @devdanzin.
- **Campaign-level health aggregation** with waste rate metrics, fleet health grading (Healthy/Degraded/Unhealthy), per-instance health in the leaderboard, and top-offender identification in both text and HTML reports, by @devdanzin.
- A **HEALTH section** in the instance report (`lafleur-report`) showing waste rate, event breakdown by category, top offender files, and ignored crash profile, by @devdanzin.
- A **hygiene mutator system** — a post-processing layer that applies mutators at fixed probabilities independent of the learning system, preventing feedback loops where corpus-maintenance mutators accumulate misleading rewards, by @devdanzin.
- An `ImportPrunerMutator` that removes accumulated import statements (both bare imports and try/except import blocks) to counteract import bloat from ImportChaosMutator, by @devdanzin.
- A **crash-attribution feedback system** with two-tier rewards: direct attribution (5× reward) for mutators in the crashing mutation and lineage attribution (2× reward) for mutators in the ancestry chain, giving the learning system a signal tied to actual bug discovery rather than just coverage, by @devdanzin.
- A **CRASH ATTRIBUTION section** in the instance report showing per-instance crash-productive mutators and lineage depth statistics, by @devdanzin.
- A **CRASH-PRODUCTIVE MUTATORS section** in the campaign report showing fleet-aggregated crash attribution rankings with combined scores matching the learning system's internal weighting, by @devdanzin.
- A `GeneratorFrameInliningMutator` that attacks the JIT's generator frame inlining optimization (`_FOR_ITER_GEN_FRAME`, `_SEND_GEN_FRAME`) by corrupting generator state across yield boundaries through six vectors: gi_frame local modification, send() type confusion, throw() at optimized points, yield-from delegation target corruption, generator resurrection via __del__, and concurrent exhaustion from multiple call sites, by @devdanzin.
- CLI argument plumbing tests verifying that all CLI options are correctly threaded through to their respective manager classes, by @devdanzin.
- A directory column in the campaign instance leaderboard for identifying instance paths, by @devdanzin.


### Enhanced

- `BuiltinNamespaceCorruptor` with test_optimizer.py-inspired attacks: direct `__builtins__["KEY"]` style modifications, `ModuleType` vs dict representation handling, and high-frequency builtin corruption (corrupting `len`, `isinstance`, and `type` simultaneously), by @devdanzin.
- `BloomFilterSaturator` with probe-based saturation detection, strategic global modifications, and multi-phase attacks (warmup, saturation, exploitation, verification) to better exploit the JIT's global variable tracking bloom filter, by @devdanzin.
- Legacy mode (non-session) crash handling now generates proper directory structure and `metadata.json` files, making legacy crashes visible to `lafleur-campaign` and `lafleur-triage` tools, by @devdanzin.
- `ImportChaosMutator` moved from the weighted learning pool to the hygiene layer at 15% fixed probability, preventing a runaway feedback loop where trivially novel import edges led to over-selection and corpus bloat, by @devdanzin.
- `RedundantStatementSanitizer` moved from the weighted learning pool to the hygiene layer at 5% fixed probability, ensuring consistent statement cleanup regardless of learning-system scoring, by @devdanzin.
- `StatementDuplicator` uncommented and added to the hygiene layer at 8% fixed probability, providing controlled JIT warming pressure through statement duplication without the unbounded growth that caused it to be disabled, by @devdanzin.
- Learning system now filters hygiene mutators from `record_success()` calls, preventing corpus-maintenance operations from accumulating misleading reward signals, by @devdanzin.
- Health event logging enriched with `parent_id`, mutation strategy, error excerpts, and sterile-file filtering in parent selection, by @devdanzin.


### Fixed

- Filter SyntaxError/IndentationError crashes from invalid mutations, by @devdanzin.
- Delta tachycardia scoring applied an eternal reward because `parent_jit_stats` used a different key name than what `_prepare_new_coverage_result` stored, causing every child to appear to have higher density than its parent, by @devdanzin.
- Delta tachycardia density threshold used a fixed minimum instead of a parent-relative calculation, making the bonus trivially easy to earn for any file above baseline, by @devdanzin.
- `SlicingMutator` mis-attributed coverage discoveries to the wrong transformers in the learning system because the slicing pipeline replaced the transformer list without preserving the original selection, by @devdanzin.
- JIT-induced `ast.unparse()` corruption could produce silently malformed Python source, now detected and handled gracefully with a re-parse verification step, by @devdanzin.
- `SyntaxError` false-positive filter was too broad, rejecting valid crashes whose log output happened to contain "SyntaxError" as a substring (e.g., in tracebacks about SyntaxError handling), causing instances to become stuck, by @devdanzin.
- Campaign report crashed when generating reports for instances with null JIT stats (e.g., from `--no-ekg` runs), by @devdanzin.
- Exit code 1 could fall through crash detection without being properly classified when the fingerprinter returned a non-`PYTHON_UNCAUGHT` type, by @devdanzin.
- File descriptor leak in the test suite caused by `MagicMock.__index__` returning 1, which led `shutil.copy` to interpret the mock as fd 1 (stdout) and close it during garbage collection, by @devdanzin.
- `ConstantPerturbator` crash when encountering certain constant node types during mutation, found during code review, by @devdanzin.
- Numerous mutator bugs across all modules found during systematic code review campaign: `TypeInstabilityInjector` scoping issues, `NumericMutator` `visit_Call` scoping bug, hardcoded variable names in three `scenarios_data` mutators, `ContainerChanger` probability distribution imbalance, `GuardInjector` over-wrapping, and others, by @devdanzin.
- Unparseable corpus files could poison the corpus and waste mutation cycles; now validated with `ast.parse()` before saving and unparseable parents are marked sterile so the scheduler deprioritizes them, by @devdanzin.


### Documentation

- Complete rewrite of **README.md** with proper project description, architecture overview, quick start guide, and campaign workflow documentation, by @devdanzin.
- Enriched **CREDITS.md** with detailed contributor attributions and contribution descriptions, by @devdanzin.
- Updated **CONTRIBUTING.md** with quality-gate checklist, AI-assisted development guidance, and changelog/credits update instructions, by @devdanzin.
- Complete rewrite of all eight **developer documentation** chapters (01–08) covering architecture, the evolutionary loop, coverage and feedback, the mutation engine, state formats, getting started, extending lafleur, and testing, by @devdanzin.



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
