# Changelog

All notable changes to this project should be documented in this file.

## [0.0.2] - Unreleased

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


## [0.0.1] - 2024-11-20

- Initial release of the `lafleur` evolutionary fuzzer.
- Core components: Orchestrator, Corpus Manager, AST Mutator, and Coverage Parser.
- Suite of JIT-specific mutation strategies.
- Differential testing mode for finding correctness bugs.
