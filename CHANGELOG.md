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

### Fixed

- Correctly delete all temporary files created by multiple runs, by @devdanzin.
- Avoid adding RNG seeding and GC tuning multiple times, by @devdanzin.
- Avoid double counting crashes, by @devdanzin.
- Avoid IndentationErrors after mutation with `GuardRemover`, by @devdanzin.
- Delete temporary compressed files, by @devdanzin.
- Avoid overwriting new files manually added to the corpus, by @devdanzin.
- Code generation bugs in FuzzerSetupNormalizer, DeepCallMutator and ExitStresser, by @devdanzin.
- Detect interestingness of manually added files to the corpus, by @devdanzin.
- Use `FuzzerSetupNormalizer` to remove extraneous GC and RNG tuning, by @devdanzin.
- Sanitize all blocks that would have an empty block to contain `pass`, by @devdanzin.
- Avoid overwriting crash files by giving them unique names, by @devdanzin.


## [0.0.1] - 2024-11-20

- Initial release of the `lafleur` evolutionary fuzzer.
- Core components: Orchestrator, Corpus Manager, AST Mutator, and Coverage Parser.
- Suite of JIT-specific mutation strategies.
- Differential testing mode for finding correctness bugs.
