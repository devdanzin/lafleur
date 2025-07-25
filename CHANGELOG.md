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


### Enhanced

- Timeout log files will be compressed with zstd if larger than 1MB, by @devdanzin.
- Mutations (`GuardInjector`) will add non-determinism again in a reproducible way, by @devdanzin.

## [0.0.1] - 2024-11-20

- Initial release of the `lafleur` evolutionary fuzzer.
- Core components: Orchestrator, Corpus Manager, AST Mutator, and Coverage Parser.
- Suite of JIT-specific mutation strategies.
- Differential testing mode for finding correctness bugs.
