# Changelog

All notable changes to this project should be documented in this file.

## [0.0.2] - Unreleased

### Added

- A `bump_version.py` script to automate version update, by @smiyashaji.
- A `--timeout` CLI option for configurable script running timeouts, by @ShrayJP.

### Enhanced

- Timeout log files will be compressed with zstd if larger than 1MB, by @devdanzin.

## [0.0.1] - 2024-11-20

- Initial release of the `lafleur` evolutionary fuzzer.
- Core components: Orchestrator, Corpus Manager, AST Mutator, and Coverage Parser.
- Suite of JIT-specific mutation strategies.
- Differential testing mode for finding correctness bugs.
