# Lafleur Developer Documentation: 08. Testing

### Introduction

Reliability is critical for a fuzzer. If the fuzzer crashes, it cannot find bugs. If the coverage parser is inaccurate, the evolutionary search becomes random noise. Therefore, `lafleur` maintains a rigorous test suite covering everything from low-level AST mutations to high-level orchestration logic.

This document guides you through running the tests, understanding the test architecture, and writing new tests for your contributions. For development workflow including quality checks, see [06. Developer Getting Started](./06_developer_getting_started.md) and [CONTRIBUTING.md](../../CONTRIBUTING.md).

-----

### Running the Tests

The test suite is built using Python's standard `unittest` framework. Test configuration lives in `pyproject.toml`, which sets `testpaths = ["tests"]` and excludes directories like `cpython-src`, `.git`, `build`, and `venv` from test discovery.

Run the entire suite from the project root:

```bash
python -m unittest discover tests
```

Run a specific test file:

```bash
python -m unittest tests/mutators/test_engine.py
```

Run a specific test case:

```bash
python -m unittest tests.mutators.test_engine.TestASTMutator.test_mutate_with_seed
```

Run with coverage reporting:

```bash
coverage run -m unittest discover tests
coverage report
```

Tests are only one part of the quality check pipeline. Before submitting a PR, also run `ruff format --check .`, `ruff check .`, and `mypy lafleur/` as described in [CONTRIBUTING.md](../../CONTRIBUTING.md).

---

### Test Suite Architecture

The tests are organized to mirror the source code structure, with two main subdirectories (`tests/mutators/` and `tests/orchestrator/`) plus standalone test files in `tests/` for core modules and tooling.

#### 1. Mutator Tests (`tests/mutators/`)

This is the largest part of the suite. It verifies that the "Hands" of the fuzzer produce valid, deterministic, and "evil" Python code. See `tests/mutators/README.md` for coverage goals and `MUTATOR_TEST_PLAN.md` for detailed implementation status.

* **`test_engine.py`**: Tests the `ASTMutator` orchestration and the `SlicingMutator` optimization.
* **`test_generic.py`**: Tests standard mutations like `OperatorSwapper` or `BoundaryValuesMutator`.
* **`test_scenarios_types.py`**: Tests type system attack mutators (MRO manipulation, descriptors).
* **`test_scenarios_control.py`**: Tests control flow mutators (recursion depth attacks, exception storms).
* **`test_scenarios_data.py`**: Tests data structure mutators (builtin overrides, comprehension mutations).
* **`test_scenarios_runtime.py`**: Tests runtime manipulation mutators (frame injection, weakref abuse).
* **`test_utils.py`**: Tests utility transformers (instrumentation, normalization).
* **Key Pattern**: These tests heavily use `ast.parse()` to verify that mutated code is syntactically valid, and `unittest.mock.patch` on `random` to ensure mutations are deterministic. Each mutator file in `tests/mutators/` corresponds 1:1 with a source module in `lafleur/mutators/`.

#### 2. Orchestrator Tests (`tests/orchestrator/`)

These tests verify the "Brain" of the fuzzer — the evolutionary loop, scoring logic, and execution pipeline.

* **`test_execution.py`**: Mocks `subprocess.run` to verify child script assembly, timeout handling, and crash detection by `ExecutionManager`.
* **`test_coverage.py`**: Tests `ScoringManager.find_new_coverage` — global vs. relative discovery detection, empty coverage handling.
* **`test_scoring.py`**: Verifies the `InterestingnessScorer` math: richness bonus, density penalty, minimum score thresholds.
* **`test_jit_scoring.py`**: Tests JIT vitals scoring factors: zombie bonus (+50), tachycardia bonus, chain depth bonus (+10), stub bonus (+5), and stacked multi-factor scoring.
* **`test_jit_differential.py`**: Tests parent-relative density scoring — the delta and absolute tachycardia paths, minimum thresholds, and the condition where children must exceed their parent's instability.
* **`test_jit_clamping.py`**: Tests dynamic density clamping math (`min(parent × 5, child)`) and tachycardia decay (× 0.95).
* **`test_crash_detection.py`**: Tests `ArtifactManager` crash detection and artifact saving — signal-based crashes, keyword matching, session bundle creation, log compression.
* **`test_main_loop.py`**: Tests `execute_mutation_and_analysis_cycle`, deepening session sterility limits, run summary formatting, and the main CLI entry point.
* **`test_integration.py`**: End-to-end tests with real file I/O and temporary directories. Covers full mutation cycles, state persistence across orchestrator restarts, corpus bootstrapping, and timeout artifact saving.
* **`test_sniper_targeting.py`**: Tests that the harness function name is excluded from `watched_keys` passed to the Sniper strategy.

#### 3. Core Module Tests (`tests/`)

These files test standalone components and the coverage pipeline.

* **`test_coverage.py`**: Tests the "Eyes" of the fuzzer. Verifies regex patterns (`UOP_REGEX`, `HARNESS_MARKER_REGEX`, `RARE_EVENT_REGEX`), the state machine's attribution of edges to `TRACING`/`OPTIMIZED`/`EXECUTING` states, spurious UOP filtering, side exit tracking, multi-harness parsing, and `CoverageManager` integer ID mapping.
* **`test_learning.py`**: Tests the adaptive learning engine — score decay over attempts, weight floor enforcement, grace period behavior, and score persistence.
* **`test_corpus_manager.py`**: Tests `CorpusScheduler` heuristics and corpus pruning logic — subsumption detection, dry-run safety, and metadata mutation guards.

#### 4. Analysis and Tooling Tests (`tests/`)

These files test the post-run analysis tools and CLI entry points.

* **`test_analysis.py`**: Tests `CrashFingerprinter` — ASAN report parsing (heap-use-after-free, stack-buffer-overflow), assertion matching, signal detection, Python panic recognition, and fallback fingerprinting for unrecognized crash types.
* **`test_report.py`**: Tests `lafleur-report` generation — formatting helpers, JIT/ASAN status detection from build flags, duration calculation from metadata and stats.
* **`test_campaign.py`**: Tests `lafleur-campaign` — `CampaignAggregator` instance loading, crash deduplication across instances, registry enrichment, HTML report generation, and handling of many-instance campaigns.
* **`test_triage.py`**: Tests `lafleur-triage` — `CrashRegistry` database operations, instance discovery, crash import from campaign directories, interactive triage actions (set status, record issue), list/filter/show commands, and export/import.
* **`test_triage_display.py`**: Tests triage display formatting and presentation logic.
* **`test_state_tool.py`**: Tests state file inspection — JSON conversion, set-to-list serialization for JSON compatibility, and old-to-new format migration.
* **`test_cli_entry_points.py`**: Tests `main()` functions for `coverage.py`, `driver.py`, and `minimize.py` — argument parsing, error handling for missing files, and end-to-end execution.

#### 5. JIT Introspection Tests (`tests/`)

* **`test_driver_internals.py`**: Tests driver internals — `walk_code_objects` recursion and cycle detection, `snapshot_executor_state` baseline capture, mock executor pointer construction for controlled introspection testing.
* **`test_bloom_integration.py`**: Tests Bloom filter probing — verifies that `scan_watched_variables` is triggered when exit density is high and correctly identifies watched globals through the mock bloom filter.

---

### Best Practices for Contributors

When contributing code to `lafleur`, you are expected to add corresponding tests. For a full walkthrough of adding a new mutator with tests, see [07. Extending Lafleur](./07_extending_lafleur.md).

#### 1. Determinism is King

Fuzzing involves randomness, but **tests must be deterministic**.

* **Never** rely on actual `random.random()`.
* **Always** use `unittest.mock.patch` to force the RNG to return known values.
```python
@patch("random.random", return_value=0.05)
def test_my_mutation(self, mock_random):
    # ... logic that expects the mutation to trigger ...
```

#### 2. Verify Syntax Validity

If you write a new mutator, you **must** include a test case that parses the output.

```python
def test_produces_valid_code(self):
    # ... apply mutation ...
    try:
        ast.parse(mutated_code)
    except SyntaxError:
        self.fail("Mutator produced invalid Python syntax")
```

#### 3. Mock External Systems

Do not interact with the real filesystem or run real subprocesses unless you are writing an integration test (like those in `test_integration.py`).

* Use `tempfile.TemporaryDirectory()` when you need real files, and always clean up in `tearDown`.
* Mock `subprocess.run` to test execution logic without spawning processes.
* Use `unittest.mock.patch` on module-level constants (like `CORPUS_DIR`) to redirect file operations to temporary directories.

#### 4. Test the "Happy Path" and the "Safety Net"

* **Happy Path**: Does the mutator inject the code when the probability is met?
* **Safety Net**: Does the mutator *avoid* crashing when passed invalid input, an empty function, or a file with no loops?

#### 5. Test Coverage Goals

Each mutator or component should have tests that verify (from `tests/mutators/README.md`):
1. **Basic functionality** — the transformation is applied correctly.
2. **Probabilistic behavior** — respects random probability thresholds.
3. **Valid output** — produces parseable Python code.
4. **Edge cases** — empty bodies, missing variables, nested structures.
5. **Output quality** — generated code matches expected patterns.
