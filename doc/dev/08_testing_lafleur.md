# Lafleur Developer Documentation: 08. Testing

### Introduction

Reliability is critical for a fuzzer. If the fuzzer crashes, it cannot find bugs. If the coverage parser is inaccurate, the evolutionary search becomes random noise. Therefore, `lafleur` maintains a rigorous test suite covering everything from low-level AST mutations to high-level orchestration logic.

This document guides you through running the tests, understanding the test architecture, and writing new tests for your contributions.

-----

### Running the Tests

The test suite is built using Python's standard `unittest` framework. You can run the entire suite from the project root:

```bash
python -m unittest discover tests

```

To run a specific test file (e.g., just the mutator tests):

```bash
python -m unittest tests/mutators/test_engine.py

```

To run a specific test case:

```bash
python -m unittest tests.mutators.test_engine.TestASTMutator.test_mutate_with_seed

```

---

### Test Suite Architecture

The tests are organized to mirror the source code structure.

#### 1. Mutator Tests (`tests/mutators/`)

This is the largest part of the suite. It verifies that the "Hands" of the fuzzer produce valid, deterministic, and "evil" Python code.

* **`test_engine.py`**: Tests the `ASTMutator` orchestration and the `SlicingMutator` optimization.
* **`test_generic.py`**: Tests standard mutations like `OperatorSwapper` or `BoundaryValuesMutator`.
* **`test_scenarios_*.py`**: These files correspond 1:1 with the source modules. They verify the complex JIT attack patterns (e.g., `test_scenarios_control.py` tests recursion depth attacks).
* **Key Pattern**: These tests heavily use `ast.parse()` to verify that mutated code is syntactically valid, and `unittest.mock.patch` on `random` to ensure mutations are deterministic.

#### 2. Orchestrator Tests (`tests/orchestrator/`)

These tests verify the "Brain" of the fuzzer.

* **`test_execution.py`**: Mocks `subprocess.run` to verify that the child script is assembled correctly and that timeouts/crashes are caught.
* **`test_scoring.py`**: Verifies the math behind the `InterestingnessScorer` (richness bonus, density penalty).
* **`test_crash_detection.py`**: Ensures that artifacts (crashes, divergences) are saved to the correct directories and that logs are compressed.

#### 3. Core Module Tests (`tests/`)

These files test the remaining standalone components.

* **`test_coverage.py`**: Tests the "Eyes" of the fuzzer. It verifies that the regexes correctly parse JIT logs and that the state machine correctly attributes edges to `TRACING` or `OPTIMIZED` states.
* **`test_learning.py`**: Tests the adaptive learning engine, verifying that mutator scores decay correctly over time.
* **`test_corpus_manager.py`**: Tests the `CorpusScheduler` heuristics and the corpus pruning logic.

---

### Best Practices for Contributors

When contributing code to `lafleur`, you are expected to add corresponding tests.

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

Do not interact with the real filesystem or run real subprocesses unless absolutely necessary (e.g., in `test_integration.py`).

* Use `tempfile` if you need real files.
* Mock `subprocess.run` to test execution logic without spawning processes.

#### 4. Test the "Happy Path" and the "Safety Net"

* **Happy Path**: Does the mutator inject the code when the probability is met?
* **Safety Net**: Does the mutator *avoid* crashing when passed invalid input, an empty function, or a file with no loops?
