# Lafleur Developer Documentation: 06. Getting Started

### Introduction

This document provides a practical, hands-on guide for a new developer to set up a complete `lafleur` fuzzing environment, from building the CPython target to running a fuzzing session and interpreting the results.

For the high-level architecture and module breakdown, see [01. Architecture Overview](./01_architecture_overview.md). For the contribution workflow and code quality guidelines, see [CONTRIBUTING.md](../../CONTRIBUTING.md).

-----

### Prerequisites

Before you can run `lafleur`, you must set up a specific [CPython build environment](https://devguide.python.org/getting-started/setup-building/#setup-and-building). The fuzzer relies on a **debug build** of CPython with the [**experimental JIT compiler enabled**](https://github.com/python/cpython/blob/main/Tools/jit/README.md).

To make fuzzing easier and more effective, `lafleur` includes a script for adjusting JIT thresholds, so it's recommended to install it and then tune the JIT before building CPython a second time.

#### 1. CPython Build (1st time)

1.  **Clone the CPython Repository:** Clone the CPython source code from the official repository. It is recommended to check out the specific commit or branch that `lafleur` is currently targeting to ensure compatibility.

    ```bash
    git clone https://github.com/python/cpython.git
    cd cpython
    ```

2.  **Configure the Build:** Configure as a debug build (`--with-pydebug`) and enable the experimental JIT compiler.

    ```bash
    ./configure --with-pydebug --enable-experimental-jit
    ```

    **Optional — ASAN build:** To find memory safety bugs (use-after-free, buffer overflows), add the AddressSanitizer flag:

    ```bash
    ./configure --with-pydebug --enable-experimental-jit --with-address-sanitizer
    ```

3.  **Compile CPython:**

    ```bash
    make -j$(nproc)
    ```

4.  **Create a Virtual Environment:** Create a dedicated virtual environment using your newly-built interpreter.

    ```bash
    ./python -m venv ~/venvs/lafleur_venv
    ```

-----

### Installation and JIT Tuning

1.  **Activate Your Virtual Environment:**

    ```bash
    source ~/venvs/lafleur_venv/bin/activate
    ```

2.  **Clone and Install `lafleur`:** Install in editable mode so code changes take effect immediately without reinstalling.

    ```bash
    git clone https://github.com/devdanzin/lafleur.git
    cd lafleur
    pip install -e .
    ```

3.  **Tune the JIT:** Configure JIT parameters (`JIT_THRESHOLD`, `trace_stack_size`) to make fuzzing more effective:

    ```bash
    lafleur-jit-tweak /path/to/cpython
    ```

4.  **CPython Build (2nd time):** Rebuild CPython to apply the tuned settings:

    ```bash
    cd /path/to/cpython
    make -j$(nproc)
    ```

#### fusil Seeder (Optional)

`lafleur` can use the classic `fusil` fuzzer to generate an initial set of interesting seed files. This step is recommended but optional.

```bash
git clone https://github.com/devdanzin/fusil.git
cd fusil
pip install .
```

If you prefer not to install `fusil`, you can create a directory named `corpus/jit_interesting_tests/` in your working directory and place your own hand-crafted Python seed files inside it.

-----

### Running the Fuzzer

With the project installed, you can run the fuzzer from any directory. Output subdirectories (`corpus/`, `crashes/`, `coverage/`, etc.) will be created in the current working directory.

#### Example Commands

  * **Starting a new run from scratch:**

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --min-corpus-files 20
    ```

  * **Resuming an existing run:**

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded
    ```

  * **Session fuzzing (JIT state fuzzing):** Executes scripts in a shared process with random "polluter" scripts to stress the JIT's cache and memory management. Highly effective for finding optimization invalidation bugs and Use-After-Free in executor lifecycles.

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --session-fuzz
    ```

  * **Using a different CPython build:** If you have multiple CPython builds (e.g., one with ASAN, one without), point lafleur at a specific interpreter:

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --target-python /path/to/cpython/python
    ```

  * **Multiple executions (for non-deterministic bugs):**

    ```bash
    # Run each mutation 5 times
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --runs 5

    # Use dynamic run counts based on parent score
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --dynamic-runs
    ```

  * **Retaining logs for analysis:**

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --keep-tmp-logs
    ```

-----

### Development Workflow

When working on `lafleur` itself, use these quality checks before committing:

```bash
ruff format .                        # Format code
ruff check .                         # Lint for errors
mypy lafleur/                        # Type-check (optional but encouraged)
python -m unittest discover tests    # Run the test suite
```

For the full contribution workflow, commit message conventions, and PR process, see [CONTRIBUTING.md](../../CONTRIBUTING.md). For details on the test architecture and writing new tests, see [08. Testing](./08_testing_lafleur.md).

-----

### Interpreting the Results

The most important findings from a fuzzing run will be saved in two directories:

  * **`crashes/`**: Contains scripts that caused a hard crash (e.g., SegFault) or raised a critical error. Each `.py` file is accompanied by a `.log` file containing the output from the crash. Since many crashes are of low value (syntax errors from mutations), use this command to filter for potentially high-value crashes:

    ```bash
    grep -L -E "(statically|indentation|unsupported|formatting|invalid syntax)" crashes/*.log | sed 's/\.log$/.py/'
    ```

  * **`timeouts/`**: Contains scripts and their logs that caused a timeout (default: 10 seconds) while executing, which might indicate interesting JIT behavior. Most common causes are infinite loops (e.g., from unpacking an object with a `__getitem__` that unconditionally returns a value) and too deeply nested `for` loops.

-----

### Corpus Maintenance

Over a long fuzzing campaign, the corpus can grow large with many redundant test cases. `lafleur` includes a tool to prune the corpus by finding and removing files whose coverage is a subset of other, more efficient files.

* **Dry run** (reports which files would be deleted without touching them):

    ```bash
    lafleur --prune-corpus
    ```

* **Permanently delete** redundant files (**irreversible**):

    ```bash
    lafleur --prune-corpus --force
    ```

-----

### Using the State Tool

The fuzzer's main state file, `coverage/coverage_state.pkl`, is a binary file that is not human-readable. The `state_tool` module is provided to inspect, convert, and migrate this file.

* **View the state file as JSON:**

    ```bash
    python -m lafleur.state_tool coverage/coverage_state.pkl
    ```

* **Convert to a JSON file:**

    ```bash
    python -m lafleur.state_tool coverage/coverage_state.pkl coverage/pretty_state.json
    ```

* **Migrate an old state file** (string-based to integer-based format):

    ```bash
    python -m lafleur.state_tool /path/to/old_state.pkl /path/to/new_state.pkl
    ```

-----

### Minimizing Crashes

When `lafleur` finds a crash in **Session Mode**, it saves a bundle of scripts (e.g., `00_polluter.py`, `01_warmup.py`, `02_attack.py`). Minimizing these manually is difficult because the crash often depends on the specific sequence of JIT operations triggered by the earlier scripts.

`lafleur` provides a specialized minimization tool to automate this process. It uses **Crash Fingerprinting** (matching the exact assertion or ASan error) to ensure the bug is preserved, and leverages [**ShrinkRay**](https://github.com/DRMacIver/shrinkray) to reduce the code.

**Prerequisites:**

```bash
pip install shrinkray
```

**Usage:**

```bash
python -m lafleur.minimize crashes/session_crash_20250106_120000_1234
```

**What it does:**

1. **Script Reduction:** Determines which scripts in the session are strictly necessary. If the polluter script isn't needed to trigger the crash, it is removed.
2. **Consolidation:** Attempts to merge all necessary scripts into a single file (`combined_repro.py`), renaming harness functions to avoid collisions.
3. **Code Reduction:** Runs ShrinkRay to delete unused lines and simplify the code.

**Output:**

* `reproduce_minimized.sh`: A shell script that runs the minimal set of files needed to reproduce the crash.
* `combined_repro.py` (if successful): A single-file Minimal Reproducible Example (MRE).

-----

### Tooling for Analysis

After running fuzzing sessions, use `lafleur`'s analysis tools to verify results and track findings.

#### Verifying Local Test Runs

Use `lafleur-report` to quickly check the health of your local fuzzing instance:

```bash
lafleur-report
lafleur-report /path/to/instance
```

This shows execution speed, coverage progress, and a summary of unique crashes found.

#### Campaign Analysis and Triage

For multi-instance campaigns and crash management, see the full [Analysis & Triage Workflow](../../docs/TOOLING.md) documentation, which covers `lafleur-campaign` for aggregating metrics across instances and `lafleur-triage` for tracking crashes and linking them to GitHub issues.

-----

### Next Steps

With your environment set up and the fuzzer running, here are the most useful next documents:

* [01. Architecture Overview](./01_architecture_overview.md) — understand the system design
* [04. The Mutation Engine](./04_mutation_engine.md) — understand how test cases are generated
* [07. Extending Lafleur](./07_extending_lafleur.md) — add your own mutators
* [08. Testing](./08_testing_lafleur.md) — run and write tests
