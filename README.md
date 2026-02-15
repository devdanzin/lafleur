# lafleur

[![CI](https://github.com/devdanzin/lafleur/actions/workflows/main.yml/badge.svg)](https://github.com/devdanzin/lafleur/actions)
[![PyPI](https://img.shields.io/pypi/v/lafleur)](https://pypi.org/project/lafleur/)
[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

A feedback-driven, evolutionary fuzzer for the CPython JIT compiler.

`lafleur` is a specialized fuzzer designed to find crashes, correctness bugs, and hangs in CPython's experimental JIT compiler. Unlike traditional fuzzers that generate code randomly, `lafleur` uses a coverage-guided, evolutionary approach. It executes test cases, observes their effect on the JIT's behavior by analyzing verbose trace logs, and uses that feedback to guide its mutations, becoming progressively smarter at finding interesting code paths over time.

The name comes from the French expression *la fleur au fusil* which captures the spirit with which the project was started. `lafleur` began as an advanced feature set within the [fusil](https://github.com/devdanzin/fusil) project, created by Victor Stinner, before being spun off as a standalone tool.

## Features

  * **Coverage-Guided:** Uses stateful uop-edge coverage to track JIT behavior across tracing, optimized, and executing states, distinguishing between finding an edge in a new JIT state and finding a truly novel edge.
  * **60+ JIT-Specific Mutators:** A library of AST transformations targeting specific JIT weaknesses — type speculation, inline caching, guard handling, closure cells, frame introspection, and rare event triggers.
  * **Adaptive Learning:** An epsilon-greedy mutation engine that tracks which mutators discover new coverage and dynamically focuses on the most effective strategies, with decaying scores that favor recently successful techniques.
  * **Session Fuzzing:** Executes scripts in a shared process with "polluter" scripts to stress JIT state persistence, cache pollution, and memory layout — finding deep, state-dependent bugs that isolated execution misses.
  * **JIT Introspection:** Uses `ctypes` to inspect CPython's internal `_PyExecutorObject` structs at runtime, extracting exit density, zombie trace counts, and Bloom filter state to reward mutations that provoke JIT instability.
  * **Intelligent Scheduling:** Employs a multi-factor scoring system to prioritize test cases that are fast, small, and have discovered rare or fertile code paths.
  * **Campaign Toolchain:** Monitor individual instances, aggregate multi-core campaigns into dashboards, and triage crashes with a SQLite registry linked to GitHub issues.

-----

## Installation and Setup

`lafleur` requires a specific CPython build environment. Follow these steps carefully.

### Step 1: Build CPython with the JIT

`lafleur` must be run with a **debug build of CPython that has the experimental JIT compiler enabled**.

1.  **Clone CPython:**
    ```bash
    git clone https://github.com/python/cpython.git
    cd cpython
    ```
2.  **Configure & Build (first pass):**
    ```bash
    ./configure --with-pydebug --enable-experimental-jit
    make -j$(nproc)
    ```
3.  **Create a virtual environment:**
    ```bash
    ./python -m venv ~/venvs/lafleur_venv
    ```

### Step 2: Install `lafleur` and Tune the JIT

1.  **Activate your virtual environment:**
    ```bash
    source ~/venvs/lafleur_venv/bin/activate
    ```
2.  **Install `lafleur` from source (recommended):**
    ```bash
    git clone https://github.com/devdanzin/lafleur.git
    cd lafleur
    pip install -e .
    ```
    An editable install (`-e`) lets you stay up to date with `git pull` and is the recommended path for both users and developers. A release is also [available on PyPI](https://pypi.org/project/lafleur/) (`pip install lafleur`) but may lag behind the latest development version.

3.  **Tune the JIT:** Run the tuning script, pointing it at your CPython source directory. This lowers `JIT_THRESHOLD` and `trace_stack_size` in CPython's C headers to make the JIT compile sooner and with shallower trace stacks, which is ideal for fuzzing.
    ```bash
    lafleur-jit-tweak /path/to/your/cpython
    ```
4.  **Rebuild CPython** to apply the tuned settings:
    ```bash
    cd /path/to/your/cpython
    make -j$(nproc)
    ```

### Step 3: Seed the Corpus (Optional)

`lafleur` can use the classic `fusil` fuzzer to generate an initial set of interesting seed files. This is recommended but not required.

1.  **Install `fusil`:**
    ```bash
    git clone https://github.com/devdanzin/fusil.git
    cd fusil
    pip install .
    ```

If you prefer not to install `fusil`, you can create a directory named `corpus/jit_interesting_tests/` in your working directory and place your own hand-crafted Python seed files inside it.

> For the full developer setup guide — including session mode, multi-run execution, and detailed troubleshooting — see the [Developer Getting Started Guide](doc/dev/06_developer_getting_started.md).

-----

## Usage

Once installed, you can run `lafleur` from any directory. It will create its output subdirectories (`corpus/`, `crashes/`, etc.) in the current working directory. Don't forget to activate your venv first.

### Basic Usage (Resuming a Run)

If a corpus already exists, this command will load the state and resume the fuzzing session.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded
```

### Seeding a New Corpus

Use `--min-corpus-files` to call the `fusil` seeder until the corpus has at least 20 files before starting the main evolutionary loop.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --min-corpus-files 20
```

### Session Fuzzing (Stateful JIT Testing)

Use `--session-fuzz` to execute scripts in a shared process. This preserves JIT state across script boundaries, enabling "warm JIT" attacks where polluter scripts stress caches and memory layout before the mutated child runs.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --session-fuzz
```

### Targeting a Specific CPython Build

By default, `lafleur` uses the Python interpreter from your active virtual environment. Use `--target-python` to fuzz a different build.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --target-python /path/to/cpython/python
```

### Additional Options

| Option | Description |
|--------|-------------|
| `--runs N` | Run each mutated test case N times (useful for non-deterministic bugs) |
| `--dynamic-runs` | Automatically adjust run count based on parent score |
| `--timeout N` | Set script execution timeout in seconds (default: 10) |
| `--instance-name NAME` | Human-readable name for this fuzzing instance |
| `--deepening-probability P` | Probability of depth-first vs. breadth-first sessions (default: 0.2) |
| `--prune-corpus` | Analyze and report redundant corpus files, then exit |
| `--keep-tmp-logs` | Retain temporary log files for debugging |

-----

## Analysis & Triage

`lafleur` includes a suite of tools for monitoring fuzzing progress, aggregating campaign results, and managing crash discoveries over time.

| Tool | Purpose |
|------|---------|
| **`lafleur-report`** | Check the pulse of a running fuzzer. Generates health, coverage, and crash summaries for a single instance. |
| **`lafleur-campaign`** | Aggregate results from 50+ cores into one dashboard. Deduplicates crashes, produces fleet-wide metrics, and generates HTML reports. |
| **`lafleur-triage`** | Track regressions and known issues with a built-in SQLite database. Link crashes to GitHub issues and manage their lifecycle. |

### Quick Examples

```bash
# Single instance report
lafleur-report /path/to/instance

# Campaign dashboard with HTML output
lafleur-campaign runs/ --html report.html --registry crashes.db

# Interactive crash triage
lafleur-triage interactive
```

For detailed usage, see the [Analysis & Triage Workflow](docs/TOOLING.md) documentation.

-----

## Interpreting the Results

The most important findings from a fuzzing run will be saved in two directories:

  * **`crashes/`**: Contains scripts that caused a hard crash (e.g., SegFault) or raised a critical error. Each `.py` file is accompanied by a `.log` file containing the output from the crash.
  * **`timeouts/`**: Contains scripts that ran for too long (default > 10 seconds), often indicating an infinite loop bug.

> **Tip:** To filter out low-value crashes caused by invalid mutations and focus on potentially interesting ones you can filter out keywords that match uninteresting error messages like this:
> ```bash
> grep -L -E "(statically|indentation|unsupported|formatting|invalid syntax)" crashes/*.log | sed 's/\.log$/.py/'
> ```

-----

## Documentation

For a comprehensive understanding of `lafleur`'s internals, see the [Developer Documentation](doc/dev/00_index.md) — an 8-document series covering architecture, the evolutionary loop, coverage signals, the mutation engine, state formats, setup, extension, and testing.

-----

## Contributing & Filing Issues

`lafleur` is an open-source project, and contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide.

To file a bug report or a feature request, please use the project's [GitHub Issues](https://github.com/devdanzin/lafleur/issues) page. When filing a JIT bug found by `lafleur`, please include:

1.  The crashing test case (`.py` file).
2.  The full log file (`.log`).
3.  The commit hash of the CPython version you are fuzzing (you can get this with `python -VV`).
