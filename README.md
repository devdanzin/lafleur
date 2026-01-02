# lafleur

A feedback-driven, evolutionary fuzzer for the CPython JIT compiler.

`lafleur` is a specialized fuzzer designed to find crashes, correctness bugs, and hangs in CPython's experimental JIT compiler. Unlike traditional fuzzers that generate code randomly, `lafleur` uses a coverage-guided, evolutionary approach. It executes test cases, observes their effect on the JIT's behavior by analyzing verbose trace logs, and uses that feedback to guide its mutations, becoming progressively smarter at finding interesting code paths over time.

### Features

  * **Coverage-Guided:** Uses uop-edge coverage to intelligently guide the fuzzing process.
  * **AST-Based Mutation:** Mutates the structure of Python code directly, enabling complex and syntactically correct transformations.
  * **JIT-Specific Mutators:** Includes a library of mutation strategies specifically designed to attack common JIT compiler weaknesses like type speculation, inline caching, and guard handling.
  * **Differential Testing:** Features a mode to find silent correctness bugs by comparing the output of JIT-compiled code against the standard interpreter.
  * **Intelligent Scheduling:** Employs a multi-factor scoring system to prioritize fuzzing test cases that are fast, small, and have discovered rare or fertile code paths.

-----

### Installation and Setup

`lafleur` is a tool that requires a specific CPython build environment. Follow these steps carefully.

#### Step 1: CPython Prerequisite

`lafleur` must be run with a **debug build of CPython that has the experimental JIT compiler enabled**.

1.  **Clone CPython:**
    ```bash
    git clone https://github.com/python/cpython.git
    cd cpython
    ```
2.  **Configure & Build (First Pass):**
    ```bash
    ./configure --with-pydebug --enable-experimental-jit
    make -j$(nproc)
    ```
3.  **Create Virtual Environment:**
    ```bash
    ./python -m venv ~/venvs/lafleur_venv
    ```

#### Step 2: Install `lafleur` and Tune the JIT

With the venv created, you can now install `lafleur` and use its JIT-tuning tool.

1.  **Activate Your Virtual Environment:**
    ```bash
    source ~/venvs/lafleur_venv/bin/activate
    ```
2.  **Install `lafleur` from PyPI:**
    ```bash
    pip install lafleur
    ```
3.  **Tune the JIT:** Run the `lafleur` tuning script, pointing it at your CPython source directory. This modifies C header files to make the JIT more aggressive, which is ideal for fuzzing.
    ```bash
    lafleur-jit-tweak /path/to/your/cpython
    ```
4.  **Rebuild CPython:** Recompile CPython to apply the tuned settings.
    ```bash
    cd /path/to/your/cpython
    make -j$(nproc)
    ```

#### Step 3: `fusil` Seeder (Optional)

`lafleur` can use the classic `fusil` fuzzer to generate an initial set of interesting seed files. This is recommended but optional.

1.  **Install `fusil`:**
    ```bash
    git clone https://github.com/fusil-fuzzer/fusil.git
    cd fusil
    pip install .
    ```

  * **Alternative: Manual Seeding:** If you prefer not to install `fusil`, you can create a directory named `corpus/jit_interesting_tests/` in your working directory and place your own hand-crafted Python seed files inside it.

-----

### Usage

Once installed, you can run `lafleur` from any directory. It will create its output subdirectories (`corpus/`, `crashes/`, etc.) in the current working directory.

#### Basic Usage (Resuming a Run)

If a corpus already exists, this command will load the state and resume the fuzzing session.

```bash
# Don't forget to activate your venv first!
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded
```

#### Seeding a New Corpus

Use `--min-corpus-files` to instruct `lafleur` to call the `fusil` seeder until the corpus has at least 20 files before starting.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --min-corpus-files 20
```

#### Differential Testing

Use `--differential-testing` to enable the mode for finding silent correctness bugs.

```bash
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --differential-testing
```

-----

### Interpreting the Results

The most important findings from a fuzzing run will be saved in four directories:

  * **`crashes/`**: Contains scripts that caused a hard crash (e.g., SegFault) or raised a critical error. Each `.py` file is accompanied by a `.log` file containing the output from the crash.
  * **`timeouts/`**: Contains scripts that ran for too long (default \> 10 seconds), often indicating an infinite loop bug.
  * **`divergences/`**: When in `--differential-testing` mode, this contains scripts where the JIT's behavior differed from the standard interpreter's.
  * **`regressions/`**: When in `--timing-fuzz` mode, this contains scripts where the JIT-compiled execution was significantly slower than the standard interpreter.

A helpful command to filter out low-value crashes and find potentially interesting ones is:

```bash
grep -L -E "(statically|indentation|unsupported|formatting|invalid syntax)" crashes/*.log | sed 's/\.log$/.py/'
```

-----

### Contributing & Filing Issues

`lafleur` is an open-source project, and contributions are welcome.

To file a bug report or a feature request, please use the project's **[GitHub Issues](https://github.com/devdanzin/lafleur/issues)** page. When filing a bug, please include:

1.  The crashing test case (`.py` file).
2.  The full log file (`.log`).
3.  The commit hash of the CPython version you are fuzzing (you can paste the output of `python -VV`).

### History and the Name

`lafleur` began as an advanced feature set within the [fusil](https://github.com/devdanzin/fusil) project, which was created by Victor Stinner.

The name comes from the expression "la fleur au fusil", which matches the spirit with which the project was started.
