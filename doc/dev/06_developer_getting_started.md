# Lafleur Developer Documentation: 06. Getting Started

### Introduction

This document provides a practical, hands-on guide for a new developer to set up a complete `lafleur` fuzzing environment, from building the CPython target to running a fuzzing session and interpreting the results.

-----

### Prerequisites

Before you can run `lafleur`, you must set up a specific [CPython build environment](https://devguide.python.org/getting-started/setup-building/#setup-and-building). The fuzzer relies on a **debug build** of CPython with the [**experimental JIT compiler enabled**](https://github.com/python/cpython/blob/main/Tools/jit/README.md).

To make fuzzing easier and more effective, `lafleur` includes a script for adjusting JIT thresholds, so it's recommended to install it and then tune the JIT before building CPython a second time.

#### 1. CPython Build (1st time)

1.  **Clone the CPython Repository:** First, clone the CPython source code from the official repository. It is recommended to check out the specific commit or branch that `lafleur` is currently targeting to ensure compatibility.

    ```bash
    git clone https://github.com/python/cpython.git
    cd cpython
    ```

2.  **Configure the Build:** Configure the build to be a debug build (`--with-pydebug`) and enable the experimental JIT compiler.

    ```bash
    # From the root of the cpython directory
    ./configure --with-pydebug --enable-experimental-jit
    ```

3.  **Compile CPython:** Compile the source code. This may take a significant amount of time.

    ```bash
    make -j$(nproc)
    ```

4.  **Create a Virtual Environment:** After the build is complete, create a dedicated Python virtual environment using your newly-built interpreter. This ensures all dependencies are isolated.

    ```bash
    # From the cpython directory
    ./python -m venv ~/venvs/lafleur_venv
    ```

#### 2. `sudoers` Configuration for the `fusil` Seeder

`lafleur` uses the classic `fusil` fuzzer as a subprocess to generate initial seed files for the corpus. The `fusil` tool requires `root` privileges to operate correctly. To allow `lafleur` (running as a normal user) to call `fusil` with `sudo` without requiring a password prompt, you must add a specific rule to your system's `sudoers` configuration.

**Warning:** Always use the `visudo` command to edit this file. It performs a syntax check before saving to prevent you from being locked out of your system.

1.  Open the `sudoers` file for editing:

    ```bash
    sudo visudo
    ```

2.  Add the following line to the end of the file, replacing `your_username` and the paths with your actual system paths. **The paths must be absolute.**

    ```bash
    # Allow 'your_username' to run the fusil seed generator without a password
    your_username ALL=(ALL) NOPASSWD: /path/to/fusil/fuzzers/fusil-python-threaded
    ```

(This step will become unnecessary once fusil supports running in seeder mode without requiring root)

-----

### Installation and JIT tuning

Once the prerequisites are met, installing `lafleur` is straightforward.

1.  **Activate Your Virtual Environment:**

    ```bash
    source ~/venvs/lafleur_venv/bin/activate
    ```

2.  **Clone the `lafleur` Repository:**

    ```bash
    git clone https://github.com/devdanzin/lafleur.git
    cd lafleur
    ```

3.  **Perform an Editable Install:** Use `pip` to install `lafleur` in "editable" mode (`-e`). This allows you to edit the source code and have the changes immediately reflected without needing to reinstall.

    ```bash
    pip install -e .
    ```

4.  **Tune the JIT**: Configure JIT parameters, changing thresholds to make fuzzing more effective:

    ```bash
    lafleur-jit-tweak /path/to/cpython
    ```

5.  **CPython Build (2nd time)**: Rebuild CPython to get a properly tuned CPython JIT:

    ```bash
    cd /path/to/cpython
    make -j$(nproc)
    ```

-----

### Running the Fuzzer

With the project installed, you can run the fuzzer from any directory on your system, and subdirectories containing the corpus, coverage file, crashes etc. will be created in this directory. The `lafleur` command-line entry point is now available in your path.

#### Example Commands

  * **Starting a new run from scratch:**
    This command starts the fuzzer, tells it where to find the classic `fusil` seeder, and instructs it to generate at least 20 initial seed files before beginning the main evolutionary loop.

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --min-corpus-files 20
    ```

  * **Resuming an existing run:**
    If a corpus and state file already exist in your current directory, you can simply run `lafleur` without the `--min-corpus-files` argument. The fuzzer will automatically load the existing state and resume fuzzing.

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded
    ```

  * **Running in Differential Testing Mode:**
    To enable the "Paired Harness" mode for finding correctness bugs, add the `--differential-testing` flag.

    ```bash
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --differential-testing
    ```

  * **Running with Multiple Executions (for non-deterministic bugs):**
    To increase the chances of finding flaky, non-deterministic bugs, you can run each mutated test case multiple times.

    ```bash
    # Run each mutation 5 times with different internal random seeds
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --runs 5

    # Use dynamic run counts, where more promising parents are run more times
    lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --dynamic-runs
    ```

### Using the `state_tool.py`

The fuzzer's main state file, `coverage/coverage_state.pkl`, is a binary file that is not human-readable. The `state_tool.py` script is provided to inspect and convert this file. See [05_state_and_data_formats.md](./05_state_and_data_formats.md) for a description of this file's format and interesting fields.

  * **To view the state file as JSON:**

    ```bash
    python lafleur/state_tool.py coverage/coverage_state.pkl
    ```

  * **To convert the state file to a human-readable JSON file:**

    ```bash
    python lafleur/state_tool.py coverage/coverage_state.pkl coverage/pretty_state.json
    ```

### Interpreting the results

The main fuzzing results will be stored in three directories: `crashes/`, `timeouts/` and `divergences/`.

  * `crashes/` will contain scripts that terminated with an exit code other than 0, or which generated logs containing one of the interesting keywords such as `JITCorrectnessError` or `panic`. This is where we expect the valuable cases of abnormal termination due to JIT behavior will be recorded. The logs from executing such scripts are also stored here, allowing easy diagnostics of the cause of the crash. Since many crashes are of low value, the following command may be used to list logs that do not contain common strings for low value crashes and hence potentially contain high value crashes:

    ```bash
    grep -L -E "(statically|indentation|unsupported|formatting|invalid syntax)" crashes/*.log 
    ```

  * `timeouts/` will contain scripts and their respective logs that caused a timeout (default: 10 seconds) while executing, which might indicate interesting JIT behavior. Most common causes are infinite loops (e.g. from unpacking an object with a `__getitem__` that unconditionally returns a value) and too deeply nested `for` loops.

  * `divergences/` will contain scripts where the JITted and non-JITted versions of the same code resulted in different `locals()` at the end of execution. It's only populated when the `--differential-testing` flag is passed, and will also contain the logs from executing such scripts. This is where we expect the valuable cases of incorrectness due to JIT behavior to be recorded.
