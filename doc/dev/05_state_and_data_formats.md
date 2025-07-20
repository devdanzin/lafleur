# Lafleur Developer Documentation: 05. State and Data Formats

### Introduction

During a fuzzing campaign, `lafleur` generates several files to store its persistent state, track statistics, and save its findings. This document provides a detailed reference for the structure and purpose of each of these files.

---

### `coverage_state.pkl`

This is the **most critical file** in the fuzzer. It is a binary file serialized using Python's `pickle` module and acts as the fuzzer's complete, persistent memory of all coverage information. It is saved atomically to prevent corruption. It contains a single dictionary with two top-level keys:

* **`global_coverage`**: A dictionary that serves as the master "bitmap" of all unique coverage points ever seen by the fuzzer across all runs. It contains three sub-keys: `uops`, `edges`, and `rare_events`, each mapping the coverage item (e.g., the string `_LOAD_ATTR->_STORE_ATTR`) to its total hit count.

* **`per_file_coverage`**: A dictionary where each key is a filename in the corpus (e.g., `"123.py"`) and the value is a rich metadata object describing that file. The metadata dictionary for each file contains the following keys:
    * `parent_id`: The filename of the parent test case that this file was mutated from. `None` for initial seed files.
    * `lineage_depth`: An integer representing how many generations of successful mutations led to this file.
    * `content_hash`: The SHA256 hash of the file's "core code," used for fast duplicate detection.
    * `discovery_time`: An ISO 8601 timestamp of when the file was added to the corpus.
    * `execution_time_ms`: The time in milliseconds the test case took to run during its discovery.
    * `file_size_bytes`: The size of the core code in bytes.
    * `total_finds`: A "fertility" score; the number of interesting children this parent has produced.
    * `is_sterile`: A boolean flag that is set to `True` if the parent has been mutated many times without producing any new discoveries.
    * `baseline_coverage`: A dictionary representing the coverage this specific file generated when it was discovered. It has the same structure as the `global_coverage` map (uops, edges, rare_events) but contains only the coverage from this one file.
    * `lineage_coverage_profile`: A set-based representation of the union of all coverage found in this file's entire ancestry. This is used for the "new relative coverage" check.

---

### `fuzz_run_stats.json`

This is a human-readable JSON file that acts as a high-level dashboard for the entire fuzzing campaign. It tracks cumulative statistics across all sessions.

Key fields include:
* `total_sessions`: The total number of parents selected for mutation.
* `total_mutations`: The total number of child test cases executed.
* `crashes_found`: The total number of unique crashes discovered.
* `timeouts_found`: The total number of unique timeouts discovered.
* `divergences_found`: The total number of unique correctness divergences found.
* `new_coverage_finds`: The total number of times a new, unique, interesting test case was added to the corpus.
* `average_mutations_per_find`: An efficiency metric calculated as `total_mutations / new_coverage_finds`.
* `global_seed_counter`: A persistent counter used to ensure every mutation attempt across all runs has a unique, deterministic seed.
* `corpus_file_counter`: A persistent counter used to generate unique integer filenames for new corpus files.

---

### `logs/timeseries_... .jsonl`

This is a time-series log file in the **JSON Lines** (`.jsonl`) format, meaning each line in the file is a complete, independent JSON object.

At regular intervals (e.g., every 10 sessions), the orchestrator takes a complete snapshot of the `fuzz_run_stats.json` file and appends it as a new line to this log. This creates a detailed historical record of the fuzzer's performance over the course of a single run, which can be easily parsed for post-run analysis and plotting.

---

### Output Directories

The fuzzer saves its findings—the valuable test cases that reveal bugs—into several output directories.

* **`corpus/`**: Contains the main collection of "interesting" test cases. Every file in this directory has discovered at least one new piece of JIT coverage and serves as a parent for future mutations.
* **`crashes/`**: Stores test cases that caused the Python interpreter to crash (e.g., with a segmentation fault) or that contained a keyword indicating a fatal error. Each saved test case is accompanied by its corresponding JIT log file.
* **`timeouts/`**: Stores test cases that caused the child process to hang, exceeding the execution timeout. This is often a sign of an infinite loop or a denial-of-service vulnerability.
* **`divergences/`**: When running in differential testing mode, this directory stores test cases that revealed a correctness bug—a silent divergence in behavior between the JIT-compiled code and the regular interpreter.
