# Lafleur Developer Documentation: 03. Coverage and Feedback Signal

### Introduction

A feedback-driven fuzzer is only as good as the signal it receives. This document details the "eyes" of `lafleur`: the entire pipeline from raw JIT log output to the structured coverage data that informs the fuzzer's evolutionary strategy. This process is the key to how `lafleur` learns from its mutations and improves over time.

-----

### The JIT Log

The entire feedback process begins by capturing the verbose debug output from CPython's JIT compiler. `lafleur` achieves this by executing every child process with two specific environment variables set: `PYTHON_LLTRACE=4` and `PYTHON_OPT_DEBUG=4`. This instructs the JIT to emit a detailed trace of its internal operations to `stderr`, which the orchestrator captures to a log file.

An excerpt from a raw JIT log might look like this:

```text
[f1] lltrace: 100       _LOAD_FAST_1
[f1] lltrace: 100       _LOAD_CONST_INLINE_BORROW
...
[f1] OPTIMIZED: _BINARY_OP_ADD_INT
...
[f1] lltrace: 120       _DEOPT
...
Bailing on recursive call in function foo
```

This raw text is the data source for our entire feedback mechanism.

-----

### Parsing (`coverage.py`)

The `lafleur/coverage.py` module is responsible for transforming the raw, unstructured log text into a useful, structured data format.

The main function, `parse_log_for_edge_coverage`, uses a series of regular expressions to process the log file line by line. It identifies three key pieces of information:

1.  **Harness Markers (`[f1]`)**: These markers allow the parser to attribute all subsequent coverage to a specific harness function within the test case.
2.  **Micro-operations (uops)**: It looks for lines indicating a uop was added to a trace or executed (e.g., `ADD_TO_TRACE: _LOAD_ATTR`).
3.  **Rare Events**: It scans for a curated list of strings that signal a JIT bailout, failure, or other interesting non-standard behavior (e.g., `Bailing on recursive call`).

-----

### The Coverage Signal

The output of the parser is a "coverage profile," which is a dictionary containing the three types of feedback the fuzzer uses to make decisions. For each of these, we track the **hit count** using `collections.Counter`, not just its presence or absence.

  * **Uops**: These are the individual micro-operations executed by the JIT (e.g., `_LOAD_ATTR`). While useful, they provide a low-granularity signal.

  * **Uop Edges**: This is the **primary and most valuable feedback signal** for `lafleur`. An edge represents the control flow between two consecutive uops, such as `_LOAD_ATTR->_STORE_ATTR`. Tracking edges provides far more contextual information than tracking uops alone, as it captures the sequence of operations, not just their existence.

  * **Rare Events**: These are high-value events that indicate the JIT has entered a non-optimal or problematic state. Our curated list includes low-level bailouts from the C source code (e.g., `Trace stack overflow`, `Confidence too low`) and high-level semantic events discovered from CPython's own statistical tools (e.g., `Rare event func modification`).

-----

### The `analyze_run` Method: Deciding What's Interesting

The `analyze_run` method within the `LafleurOrchestrator` is the final step in the feedback loop. It takes the coverage profile from the parser and decides if the child test case is "interesting" enough to be saved. To ensure state consistency, it uses a robust **two-pass system**.

1.  **Pass 1: Read-Only Check**: The method first performs a read-only check. It compares the child's coverage against the `global_coverage` map (all coverage ever seen) and the parent's `lineage_coverage_profile` (all coverage seen in its ancestry). If a uop edge or rare event is found that is not in the global map, it's a **new global discovery**. If it's not new globally but is new to its lineage, it's a **new relative discovery**. In either case, an `is_interesting` flag is set to `True`. Crucially, the main `global_coverage` state is **not** modified during this pass.

2.  **Duplicate Check**: If the child is deemed interesting, its SHA256 hash is checked against the set of all known file hashes. If the hash already exists, the file is a duplicate and is discarded.

3.  **Pass 2: Commit**: Only if the child is interesting AND not a duplicate does the orchestrator proceed to the commit phase. In this pass, the `_update_global_coverage` method is called to add the new coverage to the main `global_coverage` map, and the `CorpusManager` is called to save the new file to the corpus and persist the updated state to disk.
