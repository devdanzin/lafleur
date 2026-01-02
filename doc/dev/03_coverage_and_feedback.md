# Lafleur Developer Documentation: 03. Coverage and Feedback Signal

### Introduction

A feedback-driven fuzzer is only as good as the signal it receives. This document details the "eyes" of `lafleur`: the entire pipeline from raw JIT log output to the structured coverage data that informs the fuzzer's evolutionary strategy. This process is the key to how `lafleur` learns from its mutations and improves over time.

-----

### The JIT Log

The entire feedback process begins by capturing the verbose debug output from CPython's JIT compiler. `lafleur` achieves this by executing every child process with two specific environment variables set: `PYTHON_LLTRACE=2` and `PYTHON_OPT_DEBUG=4`. This instructs the JIT to emit a detailed trace of its internal operations to `stderr`, which the orchestrator captures to a log file.

An excerpt from a raw JIT log might look like this:

```text
[f1] STRATEGY: Targeted Uop Fuzzing (['_STORE_ATTR', '_CONTAINS_OP_DICT', '_BINARY_OP_SUB_FLOAT', '_UNPACK_SEQUENCE_LIST', '_COMPARE_OP_EQ_INT'])
...
  63 ADD_TO_TRACE: _SET_IP (0, target=2255, operand0=0x55ac896b7abe, operand1=0)
  64 ADD_TO_TRACE: _LOAD_FAST_BORROW (2, target=2255, operand0=0, operand1=0)...
...
Bailing on recursive call in function foo
```

This raw text is the data source for our entire feedback mechanism.

-----

### Parsing (`coverage.py`)

The `lafleur/coverage.py` module is responsible for transforming the raw, unstructured log text into a useful, structured data format.

The main function, `parse_log_for_edge_coverage`, uses a series of regular expressions to process the log file line by line. It is implemented as a **state machine** that tracks the JIT's current operational state and identifies several key pieces of information:

1.  **Harness Markers (`[f1]`)**: These markers allow the parser to attribute all subsequent coverage to a specific harness function within the test case.
2.  **JIT State Transitions**: The parser looks for keywords like `Created a proto-trace` and `Optimized trace` to determine if the JIT is currently in the `TRACING` or `OPTIMIZED` state.
3.  **Micro-operations (uops)**: It looks for lines indicating a uop was added to a trace or executed (e.g., `ADD_TO_TRACE: _LOAD_ATTR`).
4.  **Rare Events**: It scans for a curated list of strings that signal a JIT bailout, failure, or other interesting non-standard behavior (e.g., `Bailing on recursive call`).

-----

### The Coverage Signal

The output of the parser is a "coverage profile," which is a dictionary containing the types of feedback the fuzzer uses to make decisions. For each of these, we track the **hit count** using `collections.Counter`, not just its presence or absence.

  * **Uops**: These are the individual micro-operations executed by the JIT (e.g., `_LOAD_ATTR`). While useful, they provide a low-granularity signal.

  * **Rare Events**: These are high-value events that indicate the JIT has entered a non-optimal or problematic state. Our curated list includes low-level bailouts from the C source code (e.g., `Trace stack overflow`, `Confidence too low`) and high-level semantic events discovered from CPython's own statistical tools (e.g., `Rare event func modification`).

  * **Stateful Uop Edges**: This is the **primary and most valuable feedback signal** for `lafleur`. An edge represents the control flow between two consecutive uops. Crucially, edges are now recorded as **stateful tuples** in the format `(JIT_STATE, "UOP_A->UOP_B")`. This allows the fuzzer to distinguish between finding a previously seen edge in a new JIT state (e.g., finding an edge during `OPTIMIZED` execution that was previously only seen during `TRACING`) and finding a truly novel edge. This provides a much more contextual signal.

  * **Structural Metrics**: To better guide the fuzzer toward deep JIT exploration, the parser also extracts quantitative metrics about the JIT's output:

      * **`trace_length`**: The number of uops in a successfully generated optimized trace.
      * **`side_exits`**: The number of `_DEOPT` or `_EXIT_TRACE` uops within a single trace, representing its branching complexity.
        These metrics are used by the `CorpusScheduler` to reward test cases that generate longer and more complex optimized code.

-----

### The `analyze_run` Method: Deciding What's Interesting

The `analyze_run` method within the `LafleurOrchestrator` is the final step in the feedback loop. It takes the coverage profile from the parser and decides if the child test case is "interesting" enough to be saved. To ensure state consistency, it uses a robust **two-pass system**.

1.  **Pass 1: Read-Only Check**: The method first performs a read-only check. It compares the child's coverage against the `global_coverage` map (all coverage ever seen) and the parent's `lineage_coverage_profile` (all coverage seen in its ancestry). If a stateful edge or rare event is found that is not in the global map, it's a **new global discovery**. If it's not new globally but is new to its lineage, it's a **new relative discovery**. In either case, an `is_interesting` flag is set to `True`. The main `global_coverage` state is **not** modified during this pass.

2.  **Duplicate Check**: If the child is deemed interesting, its `content_hash` (from its source code) and a new **`coverage_hash`** (from its specific execution behavior) are calculated. A child is now considered a duplicate only if the tuple `(content_hash, coverage_hash)` has been seen before. This allows the fuzzer to save multiple copies of the same source file if they produce different, non-deterministic behaviors.

3.  **Pass 2: Commit**: Only if the child is interesting AND not a duplicate does the orchestrator proceed to the commit phase. In this pass, the `_update_global_coverage` method is called to add the new coverage to the main `global_coverage` map, and the `CorpusManager` is called to save the new file to the corpus and persist the updated state to disk.
