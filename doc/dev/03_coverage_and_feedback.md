# Lafleur Developer Documentation: 03. Coverage and Feedback Signal

### Introduction

A feedback-driven fuzzer is only as good as the signal it receives. This document details the "eyes" of `lafleur`: the entire pipeline from raw JIT log output to the structured coverage data that informs the fuzzer's evolutionary strategy. This process is the key to how `lafleur` learns from its mutations and improves over time.

For how this coverage signal feeds the evolutionary loop, see [02. The Evolutionary Loop](./02_the_evolutionary_loop.md). For how it guides mutation strategy selection, see [04. The Mutation Engine](./04_mutation_engine.md). For the on-disk format of the coverage state, see [05. State and Data Formats](./05_state_and_data_formats.md).

-----

### The JIT Log

The entire feedback process begins by capturing the verbose debug output from CPython's JIT compiler. `lafleur` achieves this by executing every child process with two specific environment variables set: `PYTHON_LLTRACE=2` and `PYTHON_OPT_DEBUG=4`. This instructs the JIT to emit a detailed trace of its internal operations to `stderr`, which the execution manager captures to a log file.

An excerpt from a raw JIT log might look like this:

```text
[f1] STRATEGY: Targeted Uop Fuzzing (['_STORE_ATTR', '_CONTAINS_OP_DICT', '_BINARY_OP_SUB_FLOAT'])
...
  63 ADD_TO_TRACE: _SET_IP (0, target=2255, operand0=0x55ac896b7abe, operand1=0)
  64 ADD_TO_TRACE: _LOAD_FAST_BORROW (2, target=2255, operand0=0, operand1=0)...
...
Optimized trace (length 50):
  OPTIMIZED: _LOAD_CONST
  OPTIMIZED: _BINARY_OP_ADD_INT
...
Bailing on recursive call in function foo
```

This raw text is the data source for the text-based feedback mechanism. A second, complementary feedback channel — runtime introspection of JIT data structures — is described in the EKG section below.

-----

### Parsing (`coverage.py`)

The `lafleur/coverage.py` module transforms the raw, unstructured log text into a structured data format. The main function, `parse_log_for_edge_coverage`, processes the log file line by line using a series of regular expressions. It is implemented as a **state machine** that tracks the JIT's current operational state.

#### The State Machine

The parser maintains a `JitState` enum with three values:

- **`EXECUTING`** — Default state. General execution, no active trace compilation.
- **`TRACING`** — The JIT is creating a proto-trace from bytecode. Triggered by `Created a proto-trace`.
- **`OPTIMIZED`** — The JIT has produced an optimized trace. Triggered by `Optimized trace (length N):`.

Each state transition resets the edge context. The current state is embedded into every edge recorded, making edges **stateful** — the same UOP transition `A→B` seen during `TRACING` is a different coverage item than `A→B` seen during `OPTIMIZED`.

#### What the Parser Extracts

1. **Harness Markers (`[f1]`, `[f2]`, ...)**: These markers allow the parser to attribute all subsequent coverage to a specific harness function within the test case. When a new marker is encountered, the parser flushes metrics for the previous harness and resets its state.

2. **Micro-operations (UOPs)**: Lines matching `ADD_TO_TRACE: _UOP_NAME` or `OPTIMIZED: _UOP_NAME` are extracted. Each UOP is validated against the known `UOP_NAMES` set (from `lafleur/uop_names.py`). Unknown or spurious UOPs are silently discarded and **break the edge chain**, preventing garbage from corrupting coverage data.

3. **Stateful UOP Edges**: For each valid UOP, the parser records an edge from the previous UOP to the current one, tagged with the current JIT state: `(TRACING, "_LOAD_FAST->_STORE_FAST")`. At the start of each harness, the edge chain is seeded with a `_START_OF_HARNESS_` sentinel, creating edges like `_START_OF_HARNESS_->_LOAD_FAST` that capture which UOP each harness begins execution with.

4. **Rare Events**: The parser scans for a curated list of strings that signal JIT bailouts, failures, or interesting non-standard behavior. The complete list (from `RARE_EVENT_REGEX`):

    **JIT bailout UOPs:** `_DEOPT`, `_GUARD_FAIL`

    **Low-level bailout reasons (from CPython C source):** `Bailing on recursive call`, `Bailing due to dynamic target`, `Bailing because co_version != func_version`, `Bail, new_code == NULL`, `Unsupported opcode`, `JUMP_BACKWARD not to top ends trace`, `Trace stack overflow`, `No room for`, `Out of space in abstract interpreter`, `out of space for symbolic expression type`, `Hit bottom in abstract interpreter`, `Encountered error in abstract interpreter`, `Confidence too low`

    **High-level semantic events (from CPython's `summarize_stats.py`):** `Rare event set class`, `Rare event set bases`, `Rare event func modification`, `Rare event builtin dict`, `Rare event watched globals modification`

5. **Structural Metrics**: For each harness, the parser also extracts `trace_length` (UOP count in a successfully generated optimized trace) and `side_exits` (count of `_DEOPT` or `_EXIT_TRACE` UOPs within a trace, representing branching complexity).

#### Integer ID Compression

All coverage items (UOPs, edges, rare events) are immediately compressed from their string representations to integer IDs by the `CoverageManager`. The `get_or_create_id(item_type, item_string)` method maintains forward maps (`uop_map`, `edge_map`, `rare_event_map`) that assign monotonically increasing integers to each new string, and reverse maps for debug lookups and human-readable output (used by the `state_tool`). Each coverage type has an independent ID counter.

Hit counts are tracked as `Counter[int]`, and the persistent coverage state file stores only integer IDs. This compression reduces memory usage and speeds up set operations during the interestingness check.

-----

### The Coverage Signal

The output of the parser is a "coverage profile" — a dictionary mapping each harness ID to its coverage data. For each signal type, the fuzzer tracks **hit counts** using `collections.Counter`, not just presence or absence.

  * **UOPs**: The individual micro-operations (e.g., `_LOAD_ATTR`). Low-granularity signal — many different scripts will hit the same UOPs.

  * **Rare Events**: High-value events from the curated list above. These indicate the JIT has entered a non-optimal or problematic state. A single new rare event is weighted as heavily as a new global edge in the interestingness scorer.

  * **Stateful UOP Edges**: The **primary and most valuable feedback signal**. An edge represents the control flow between two consecutive UOPs, tagged with the JIT's operational state: `(OPTIMIZED, "_LOAD_FAST->_STORE_FAST")`. This statefulness means discovering a previously seen edge in a new JIT state (e.g., seeing it during `OPTIMIZED` when it was previously only seen during `TRACING`) counts as new coverage.

  * **Structural Metrics**: `trace_length` and `side_exits` per harness. These are used by the `CorpusScheduler` to reward test cases that generate longer and more complex optimized code.

-----

### JIT Introspection (The EKG)

Beyond text log parsing, `lafleur` employs a runtime introspection system nicknamed "The JIT EKG" (Electrocardiogram). Located in `lafleur/driver.py`, this system uses Python's `ctypes` library to inspect the internal state of the JIT compiler's data structures directly.

The driver maps the opaque `_PyExecutorObject` C struct (defined in CPython's `pycore_optimizer.h`) to a Python `ctypes.Structure`, giving the fuzzer X-ray vision into the `vm_data` fields that are normally hidden from the Python runtime. The struct definitions target CPython 3.15 and must be updated if CPython's internal layout changes.

#### Monitored Vitals

The EKG monitors several "vital signs" of the JIT's health. Abnormal values in these metrics are often precursors to crashes or state corruption bugs.

* **Exit Density (`exit_count / code_size`)**: The most critical metric for detecting "JIT Tachycardia" (thrashing). A high density (e.g., > 10.0) means the JIT compiled a trace that bails out almost every time it runs, stressing the deoptimization machinery.

* **Zombie Traces (`pending_deletion`)**: The number of JIT traces marked for deletion but not yet freed. This is the "Holy Grail" state for finding Use-After-Free bugs — if the fuzzer can trigger execution while `pending_deletion` is non-zero, it is hitting a race condition in the executor lifecycle management.

* **Chain Depth**: The length of the linked list of optimized traces chained together. Deep chains can violate stack depth assumptions or abstract interpretation limits.

* **Code Size (Hypoplasia)**: The number of micro-ops in the generated trace. Extremely short traces (1–5 UOPs) often indicate "optimization stubs" — attempts to compile that were aborted early, revealing code patterns that confuse the optimizer.

* **Valid/Warm Counts**: The number of traces in valid and warm states, providing a snapshot of the JIT's overall trace population health.

#### Delta Vitals (Session Mode)

In session fuzzing mode, the driver takes a **baseline snapshot** of all executor exit counts before each script runs (via `snapshot_executor_state()`). After execution, `get_jit_stats()` computes delta metrics that isolate the child script's contribution:

- `delta_max_exit_density` — change in maximum exit density attributable to the child
- `delta_total_exits` — total new exits across all executors
- `delta_new_executors` — executors that appeared during child execution
- `delta_new_zombies` — executors that became zombies during child execution

These delta metrics are preferred by the `InterestingnessScorer` (see [02. The Evolutionary Loop](./02_the_evolutionary_loop.md)) because they isolate the child's effect from the polluter/parent state.

#### Bloom Filter Probing

The most architecturally significant introspection feature is **Bloom filter probing**. Each `_PyExecutorObject` contains a Bloom filter (in `vm_data.bloom`) that records which globals and builtins the JIT's optimizer assumed were stable when compiling the trace. If any of these "watched" objects change at runtime, the trace must be invalidated.

The driver reimplements CPython's `bloom_filter_may_contain` algorithm in pure Python (`check_bloom()`), then uses `scan_watched_variables()` to test each global and builtin in the namespace against every executor's Bloom filter. The result is a `watched_dependencies` list — the names of all globals/builtins that the JIT is actively watching.

This list is saved to the child's corpus metadata and used by the **Sniper mutation strategy** in future generations to surgically invalidate precisely the variables the JIT is guarding. This closes the introspection → mutation feedback loop that is lafleur's most distinctive architectural feature.

-----

### The `analyze_run` Method: Deciding What's Interesting

The `analyze_run` method in the `ScoringManager` (in `scoring.py`) is the final step in the feedback loop. It takes the coverage profile from the parser, the JIT vitals from the EKG, and decides if the child test case is "interesting" enough to be saved. To ensure state consistency, it uses a robust **two-pass system**.

1. **Pass 1: Read-Only Check**: The method compares the child's coverage against two baselines:
    - The `global_coverage` map (all coverage ever seen by any corpus file). An item not in this map is a **new global discovery**.
    - The parent's `lineage_coverage_profile` (all coverage seen in its ancestry). An item new to the lineage but already known globally is a **new relative discovery**.

    The `InterestingnessScorer` then evaluates a multifactor score combining coverage novelty, JIT vitals (zombie traces, tachycardia, chain depth, stub size), and size/performance heuristics. A child must score at least 10.0 to be considered interesting. The main `global_coverage` state is **not** modified during this pass.

2. **Duplicate Check**: If the child is interesting, two hashes are calculated:
    - **Content hash**: SHA256 of the child's core code, catching syntactically identical mutations.
    - **Coverage hash**: SHA256 of the child's edge set, catching mutations that look different but produce identical coverage.

    A child is a duplicate only if the tuple `(content_hash, coverage_hash)` has been seen before. This allows the fuzzer to save multiple copies of the same source file if they produce different, non-deterministic behaviors.

3. **Pass 2: Commit**: Only if the child is interesting AND not a duplicate does the scoring manager proceed. The `_update_global_coverage` method adds the new coverage to the `global_coverage` map. Dynamic density clamping and tachycardia decay are applied to the JIT vitals before saving (see [02. The Evolutionary Loop](./02_the_evolutionary_loop.md) for details). The `CorpusManager` then saves the new file to disk and persists the updated state.