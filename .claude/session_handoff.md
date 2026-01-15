# Session Handoff Document

This document contains important context for continuing work on the lafleur project.

## Current State (January 2026)

### Completed Work
- **PR #331**: Re-enable mypy type checking - **MERGED**
- All previous PRs have been merged

### Next Task: Refactor orchestrator.py

**Goal**: Break up `lafleur/orchestrator.py` into multiple modules, splitting the features of `LafleurOrchestrator` into multiple classes.

**Rationale**: The file is ~2600 lines with the `LafleurOrchestrator` class spanning 2206 lines and containing 45 methods. This makes it difficult to maintain, test, and understand.

## LafleurOrchestrator Deep Dive

### Overview
`LafleurOrchestrator` is the central coordinator for the fuzzing process. It manages the evolutionary loop that:
1. Selects parent test cases from the corpus
2. Applies mutations to generate children
3. Executes children with JIT enabled
4. Analyzes results for new coverage, crashes, and divergences
5. Updates the corpus and statistics

### Class Statistics
- **Location**: `lafleur/orchestrator.py` lines 289-2494
- **Total lines**: 2206
- **Methods**: 45
- **Key dependencies**: `CorpusManager`, `CoverageManager`, `ASTMutator`, `MutatorScoreTracker`

### Method Categories and Suggested Modules

#### 1. Initialization & Configuration (112 lines)
Could remain in core orchestrator or move to a config module.
```
__init__                          (85 lines) - Initialize orchestrator and corpus manager
get_boilerplate                   (3 lines)  - Return cached boilerplate code
_extract_and_cache_boilerplate    (15 lines) - Parse source to extract boilerplate
_get_core_code                    (9 lines)  - Strip boilerplate from source
```

#### 2. Main Loop & Orchestration (323 lines)
Core orchestrator - coordinates all other components.
```
run_evolutionary_loop                  (93 lines)  - Main fuzzing loop entry point
execute_mutation_and_analysis_cycle    (230 lines) - Single parent mutation cycle
```

#### 3. Mutation Strategies → `mutation_strategies.py` (~350 lines)
All mutation-related logic could be extracted to a `MutationEngine` or `MutationStrategyRunner` class.
```
apply_mutation_strategy      (65 lines)  - Select and apply mutation strategy
_run_deterministic_stage     (17 lines)  - Single seeded mutation
_run_havoc_stage             (29 lines)  - Random stack of mutations
_run_spam_stage              (30 lines)  - Repeat same mutation type
_run_splicing_stage          (82 lines)  - Crossover from second parent
_run_sniper_stage            (23 lines)  - Targeted mutation via Bloom filter
_run_helper_sniper_stage     (42 lines)  - Target helper function injection
_run_slicing                 (32 lines)  - Apply mutations to large AST slice
_get_mutated_harness         (16 lines)  - Apply strategy and handle errors
_analyze_setup_ast           (15 lines)  - Map variable names to types
_calculate_mutations         (18 lines)  - Dynamic mutation count calculation
```

#### 4. Child Execution → `execution.py` (~320 lines)
Execution logic could be a `ChildExecutor` class.
```
_execute_child          (212 lines) - Run child process with JIT, handle results
_run_timed_trial        (63 lines)  - Execute with timeout and timing
_prepare_child_script   (45 lines)  - Reassemble AST to Python source
```

#### 5. Log Processing → `log_processing.py` (~120 lines)
Log handling could be a `LogProcessor` class.
```
_truncate_huge_log      (25 lines) - Truncate oversized logs
_compress_log_stream    (18 lines) - Compress log content
_process_log_file       (30 lines) - Process and optionally compress logs
_filter_jit_stderr      (12 lines) - Remove benign JIT debug messages
_parse_jit_stats        (61 lines) - Extract JIT statistics from logs
```

#### 6. Crash & Timeout Handling → `crash_handling.py` (~250 lines)
Crash detection/saving could be a `CrashHandler` class.
```
_handle_timeout            (31 lines)  - Save timeout test case
_save_regression_timeout   (16 lines)  - Save JIT-only timeout
_save_jit_hang             (14 lines)  - Save JIT hang case
_check_for_crash           (130 lines) - Detect crash cause (signal/keyword/etc)
_save_session_crash        (62 lines)  - Save session-mode crash
```

#### 7. Coverage & Analysis → `analysis.py` (~290 lines)
Analysis logic could be an `AnalysisEngine` class.
```
analyze_run                       (124 lines) - Orchestrate run analysis
_handle_analysis_data             (62 lines)  - Process analysis results
_find_new_coverage                (52 lines)  - Detect new coverage
_update_global_coverage           (9 lines)   - Commit coverage to global state
_calculate_coverage_hash          (12 lines)  - SHA256 hash of coverage
_score_and_decide_interestingness (61 lines)  - Score child interestingness
_build_lineage_profile            (33 lines)  - Build coverage lineage
_get_nodes_from_parent            (34 lines)  - Parse parent AST nodes
```

#### 8. Result Saving → `result_saving.py` (~50 lines)
Could be part of crash_handling or separate.
```
_save_divergence    (31 lines) - Save JIT divergence artifacts
_save_regression    (16 lines) - Save JIT performance regression
```

#### 9. Statistics & Logging (~65 lines)
Could remain in orchestrator or move to a stats module.
```
update_and_save_run_stats    (29 lines) - Update and persist statistics
_log_timeseries_datapoint    (36 lines) - Append stats to time-series log
```

#### 10. Debugging & Verification (~130 lines)
Testing/debugging utilities.
```
verify_target_capabilities    (70 lines) - Verify JIT target works
debug_mutation_differences    (23 lines) - Check mutation variety
verify_jit_determinism        (38 lines) - Check coverage determinism
```

### Suggested Refactoring Approach

1. **Start with lowest coupling**: Begin with `log_processing.py` - these methods have minimal dependencies on orchestrator state.

2. **Extract execution next**: `ChildExecutor` class for `_execute_child`, `_run_timed_trial`, etc.

3. **Then crash handling**: `CrashHandler` class - depends on execution but not mutation.

4. **Analysis engine**: `AnalysisEngine` - depends on coverage manager.

5. **Mutation strategies last**: Most tightly coupled to orchestrator state.

### Key State in LafleurOrchestrator.__init__

```python
# Core components
self.corpus_manager: CorpusManager
self.coverage_manager: CoverageManager
self.ast_mutator: ASTMutator
self.score_tracker: MutatorScoreTracker

# Configuration flags
self.differential_testing: bool
self.timing_fuzz: bool
self.session_fuzz: bool
self.use_dynamic_runs: bool

# Runtime state
self.run_stats: dict
self.boilerplate_code: str | None
self.global_seed_counter: int
self.mutations_since_last_find: int
self.nojit_cv: float | None  # Coefficient of variation for no-JIT runs
```

## Working Patterns

### Pre-commit Checklist
Always run before committing:
```bash
~/venvs/jit_cpython_venv/bin/python -m pytest tests
~/venvs/jit_cpython_venv/bin/python -m mypy lafleur
ruff format .
ruff check lafleur tests
```

### Commit Message Format
Follow Conventional Commits:
- `feat:` - New features
- `fix:` - Bug fixes
- `refactor:` - Code restructuring
- `docs:` - Documentation
- `test:` - Tests

Always include:
```
Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

### Python Environment
**Critical**: Use the JIT CPython venv for all commands:
```bash
~/venvs/jit_cpython_venv/bin/python
```

## Key Technical Details

### Type Patterns Used

1. **AST transformations** - Use `cast()` for `ast.parse()` returns
2. **TypedDict** for complex dict structures
3. **Callable** for conditional imports
4. **TypeVar** for generic methods

### Important Files
- `lafleur/orchestrator.py` - Target for refactoring (2600 lines)
- `lafleur/corpus_manager.py` - Corpus management
- `lafleur/coverage.py` - Coverage tracking
- `lafleur/mutators/engine.py` - Mutation engine

## GitHub Repository
- URL: https://github.com/devdanzin/lafleur
- Main branch: `main`
- Workflow: PRs to main, squash merge preferred
