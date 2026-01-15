# Session Handoff Document

This document contains important context for continuing work on the lafleur project.

## Current State (January 2026)

### Completed Work
- **PR #331**: Re-enable mypy type checking - **MERGED**
- All previous PRs have been merged
- **Testing**: `tests/` coverage is robust, including recent additions for Triage and Reporting.

### Next Task: Refactor orchestrator.py

**Goal**: Transform `LafleurOrchestrator` from a 2206-line "God Class" into a clean "Conductor" that coordinates distinct manager classes.
**Rationale**: The file is ~2600 lines with the `LafleurOrchestrator` class spanning 2206 lines and containing 45 methods. This makes it difficult to maintain, test, and understand.
**Constraint**: We must maintain passing tests and mypy checks at every step. Do not introduce circular dependencies.

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


## Architectural Plan

We will reject the idea of splitting into many tiny, fragmented modules (e.g., `log_processing.py`, `result_saving.py`). Instead, we will group responsibilities into four cohesive "Manager" modules.

**IMPORTANT:** Do not create a module named `analysis.py`. We already have `lafleur/analysis.py` (Crash Fingerprinting). Use `lafleur/scoring.py` instead.

### Phase 1: Preparation

1. **Remove Dead Code**: Ensure `debug_mutation_differences` and `verify_jit_determinism` are deleted from `orchestrator.py` before moving any code.

### Phase 2: The Refactoring Roadmap

#### 1. `lafleur/artifacts.py` ("The Librarian")

**Responsibility**: Managing files, processing logs, and saving findings. This has low coupling and is the safest place to start.

* **Move methods**:
* `_process_log_file`, `_truncate_huge_log`, `_compress_log_stream`
* `_check_for_crash`
* `_handle_timeout`, `_save_regression_timeout`, `_save_jit_hang`
* `_save_session_crash`, `_save_divergence`, `_save_regression`



#### 2. `lafleur/scoring.py` ("The Judge")

**Responsibility**: Parsing results, calculating scores, and detecting coverage.

* **Move Classes**: `InterestingnessScorer`, `NewCoverageInfo`
* **Move Methods**:
* `_parse_jit_stats`
* `_find_new_coverage`
* `_calculate_coverage_hash`
* `_score_and_decide_interestingness` (logic only; keep state updates in orchestrator if needed)



#### 3. `lafleur/execution.py` ("The Muscle")

**Responsibility**: Running subprocesses and handling the OS layer.

* **Move Classes**: `ExecutionResult` (if not already in utils)
* **Move Methods**:
* `_execute_child`
* `_run_timed_trial`
* `verify_target_capabilities`
* `_filter_jit_stderr`



#### 4. `lafleur/mutation_controller.py` ("The Strategist")

**Responsibility**: Deciding *how* to mutate and assembling the source code.

* **Move Methods**:
* `apply_mutation_strategy`
* `_run_deterministic_stage`, `_run_havoc_stage`, `_run_spam_stage`, `_run_splicing_stage`, `_run_sniper_stage`, `_run_helper_sniper_stage`, `_run_slicing`
* `_get_mutated_harness`
* `_prepare_child_script` (Source code assembly/GC injection)
* `_analyze_setup_ast`
* `_calculate_mutations`



---

## Resulting `orchestrator.py` ("The Conductor")

After refactoring, `orchestrator.py` should effectively look like this high-level story:

```python
class LafleurOrchestrator:
    def __init__(self, ...):
        self.executor = Executor(...)
        self.mutator = MutationController(...)
        self.artifacts = ArtifactManager(...)
        self.scorer = ScoreKeeper(...)

    def run_evolutionary_loop(self):
        # 1. Select Parent
        # 2. Cycle:
        #    child_src = self.mutator.create_child(parent)
        #    result = self.executor.run(child_src)
        #    if self.artifacts.is_crash(result):
        #        self.artifacts.save_crash(result)
        #    score = self.scorer.evaluate(result)
        #    if score > threshold:
        #        self.corpus.save(child)

```

## Key Dependencies & Method Map

| Method | Target Module | Dependencies to Inject |
| --- | --- | --- |
| `_execute_child` | `execution.py` | `timeout`, `target_python`, `ENV` |
| `_check_for_crash` | `artifacts.py` | `CrashFingerprinter` |
| `_prepare_child_script` | `mutation_controller.py` | `boilerplate_code` |
| `_find_new_coverage` | `scoring.py` | `CoverageManager` (read-only access) |


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
**Checks**: Run `pytest tests` and `mypy lafleur` frequently.

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
