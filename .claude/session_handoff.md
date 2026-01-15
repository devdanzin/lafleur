# Session Handoff Document

This document contains important context for continuing work on the lafleur project.

## Current State (January 2026)

### Active PR
- **PR #331**: Re-enable mypy type checking
  - Branch: `reenable_mypy`
  - Status: Open, ready for review
  - Closes: Issue #330
  - URL: https://github.com/devdanzin/lafleur/pull/331

### Recent Work Completed

1. **Re-enabled mypy** with a lenient configuration in `pyproject.toml`
2. **Fixed 130+ type errors** across 20 files:
   - Added `TypedDict` for complex structures (`HarnessCoverage`, `GlobalCorpusData`)
   - Used `typing.cast()` for AST transformations
   - Added `Sequence` for covariant parameters
   - Added `TypeVar` for generic methods
   - Fixed Optional/None handling throughout
3. **Fixed test failures** caused by type changes:
   - `mutate_ast()` now accepts `list[ast.stmt]` in addition to `ast.AST`
   - `_run_splicing_stage()` handles both `ast.Module` and list inputs
4. **Re-enabled mypy in CI** (`.github/workflows/main.yml`)

### Commits in `reenable_mypy` Branch
1. `feat: Re-enable mypy with lenient configuration`
2. `fix: Handle list inputs in mutate_ast and _run_splicing_stage`
3. `ci: Re-enable mypy in GitHub Actions workflow`

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
- `docs:` - Documentation
- `style:` - Formatting
- `refactor:` - Code restructuring
- `test:` - Tests
- `ci:` - CI/CD changes

Always include:
```
Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

### Python Environment
**Critical**: Use the JIT CPython venv for all commands:
```bash
~/venvs/jit_cpython_venv/bin/python
```

Do NOT use `python` or `python3` directly - they may not exist or point to wrong interpreters.

## Key Technical Details

### Type Patterns Used in This Codebase

1. **AST transformations** - Use `cast()` for `ast.parse()` returns:
   ```python
   from typing import cast
   return cast(ast.FunctionDef, ast.parse(code).body[0])
   ```

2. **TypedDict for complex dicts**:
   ```python
   class HarnessCoverage(TypedDict, total=False):
       uops: Counter[int]
       edges: Counter[int]
   ```

3. **Callable for conditional imports**:
   ```python
   migrate_func: Callable[[dict], dict] | None
   try:
       from module import migrate_func
   except ImportError:
       migrate_func = None
   ```

4. **TypeVar for generic methods**:
   ```python
   _LoopT = TypeVar("_LoopT", ast.For, ast.While)
   def _snipe_loop(self, node: _LoopT) -> _LoopT: ...
   ```

### Files with Complex Type Handling
- `lafleur/orchestrator.py` - Large file (~2600 lines), extensive AST manipulation
- `lafleur/coverage.py` - `HarnessCoverage` TypedDict, defaultdict typing
- `lafleur/campaign.py` - `GlobalCorpusData` TypedDict
- `lafleur/mutators/engine.py` - Handles both `ast.AST` and `list[ast.stmt]`

## Repository Structure Highlights

```
lafleur/
├── orchestrator.py      # Main fuzzing loop (largest file)
├── mutators/
│   ├── engine.py        # ASTMutator, SlicingMutator
│   ├── generic.py       # Basic mutators
│   ├── scenarios_*.py   # Specialized mutators
│   └── sniper.py        # Targeted mutation based on Bloom filter
├── coverage.py          # JIT log parsing, coverage tracking
├── corpus_manager.py    # Test case corpus management
└── campaign.py          # Multi-instance aggregation
```

## Untracked Files (Safe to Ignore)
These files exist in the working directory but are not tracked:
- `.idea/` - IDE settings
- `fuzz_run_stats.json` - Runtime stats
- `test_bloom_real.py`, `test_helper_*.py` - Local test files
- `coverage/` - Coverage data directory

## GitHub Repository
- URL: https://github.com/devdanzin/lafleur
- Main branch: `main`
- Default workflow: PRs to `main`, squash merge preferred
