# Session Handoff Document

This document contains important context for continuing work on the lafleur project.

## Current State (January 17, 2026)

### Recently Completed Work

**PR #340**: `ClosureStompMutator` - **DONE**
- Attacks JIT closure optimizations by injecting `_jit_stomp_closure` helper
- Randomly corrupts `func.__closure__[i].cell_contents` at runtime
- Invalidate type/value assumptions for nested functions

**PR #339**: `PatternMatchingChaosMutator` - **MERGED**
- Attacks JIT structural pattern matching (MATCH_MAPPING, MATCH_SEQUENCE, MATCH_CLASS)
- Injects `_JitMatchChaos` helper with dynamic `__match_args__` property
- Creates type-switching subjects that change behavior after JIT warmup
- Converts `isinstance` checks and for-loop unpacking to match statements
- 17 tests added

**PR #337**: `UnpackingChaosMutator` - **MERGED**
- Attacks JIT unpacking optimizations (UNPACK_SEQUENCE, UNPACK_EX)
- Wraps iterables in chaotic iterators that lie about length
- Three behaviors: grow, shrink, type_switch after JIT warmup
- 15 tests added

**PR #335**: Test Coverage Improvements - **MERGED**
- Increased coverage from 69% to 81%
- Added CLI entry point tests
- Increased triage.py coverage from 61% to 91%

**PR #333**: Orchestrator Refactoring - **MERGED**
- Transformed 2206-line `LafleurOrchestrator` into a clean "Conductor"
- Extracted four manager classes:
  - `ArtifactManager` in `lafleur/artifacts.py` ("The Librarian")
  - `ScoringManager` in `lafleur/scoring.py` ("The Judge")
  - `ExecutionManager` in `lafleur/execution.py` ("The Muscle")
  - `MutationController` in `lafleur/mutation_controller.py` ("The Strategist")

**PR #331**: Re-enable mypy - **MERGED**

### Test Status
- **1135 tests passing**
- mypy clean
- ruff format/check clean

## Open Issues (Potential Next Tasks)

### High Priority
- **#152**: `serialize_state` appending multiple times (bug)
- **#114**: Slicing loses or omits information (bug)

### Enhancement Ideas
- **#89**: Add new mutators (umbrella issue)
- **#122**: Study and target UOPs we don't currently cover
- **#115**: Tweak probabilities for mutators
- **#197**: Keep documentation updated

### Larger Features
- **#316**: Fleet Management System
- **#315**: Visualize Lineage Trees
- **#314**: Web UI Dashboard
- **#313**: Automated GitHub issue reporting

## Architecture Overview

The project was recently refactored. Key modules:

```
lafleur/
├── orchestrator.py        # "The Conductor" - coordinates the fuzzing loop
├── artifacts.py           # "The Librarian" - log processing, crash saving
├── scoring.py             # "The Judge" - coverage analysis, interestingness
├── execution.py           # "The Muscle" - subprocess execution
├── mutation_controller.py # "The Strategist" - mutation strategy
├── corpus_manager.py      # Corpus management and scheduling
├── coverage.py            # Coverage tracking and persistence
├── mutators/
│   ├── engine.py          # ASTMutator, registers all transformers
│   ├── generic.py         # General-purpose mutators
│   ├── scenarios_types.py # Type system attacks
│   ├── scenarios_control.py # Control flow stress (incl. PatternMatchingChaosMutator)
│   ├── scenarios_data.py  # Data manipulation (incl. UnpackingChaosMutator)
│   ├── scenarios_runtime.py # Runtime state corruption
│   ├── helper_injection.py # HelperFunctionInjector
│   └── sniper.py          # SniperMutator
└── [analysis, triage, reporting tools]
```

## Development Workflow

### Python Environment
**Critical**: Always use the JIT CPython venv:
```bash
~/venvs/jit_cpython_venv/bin/python
```

### Pre-commit Checklist
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
- `test:` - Tests
- `docs:` - Documentation

Always include:
```
Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```
(or appropriate AI assistant attribution)

## Mutator Development Patterns

### Pattern 1: Scenario Injection (preferred for complex mutations)
```python
class MyMutator(ast.NodeTransformer):
    """One-line description."""

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if not node.name.startswith("uop_harness"):
            return node
        if random.random() < 0.1:
            scenario = ast.parse("# injected code").body
            node.body = scenario + node.body
            ast.fix_missing_locations(node)
        return node
```

### Testing Pattern
```python
def test_my_mutator_basic(self):
    code = dedent('''
        def uop_harness_test():
            x = 1
    ''')
    tree = ast.parse(code)

    with patch("random.random", return_value=0.05):
        mutator = MyMutator()
        mutated = mutator.visit(tree)

    result = ast.unparse(mutated)
    self.assertIn("expected_code", result)
```

### Common Pitfalls
1. **Comments don't survive AST round-trip** - Check for code elements, not comments
2. **Mock enough random values** - Provide `side_effect=[0.1] * 20` for multiple calls
3. **Type annotations for mypy** - Use `cast()` for AST returns, explicit type annotations for pattern variables

## GitHub Repository
- URL: https://github.com/devdanzin/lafleur
- Main branch: `main`
- Workflow: Feature branches, PRs to main, user merges PRs

## JIT-Specific Concepts

Effective mutators target:
- **Type speculation** - JIT assumes stable types; inject type changes mid-loop
- **Guard handling** - Stress guard failure paths
- **Inline caching** - Invalidate with `__class__` changes
- **Deoptimization** - Force fallback to interpreter mid-execution
- **Pattern matching** - Dynamic `__match_args__`, type-switching subjects
- **Unpacking** - Iterators that lie about length or change behavior
- **Global-to-constant promotion** - Swap globals after JIT trusts them
- **Code object metadata** - Swap `__code__` attributes
