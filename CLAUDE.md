# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`lafleur` is a feedback-driven, evolutionary fuzzer specifically designed to find crashes, correctness bugs, and hangs in CPython's experimental JIT compiler. It uses a coverage-guided approach that analyzes JIT trace logs to intelligently guide mutations.

**Key characteristics:**
- AST-based mutations for syntactically correct Python code transformations
- Adaptive learning system that prioritizes effective mutation strategies
- JIT-specific mutators targeting type speculation, inline caching, and guard handling
- Coverage feedback based on uop-edge analysis from JIT trace logs

## Development Commands

### Python Interpreter

**Important**: Always use the JIT CPython venv for running commands:
```bash
~/venvs/jit_cpython_venv/bin/python
```

For pytest and mypy:
```bash
~/venvs/jit_cpython_venv/bin/python -m pytest tests
~/venvs/jit_cpython_venv/bin/python -m mypy lafleur
```

### Testing
```bash
# Run tests with pytest (preferred)
~/venvs/jit_cpython_venv/bin/python -m pytest tests

# Run a specific test file
~/venvs/jit_cpython_venv/bin/python -m pytest tests/test_mutator.py

# Run with verbose output
~/venvs/jit_cpython_venv/bin/python -m pytest tests -v
```

## Testing Mutators

Each mutator should have tests in either `tests/test_mutator.py` or `tests/test_mutators/*.py` that verify:
1. The mutator produces valid, parseable Python code
2. Edge cases are handled gracefully (empty bodies, missing variables, etc.)
3. The mutation is applied probabilistically (use `patch("random.random")`)
4. Complex AST structures don't cause crashes

Example test pattern:
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
    
    self.assertIsInstance(mutated, ast.Module)
    # Verify mutation was applied...
```

### Code Quality
```bash
# Format code with ruff (required before committing)
ruff format .

# Run type checker
mypy lafleur/

# Lint with ruff
ruff check .
```

### Running the Fuzzer
```bash
# Basic fuzzing run (requires CPython JIT build and activated venv)
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded

# Start with seeding
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --min-corpus-files 20

# Differential testing mode (for silent correctness bugs)
lafleur --fusil-path /path/to/fusil/fuzzers/fusil-python-threaded --differential-testing
```

### Utility Commands
```bash
# Tune CPython JIT for more aggressive behavior (run after initial build)
lafleur-jit-tweak /path/to/cpython

# Analyze coverage data
python scripts/analyze_uop_coverage.py

# Filter interesting crashes
grep -L -E "(statically|indentation|unsupported|formatting|invalid syntax)" crashes/*.log | sed 's/\.log$/.py/'
```

### Analysis & Triage Tools
```bash
# Single instance health report
lafleur-report /path/to/instance

# Campaign aggregation with HTML dashboard
lafleur-campaign runs/ --html report.html --registry crashes.db

# Import crashes to registry
lafleur-triage import runs/

# Interactive crash triage (review NEW crashes)
lafleur-triage interactive

# Review/update previously triaged crashes
lafleur-triage review --status REPORTED

# Export known issues for sharing
lafleur-triage export-issues known_issues.json
```

## Architecture Overview

### Project Structure

- `lafleur/` — Main package
  - `orchestrator.py` — Core fuzzing loop coordinator ("The Conductor")
  - `artifacts.py` — Log processing and findings management ("The Librarian")
  - `scoring.py` — Coverage analysis and interestingness scoring ("The Judge")
  - `execution.py` — Subprocess execution and timeout handling ("The Muscle")
  - `mutation_controller.py` — Mutation strategy and source assembly ("The Strategist")
  - `mutators/` — AST-based mutation strategies
    - `engine.py` — ASTMutator class, registers all transformers
    - `generic.py` — General-purpose mutators (OperatorSwapper, ConstantPerturbator, etc.)
    - `scenarios_types.py` — Type system attacks (TypeInstabilityInjector, InlineCachePolluter, etc.)
    - `scenarios_control.py` — Control flow stress testing (DeepCallMutator, TraceBreaker, PatternMatchingChaosMutator, etc.)
    - `scenarios_data.py` — Data structure manipulation (DictPolluter, UnpackingChaosMutator, etc.)
    - `scenarios_runtime.py` — Runtime state corruption (FrameManipulator, GCInjector, etc.)
    - `utils.py` — Shared utilities for mutators
    - `helper_injection.py` — HelperFunctionInjector for Sniper targeting
    - `sniper.py` — SniperMutator for surgical Bloom filter invalidation
  - `coverage_parser.py` — Parses JIT trace logs for uop-edge coverage
  - `corpus_manager.py` — Manages test case corpus and scheduling
  - `report.py` — Single-instance text reporter CLI
  - `campaign.py` — Multi-instance campaign aggregator with HTML reports
  - `registry.py` — SQLite-based crash registry for historical tracking
  - `triage.py` — Interactive crash triage CLI
- `tests/` — Test suite (unittest-based)
- `doc/dev/` — Developer documentation
- `docs/` — User-facing documentation (TOOLING.md)

### Core Components

**lafleur/orchestrator.py** - The main evolutionary loop coordinator ("The Conductor")
- `LafleurOrchestrator` class coordinates the four-stage feedback cycle: Selection → Mutation → Execution → Analysis
- Delegates to specialized managers: `ArtifactManager`, `ScoringManager`, `ExecutionManager`, `MutationController`
- Orchestrates the fuzzing loop without implementing low-level details

**lafleur/artifacts.py** - File and finding management ("The Librarian")
- `ArtifactManager` handles log processing, crash detection, and saving findings
- Methods: `process_log_file`, `check_for_crash`, `save_crash`, `save_timeout`, `save_divergence`

**lafleur/scoring.py** - Coverage analysis and scoring ("The Judge")
- `ScoringManager` parses JIT stats, detects new coverage, and calculates interestingness
- Classes: `InterestingnessScorer`, `NewCoverageInfo`

**lafleur/execution.py** - Subprocess execution ("The Muscle")
- `ExecutionManager` runs test cases with JIT enabled and handles timeouts
- Methods: `execute_child`, `run_timed_trial`, `verify_target_capabilities`

**lafleur/mutation_controller.py** - Mutation strategy ("The Strategist")
- `MutationController` decides mutation approach and assembles source code
- Implements stages: deterministic, havoc, spam, splicing, sniper, helper_sniper

**lafleur/corpus_manager.py** - Corpus and parent selection management
- `CorpusManager` handles all corpus file operations and state synchronization
- `CorpusScheduler` implements intelligent parent selection using multi-factor scoring:
  - Performance (execution time, file size)
  - Rarity (globally rare coverage patterns)
  - Fertility (historical success producing interesting children)
  - Depth (mutation chain depth)
  - Trace quality (trace length, side exits)

**lafleur/coverage.py** - JIT trace log parsing and coverage extraction
- `CoverageManager` manages the persistent state file (`coverage_state.pkl`)
- Extracts uop-edge coverage from verbose JIT logs
- Uses integer ID mappings for memory-efficient state storage
- Tracks rare JIT events (deopt, guard failures, bailouts)
- Defines execution states: TRACING, OPTIMIZED, EXECUTING

**lafleur/mutators/engine.py** - Mutation orchestration
- `ASTMutator` manages the library of mutation transformers
- Applies randomized mutation pipelines to ASTs
- `SlicingMutator` meta-mutator for efficiently fuzzing large functions (>100 statements)

**lafleur/learning.py** - Adaptive mutation strategy learning
- `MutatorScoreTracker` tracks historical success of each mutator
- Implements decaying scores (0.995 factor) to favor recent successes
- Uses epsilon-greedy selection to balance exploration vs exploitation

### Analysis & Triage Components

**lafleur/report.py** - Single instance reporter
- Generates text summaries of fuzzing instance health
- Reads from `fuzz_run_stats.json`, `logs/run_metadata.json`, `corpus_stats.json`
- Sections: System, Performance, Coverage, Corpus Evolution, Crash Digest

**lafleur/campaign.py** - Campaign aggregator
- `CampaignAggregator` class aggregates metrics across multiple instances
- Deduplicates crashes by fingerprint across the fleet
- Produces both text and HTML reports with `--html` flag
- Integrates with crash registry via `--registry` for status enrichment
- Status labels: NEW, KNOWN, REGRESSION, NOISE

**lafleur/registry.py** - Crash registry
- `CrashRegistry` class provides SQLite-based crash tracking
- Three tables: `reported_issues`, `crashes`, `sightings`
- Tracks crash fingerprints, links to GitHub issues, triage status
- Supports import/export of known issues as JSON

**lafleur/triage.py** - Triage CLI
- Subcommands: `import`, `interactive`, `review`, `record-issue`, `status`, `list`, `show`, `export-issues`, `import-issues`
- Interactive triage loop for NEW crashes with actions: Report, Ignore, Mark Fixed, Note, Skip
- Review mode for auditing/correcting previous triage decisions

### Mutation Categories

The mutators are organized into several submodules under `lafleur/mutators/`:

**generic.py** - General-purpose structural mutations
- Basic operator/comparison swapping, constant perturbation
- Container type changes, variable swapping
- Control flow modifications (loops, exception handling, pattern matching)
- Examples: `OperatorSwapper`, `ComparisonSwapper`, `ForLoopInjector`, `GuardRemover`

**scenarios_types.py** - Type system and caching attacks
- Inline cache pollution, type instability injection
- MRO manipulation, descriptor chaos
- Function patching, code object swapping
- Examples: `TypeInstabilityInjector`, `InlineCachePolluter`, `LoadAttrPolluter`, `MROShuffler`

**scenarios_control.py** - Control flow stress testing
- Deep call chains, recursion wrapping
- Exception handler mazes, trace breaking
- Guard exhaustion, side exit stress
- Pattern matching chaos (dynamic `__match_args__`, type-switching subjects)
- Examples: `DeepCallMutator`, `ExceptionHandlerMaze`, `GuardExhaustionGenerator`, `TraceBreaker`, `PatternMatchingChaosMutator`

**scenarios_data.py** - Data structure manipulation
- Dictionary pollution, comprehension bombs
- Iterator/iterable misbehavior, numeric edge cases
- Magic method attacks, builtin namespace corruption
- Global optimization invalidation, code object hot-swapping
- Unpacking chaos (iterators that lie about length, change after JIT warmup)
- Examples: `DictPolluter`, `MagicMethodMutator`, `GlobalOptimizationInvalidator`, `CodeObjectHotSwapper`, `UnpackingChaosMutator`

**scenarios_runtime.py** - Runtime state corruption
- Frame manipulation, garbage collection stress
- Global invalidation, side effect injection
- Weak reference chaos
- Examples: `FrameManipulator`, `GCInjector`, `SideEffectInjector`, `WeakRefCallbackChaos`

**utils.py** - Utility transformers
- `FuzzerSetupNormalizer`: Removes fuzzer-injected setup code from previous generations
- `EmptyBodySanitizer`: Ensures syntactic validity by adding `pass` statements
- `HarnessInstrumentor`: Adds monitoring/serialization code
- `VariableRenamer`: Renames variables for corpus deduplication

### Data Flow

1. **Selection**: `CorpusScheduler` scores all corpus files; orchestrator selects parent
2. **Mutation**: Parent AST normalized, mutation pipeline applied, sanitized
3. **Execution**: Child runs in subprocess with `PYTHON_LLTRACE=2` and `PYTHON_JIT=1`
4. **Analysis**: Log parsed for coverage; if interesting (new edges/events), added to corpus

### State Persistence

- **coverage/coverage_state.pkl**: Binary pickle file containing:
  - Per-file metadata (coverage, execution time, lineage, fertility)
  - Global coverage maps (uop_map, edge_map, rare_event_map with integer IDs)
  - Mutator success scores
- **corpus/jit_interesting_tests/**: Directory of Python test files
- **crashes/**, **timeouts/**, **divergences/**: Findings with accompanying .log files

## Code Conventions
  
### Type Hints
- All functions must have complete type hints
- See `pyproject.toml` for strict mypy configuration

### Formatting
- Line length: 100 characters
- Use ruff for formatting (configuration in `pyproject.toml`)
- Double quotes for strings
- 4-space indentation

## Code Style

- Use `ruff format` before committing
- Docstrings required for classes and public methods
- Line length: 100 characters
- Python 3.14+ features are acceptable

### Commit Messages
Follow Conventional Commits specification:
- `feat: Add new SideEffectInjector mutator`
- `fix: Prevent crash when unparsing deeply nested ASTs`
- `docs: Add getting started guide for developers`

### AI-Assisted Code Review Checklist
When reviewing AI-generated code:
- **Focus**: Does the change stay on task? Watch for unrelated modifications or deleted docstrings
- **Correctness**: Does the logic match requirements? Validate the implementation carefully
- **Simplicity**: Is the solution unnecessarily complex? Look for simpler alternatives
- **Redundancy**: Remove boilerplate comments that restate code

## Adding New Mutators

1. Choose the appropriate scenario module (`generic.py`, `scenarios_types.py`, etc.)
2. Create a class inheriting from `ast.NodeTransformer`
3. Implement visitor methods (`visit_*`) for target AST node types
4. Import and register in `lafleur/mutators/engine.py`
5. The learning system will automatically track its effectiveness

### Pattern 1: Scenario Injection (preferred for complex mutations)
```python
class MyMutator(ast.NodeTransformer):
    """One-line description of what this mutator does."""
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        if random.random() < 0.1:  # Probabilistic application
            scenario = ast.parse("# my injected code").body
            node.body = scenario + node.body
            ast.fix_missing_locations(node)
        return node
```

### Pattern 2: In-Place Modification (for simple transformations)
```python
def visit_BinOp(self, node: ast.BinOp) -> ast.BinOp:
    if random.random() < 0.3:
        node.op = ast.Sub()  # Direct modification
    return node
```
- Mutators must handle edge cases: empty functions, no variables, deeply nested ASTs

## JIT-Specific Concepts

Effective mutators target these JIT weaknesses, among others:
- **Type speculation** — JIT assumes stable types; inject type changes mid-loop
- **Guard handling** — JIT inserts guards; stress guard failure paths
- **Inline caching** — JIT caches attribute lookups; invalidate with `__class__` changes
- **Deoptimization** — Force JIT to fall back to interpreter mid-execution
- **MRO manipulation** — Change class hierarchy after JIT has traced
- **Global-to-constant promotion** — JIT promotes stable globals to constants; swap them mid-execution
- **Code object metadata** — JIT caches function/generator metadata; swap `__code__` attributes

## Important Environment Variables

When executing test cases, the fuzzer sets:
- `PYTHON_LLTRACE=2`: Verbose JIT trace logging
- `PYTHON_OPT_DEBUG=4`: Optimizer debug output
- `PYTHON_JIT=1`: Enable JIT compilation
- `ASAN_OPTIONS=detect_leaks=0`: Disable leak detection in ASAN builds

## Fuzzing Prerequisites

The fuzzer requires:
1. CPython debug build with experimental JIT: `./configure --with-pydebug --enable-experimental-jit`
2. JIT tuning applied via `lafleur-jit-tweak`
3. Virtual environment created with the tuned CPython build
4. Optional: fusil for seeding (`pip install git+https://github.com/fusil-fuzzer/fusil.git`)

## Documentation

Developer documentation is in `doc/dev/`:
- `01_architecture_overview.md`: High-level system design
- `02_the_evolutionary_loop.md`: Feedback cycle details
- `03_coverage_and_feedback.md`: Coverage extraction
- `04_mutation_engine.md`: Mutation strategies
- `05_state_and_data_formats.md`: State file format
- `06_developer_getting_started.md`: Development setup
- `07_extending_lafleur.md`: Adding features

User-facing documentation is in `docs/`:
- `TOOLING.md`: Analysis & triage workflow guide (report, campaign, triage tools)

## CLI Entry Points

Defined in `pyproject.toml` under `[project.scripts]`:
- `lafleur` → `lafleur.orchestrator:main` — Main fuzzer
- `lafleur-jit-tweak` → `lafleur.jit_tuner:main` — JIT parameter tuning
- `lafleur-report` → `lafleur.report:main` — Single instance reporter
- `lafleur-campaign` → `lafleur.campaign:main` — Campaign aggregator
- `lafleur-triage` → `lafleur.triage:main` — Crash triage CLI
  