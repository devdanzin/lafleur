# Lafleur Developer Documentation: 09. Diagnostic Mode

### Introduction

Diagnostic mode is a set of CLI options that allow lafleur to run in bounded,
reproducible, and introspectable configurations. It is designed for three
primary use cases:

1. **Post-refactoring smoke tests** — verify nothing broke after code changes
2. **Mutator development** — test new or enhanced mutators in isolation
3. **Debugging** — inspect generated children and mutation strategies

### Quick Reference

| Option | Type | Default | Purpose |
|--------|------|---------|---------|
| `--max-sessions N` | int | unlimited | Stop after N sessions |
| `--max-mutations-per-session N` | int | dynamic | Fixed mutations per session |
| `--seed N` | int | random | Global RNG seed |
| `--workdir PATH` | path | cwd | Working directory |
| `--keep-children` | flag | off | Retain all children in tmp_fuzz_run/ |
| `--dry-run` | flag | off | Mutate only, skip execution |
| `--list-mutators` | flag | — | Print mutator pool and exit |
| `--mutators A,B,C` | string | all | Filter mutator pool |
| `--strategy NAME` | choice | adaptive | Force mutation strategy |

### Workflow Examples

#### Smoke Test After Refactoring

```bash
tmpdir=$(mktemp -d)
python -m lafleur \
    --workdir "$tmpdir" \
    --max-sessions 3 \
    --max-mutations-per-session 2 \
    --seed 42 \
    --runs 1
echo "Exit code: $?"
rm -rf "$tmpdir"
```

If exit code is 0 and no crashes are in `$tmpdir/crashes/`, the refactoring
didn't break the mutation → execution → analysis pipeline.

#### Testing a New Mutator

```bash
python -m lafleur \
    --workdir /tmp/mutator_test \
    --max-sessions 1 \
    --max-mutations-per-session 5 \
    --mutators BoundaryComparisonMutator \
    --strategy spam \
    --keep-children \
    --dry-run \
    --seed 42

# Inspect the generated children
ls /tmp/mutator_test/tmp_fuzz_run/
cat /tmp/mutator_test/tmp_fuzz_run/child_1_1_dryrun.py
```

This generates 5 children, all produced by spamming `BoundaryComparisonMutator`,
without executing any subprocesses. Each child is written to disk for manual review.

#### Inspecting Strategy Behavior

```bash
python -m lafleur \
    --workdir /tmp/strategy_test \
    --max-sessions 2 \
    --max-mutations-per-session 3 \
    --strategy havoc \
    --keep-children \
    --keep-tmp-logs \
    --seed 100

# After run completes, examine:
ls /tmp/strategy_test/tmp_fuzz_run/     # Child scripts
ls /tmp/strategy_test/logs/run_logs/    # Execution logs
cat /tmp/strategy_test/logs/run_metadata.json  # Recorded settings
```

#### Discovering Available Mutators

```bash
python -m lafleur --list-mutators
```

Sample output:
```
Available mutators (76 total):

  AbstractInterpreterConfusionMutator     Attack the JIT's abstract interpreter...
  ArithmeticSpamMutator                   Inject chains of arithmetic operations...
  AsyncConstructMutator                   Inject async/await constructs...
  ...
```

### Reproducibility

When `--seed` is provided, the following become deterministic:

- **Corpus parent selection** — which file is chosen as mutation input
- **Strategy selection** — which strategy (havoc, spam, etc.) is used
- **Mutation pipeline** — which transformers are applied and in what order
- **Deepening decisions** — whether a session goes depth-first or breadth-first

The seed is recorded in `logs/run_metadata.json` as `global_seed`, enabling
exact reproduction of a diagnostic run.

### Integration with CI and Claude Code

The diagnostic options are designed to be composable with the standard CLI.
All existing options (`--session-fuzz`, `--differential-testing`, `--timeout`,
etc.) work alongside the diagnostic flags.

A typical Claude Code verification workflow:

```bash
# After making changes, run a quick smoke test
tmpdir=$(mktemp -d)
python -m lafleur --workdir "$tmpdir" --max-sessions 3 --max-mutations-per-session 2 --seed 42 --runs 1
if [ $? -ne 0 ]; then
    echo "FAIL: lafleur exited with non-zero code"
    cat "$tmpdir/logs/"*.log
fi
rm -rf "$tmpdir"
```
