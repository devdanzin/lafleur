# Mutator Tests

This directory contains comprehensive unit tests for all mutators in `lafleur/mutators/`.

## Structure

- `test_generic.py` - Tests for generic AST mutators (operator swapping, container changes, etc.)
- `test_scenarios_types.py` - Tests for type system attack mutators (MRO, descriptors, etc.)
- `test_scenarios_control.py` - Tests for control flow mutators (recursion, exceptions, etc.)
- `test_scenarios_data.py` - Tests for data structure mutators (builtins, comprehensions, etc.)
- `test_scenarios_runtime.py` - Tests for runtime manipulation mutators (frames, weakrefs, etc.)
- `test_utils.py` - Tests for utility transformers (instrumentation, normalization, etc.)
- `test_engine.py` - Tests for mutation engine components (slicing, orchestration, etc.)

## Running Tests

Run all mutator tests:
```bash
python -m unittest tests.mutators -v
```

Run a specific test file:
```bash
python -m unittest tests.mutators.test_generic -v
```

Run with coverage:
```bash
coverage run -m unittest tests.mutators
```

## Test Coverage Goals

Each mutator should have tests that verify:
1. **Basic functionality** - Mutation is applied correctly
2. **Probabilistic behavior** - Respects random probability thresholds
3. **Valid output** - Produces parseable Python code
4. **Edge cases** - Empty bodies, missing variables, nested structures
5. **Output quality** - Generated code matches expected patterns

## Implementation Status

See `MUTATOR_TEST_PLAN.md` in the repository root for detailed implementation status and plan.
