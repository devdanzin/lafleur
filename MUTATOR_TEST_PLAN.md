# Mutator Test Plan

## Overview

This document outlines the comprehensive testing plan for all mutators in the `lafleur/mutators/` package. The goal is to ensure every mutator has thorough unit tests that verify correct behavior, edge case handling, and output quality.

## Current Test Coverage Status

### Existing Tests (in `tests/test_mutator.py`)

The following mutators already have test coverage:

**Generic mutators (generic.py):**
- ✓ OperatorSwapper
- ✓ ComparisonSwapper
- ✓ ConstantPerturbator
- ✓ GuardInjector
- ✓ ContainerChanger
- ✓ VariableSwapper
- ✓ StatementDuplicator
- ✓ VariableRenamer
- ✓ ForLoopInjector
- ✓ GuardRemover

**Type-focused mutators (scenarios_types.py):**
- ✓ TypeInstabilityInjector
- ✓ InlineCachePolluter
- ✓ LoadAttrPolluter
- ✓ TypeIntrospectionMutator
- ✓ FunctionPatcher
- ✓ ManyVarsInjector

**Control flow mutators (scenarios_control.py):**
- ✓ TraceBreaker
- ✓ ExitStresser
- ✓ DeepCallMutator
- ✓ GuardExhaustionGenerator

**Data structure mutators (scenarios_data.py):**
- ✓ MagicMethodMutator
- ✓ NumericMutator
- ✓ IterableMutator
- ✓ DictPolluter

**Runtime mutators (scenarios_runtime.py):**
- ✓ GCInjector
- ✓ GlobalInvalidator
- ✓ SideEffectInjector
- ✓ StressPatternInjector

**Utility transformers (utils.py):**
- ✓ FuzzerSetupNormalizer
- ✓ EmptyBodySanitizer

**Engine (engine.py):**
- ✓ ASTMutator

## Test Files to Create

We will create the following test files in `tests/mutators/`:

### 1. `test_generic.py`
Tests for untested mutators in `lafleur/mutators/generic.py`:

**Mutators to test (12):**
1. **BoundaryValuesMutator** - Tests mutating numeric constants to boundary values
   - Test: Integer to MIN/MAX values
   - Test: Float to edge cases (inf, -inf, nan)
   - Test: Preserves non-numeric constants
   - Test: Edge case with empty code

2. **BlockTransposerMutator** - Tests reordering independent statements
   - Test: Transposes simple assignments
   - Test: Preserves dependencies
   - Test: Handles empty blocks
   - Test: Doesn't transpose return/break/continue

3. **UnpackingMutator** - Tests tuple/list unpacking mutations
   - Test: Mutates tuple unpacking
   - Test: Handles nested unpacking
   - Test: Edge case with single element
   - Test: Preserves starred expressions

4. **NewUnpackingMutator** - Tests extended unpacking patterns
   - Test: Adds starred expressions
   - Test: Mutates existing starred unpacking
   - Test: Handles edge cases
   - Test: Produces valid syntax

5. **DecoratorMutator** - Tests decorator mutations
   - Test: Adds decorators to functions
   - Test: Removes existing decorators
   - Test: Mutates decorator arguments
   - Test: Handles class decorators

6. **SliceMutator** - Tests slice expression mutations
   - Test: Mutates slice bounds
   - Test: Adds/removes step parameter
   - Test: Edge cases (negative indices)
   - Test: Preserves slice syntax validity

7. **PatternMatchingMutator** - Tests match/case statement mutations
   - Test: Adds match statements
   - Test: Mutates case patterns
   - Test: Reorders case clauses
   - Test: Edge case with empty matches

8. **ArithmeticSpamMutator** - Tests injection of arithmetic operations
   - Test: Injects arithmetic spam into loops
   - Test: Uses complex expressions
   - Test: Handles different numeric types
   - Test: Produces parseable output

9. **StringInterpolationMutator** - Tests f-string mutations
   - Test: Converts to f-strings
   - Test: Mutates f-string expressions
   - Test: Handles nested braces
   - Test: Edge case with special characters

10. **ExceptionGroupMutator** - Tests exception group (PEP 654) mutations
    - Test: Wraps in try/except*
    - Test: Creates exception groups
    - Test: Mutates exception group patterns
    - Test: Valid exception handling

11. **AsyncConstructMutator** - Tests async/await mutations
    - Test: Converts to async functions
    - Test: Adds await expressions
    - Test: Mutates async comprehensions
    - Test: Preserves async validity

12. **SysMonitoringMutator** - Tests sys.monitoring API mutations
    - Test: Injects monitoring code
    - Test: Adds event callbacks
    - Test: Handles monitoring tools
    - Test: Valid monitoring setup

### 2. `test_scenarios_types.py`
Tests for untested mutators in `lafleur/mutators/scenarios_types.py`:

**Mutators to test (4):**
1. **DescriptorChaosGenerator** - Tests descriptor protocol attacks
   - Test: Injects __get__/__set__ chaos
   - Test: Creates conflicting descriptors
   - Test: Attacks property caching
   - Test: Valid descriptor classes

2. **MROShuffler** - Tests method resolution order mutations
   - Test: Reorders base classes
   - Test: Adds diamond inheritance
   - Test: Forces MRO conflicts
   - Test: Handles metaclasses

3. **SuperResolutionAttacker** - Tests super() call mutations
   - Test: Mutates super() arguments
   - Test: Creates ambiguous super() calls
   - Test: Attacks cooperative inheritance
   - Test: Valid super() usage

4. **CodeObjectSwapper** - Tests code object manipulation
   - Test: Swaps function code objects
   - Test: Mutates code attributes
   - Test: Creates invalid code objects
   - Test: Handles closure variables

### 3. `test_scenarios_control.py`
Tests for untested mutators in `lafleur/mutators/scenarios_control.py`:

**Mutators to test (3):**
1. **RecursionWrappingMutator** - Tests recursive call injection
   - Test: Wraps code in recursive functions
   - Test: Controls recursion depth
   - Test: Adds base cases
   - Test: Handles tail recursion

2. **ExceptionHandlerMaze** - Tests complex exception handling
   - Test: Creates nested try/except blocks
   - Test: Adds multiple exception types
   - Test: Injects finally blocks
   - Test: Valid exception handling

3. **CoroutineStateCorruptor** - Tests coroutine state manipulation
   - Test: Corrupts async generator state
   - Test: Mutates coroutine internals
   - Test: Attacks yield/send
   - Test: Valid async code

### 4. `test_scenarios_data.py`
Tests for untested mutators in `lafleur/mutators/scenarios_data.py`:

**Mutators to test (2):**
1. **BuiltinNamespaceCorruptor** - Tests builtin shadowing
   - Test: Shadows builtin functions
   - Test: Reassigns builtin names
   - Test: Restores builtins
   - Test: Handles __builtins__ access

2. **ComprehensionBomb** - Tests nested comprehension attacks
   - Test: Creates deeply nested comprehensions
   - Test: Adds complex filters
   - Test: Mutates comprehension structure
   - Test: Valid comprehension syntax

### 5. `test_scenarios_runtime.py`
Tests for untested mutators in `lafleur/mutators/scenarios_runtime.py`:

**Mutators to test (2):**
1. **FrameManipulator** - Tests stack frame manipulation
   - Test: Accesses frame locals
   - Test: Mutates frame globals
   - Test: Injects frame modifications
   - Test: Handles frame edge cases

2. **WeakRefCallbackChaos** - Tests weakref callback attacks
   - Test: Creates weakref with callbacks
   - Test: Mutates callback behavior
   - Test: Triggers during GC
   - Test: Valid weakref usage

### 6. `test_utils.py`
Tests for untested utilities in `lafleur/mutators/utils.py`:

**Transformer to test (1):**
1. **HarnessInstrumentor** - Tests harness instrumentation
   - Test: Adds monitoring markers
   - Test: Injects serialization code
   - Test: Preserves function behavior
   - Test: Valid instrumentation output

### 7. `test_engine.py`
Tests for untested components in `lafleur/mutators/engine.py`:

**Component to test (1):**
1. **SlicingMutator** - Tests large function slicing
   - Test: Slices functions with >100 statements
   - Test: Applies mutations to slice
   - Test: Preserves rest of function
   - Test: Handles edge cases (exactly 100 statements)

## Test Structure Template

Each test file should follow this structure:

```python
#!/usr/bin/env python3
"""
Tests for [module_name] mutators.

This module contains unit tests for mutators defined in
lafleur/mutators/[module_name].py
"""

import ast
import random
import unittest
from textwrap import dedent
from unittest.mock import patch

from lafleur.mutators.[module_name] import (
    MutatorClass1,
    MutatorClass2,
    # ... etc
)


class TestMutatorClass1(unittest.TestCase):
    """Test MutatorClass1 mutator."""

    def setUp(self):
        """Set random seed for reproducible tests."""
        random.seed(42)

    def test_basic_mutation(self):
        """Test basic mutation behavior."""
        code = dedent('''
            def uop_harness_test():
                x = 1
        ''')
        tree = ast.parse(code)

        with patch("random.random", return_value=0.05):
            mutator = MutatorClass1()
            mutated = mutator.visit(tree)

        # Assertions
        self.assertIsInstance(mutated, ast.Module)
        # ... specific checks

    def test_edge_case_empty(self):
        """Test edge case with empty code."""
        # ... test implementation

    def test_produces_valid_code(self):
        """Test that output is valid, parseable Python."""
        # ... test implementation

    def test_no_mutation_when_probabilty_high(self):
        """Test that mutation doesn't occur with low probability."""
        # ... test implementation


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

## Testing Principles

For each mutator, tests should verify:

1. **Basic Functionality**: The mutator applies its transformation when triggered
2. **Probabilistic Application**: Respects probability thresholds (use `patch("random.random")`)
3. **Valid Output**: Produces syntactically valid, parseable Python code
4. **Edge Cases**:
   - Empty function bodies
   - No variables to mutate
   - Already mutated code
   - Deeply nested AST structures
   - Missing expected node types
5. **Output Quality**: Generated code matches expected pattern
6. **Type Safety**: Returns correct AST node types
7. **Preservation**: Doesn't corrupt unrelated code

## Test Execution

Run all mutator tests:
```bash
# Run all tests in the mutators directory
python -m unittest tests.mutators. -v

# Run a specific test file
python -m unittest tests.mutators.test_generic -v

# Run a specific test class
python -m unittest tests.mutators.test_generic.TestBoundaryValuesMutator -v

# Run with coverage
coverage run -m unittest tests.mutators
```

## Success Criteria

- All 25 untested mutators have comprehensive test coverage
- Each mutator has at least 4 test methods covering different aspects
- All tests pass with both Python 3.11+ and Python 3.13+
- Code coverage for mutators package increases to >90%
- Tests run in <30 seconds total
- No flaky tests (tests pass consistently with different random seeds)

## Implementation Order

Recommended implementation order (easiest to hardest):

1. **Phase 1 - Utils & Engine** (2 mutators)
   - `test_utils.py` - HarnessInstrumentor
   - `test_engine.py` - SlicingMutator

2. **Phase 2 - Generic Mutators** (12 mutators)
   - Start with simpler mutators: BoundaryValuesMutator, SliceMutator
   - Then structural: BlockTransposerMutator, UnpackingMutator
   - Finally complex: PatternMatchingMutator, SysMonitoringMutator

3. **Phase 3 - Data Mutators** (2 mutators)
   - `test_scenarios_data.py` - Both mutators are relatively straightforward

4. **Phase 4 - Runtime Mutators** (2 mutators)
   - `test_scenarios_runtime.py` - More complex runtime manipulation

5. **Phase 5 - Type Mutators** (4 mutators)
   - `test_scenarios_types.py` - Complex type system attacks

6. **Phase 6 - Control Mutators** (3 mutators)
   - `test_scenarios_control.py` - Most complex control flow scenarios

## Notes

- All tests should be compatible with Python 3.11+ (as per pyproject.toml)
- Use `ast.unparse()` to verify generated code structure
- Mock `random.random()` and `random.choice()` for deterministic tests
- Follow existing test patterns in `tests/test_mutator.py`
- Each test file should be runnable independently
- Tests should not require actual CPython JIT build to run
