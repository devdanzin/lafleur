"""
The `lafleur.mutators` package contains the core mutation engine and the library
of mutation strategies used by the fuzzer.

It exposes the main `ASTMutator` engine, the `SlicingMutator` meta-mutator, and
essential utility transformers like `FuzzerSetupNormalizer` and `EmptyBodySanitizer`
for easy access by the orchestrator.
"""

from lafleur.mutators.engine import ASTMutator, SlicingMutator
from lafleur.mutators.utils import (
    FuzzerSetupNormalizer,
    EmptyBodySanitizer,
    HarnessInstrumentor,
)
from lafleur.mutators.generic import VariableRenamer

__all__ = [
    "ASTMutator",
    "SlicingMutator",
    "FuzzerSetupNormalizer",
    "EmptyBodySanitizer",
    "HarnessInstrumentor",
    "VariableRenamer",
]
