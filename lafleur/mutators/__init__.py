"""
The `lafleur.mutators` package contains the core mutation engine and the library
of mutation strategies used by the fuzzer.

It exposes the main `ASTMutator` engine, the `SlicingMutator` meta-mutator, and
essential utility transformers like `FuzzerSetupNormalizer` and `EmptyBodySanitizer`
for easy access by the orchestrator.
"""

from lafleur.mutators.engine import ASTMutator, SlicingMutator, _dump_unparse_diagnostics
from lafleur.mutators.generic import ImportPrunerMutator, StatementDuplicator, VariableRenamer
from lafleur.mutators.utils import (
    EmptyBodySanitizer,
    FuzzerSetupNormalizer,
    HarnessInstrumentor,
    RedundantStatementSanitizer,
)

__all__ = [
    "ASTMutator",
    "SlicingMutator",
    "_dump_unparse_diagnostics",
    "FuzzerSetupNormalizer",
    "EmptyBodySanitizer",
    "HarnessInstrumentor",
    "ImportPrunerMutator",
    "RedundantStatementSanitizer",
    "StatementDuplicator",
    "VariableRenamer",
]
