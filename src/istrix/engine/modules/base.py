"""Abstract base class for all scan modules."""

from abc import ABC, abstractmethod

from istrix.models.finding import Finding


class ScanModule(ABC):
    """Base class for pluggable scan modules.

    Each module declares what finding types it consumes and produces.
    The orchestrator dispatches findings to modules whose consumed_types
    match the finding's type.
    """

    name: str = "base"
    description: str = ""
    consumed_types: list[str] = []
    produced_types: list[str] = []
    optional: bool = True

    @abstractmethod
    def run(self, findings: list[Finding]) -> list[Finding]:
        """Execute the module on the given findings.

        Args:
            findings: Input findings to process (filtered by consumed_types).

        Returns:
            New findings produced by this module.
        """
        ...
