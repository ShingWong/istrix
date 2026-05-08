"""iStrix plugin system — extensible tools, skills, and knowledge sources.

Three plugin types:
  - Tool       : external capability wrappers (nmap, snmp, ssh, fetch, ftp, websearch)
  - Skill      : scan enrichment modules (existing ScanModule subclasses)
  - Knowledge  : data sources (CVE KB, vector DB, remediation guides)

All plugins are auto-discovered from the plugins/tools/ and plugins/knowledge/
directories, plus the existing engine/modules/ for skills.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ──────────────────────────────────────────────────────────────────
# Tool plugins
# ──────────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    success: bool
    output: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0


class BaseTool(ABC):
    """A tool plugin wraps an external utility or protocol.

    Examples: nmap, snmpwalk, ssh commands, HTTP fetch, FTP, web search.
    """

    name: str = "base_tool"
    description: str = ""
    version: str = "0.1.0"
    required_binaries: list[str] = field(default_factory=list)
    required_packages: list[str] = field(default_factory=list)

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the tool with given parameters."""
        ...

    def is_available(self) -> bool:
        """Check if this tool can run (binaries/packages present)."""
        import shutil
        import importlib
        for binary in self.required_binaries:
            if not shutil.which(binary):
                return False
        for pkg in self.required_packages:
            try:
                importlib.import_module(pkg)
            except ImportError:
                return False
        return True


# ──────────────────────────────────────────────────────────────────
# Knowledge plugins
# ──────────────────────────────────────────────────────────────────

class BaseKnowledge(ABC):
    """A knowledge source plugin for enriching findings with context.

    Examples: CVE database, vector DB, remediation guides, vendor advisories.
    """

    name: str = "base_knowledge"
    description: str = ""
    version: str = "0.1.0"

    @abstractmethod
    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search the knowledge base for relevant entries."""
        ...

    @abstractmethod
    async def get(self, key: str) -> dict | None:
        """Retrieve a specific knowledge entry by key."""
        ...

    @abstractmethod
    async def ingest(self, entries: list[dict]) -> int:
        """Ingest new knowledge entries. Returns count added."""
        ...

    @abstractmethod
    async def stats(self) -> dict:
        """Return statistics about the knowledge base."""
        ...
