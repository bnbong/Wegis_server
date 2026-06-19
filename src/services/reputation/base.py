# --------------------------------------------------------------------------
# URL reputation provider abstraction
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

import httpx

# Verdict values returned by reputation providers.
MALICIOUS = "malicious"
CLEAN = "clean"
UNKNOWN = "unknown"


@dataclass
class ReputationResult:
    """Outcome of a reputation lookup (single provider or merged)."""

    verdict: str  # MALICIOUS | CLEAN | UNKNOWN
    confidence: float
    source: str  # e.g. "reputation:gsb"
    provider: str  # e.g. "gsb"
    reason_codes: list[str] = field(default_factory=list)
    raw: Optional[dict] = None

    @property
    def is_malicious(self) -> bool:
        return self.verdict == MALICIOUS


class ReputationProvider(ABC):
    """A pluggable URL reputation feed.

    Implementations should raise on transport/parse errors; the service layer
    wraps every call with a timeout and swallows failures (fail-open).
    """

    name: str

    @property
    @abstractmethod
    def enabled(self) -> bool:
        """Whether the provider is configured (e.g. API key present)."""

    def applies_to(self, url: str) -> bool:
        """Whether this provider should be queried for ``url``.

        Defaults to all URLs. Costly/targeted providers (e.g. a malware scanner)
        override this to restrict themselves to, say, high-risk download URLs.
        """
        return True

    @abstractmethod
    async def check(self, url: str, client: httpx.AsyncClient) -> ReputationResult:
        """Look up ``url`` and return a per-provider reputation result."""
