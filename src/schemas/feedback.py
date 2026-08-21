# --------------------------------------------------------------------------
# Feedback schema module
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import re

from typing import Annotated, Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, StringConstraints, ValidationInfo, field_validator

from src.services.url_utils import canonicalize_url

# Longest URL accepted. Beyond this it is a client bug or an abuse attempt, not
# a page a user actually browsed to and reported.
MAX_URL_LENGTH = 2048
# The extension version is observability only, so it is TRUNCATED rather than
# rejected: an odd value must not cost us the whole report.
MAX_EXT_VERSION_LENGTH = 32

# Values this server understands today. Anything outside these sets is coerced
# to None instead of rejected, so a newer (or older) client shipping a value we
# do not know yet still gets its report stored, minus the unknown field.
_KNOWN_VALUES: dict[str, frozenset[str]] = {
    "reported_verdict": frozenset(
        {"safe", "phishing", "suspicious", "unknown", "unsupported_language", "error"}
    ),
    "user_label": frozenset({"false_positive", "false_negative"}),
    "context": frozenset({"navigation", "link"}),
}

# "scheme://" — an absolute URL carrying an authority component.
_SCHEME_AUTHORITY_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://")
# Opaque "scheme:payload" (javascript:, data:, mailto:, …). The negative
# lookahead keeps "host:8080/path" out of this branch: there the colon
# introduces a port, and urlsplit() would otherwise read "host" as the scheme.
_OPAQUE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!\d)")

FeedbackURL = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_URL_LENGTH),
]


class FeedbackRequest(BaseModel):
    """A user-reported correction of the verdict the extension displayed.

    Only `url` is required. Every other field is best-effort telemetry, so an
    unrecognised value is dropped (set to None) rather than failing the request.
    """

    # Validated AND canonicalized here so that a malformed URL is a 422 at the
    # boundary instead of an exception further in, and so the stored value
    # matches the form the analysis path uses as its cache key.
    url: FeedbackURL
    reported_verdict: Optional[str] = None
    user_label: Optional[str] = None
    context: Optional[str] = None
    ext_version: Optional[str] = None

    @field_validator("url")
    @classmethod
    def _normalize_url(cls, value: str) -> str:
        match = _SCHEME_AUTHORITY_RE.match(value)
        if match:
            scheme = match.group(1).lower()
            if scheme not in ("http", "https"):
                raise ValueError("URL scheme must be http or https")
            # canonicalize_url() only recognises a lowercase scheme prefix.
            value = f"{scheme}://{value[match.end() :]}"
        elif _OPAQUE_SCHEME_RE.match(value):
            # javascript:, data:, mailto:, … — never a page a user navigated to.
            raise ValueError("URL scheme must be http or https")

        try:
            # A scheme-less value is assumed https, same as the analysis contract.
            canonical = canonicalize_url(value)
        except ValueError as exc:  # e.g. an out-of-range port
            raise ValueError("URL could not be parsed") from exc

        if not urlsplit(canonical).hostname:
            raise ValueError("URL has no host")
        return canonical

    @field_validator("reported_verdict", "user_label", "context", mode="before")
    @classmethod
    def _drop_unknown_values(cls, value: Any, info: ValidationInfo) -> Optional[str]:
        """Keep only values in _KNOWN_VALUES; everything else becomes None.

        Runs in "before" mode so non-string junk is dropped too instead of
        producing a 422 on a field the report can perfectly well live without.
        """
        if not isinstance(value, str):
            return None
        normalized = value.strip().lower()
        allowed = _KNOWN_VALUES.get(info.field_name or "", frozenset())
        return normalized if normalized in allowed else None

    @field_validator("ext_version", mode="before")
    @classmethod
    def _cap_ext_version(cls, value: Any) -> Optional[str]:
        if not isinstance(value, str):
            return None
        return value.strip()[:MAX_EXT_VERSION_LENGTH] or None


class FeedbackResponse(BaseModel):
    """Acceptance receipt. The client ignores this body and only checks for 2xx."""

    accepted: bool = True
    # Reports are queued for offline review and never auto-applied to the
    # blacklist/whitelist (see orm_models.Feedback).
    review_status: str = "pending"
