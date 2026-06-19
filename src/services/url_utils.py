# --------------------------------------------------------------------------
# URL utility module
# --------------------------------------------------------------------------
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Volatile query parameters are stripped before canonicalization so that signed
# URLs which differ only by signature/expiry collapse to a single cache key.
#
# IMPORTANT: stripping is scoped to *recognised signing schemes* (detected by a
# scheme-specific signature parameter). We deliberately do NOT strip generic
# names like "token"/"sig" globally, because for an arbitrary host
# "/d?token=benign" and "/d?token=malware" are distinct resources and collapsing
# them would poison the analysis/reputation cache.

# AWS SigV4 presigned (also S3-compatible: NCloud, MinIO, …): triggered by
# x-amz-signature. Strips every x-amz-* plus the response-override params.
_AWS_RESPONSE_OVERRIDES = frozenset(
    {
        "response-content-disposition",
        "response-content-type",
        "response-cache-control",
        "response-content-encoding",
        "response-content-language",
        "response-expires",
    }
)

# Azure Blob SAS: triggered by sig + sv (signed version). These names are generic
# on their own, so we only strip them when the SAS signature pair is present.
_AZURE_SAS_PARAMS = frozenset(
    {
        "sig",
        "sv",
        "se",
        "st",
        "sp",
        "sr",
        "spr",
        "si",
        "sip",
        "skoid",
        "sktid",
        "skt",
        "ske",
        "sks",
        "skv",
        "rscd",
        "rscc",
        "rsce",
        "rscl",
        "rsct",
    }
)


def _volatile_keys(keys: set[str]) -> set[str]:
    """Return the subset of (lowercased) query keys to strip, based on which
    signed-URL scheme is detected."""
    drop: set[str] = set()

    # AWS SigV4 presigned URL.
    if "x-amz-signature" in keys:
        drop |= {k for k in keys if k.startswith("x-amz-")}
        drop |= _AWS_RESPONSE_OVERRIDES & keys

    # Google Cloud Storage V4 presigned URL.
    if "x-goog-signature" in keys:
        drop |= {k for k in keys if k.startswith("x-goog-")}

    # GCS legacy (v2) presigned URL: GoogleAccessId + Signature + Expires.
    if {"googleaccessid", "signature", "expires"} <= keys:
        drop |= {"googleaccessid", "signature", "expires"}

    # Azure Blob SAS token.
    if "sig" in keys and "sv" in keys:
        drop |= _AZURE_SAS_PARAMS & keys

    return drop


def _strip_volatile_query(query_items: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Drop signed-URL parameters, scoped to recognised signing schemes."""
    keys = {key.lower() for key, _ in query_items}
    drop = _volatile_keys(keys)
    if not drop:
        return query_items
    return [(key, value) for key, value in query_items if key.lower() not in drop]


def canonicalize_url(url: str) -> str:
    raw = url.strip()
    if not raw:
        return raw

    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parts = urlsplit(raw)
    scheme = parts.scheme.lower() if parts.scheme else "https"
    hostname = (parts.hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    port = parts.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = hostname
    else:
        netloc = f"{hostname}:{port}" if port else hostname

    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"

    query_items = _strip_volatile_query(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(sorted(query_items))

    return urlunsplit((scheme, netloc, path, query, ""))
