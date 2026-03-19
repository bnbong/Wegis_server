# --------------------------------------------------------------------------
# URL utility module
# --------------------------------------------------------------------------
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


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

    query_items = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(query_items)

    return urlunsplit((scheme, netloc, path, query, ""))
