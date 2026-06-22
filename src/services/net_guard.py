# --------------------------------------------------------------------------
# SSRF guard for outbound fetches (design 03B)
#
# The server fetches arbitrary user-supplied URLs, so it must refuse to connect
# to internal/reserved addresses (loopback, RFC1918, link-local incl. cloud
# metadata 169.254.169.254, ULA, reserved, multicast).
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import ipaddress
import logging
import socket
from urllib.parse import urlsplit

logger = logging.getLogger("main")

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


class SSRFBlockedError(Exception):
    """Raised when an outbound fetch target fails the SSRF guard."""


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def validate_public_url(url: str) -> bool:
    """Return True only if ``url`` is http(s) on an allowed port whose host
    resolves entirely to public IP addresses.

    Resolution happens here (pre-connect). This blocks the common SSRF vectors;
    DNS-rebinding is only partially mitigated and should be backstopped by an
    egress firewall on the fetcher's network.
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if parts.scheme not in ALLOWED_SCHEMES:
        return False

    host = parts.hostname
    if not host:
        return False

    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    if port not in ALLOWED_PORTS:
        return False

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return False
    if not infos:
        return False

    return all(_is_public_ip(info[4][0]) for info in infos)
