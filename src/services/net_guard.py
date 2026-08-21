# --------------------------------------------------------------------------
# SSRF guard for outbound fetches (design 03B)
#
# The server fetches arbitrary user-supplied URLs, so it must refuse to connect
# to internal/reserved addresses (loopback, RFC1918, link-local incl. cloud
# metadata 169.254.169.254, ULA, reserved, multicast).
#
# The guard resolves the host itself and hands the inspected addresses back to
# the caller (``ResolvedTarget``), so the connection can be pinned to an address
# that was actually checked rather than re-resolved at connect time.
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

logger = logging.getLogger("main")

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


class SSRFBlockedError(Exception):
    """Raised when an outbound fetch target fails the SSRF guard."""


@dataclass(frozen=True)
class ResolvedTarget:
    """A fetch target whose host resolved entirely to public IP addresses.

    ``ips`` is the exact address list the guard inspected, in resolver order.
    Callers must connect to one of these addresses instead of letting the HTTP
    client resolve the host a second time; otherwise a short-TTL record can
    answer differently between check and connect (DNS rebinding).
    """

    scheme: str
    host: str
    port: int
    ips: tuple[str, ...]


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
        # RFC 6598 shared address space (100.64.0.0/10) trips none of the flags
        # above, yet cloud CNIs and carrier-grade NATs route it internally.
        # ``is_global`` excludes it, but only as an addition to the explicit
        # flags: for IPv4 it is defined as "outside 100.64.0.0/10 and not
        # private", so on its own it would still admit multicast and part of
        # the reserved space.
        or not addr.is_global
    )


def resolve_public_url(url: str) -> ResolvedTarget | None:
    """Resolve ``url`` and return its target, or ``None`` when it is not http(s)
    on an allowed port whose host resolves entirely to public IP addresses.

    Resolution happens here (pre-connect), and the addresses it inspected are
    returned so the caller can pin the connection to one of them. Pinning is
    what closes the DNS-rebinding window: a caller that re-resolves the host at
    connect time gets a second, unchecked answer. Callers that cannot pin (the
    browser fallback drives its own DNS) still get the pre-connect check, but
    must be backstopped by an egress firewall on the fetcher's network.
    """
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if parts.scheme not in ALLOWED_SCHEMES:
        return None

    host = parts.hostname
    if not host:
        return None

    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    if port not in ALLOWED_PORTS:
        return None

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception:
        return None
    if not infos:
        return None

    # Fail closed on the first non-public answer: a split-horizon record that
    # mixes a public address with an internal one must not be reachable.
    ips: list[str] = []
    for info in infos:
        # sockaddr[0] is the address string for both AF_INET and AF_INET6.
        ip = str(info[4][0])
        if not _is_public_ip(ip):
            return None
        if ip not in ips:
            ips.append(ip)

    return ResolvedTarget(scheme=parts.scheme, host=host, port=port, ips=tuple(ips))


def validate_public_url(url: str) -> bool:
    """Return True only if ``url`` passes :func:`resolve_public_url`.

    Boolean shorthand for callers that cannot pin the resolved address and only
    need the pre-connect verdict (the browser fallback).
    """
    return resolve_public_url(url) is not None
