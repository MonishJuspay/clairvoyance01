"""
Shared SSRF-safe egress policy for all outbound HTTP sinks.

Every place the platform fetches an operator/tenant/LLM-influenced URL must run
it through :func:`validate_egress_url` BEFORE the request, and must re-validate
every redirect hop (or disable redirects). The validator resolves the hostname
and rejects the request if any resolved address is loopback, private, link-local
(includes the 169.254.169.254 cloud-metadata address), multicast, reserved, or
otherwise non-global — closing the "DNS name resolving to an internal address"
bypass, and narrowing the DNS-rebinding window by checking the exact addresses
resolved.

Design notes:
- Resolution runs off the event loop (``asyncio.to_thread``, getaddrinfo is
  blocking); any non-public A/AAAA record fails the whole request (fail closed),
  defeating mixed good/bad record rebinding.
- ``SSRF_ALLOW_PRIVATE_EGRESS=true`` is a local-dev-only escape hatch, off by
  default regardless of ENVIRONMENT.
- Everything here is client-agnostic. ``app.core.network.make_request`` applies
  this policy to every hop of an aiohttp request; an httpx or requests caller
  should call ``validate_egress_url`` per hop itself, with redirects disabled.
"""

import asyncio
import ipaddress
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from yarl import URL

from app.core.config.static import SSRF_ALLOW_PRIVATE_EGRESS
from app.core.logger import logger

# Checked answers are reused this long, like aiohttp's own DNS cache.
_DNS_TTL = 10.0
_DNS_CACHE: Dict[Tuple[str, int], Tuple[float, List[str]]] = {}

# Local-dev escape hatch; off by default regardless of ENVIRONMENT.
_ALLOW_PRIVATE_EGRESS = SSRF_ALLOW_PRIVATE_EGRESS


class SSRFError(ValueError):
    """Raised when a URL fails SSRF egress validation."""


class EgressResolutionError(SSRFError):
    """The host could not be resolved — a transient failure, not a refusal.

    Subclasses SSRFError so fail-closed callers are unchanged, but a caller
    with a retry loop should catch this FIRST: a resolver hiccup is worth
    retrying, unlike a blocked address, and conflating the two makes a DNS
    outage look like a policy refusal.
    """


def ip_block_reason(ip_str: str) -> Optional[str]:
    """Return a human reason if the IP must not be reached, else None.

    Blocks loopback, private, link-local (includes the 169.254.169.254 /
    fe80:: cloud-metadata addresses), multicast, reserved, unspecified, and
    any address that is not globally routable.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"not an IP address: {ip_str!r}"

    if _ALLOW_PRIVATE_EGRESS:
        return None

    # IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) must be unwrapped and re-checked.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return ip_block_reason(str(mapped))

    if ip.is_loopback:
        return f"loopback address {ip}"
    if ip.is_link_local:
        return f"link-local address {ip} (includes cloud metadata)"
    if ip.is_private:
        return f"private address {ip}"
    if ip.is_multicast:
        return f"multicast address {ip}"
    if ip.is_reserved:
        return f"reserved address {ip}"
    if ip.is_unspecified:
        return f"unspecified address {ip}"
    if not ip.is_global:
        return f"non-global address {ip}"
    return None


def _remember(cache: dict, key: Any, value: Any, limit: int) -> None:
    """Bounded insert: drop the oldest entry once ``limit`` is reached."""
    if key not in cache and len(cache) >= limit:
        cache.pop(next(iter(cache)))
    cache[key] = value


async def _resolve_host(hostname: str, port: int) -> List[str]:
    """Resolve a hostname to all its IP addresses (off the event loop)."""
    key = (hostname.lower(), port)
    hit = _DNS_CACHE.get(key)
    if hit and hit[0] > time.monotonic():
        return list(hit[1])

    def _lookup() -> List[str]:
        infos = socket.getaddrinfo(
            hostname,
            port or None,
            proto=socket.IPPROTO_TCP,
            flags=socket.AI_ADDRCONFIG,  # no AAAA queries on an IPv4-only pod
        )
        return [str(info[4][0]) for info in infos]

    ips = await asyncio.to_thread(_lookup)
    _remember(_DNS_CACHE, key, (time.monotonic() + _DNS_TTL, ips), 256)
    return list(ips)


async def validate_egress_url(url: str, *, allow_http: bool = False) -> List[str]:
    """Validate a URL is safe for server-side egress; return its resolved IPs.

    Args:
        url: Fully resolved URL (no template placeholders left).
        allow_http: Permit plain http:// (default: https only), for providers
            that genuinely require it.

    Returns:
        The list of resolved IP strings (all validated as public).

    Raises:
        SSRFError: scheme disallowed, host missing, resolution failed, or any
            resolved address is non-public.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:  # pragma: no cover - urlparse rarely raises
        raise SSRFError(f"Invalid URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    allowed_schemes = ("http", "https") if allow_http else ("https",)
    if scheme not in allowed_schemes:
        raise SSRFError(f"Disallowed URL scheme {scheme!r}; allowed: {allowed_schemes}")

    # yarl's raw_host, not urlparse's hostname: they disagree on internationalised
    # names (stdlib idna is IDNA 2003, yarl is IDNA 2008/UTS46), and aiohttp
    # resolves yarl's answer. Validating the other one checks a different name.
    try:
        hostname = URL(url).raw_host
    except (ValueError, TypeError) as exc:
        raise SSRFError(f"Invalid URL host: {exc}") from exc
    if not hostname:
        raise SSRFError("URL has no hostname")

    # Outside the try: a bad port raises bare ValueError, escaping `except SSRFError`.
    try:
        port = parsed.port
    except ValueError as exc:
        raise SSRFError(f"Invalid port in URL: {exc}") from exc

    # IP-literal block sits outside the try: SSRFError subclasses ValueError.
    is_ip_literal = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        pass

    if is_ip_literal:
        reason = ip_block_reason(hostname)
        if reason:
            raise SSRFError(f"Blocked egress to {reason}")
        return [hostname]

    try:
        resolved = await _resolve_host(hostname, port or 0)
    except UnicodeError as exc:
        # A malformed hostname, not a transient failure: refuse, do not retry.
        raise SSRFError(f"Invalid hostname {hostname!r}: {exc}") from exc
    except (socket.gaierror, OSError) as exc:
        raise EgressResolutionError(
            f"Could not resolve host {hostname!r}: {exc}"
        ) from exc

    if not resolved:
        raise EgressResolutionError(f"Host {hostname!r} resolved to no addresses")

    for ip_str in resolved:
        reason = ip_block_reason(ip_str)
        if reason:
            logger.warning(f"SSRF egress blocked: {hostname!r} resolved to {reason}")
            raise SSRFError(f"Blocked egress to {hostname!r} — resolves to {reason}")

    return resolved


def host_matches_allowlist(url: str, allowed_suffixes: List[str]) -> bool:
    """True if the URL host equals or is a subdomain of an allow-listed suffix.

    Used to gate attaching provider/tenant credentials to an outbound URL: never
    send secrets to a host that is not on the allow-list.
    """
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    for suffix in allowed_suffixes:
        s = suffix.lower().lstrip(".").rstrip(".")
        if not s:
            continue
        if host == s or host.endswith("." + s):
            return True
    return False


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _effective_port(parts: Any) -> Optional[int]:
    """The port a URL actually reaches, filling in the scheme's default.

    ``urlparse`` leaves ``port`` as None when the URL does not spell one out,
    so a bare comparison treats ``https://h`` and ``https://h:8443`` as equal
    on one side and unequal on the other depending on how they were written.
    """
    return parts.port if parts.port is not None else _DEFAULT_PORTS.get(parts.scheme)


def is_same_origin(previous: str, target: str) -> bool:
    """True if ``target`` is the same origin as ``previous``.

    Same host and port, and the same scheme or the one scheme change that is
    not a downgrade (http -> https, and only between their default ports).
    Used to follow a redirect that stays on the destination the caller already
    chose, while refusing one that moves the request somewhere they did not.
    """
    a, b = urlparse(previous), urlparse(target)
    if (a.hostname or "").lower() != (b.hostname or "").lower():
        return False
    if a.scheme == b.scheme:
        return _effective_port(a) == _effective_port(b)
    # A scheme upgrade counts as same-origin only on the default ports.
    return (
        a.scheme == "http"
        and b.scheme == "https"
        and _effective_port(a) == 80
        and _effective_port(b) == 443
    )
