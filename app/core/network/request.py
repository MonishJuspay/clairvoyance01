"""``make_request``: an aiohttp request with the egress policy on every hop.

The policy itself (which addresses may be reached, allow-lists, origins) lives
in app.core.security.ssrf; this module applies it to a real request: it follows
redirects itself so each hop is checked, connects to the checked address, and
keeps credentials and bodies from following a redirect off the caller's host.
Policy refusals surface as app.core.network errors.
"""

import asyncio
import ipaddress
import ssl
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence
from urllib.parse import urljoin, urlparse

import aiohttp
from yarl import URL

from app.core.logger import logger
from app.core.network.errors import (
    HostUnresolvable,
    RequestBlocked,
    TooManyRedirects,
)
from app.core.network.urls import redact_url
from app.core.security.ssrf import (
    EgressResolutionError,
    SSRFError,
    host_matches_allowlist,
    is_same_origin,
    validate_egress_url,
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Connect cap for every address but the last, so a dead one fails over quickly.
ADDRESS_CONNECT_CAP = 1.0
_TLS_CONTEXTS: Dict[str, ssl.SSLContext] = {}
_BODY_KWARGS = frozenset({"json", "data", "content"})
# Carried credentials that are not headers: aiohttp merges `params` into the
# target's query string and sends `cookies` whatever the host.
_CREDENTIAL_KWARGS = frozenset({"params", "cookies"})

# Allow-list, not deny-list: auth material isn't confined to known header names.
_SAFE_REDIRECT_HEADERS = frozenset(
    {"accept", "accept-encoding", "accept-language", "content-type", "user-agent"}
)


def _remember(cache: dict, key: Any, value: Any, limit: int) -> None:
    """Bounded insert: drop the oldest entry once ``limit`` is reached."""
    if key not in cache and len(cache) >= limit:
        cache.pop(next(iter(cache)))
    cache[key] = value


def _without_credential_headers(kwargs: dict, target: str) -> dict:
    """Return ``kwargs`` with caller headers reduced to :data:`_SAFE_REDIRECT_HEADERS`.

    Used on redirect hops that leave the allow-list or change host, so header
    credentials cannot follow the request to a host the caller never chose.
    """
    headers = kwargs.get("headers")
    if not headers:
        return kwargs
    kept = {
        k: v for k, v in dict(headers).items() if k.lower() in _SAFE_REDIRECT_HEADERS
    }
    dropped = sorted(set(dict(headers)) - set(kept))
    if dropped:
        logger.warning(
            f"make_request: withholding {dropped} on cross-host redirect "
            f"to {urlparse(target).hostname!r}"
        )
    return {**kwargs, "headers": kept}


def _total_timeout_seconds(candidate: Any) -> Optional[float]:
    """The ``total`` budget a caller asked for, or None if they asked for none.

    Accepts what aiohttp accepts in a ``timeout=`` slot: a ClientTimeout, or a
    bare number (older callers). Anything else — including ClientTimeout with
    total=None, which means "no overall limit" — yields None.
    """
    if candidate is None:
        return None
    total = getattr(candidate, "total", candidate)
    if isinstance(total, (int, float)) and total > 0:
        return float(total)
    return None


def _with_total(
    base: Optional[aiohttp.ClientTimeout],
    total: Optional[float],
    sock_connect_cap: Optional[float] = None,
) -> aiohttp.ClientTimeout:
    """Copy ``base`` with a new ``total``, keeping every other field.

    ``sock_connect_cap`` lowers ``sock_connect`` to at most that many seconds.

    ClientTimeout is a dataclass in some aiohttp versions and attrs in others,
    so neither ``dataclasses.replace`` nor ``attr.evolve`` is portable; copying
    the fields the installed version actually declares is.
    """
    carried = {
        name: getattr(base, name)
        for name in ("connect", "sock_read", "sock_connect", "ceil_threshold")
        if base is not None and hasattr(base, name)
    }
    if sock_connect_cap is not None:
        current = carried.get("sock_connect")
        carried["sock_connect"] = min(current or sock_connect_cap, sock_connect_cap)
    return aiohttp.ClientTimeout(total=total, **carried)


async def _tls_context(tls_name: str) -> ssl.SSLContext:
    """One context per TLS name: aiohttp reuses connections by IP and context, so
    two names on one IP would otherwise share a connection opened for the first."""
    context = _TLS_CONTEXTS.get(tls_name)
    if context is None:
        # Loading the CA bundle blocks for a few ms; about 1 MB each, so capped.
        context = await asyncio.to_thread(ssl.create_default_context)
        _remember(_TLS_CONTEXTS, tls_name, context, 16)
    return context


def _pinned_targets(url: str, ips: List[str]) -> List[tuple]:
    """(url, host_header, tls_name) per validated address, in order.

    aiohttp resolves the name again at connect time, and that second answer is
    not the one that was validated — the gap a rebinding host walks through, and
    the one a proxy widens by resolving on our behalf. Connecting to a literal
    address closes both; the Host header and TLS name still carry the real host,
    so routing and certificate verification are unchanged.

    Every checked address is offered, not just the first, so a host with both an
    A and an AAAA record keeps its failover. ``make_request`` caps the
    connect time of each address but the last, so a silent one is skipped fast.
    """
    parts = URL(url)
    host = parts.raw_host
    if not host:
        return [(url, None, None)]
    try:
        ipaddress.ip_address(host)
        return [(url, None, None)]  # already a literal; nothing to pin
    except ValueError:
        pass
    authority = host if parts.explicit_port is None else f"{host}:{parts.port}"
    return [(str(parts.with_host(ip)), authority, host) for ip in ips]


@asynccontextmanager
async def make_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    auth: Optional[aiohttp.BasicAuth] = None,
    allowed_host_suffixes: Optional[Sequence[str]] = None,
    allow_http: bool = False,
    max_redirects: int = 3,
    same_origin_only: bool = False,
    **kwargs: Any,
) -> AsyncIterator[aiohttp.ClientResponse]:
    """Issue an aiohttp request with the egress policy checked on every hop.

    Redirects are followed manually so each hop is re-validated (aiohttp's own
    redirect following would skip the check). Behaviour:

    - Every hop goes through the egress policy, blocking an internal/metadata
      target at any point in the chain.
    - ``allowed_host_suffixes``: the initial host must be on the allow-list
      (hard gate); a redirect leaving it drops ``auth`` but may still follow
      to e.g. a public CDN.
    - ``same_origin_only`` restricts redirects to the same host (plus an
      http->https upgrade) — what makes following a redirect safe at all for
      a request whose body is a signed webhook payload.
    - Redirect method/body follow the browser rule, not a raw replay:
      301/302/303 rewrite to GET and drop the body; only 307/308 preserve
      both.
    - Exhausting ``max_redirects`` raises rather than returning the final 3xx.

    Raises:
        RequestBlocked: the policy refused a hop. Never retry.
        HostUnresolvable: a hop's host could not be resolved. Worth retrying.
        TooManyRedirects: the chain ran past ``max_redirects``.

    The yielded response must be consumed inside the ``async with`` block.
    """
    # Redirects always drive here; caller-supplied allow_redirects would collide.
    if kwargs.pop("allow_redirects", None) is not None:
        logger.warning(
            "make_request: ignoring caller-supplied allow_redirects; "
            "redirects are followed manually so every hop can be revalidated"
        )

    # One deadline for the whole chain, not per hop, else each hop gets a fresh budget.
    caller_timeout = kwargs.get("timeout")
    total_budget = _total_timeout_seconds(caller_timeout)
    if total_budget is None:
        total_budget = _total_timeout_seconds(getattr(session, "timeout", None))
    loop = asyncio.get_running_loop()
    deadline = loop.time() + total_budget if total_budget is not None else None

    # Only `total` shrinks along the chain; connect/sock_read/... stay the
    # caller's. aiohttp does not merge a request timeout with the session's, so
    # the session's fields are carried over explicitly.
    base_timeout = (
        caller_timeout
        if isinstance(caller_timeout, aiohttp.ClientTimeout)
        else getattr(session, "timeout", None)
    )
    if not isinstance(base_timeout, aiohttp.ClientTimeout):
        base_timeout = None

    def time_left(hop: int) -> Optional[float]:
        if deadline is None:
            return None
        remaining = deadline - loop.time()
        if remaining <= 0:
            # Same exception a request would raise: retryable, unlike RequestBlocked.
            raise asyncio.TimeoutError(
                f"Redirect chain exceeded the {total_budget:g}s budget "
                f"after {hop} hop(s) fetching {redact_url(url)}"
            )
        return remaining

    current = url
    cur_method = method
    credentials_dropped = False
    for hop in range(max_redirects + 1):
        # The lookup spends the same budget: a stalled resolver is a timeout.
        try:
            validated = await asyncio.wait_for(
                validate_egress_url(current, allow_http=allow_http), time_left(hop)
            )
        except EgressResolutionError as e:
            raise HostUnresolvable(str(e)) from e
        except SSRFError as e:
            raise RequestBlocked(str(e)) from e

        send_auth = auth
        drop_credentials = False
        if allowed_host_suffixes is not None and not host_matches_allowlist(
            current, list(allowed_host_suffixes)
        ):
            if hop == 0:
                raise RequestBlocked(
                    "Refusing request: initial host not on allow-list: "
                    f"{redact_url(current)}"
                )
            send_auth = None  # off-allow-list redirect target — never send creds
            drop_credentials = True

        # ORIGINAL url compared here, not the previous hop; A->B->B re-attaches else.
        # http upgrade is not a departure: checksum header is outside the allow-list.
        if not credentials_dropped and not is_same_origin(url, current):
            credentials_dropped = True

        if credentials_dropped:
            send_auth = None
            drop_credentials = True

        # Header-borne creds (bearer token, cookie) dropped on the same hops as auth.
        send_kwargs = kwargs
        if drop_credentials:
            send_kwargs = _without_credential_headers(kwargs, current)

        # Body drops on the same hops creds do; 307/308 would else replay it off-host.
        if credentials_dropped:
            send_kwargs = {
                k: v
                for k, v in send_kwargs.items()
                if k not in _BODY_KWARGS and k not in _CREDENTIAL_KWARGS
            }

        # Connect to an address that was actually checked, not to the name.
        response = None
        last_error: Optional[BaseException] = None
        targets = _pinned_targets(current, validated)
        for index, (target, host_header, tls_name) in enumerate(targets):
            attempt_kwargs = dict(send_kwargs)
            remaining = time_left(hop)
            cap = None if index == len(targets) - 1 else ADDRESS_CONNECT_CAP
            if remaining is not None or cap is not None:
                if remaining is None:  # no deadline: keep the caller's total
                    remaining = getattr(base_timeout, "total", None)
                attempt_kwargs["timeout"] = _with_total(base_timeout, remaining, cap)
            if host_header is not None:
                headers = dict(attempt_kwargs.get("headers") or {})
                headers.setdefault("Host", host_header)
                attempt_kwargs["headers"] = headers
                if URL(current).scheme == "https":
                    attempt_kwargs.setdefault("server_hostname", tls_name)
                    if "ssl" not in attempt_kwargs:
                        attempt_kwargs["ssl"] = await _tls_context(tls_name)
            try:
                response = await session.request(
                    cur_method,
                    target,
                    auth=send_auth,
                    allow_redirects=False,
                    **attempt_kwargs,
                )
                break
            except (
                aiohttp.ClientConnectorError,
                aiohttp.ConnectionTimeoutError,
            ) as exc:
                # This address is unreachable; the others were validated too.
                last_error = exc
        if response is None:
            raise last_error or aiohttp.ClientError(f"could not reach {hop}")
        location = response.headers.get("Location")
        if response.status in _REDIRECT_STATUSES and location:
            if hop >= max_redirects:
                response.release()
                raise TooManyRedirects(
                    f"Too many redirects while fetching {redact_url(url)!r} "
                    f"(limit {max_redirects})"
                )
            response.release()
            target = urljoin(current, location)
            if same_origin_only and not is_same_origin(current, target):
                raise RequestBlocked(
                    f"Refusing to follow an off-origin redirect: "
                    f"{redact_url(current)} -> {redact_url(target)}"
                )
            current = target
            # The Location carries its own query; re-sending `params` appended
            # the caller's to it (?token=S&token=S on a same-origin hop).
            kwargs = {k: v for k, v in kwargs.items() if k != "params"}
            # aiohttp's rule: 303 becomes GET (not HEAD), 301/302 only for POST.
            # Any other method keeps itself and its body, as before this guard.
            method = cur_method.upper()
            if (response.status == 303 and method not in ("GET", "HEAD")) or (
                response.status in (301, 302) and method == "POST"
            ):
                cur_method = "GET"
                kwargs = {k: v for k, v in kwargs.items() if k not in _BODY_KWARGS}
            continue

        try:
            yield response
        finally:
            response.release()
        return

    raise TooManyRedirects(f"Too many redirects while fetching {url!r}")
