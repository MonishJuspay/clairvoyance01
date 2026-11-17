"""URL helpers for outbound requests."""

from urllib.parse import urlparse


def redact_url(url: str) -> str:
    """Return ``url`` with its query string and userinfo removed.

    Tenants routinely authenticate receivers with a query token or HTTP Basic
    userinfo, so a destination URL isn't safe to log as-is; scheme, host, port
    and path survive, which is what triage needs. Never raises — used to build
    error messages and log lines, so it must not become a second failure mode.
    """
    try:
        parts = urlparse(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        if parts.username:
            netloc = f"REDACTED@{netloc}"
        redacted = parts._replace(netloc=netloc, query="", fragment="")
        return redacted.geturl() + ("?REDACTED" if parts.query else "")
    except Exception:  # pragma: no cover - defensive; logging must not break
        return "<unparseable url>"
