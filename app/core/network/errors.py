"""Errors raised by app.core.network.

Callers catch these, never the security checks that produce them: the network
layer runs the egress policy (app.core.security.ssrf) internally and reports
its answer in these terms.
"""


class NetworkError(Exception):
    """Base for every error app.core.network raises."""


class RequestBlocked(NetworkError):
    """The egress policy refused the destination: an internal or metadata
    address, a disallowed scheme, a host off the allow-list, or an off-origin
    redirect. The same request gets the same answer, so never retry it."""


class HostUnresolvable(NetworkError):
    """The host could not be resolved: a transient failure worth retrying,
    not a refusal."""


class TooManyRedirects(NetworkError):
    """The redirect chain ran past ``max_redirects``: a fault, not a refusal."""
