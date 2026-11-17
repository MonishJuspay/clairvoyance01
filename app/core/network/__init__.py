"""Outbound network requests.

The one way the platform calls a URL it does not control. ``make_request``
runs the egress policy (app.core.security.ssrf) on every hop internally;
callers see only this package's errors.
"""

from app.core.network.errors import (
    HostUnresolvable,
    NetworkError,
    RequestBlocked,
    TooManyRedirects,
)
from app.core.network.request import ADDRESS_CONNECT_CAP, make_request
from app.core.network.urls import redact_url

__all__ = [
    "ADDRESS_CONNECT_CAP",
    "HostUnresolvable",
    "NetworkError",
    "RequestBlocked",
    "TooManyRedirects",
    "make_request",
    "redact_url",
]
