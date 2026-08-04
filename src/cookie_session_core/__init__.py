"""Headless cookie-session primitives for integration into an existing backend."""

from .cloudflare_detection import (
    ClassificationResult,
    UpstreamClassification,
    classify_upstream_response,
)
from .cloudflare_provider import (
    CloudflareClearanceNotIssuedError,
    CloudflareCookie,
    CloudflareCookieCoordinator,
    CloudflareCookieProvider,
    CloudflareCookieProviderError,
    CloudflareCookieResult,
    CloudflareProviderAuthenticationError,
    CloudflareProviderProtocolError,
    CloudflareProviderTimeoutError,
    CloudflareProviderUnavailableError,
    CloudflareProviderValidationError,
    CloudflareSessionStore,
    HttpCloudflareCookieProvider,
)
from .core import ConsumedLaunch, CookieSessionCore
from .models import ImportedCookie, ImportedLocalStorageItem, ServicePolicy
from .parser import parse_cookie_import, parse_localstorage_import
from .vault import CookieVault

__all__ = [
    "ConsumedLaunch",
    "CloudflareCookie",
    "CloudflareCookieCoordinator",
    "CloudflareCookieProvider",
    "CloudflareCookieProviderError",
    "CloudflareProviderAuthenticationError",
    "CloudflareProviderProtocolError",
    "CloudflareProviderTimeoutError",
    "CloudflareProviderUnavailableError",
    "CloudflareProviderValidationError",
    "CloudflareClearanceNotIssuedError",
    "ClassificationResult",
    "UpstreamClassification",
    "classify_upstream_response",
    "CloudflareCookieResult",
    "CloudflareSessionStore",
    "HttpCloudflareCookieProvider",
    "CookieSessionCore",
    "CookieVault",
    "ImportedCookie",
    "ImportedLocalStorageItem",
    "ServicePolicy",
    "parse_cookie_import",
    "parse_localstorage_import",
]
