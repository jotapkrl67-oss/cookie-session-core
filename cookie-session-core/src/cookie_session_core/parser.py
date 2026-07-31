from __future__ import annotations

import json
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from .models import ImportedCookie, ServicePolicy


def _same_site(value: object) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_")
    if normalized in {"strict", "lax"}:
        return normalized.capitalize()
    if normalized in {"none", "no_restriction"}:
        return "None"
    return None


def _expiry(value: object) -> datetime | None:
    if value in (None, "", 0, "0", "Session"):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_cookie_import(raw: str, default_domain: str) -> list[ImportedCookie]:
    """Accept DevTools tables, JSON exports, Netscape files, or a Cookie header."""
    if not raw.strip() or len(raw.encode()) > 100_000:
        raise ValueError("Cookie input is empty or larger than 100 KB")
    output: list[ImportedCookie] = []
    text = raw.strip()

    if text.startswith(("[", "{")):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid cookie JSON") from exc
        items = decoded.get("cookies", []) if isinstance(decoded, dict) else decoded
        if not isinstance(items, list):
            raise ValueError("Cookie JSON must contain a list")
        for item in items:
            if not isinstance(item, dict) or not item.get("name") or "value" not in item:
                raise ValueError("A JSON cookie is missing name/value")
            output.append(
                ImportedCookie(
                    name=str(item["name"]),
                    value=str(item["value"]),
                    domain=str(item.get("domain") or default_domain),
                    path=str(item.get("path") or "/"),
                    expires_at=_expiry(item.get("expirationDate") or item.get("expires")),
                    secure=bool(item.get("secure", True)),
                    http_only=bool(item.get("httpOnly", True)),
                    same_site=_same_site(item.get("sameSite")),
                )
            )
    else:
        lines = [
            line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        columns = [line.split("\t") for line in lines]
        is_netscape = bool(columns) and all(
            len(parts) >= 7
            and parts[1].upper() in {"TRUE", "FALSE"}
            and parts[2].startswith("/")
            and parts[3].upper() in {"TRUE", "FALSE"}
            for parts in columns
        )
        is_devtools = bool(columns) and all(
            len(parts) >= 4 and parts[0].strip() and parts[2].strip()
            for parts in columns
        )
        if is_netscape:
            for line in lines:
                domain, _, path, secure, expires, name, value = line.split("\t", 6)
                output.append(
                    ImportedCookie(
                        name=name,
                        value=value,
                        domain=domain,
                        path=path or "/",
                        expires_at=_expiry(expires),
                        secure=secure.upper() == "TRUE",
                    )
                )
        elif is_devtools:
            for parts in columns:
                name, value, domain, path = (part.strip() for part in parts[:4])
                rest = [part.strip() for part in parts[4:]]
                same_site = next((_same_site(part) for part in rest if _same_site(part)), None)
                output.append(
                    ImportedCookie(
                        name=name,
                        value=value,
                        domain=domain or default_domain,
                        path=path or "/",
                        expires_at=_expiry(rest[0]) if rest else None,
                        secure=True,
                        http_only=True,
                        same_site=same_site,
                    )
                )
        else:
            parsed = SimpleCookie()
            parsed.load(text.removeprefix("Cookie:").strip())
            output = [
                ImportedCookie(name=name, value=morsel.value, domain=default_domain)
                for name, morsel in parsed.items()
            ]

    if not 1 <= len(output) <= 200:
        raise ValueError("Import must contain between 1 and 200 cookies")
    keys = {(item.name, item.domain.lower(), item.path) for item in output}
    if len(keys) != len(output):
        raise ValueError("Cookie import contains duplicates")
    return output


def cookie_matches_host(cookie_domain: str, host: str) -> bool:
    domain = cookie_domain.lower().lstrip(".")
    host = host.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def validate_cookie(cookie: ImportedCookie, policy: ServicePolicy) -> None:
    if not cookie.name or len(cookie.name) > 250 or len(cookie.value.encode()) > 16_384:
        raise ValueError("Invalid cookie name or value")
    domain = cookie.domain.lower().lstrip(".")
    explicitly_allowed = any(
        domain == allowed.lower().lstrip(".")
        or domain.endswith("." + allowed.lower().lstrip("."))
        for allowed in policy.allowed_domains
    )
    upstream_host = (urlparse(policy.upstream_url).hostname or "").lower()
    parts = domain.split(".")
    common_public_suffixes = {"ac", "co", "com", "edu", "gov", "net", "org"}
    looks_like_public_suffix = (
        len(parts) == 2 and len(parts[-1]) == 2 and parts[-2] in common_public_suffixes
    )
    parent_cookie_for_upstream = (
        len(parts) >= 2
        and not looks_like_public_suffix
        and cookie_matches_host(domain, upstream_host)
    )
    if not explicitly_allowed and not parent_cookie_for_upstream:
        raise ValueError(f"Cookie domain is not allowed: {cookie.domain}")
    if policy.allowed_cookie_names and cookie.name not in policy.allowed_cookie_names:
        raise ValueError(f"Cookie name is not allowed: {cookie.name}")
    if not cookie.path.startswith("/") or not any(
        cookie.path.startswith(prefix) for prefix in policy.allowed_paths
    ):
        raise ValueError(f"Cookie path is not allowed: {cookie.path}")
