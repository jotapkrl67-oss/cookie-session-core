import json
import os
from http.cookies import SimpleCookie

import pytest
from cryptography.exceptions import InvalidTag

from cookie_session_core.config import Settings
from cookie_session_core.core import (
    ConsumedLaunch,
    CookieSessionCore,
    _strip_extended_cookie_attributes,
)
from cookie_session_core.models import ServicePolicy
from cookie_session_core.parser import (
    parse_cookie_import,
    parse_localstorage_import,
    validate_cookie,
)
from cookie_session_core.schemas import CookieImport, LaunchInput, ServiceInput
from cookie_session_core.vault import CookieVault


def test_proxy_has_canonical_root_route_for_cookie_path_boundary():
    # Route inspection does not start the database-backed application lifespan.
    os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/test")
    os.environ.setdefault("SUPABASE_URL", "https://example.supabase.co")
    os.environ.setdefault("SUPABASE_PUBLISHABLE_KEY", "x" * 32)
    os.environ.setdefault("ADMIN_PROXY_SECRET", "a" * 32)
    os.environ.setdefault("PUBLIC_BASE_URL", "https://proxy.example.com")
    os.environ.setdefault("ALLOWED_ORIGINS", "https://app.example.com")
    os.environ.setdefault("COOKIE_VAULT_KEY_BASE64", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=")
    os.environ.setdefault(
        "LAUNCH_TOKEN_PEPPER_BASE64", "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="
    )
    from cookie_session_core.app import create_app

    app = create_app()
    paths = {route.path for route in app.routes}
    assert "/proxy/{service_id}" in paths
    assert "/proxy/{service_id}/{path:path}" in paths


def test_public_urls_are_strict_origins_without_paths():
    values = {
        "database_url": "postgresql://user:pass@localhost/test",
        "supabase_url": "https://example.supabase.co",
        "supabase_publishable_key": "x" * 32,
        "cookie_vault_key_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "launch_token_pepper_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "admin_proxy_secret": "a" * 32,
        "public_base_url": "https://proxy.example.com",
        "allowed_origins": "https://app.example.com",
    }
    assert Settings(**values).origin_list == ["https://app.example.com"]
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL"):
        Settings(**{**values, "public_base_url": "https://proxy.example.com/path"})
    with pytest.raises(ValueError, match="ALLOWED_ORIGINS"):
        Settings(**{**values, "allowed_origins": "https://app.example.com/path"}).origin_list


def test_playwright_provider_configuration_is_optional_and_auto_refreshable():
    values = {
        "database_url": "postgresql://user:pass@localhost/test",
        "supabase_url": "https://example.supabase.co",
        "supabase_publishable_key": "x" * 32,
        "cookie_vault_key_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "launch_token_pepper_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "admin_proxy_secret": "a" * 32,
        "public_base_url": "https://proxy.example.com",
        "allowed_origins": "https://app.example.com",
    }

    disabled = Settings(**values)
    assert disabled.cf_auto_refresh is True
    assert disabled.cloudflare_cookie_provider_enabled is False

    enabled = Settings(
        **values,
        playwright_service_url="https://playwright.example.com",
        playwright_service_token=" " + "t" * 32 + " ",
    )
    assert enabled.playwright_service_token == "t" * 32
    assert enabled.cloudflare_cookie_provider_enabled is True

    explicitly_disabled = Settings(
        **values,
        playwright_service_url="https://playwright.example.com",
        playwright_service_token="t" * 32,
        cf_auto_refresh=False,
    )
    assert explicitly_disabled.cloudflare_cookie_provider_enabled is False


def test_playwright_provider_configuration_rejects_unsafe_or_incomplete_origins():
    values = {
        "database_url": "postgresql://user:pass@localhost/test",
        "supabase_url": "https://example.supabase.co",
        "supabase_publishable_key": "x" * 32,
        "cookie_vault_key_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "launch_token_pepper_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "admin_proxy_secret": "a" * 32,
        "public_base_url": "https://proxy.example.com",
        "allowed_origins": "https://app.example.com",
    }

    with pytest.raises(ValueError, match="PLAYWRIGHT_SERVICE_TOKEN"):
        Settings(**values, playwright_service_url="https://playwright.example.com")
    with pytest.raises(ValueError, match="PLAYWRIGHT_SERVICE_URL"):
        Settings(
            **values,
            playwright_service_url="https://playwright.example.com/api",
            playwright_service_token="t" * 32,
        )


def test_upstream_proxy_configuration_is_validated_and_credentials_are_encoded():
    values = {
        "database_url": "postgresql://user:pass@localhost/test",
        "supabase_url": "https://example.supabase.co",
        "supabase_publishable_key": "x" * 32,
        "cookie_vault_key_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "launch_token_pepper_base64": "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=",
        "admin_proxy_secret": "a" * 32,
        "public_base_url": "https://proxy.example.com",
        "allowed_origins": "https://app.example.com",
    }
    direct = Settings(**values)
    assert direct.egress_id == "direct"
    assert direct.httpx_proxy_url is None

    proxied = Settings(
        **values,
        upstream_proxy_url="http://proxy.example.com:3128",
        upstream_proxy_username="user@example.com",
        upstream_proxy_password="p:a/ss",
    )
    assert proxied.httpx_proxy_url == (
        "http://user%40example.com:p%3Aa%2Fss@proxy.example.com:3128"
    )
    assert proxied.egress_id != "direct"

    with pytest.raises(ValueError, match="USERNAME"):
        Settings(
            **values,
            upstream_proxy_url="http://proxy.example.com:3128",
            upstream_proxy_password="password-only",
        )


def test_devtools_table_and_policy():
    raw = "session\tsecret\t.example.com\t/\t2027-01-01T00:00:00Z\t20\t✓\t✓\tLax"
    cookie = parse_cookie_import(raw, "example.com")[0]
    validate_cookie(
        cookie,
        ServicePolicy(
            id="service",
            name="Example",
            upstream_url="https://example.com/",
            allowed_domains=("example.com",),
        ),
    )
    assert cookie.name == "session"
    assert cookie.same_site == "Lax"
    assert cookie.http_only is True
    assert cookie.secure is True


def test_devtools_table_preserves_script_visible_cookie_flag():
    raw = "csrf_token\tvisible\t.example.com\t/\tSession\t20\t\t✓\tLax"
    cookie = parse_cookie_import(raw, "example.com")[0]
    assert cookie.http_only is False
    assert cookie.secure is True


def test_vault_is_bound_to_user_service_and_name():
    vault = CookieVault(b"x" * 32)
    encrypted = vault.encrypt("secret", "user-a", "service-a", "session")
    assert (
        vault.decrypt(encrypted.ciphertext, encrypted.nonce, "user-a", "service-a", "session")
        == "secret"
    )
    with pytest.raises(InvalidTag):
        vault.decrypt(encrypted.ciphertext, encrypted.nonce, "user-b", "service-a", "session")


def test_cookie_header():
    cookies = parse_cookie_import("session=abc; theme=dark", "example.com")
    assert [item.name for item in cookies] == ["session", "theme"]


def test_json_cookie_booleans_and_host_only_semantics_are_preserved():
    cookies = parse_cookie_import(
        '[{"name":"host","value":"a","domain":"app.example.com",'
        '"secure":"false","httpOnly":"false"},'
        '{"name":"parent","value":"b","domain":".example.com"},'
        '{"name":"explicit","value":"c","domain":"example.com","hostOnly":false}]',
        "example.com",
    )

    assert cookies[0].host_only is True
    assert cookies[0].secure is False
    assert cookies[0].http_only is False
    assert cookies[1].host_only is False
    assert cookies[2].host_only is False


def test_extended_set_cookie_attributes_are_removed_without_corrupting_quoted_values():
    cleaned = _strip_extended_cookie_attributes(
        'session="value;still-value"; Path=/; Secure; HttpOnly; '
        "Priority=High; Partitioned; SameParty"
    )
    parsed = SimpleCookie()
    parsed.load(cleaned)

    assert parsed["session"].value == "value;still-value"
    assert parsed["session"]["secure"] is True
    assert "Priority" not in cleaned
    assert "Partitioned" not in cleaned


def test_localstorage_import_preserves_real_web_storage_keys_and_values():
    items = parse_localstorage_import(
        '{"":"empty key"," spaced ":"kept", "object":{"nested":true}, "number":42}'
    )

    assert {item.key: item.value for item in items} == {
        "": "empty key",
        " spaced ": "kept",
        "object": '{"nested": true}',
        "number": "42",
    }


def test_localstorage_import_rejects_postgres_incompatible_null_key():
    with pytest.raises(ValueError, match="null character"):
        parse_localstorage_import('{"bad\\u0000key":"value"}')


@pytest.mark.asyncio
async def test_localstorage_sync_rejects_ambiguous_or_invalid_batches_before_database_use():
    class UnusedPool:
        def acquire(self):
            raise AssertionError("invalid sync must not reach the database")

    core = CookieSessionCore(UnusedPool(), b"v" * 32, b"p" * 32)
    item = ConsumedLaunch(
        user_id="user-a",
        service_id="00000000-0000-0000-0000-000000000001",
        upstream_url="https://example.com/",
        allowed_domains=("example.com",),
        allowed_paths=("/",),
        allowed_cookie_names=(),
        cookies=[],
    )

    with pytest.raises(ValueError, match="update and delete"):
        await core.sync_local_storage(
            launch=item,
            upserts={"same": "new"},
            deletes=["same"],
        )
    with pytest.raises(ValueError, match="value must be a string"):
        await core.sync_local_storage(launch=item, upserts={"key": 1})
    with pytest.raises(ValueError, match="key must be a string"):
        await core.sync_local_storage(launch=item, deletes=[{}])


def test_rejects_cookie_from_another_domain():
    cookie = parse_cookie_import("session=abc", "evil.example")[0]
    with pytest.raises(ValueError):
        validate_cookie(
            cookie,
            ServicePolicy(
                id="service",
                name="Example",
                upstream_url="https://example.com/",
                allowed_domains=("example.com",),
            ),
        )


def test_json_same_site_is_normalized_for_playwright():
    cookie = parse_cookie_import(
        '[{"name":"session","value":"fake","domain":"example.com","sameSite":"no_restriction"}]',
        "example.com",
    )[0]
    assert cookie.same_site == "None"


@pytest.mark.parametrize("expiry", [-1, -1.0, "-1", "-1.0"])
def test_json_negative_expiry_is_a_live_session_cookie(expiry):
    cookie = parse_cookie_import(
        json.dumps(
            [
                {
                    "name": "session",
                    "value": "active",
                    "domain": "example.com",
                    "expirationDate": expiry,
                }
            ]
        ),
        "example.com",
    )[0]

    assert cookie.expires_at is None


def test_service_rejects_private_destination_and_public_suffix():
    with pytest.raises(ValueError):
        ServiceInput(
            name="Private",
            upstream_url="https://127.0.0.1/",
            allowed_domains=["127.0.0.1"],
        )
    with pytest.raises(ValueError):
        ServiceInput(
            name="Suffix",
            upstream_url="https://example.co.uk/",
            allowed_domains=["co.uk"],
        )
    with pytest.raises(ValueError):
        ServiceInput(
            name="Shared hosting suffix",
            upstream_url="https://example.github.io/",
            allowed_domains=["github.io"],
        )
    with pytest.raises(ValueError):
        ServiceInput(
            name="SSRF allowlist",
            upstream_url="https://example.com/",
            allowed_domains=["example.com", "127.0.0.1"],
        )
    with pytest.raises(ValueError):
        ServiceInput(
            name="Malformed allowlist",
            upstream_url="https://example.com/",
            allowed_domains=["example.com", "bad..example.com"],
        )


def test_service_accepts_only_clean_transparent_proxy_hostname():
    service = ServiceInput(
        name="Transparent",
        upstream_url="https://example.com/",
        proxy_hostname="Chat.Example-Proxy.com.",
        allowed_domains=["example.com"],
    )
    assert service.proxy_hostname == "chat.example-proxy.com"
    with pytest.raises(ValueError):
        ServiceInput(
            name="Bad host",
            upstream_url="https://example.com/",
            proxy_hostname="https://proxy.example.com/path",
            allowed_domains=["example.com"],
        )


def test_launch_and_cookie_import_do_not_accept_profiles():
    LaunchInput()
    CookieImport(cookies="session=fake")
    with pytest.raises(ValueError):
        LaunchInput(profile_id="00000000-0000-0000-0000-000000000001")
    with pytest.raises(ValueError):
        CookieImport(cookies="session=fake", label="Old profile")


def test_cookie_security_validation():
    policy = ServicePolicy(
        id="service",
        name="Example",
        upstream_url="https://example.com/",
        allowed_domains=("example.com",),
    )
    with pytest.raises(ValueError, match="control"):
        parse_cookie_import(
            '[{"name":"session","value":"bad\\u0000value","domain":"example.com"}]',
            "example.com",
        )
    with pytest.raises(ValueError, match="SameSite=None"):
        parse_cookie_import(
            '[{"name":"session","value":"ok","domain":"example.com",'
            '"sameSite":"None","secure":false}]',
            "example.com",
        )
    suffix_cookie = parse_cookie_import("session=ok", "com.br")[0]
    with pytest.raises(ValueError, match="public suffix"):
        validate_cookie(suffix_cookie, policy)


def test_cookie_allowed_path_uses_an_rfc_boundary():
    policy = ServicePolicy(
        id="service",
        name="Restricted",
        upstream_url="https://example.com/admin",
        allowed_domains=("example.com",),
        allowed_paths=("/admin",),
    )
    allowed = parse_cookie_import(
        '[{"name":"session","value":"ok","domain":"example.com","path":"/admin/users"}]',
        "example.com",
    )[0]
    rejected = parse_cookie_import(
        '[{"name":"session","value":"bad","domain":"example.com","path":"/administrator"}]',
        "example.com",
    )[0]

    validate_cookie(allowed, policy)
    with pytest.raises(ValueError, match="path is not allowed"):
        validate_cookie(rejected, policy)


@pytest.mark.asyncio
async def test_jti_replay_guard_blocks_duplicate_launch():
    """The project's opaque one-use launch credential is the replay guard."""

    class Connection:
        available = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def transaction(self):
            return self

        async def fetchrow(self, query, *_args):
            if "DELETE FROM cookie_core_launch_tokens" in query:
                if not self.available:
                    return None
                self.available = False
                return {
                    "user_id": "user-a",
                    "service_id": "00000000-0000-0000-0000-000000000001",
                }
            return {
                "upstream_url": "https://example.com/",
                "allowed_domains": ["example.com"],
                "allowed_paths": ["/"],
                "allowed_cookie_names": [],
                "proxy_hostname": None,
            }

        async def fetch(self, *_args):
            return []

        async def execute(self, *_args):
            return None

    class Pool:
        def __init__(self):
            self.connection = Connection()

        def acquire(self):
            return self.connection

    core = CookieSessionCore(Pool(), b"v" * 32, b"p" * 32)
    await core.consume_launch(raw_token="one-use-launch")
    with pytest.raises(ValueError, match="already used"):
        await core.consume_launch(raw_token="one-use-launch")
