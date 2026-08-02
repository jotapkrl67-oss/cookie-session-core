import json

import pytest
from cryptography.exceptions import InvalidTag

from cookie_session_core.core import CookieSessionCore
from cookie_session_core.models import ServicePolicy
from cookie_session_core.parser import parse_cookie_import, validate_cookie
from cookie_session_core.schemas import CookieImport, LaunchInput, ServiceInput
from cookie_session_core.vault import CookieVault


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
