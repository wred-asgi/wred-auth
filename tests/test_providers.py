import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from wred_auth import AuthError
from wred_auth.providers import GitHub, Google


async def test_google_signature_nonce_and_pkce():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "test-key"
    nonce = "expected-nonce"

    async def server(request):
        if request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [jwk]})
        fields = parse_qs(request.content.decode())
        assert fields["code_verifier"] == ["v" * 48]
        claims = {
            "iss": "https://accounts.google.com",
            "aud": "client",
            "sub": "google-123",
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
            "nonce": nonce,
            "email": "alice@example.test",
            "email_verified": True,
        }
        return httpx.Response(
            200,
            json={
                "access_token": "provider-access",
                "token_type": "Bearer",
                "id_token": jwt.encode(
                    claims, key, algorithm="RS256", headers={"kid": "test-key"}
                ),
            },
        )

    provider = Google("client", "secret", transport=httpx.MockTransport(server))
    url = provider.authorization_url(
        state="state",
        nonce="expected-nonce",
        verifier="v" * 48,
        redirect_uri="https://example.test/callback",
    )
    params = parse_qs(urlparse(url).query)
    assert params["code_challenge_method"] == ["S256"] and params["state"] == ["state"]
    result = await provider.exchange(
        code="code",
        verifier="v" * 48,
        nonce="expected-nonce",
        redirect_uri="https://example.test/callback",
    )
    assert result["subject"] == "google-123" and result["email_verified"]
    with pytest.raises(AuthError):
        await provider.exchange(
            code="code",
            verifier="v" * 48,
            nonce="wrong-nonce",
            redirect_uri="https://example.test/callback",
        )


async def test_github_flow_binding_linking_and_replay(accounts):
    auth, delivered = accounts

    async def server(request):
        if request.url.path.endswith("/access_token"):
            return httpx.Response(
                200, json={"access_token": "provider-access", "token_type": "Bearer"}
            )
        assert request.headers["authorization"] == "Bearer provider-access"
        if request.url.path.endswith("/emails"):
            return httpx.Response(
                200,
                json=[
                    {"email": "alice@example.test", "verified": True, "primary": True}
                ],
            )
        return httpx.Response(200, json={"id": 123})

    auth.providers["github"] = GitHub(
        "client", "secret", transport=httpx.MockTransport(server)
    )

    async def start(user=None):
        result = await auth.oauth_start(
            "github", callback_url="https://example.test/callback", user=user
        )
        state = parse_qs(urlparse(result["url"]).query)["state"][0]
        return state, result["browser"]

    state, browser = await start()
    with pytest.raises(AuthError):
        await auth.oauth_callback("github", state=state, code="code", browser="wrong")
    tokens = await auth.oauth_callback(
        "github", state=state, code="code", browser=browser
    )
    user = await auth.authenticate(tokens["access_token"])
    with pytest.raises(AuthError):
        await auth.oauth_callback("github", state=state, code="code", browser=browser)
    # Another provider identity with the same email cannot silently link itself.
    auth.providers["another"] = auth.providers["github"]
    result = await auth.oauth_start(
        "another", callback_url="https://example.test/callback"
    )
    state = parse_qs(urlparse(result["url"]).query)["state"][0]
    with pytest.raises(AuthError, match="existing account"):
        await auth.oauth_callback(
            "another", state=state, code="code", browser=result["browser"]
        )
    result = await auth.oauth_start(
        "another", callback_url="https://example.test/callback", user=user
    )
    state = parse_qs(urlparse(result["url"]).query)["state"][0]
    assert await auth.oauth_callback(
        "another", state=state, code="code", browser=result["browser"]
    ) == {"detail": "Identity linked"}
