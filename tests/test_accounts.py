import asyncio
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pyotp
import pytest
from wred import App

from wred_auth import Auth, AuthError, JWTVerifier, Principal

PASSWORD = "a long test password 123!"


def token(delivered):
    return parse_qs(urlparse(delivered[-1][2]).query)["token"][0]


async def registered(auth, delivered, email="alice@example.test"):
    await auth.register(email, PASSWORD)
    verification = token(delivered)
    await auth.verify_email(verification)
    return await auth.login(email, PASSWORD)


async def test_registration_login_and_rotation_replay(accounts):
    auth, delivered = accounts
    await auth.register("alice@example.test", PASSWORD)
    verification = token(delivered)
    with pytest.raises(AuthError):
        await auth.login("alice@example.test", PASSWORD)
    await auth.verify_email(verification)
    with pytest.raises(AuthError):
        await auth.verify_email(verification)
    tokens = await auth.login("alice@example.test", PASSWORD)
    user = await auth.authenticate(tokens["access_token"])
    rotated = await auth.refresh(tokens["refresh_token"])
    assert (await auth.authenticate(rotated["access_token"])).id == user.id
    with pytest.raises(AuthError):
        await auth.refresh(tokens["refresh_token"])
    with pytest.raises(AuthError):
        await auth.authenticate(rotated["access_token"])
    with pytest.raises(AuthError):
        await auth.refresh(rotated["refresh_token"])


async def test_concurrent_refresh_serialized(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    results = await asyncio.gather(
        *(auth.refresh(tokens["refresh_token"]) for _ in range(2)),
        return_exceptions=True,
    )
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, AuthError) for r in results) == 1
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])


async def test_reset_revokes_and_one_use(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    known = await auth.request_token("alice@example.test")
    reset = token(delivered)
    unknown = await auth.request_token("unknown@example.test")
    assert known == unknown
    await auth.reset_password(reset, PASSWORD + "new")
    with pytest.raises(AuthError):
        await auth.reset_password(reset, PASSWORD)
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])
    with pytest.raises(AuthError):
        await auth.login("alice@example.test", PASSWORD)
    assert "access_token" in await auth.login("alice@example.test", PASSWORD + "new")


async def test_mfa_challenges_recovery_and_replay(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    user = await auth.authenticate(tokens["access_token"])
    setup = await auth.setup_mfa(user)
    code = pyotp.TOTP(setup["secret"]).now()
    result = await auth.confirm_mfa(user, code)
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])
    challenge = await auth.login("alice@example.test", PASSWORD)
    assert challenge["mfa_required"]
    with pytest.raises(AuthError):
        await auth.complete_mfa(challenge["challenge"], code)
    tokens = await auth.complete_mfa(
        challenge["challenge"], result["recovery_codes"][0]
    )
    with pytest.raises(AuthError):
        await auth.complete_mfa(challenge["challenge"], result["recovery_codes"][1])
    another = await auth.login("alice@example.test", PASSWORD)
    with pytest.raises(AuthError):
        await auth.complete_mfa(another["challenge"], result["recovery_codes"][0])
    await auth.request_token("alice@example.test")
    await auth.reset_password(token(delivered), PASSWORD + " reset")
    with pytest.raises(AuthError):
        await auth.complete_mfa(another["challenge"], result["recovery_codes"][1])
    fresh = await auth.login("alice@example.test", PASSWORD + " reset")
    tokens = await auth.complete_mfa(fresh["challenge"], result["recovery_codes"][1])
    user = await auth.authenticate(tokens["access_token"])
    await auth.disable_mfa(user, result["recovery_codes"][2])
    assert "access_token" in await auth.login("alice@example.test", PASSWORD + " reset")


async def test_http_roles_logout_and_input(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    user = await auth.authenticate(tokens["access_token"])
    app = App()
    auth.mount(app)

    @app.route("/orders/{order_id}")
    @auth.require_auth()
    @auth.require_role("admin")
    async def order(request, order_id):
        return {"id": order_id}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://example.test"
    ) as client:
        assert (await client.get("/orders/1")).status_code == 401
        client.headers["authorization"] = "Bearer " + tokens["access_token"]
        assert (await client.get("/orders/1")).status_code == 403
        await auth.set_roles(user.id, ["admin"])
        assert (await client.get("/orders/1")).json() == {"id": "1"}
        assert (await client.post("/auth/login", json=[])).status_code == 422
        assert (
            await client.post(
                "/auth/login", json={"email": "invalid", "password": PASSWORD}
            )
        ).status_code == 422
        assert (await client.post("/auth/logout", json={})).status_code == 200
        assert (await client.get("/orders/1")).status_code == 401


async def test_password_change_deactivation_and_recent_auth(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    user = await auth.authenticate(tokens["access_token"])
    with pytest.raises(AuthError):
        await auth.setup_mfa(
            Principal(user.id, session_id=user.session_id, auth_time=1)
        )
    await auth.request_token("alice@example.test")
    outstanding_reset = token(delivered)
    await auth.change_password(user, PASSWORD, PASSWORD + "changed")
    with pytest.raises(AuthError):
        await auth.reset_password(outstanding_reset, PASSWORD + "stolen")
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])
    tokens = await auth.login("alice@example.test", PASSWORD + "changed")
    await auth.set_active(user.id, False)
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])
    with pytest.raises(AuthError):
        await auth.login("alice@example.test", PASSWORD + "changed")


async def test_invalid_reset_does_not_spend_password_hashing_budget(
    accounts, monkeypatch
):
    auth, _ = accounts

    def unexpected_hash(*args):
        pytest.fail("Invalid reset credentials reached expensive password hashing")

    monkeypatch.setattr(type(auth.hasher), "hash", unexpected_hash)
    with pytest.raises(AuthError):
        await auth.reset_password("invalid-reset-token", PASSWORD)


async def test_mount_respects_configured_limiter_identity(accounts):
    auth, _ = accounts
    # Represents an identity populated by trusted application middleware. Do not
    # use untrusted forwarding headers as a production rate-limit identity.
    auth.limiter.key = lambda request: request.query["client"]
    app = App()
    auth.mount(app, rule="1/minute")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://example.test"
    ) as client:
        for identity, expected in (("alice", 200), ("bob", 200), ("alice", 429)):
            result = await client.post(
                "/auth/forgot-password?client=" + identity,
                json={"email": identity + "@example.test"},
            )
            assert result.status_code == expected


async def test_password_work_is_bounded_and_does_not_lock_authentication(
    accounts, monkeypatch
):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    original = type(auth.hasher).verify
    release = threading.Event()
    entered = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def slow_verify(hasher, *args):
        loop.call_soon_threadsafe(entered.put_nowait, True)
        if not release.wait(10):
            raise RuntimeError("Test did not release password worker")
        return original(hasher, *args)

    monkeypatch.setattr(type(auth.hasher), "verify", slow_verify)
    tasks = [
        asyncio.create_task(auth.login("alice@example.test", PASSWORD))
        for _ in range(2)
    ]
    try:
        for _ in tasks:
            await asyncio.wait_for(entered.get(), 2)
        # Real account reads still succeed while the hash workers are occupied.
        assert (await asyncio.wait_for(auth.authenticate(tokens["access_token"]), 2)).id
        with pytest.raises(AuthError) as busy:
            await auth.login("alice@example.test", PASSWORD)
        assert busy.value.status == 503
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        with pytest.raises(AuthError) as still_busy:
            await auth.login("alice@example.test", PASSWORD)
        assert still_busy.value.status == 503
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Wait for the cancelled callers' background hash work to drain before
        # fixture teardown. Retry through the public API, not semaphore internals.
        async with asyncio.timeout(3):
            while True:
                try:
                    assert "access_token" in await auth.login(
                        "alice@example.test", PASSWORD
                    )
                    break
                except AuthError as exc:
                    if exc.status != 503:
                        raise
                    await asyncio.sleep(0.01)


async def test_login_revalidates_password_after_hashing(accounts, monkeypatch):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    user = await auth.authenticate(tokens["access_token"])
    original = type(auth.hasher).verify
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def slow_verify(hasher, *args):
        loop.call_soon_threadsafe(entered.set)
        if not release.wait(10):
            raise RuntimeError("Test did not release password worker")
        return original(hasher, *args)

    monkeypatch.setattr(type(auth.hasher), "verify", slow_verify)
    pending = asyncio.create_task(auth.login("alice@example.test", PASSWORD))
    try:
        await asyncio.wait_for(entered.wait(), 2)
        await auth.request_token("alice@example.test")
        await auth.reset_password(token(delivered), PASSWORD + "new")
        release.set()
        with pytest.raises(AuthError):
            await pending
        assert await auth.sessions(user) == []
    finally:
        release.set()
        await asyncio.gather(pending, return_exceptions=True)


async def test_cleanup_is_batched_and_preserves_live_refresh_replay(accounts):
    auth, delivered = accounts
    original = await registered(auth, delivered)
    user = await auth.authenticate(original["access_token"])
    rotated = await auth.refresh(original["refresh_token"])

    async def seed_expired(tx):
        for number in range(3):
            await tx.insert(
                "sessions",
                {
                    "id": f"expired-session-{number}",
                    "user_id": user.id,
                    "created": 0,
                    "auth_time": 0,
                    "expires": 1,
                    "revoked": False,
                },
            )
            await tx.insert(
                "tokens",
                {
                    "id": f"expired-token-{number}",
                    "user_id": user.id,
                    "kind": "reset",
                    "expires": 1,
                    "used": False,
                    "data": {},
                },
            )

    await auth.store.run(seed_expired)
    assert await auth.cleanup(batch_size=2) == {"tokens": 2, "sessions": 2}
    assert await auth.cleanup(batch_size=2) == {"tokens": 1, "sessions": 1}
    assert await auth.cleanup(batch_size=2) == {"tokens": 0, "sessions": 0}
    assert (await auth.authenticate(rotated["access_token"])).id == user.id
    with pytest.raises(AuthError, match="Session revoked"):
        await auth.refresh(original["refresh_token"])
    with pytest.raises(AuthError):
        await auth.authenticate(rotated["access_token"])


async def test_sessions_are_paginated_and_filter_expired_and_revoked(accounts):
    auth, delivered = accounts
    first = await registered(auth, delivered)
    user = await auth.authenticate(first["access_token"])
    for _ in range(3):
        await auth.login("alice@example.test", PASSWORD)

    async def seed_expired(tx):
        expired = await tx.get("sessions", user.session_id)
        await tx.insert("sessions", {**expired, "id": "expired", "expires": 1})

    await auth.store.run(seed_expired)
    await auth.revoke(user)
    first_page = await auth.sessions(user, limit=2)
    second_page = await auth.sessions(user, limit=2, after=first_page[-1]["id"])
    assert len(first_page) == 2 and len(second_page) == 1
    assert len({s["id"] for s in first_page + second_page}) == 3
    assert all(s["expires"] > time.time() for s in first_page + second_page)


async def test_concurrent_registration_only_sends_one_verification(accounts):
    auth, delivered = accounts
    results = await asyncio.gather(
        *(auth.register("same@example.test", PASSWORD) for _ in range(2))
    )
    assert results[0] == results[1]
    assert len(delivered) == 1
    await auth.verify_email(token(delivered))
    assert "access_token" in await auth.login("same@example.test", PASSWORD)


async def test_reset_rechecks_token_after_concurrent_hashing(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    await auth.request_token("alice@example.test")
    reset = token(delivered)
    outcomes = await asyncio.gather(
        auth.reset_password(reset, PASSWORD + "first"),
        auth.reset_password(reset, PASSWORD + "second"),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) for result in outcomes) == 1
    assert (
        sum(
            isinstance(result, AuthError) and result.status == 401
            for result in outcomes
        )
        == 1
    )
    with pytest.raises(AuthError):
        await auth.authenticate(tokens["access_token"])


async def test_custom_verifier_and_jwt_rejections():
    async def verifier(token):
        if token != "opaque":
            raise AuthError()
        return Principal("custom", ("admin",))

    auth = Auth(verifier=verifier)
    assert (await auth.authenticate("opaque")).id == "custom"
    with pytest.raises(AuthError):
        await auth.authenticate("wrong")
    verifier = JWTVerifier(
        "a" * 32, algorithms=["HS256"], issuer="issuer", audience="audience"
    )
    for claims in (
        {"sub": "1"},
        {"sub": "1", "exp": 1, "iss": "issuer", "aud": "audience"},
        {"sub": "1", "exp": 9999999999, "iss": "wrong", "aud": "audience"},
    ):
        with pytest.raises(AuthError):
            await verifier(jwt.encode(claims, "a" * 32, algorithm="HS256"))
