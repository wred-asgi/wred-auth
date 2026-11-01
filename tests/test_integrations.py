import os
import uuid

import httpx
import pytest
from pydantic import BaseModel, Field
from test_accounts import PASSWORD, registered
from wred import App
from wred_pydantic import body, path, response
from wred_ratelimit import Limiter

from wred_auth import Auth, AuthError, Principal, principal


async def test_auth_rate_limit_and_pydantic_decorators_compose():
    class OrderInput(BaseModel):
        quantity: int = Field(gt=0)

    class OrderPath(BaseModel):
        order_id: int

    class OrderOutput(BaseModel):
        id: int
        quantity: int
        user: str

    async def verify(token):
        if token == "admin":
            return Principal("alice", ("admin",))
        if token == "member":
            return Principal("bob")
        raise AuthError()

    auth = Auth(verifier=verify)
    async with Limiter() as limiter:
        app = App()

        @app.route("/orders/{order_id}", methods=["POST"])
        @limiter.limit("8/minute")
        @response(OrderOutput)
        @auth.require_auth()
        @auth.require_role("admin")
        @path(OrderPath)
        @body(OrderInput, max_bytes=64)
        async def order(request, order_id, path, body):
            return {
                "id": path.order_id,
                "quantity": body.quantity,
                "user": principal(request).id,
            }

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://example.test"
        ) as client:
            assert (
                await client.post("/orders/1", json={"quantity": 1})
            ).status_code == 401
            client.headers["authorization"] = "Bearer member"
            assert (
                await client.post("/orders/1", json={"quantity": 1})
            ).status_code == 403
            client.headers["authorization"] = "Bearer admin"
            assert (
                await client.post("/orders/nope", json={"quantity": 1})
            ).status_code == 422
            invalid = await client.post(
                "/orders/1", json={"quantity": "private-invalid-input"}
            )
            assert invalid.status_code == 422
            assert "private-invalid-input" not in invalid.text
            assert (
                await client.post("/orders/1", content=b" " * 65)
            ).status_code == 413
            for _ in range(3):
                result = await client.post("/orders/1", json={"quantity": 2})
                assert result.json() == {"id": 1, "quantity": 2, "user": "alice"}
            denied = await client.post("/orders/1", json={"quantity": 2})
            assert denied.status_code == 429 and "retry-after" in denied.headers
        metadata = order.__wred_openapi__
        assert metadata["security"] == [{"bearerAuth": []}]
        assert {"body", "path", "responses"} <= metadata.keys()


async def test_account_routes_share_redis_quotas_across_instances(accounts):
    url = os.getenv("WRED_TEST_REDIS")
    if not url:
        pytest.skip("Set WRED_TEST_REDIS for real Redis integration")
    auth, delivered = accounts
    await registered(auth, delivered)
    namespace = "auth-test-" + uuid.uuid4().hex
    async with (
        Limiter.redis(url, namespace=namespace) as first_limiter,
        Limiter.redis(url, namespace=namespace) as second_limiter,
    ):
        await auth.limiter.aclose()
        auth.limiter = first_limiter
        app = App()
        auth.mount(app, rule="100/minute", account_rule="1/minute")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app, client=("192.0.2.1", 1)),
            base_url="https://example.test",
        ) as client:
            first = await client.post(
                "/auth/login",
                json={"email": "alice@example.test", "password": PASSWORD},
            )
            assert first.status_code == 200
        # A second mount and Redis client share account quotas even when the
        # connection identity differs, as it does across workers or IPs.
        auth.limiter = second_limiter
        second_app = App()
        auth.mount(second_app, rule="100/minute", account_rule="1/minute")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(second_app, client=("192.0.2.2", 1)),
            base_url="https://example.test",
        ) as client:
            denied = await client.post(
                "/auth/login",
                json={"email": "ALICE@example.test", "password": PASSWORD},
            )
            assert denied.status_code == 429 and "retry-after" in denied.headers
            assert denied.headers["cache-control"] == "no-store"


async def test_auth_fails_closed_when_redis_is_unavailable(accounts, tmp_path):
    pytest.importorskip("redis")
    auth, _ = accounts
    await auth.limiter.aclose()
    auth.limiter = Limiter.redis("redis+unix://" + str(tmp_path / "missing.sock"))
    app = App()
    auth.mount(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://example.test"
    ) as client:
        result = await client.post(
            "/auth/login", json={"email": "alice@example.test", "password": PASSWORD}
        )
        assert result.status_code == 503
        assert result.headers["cache-control"] == "no-store"
        assert "password" not in result.text
