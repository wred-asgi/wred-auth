import httpx
import pytest
from cryptography.fernet import Fernet
from wred_auth import Auth
from wred_auth.sqlalchemy import SQLAlchemyStore
from wred_ratelimit import Limiter

from wred import App


@pytest.mark.parametrize("prebuffer", [False, True])
async def test_account_body_limit_precedes_json_parsing_and_database_work(prebuffer):
    async def send_email(*args):
        pytest.fail("Oversized account request reached email delivery")

    # No schema is provisioned: oversized input must never reach database work.
    async with Auth(
        store=SQLAlchemyStore("sqlite+aiosqlite:///:memory:"),
        signing_key="test-only-key" * 4,
        encryption_key=Fernet.generate_key(),
        public_url="https://example.test",
        send_email=send_email,
        limiter=Limiter(strategy="fixed"),
    ) as auth:
        app = App()
        auth.mount(app)
        if prebuffer:
            mounted = app.routes["/auth/login"]["POST"]

            @app.route("/auth/login", methods=["POST"])
            async def prefetch(request):
                await request.body()
                return await mounted(request)

        consumed = []

        async def chunks():
            for chunk in (b" " * 32768, b" " * 32768, b" ", b"[]"):
                consumed.append(chunk)
                yield chunk

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://example.test"
        ) as client:
            result = await client.post("/auth/login", content=chunks())
        assert result.status_code == 413
        assert result.headers["cache-control"] == "no-store"
        assert len(consumed) == (4 if prebuffer else 3)
