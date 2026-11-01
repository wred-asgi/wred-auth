import asyncio

import pytest
from cryptography.fernet import Fernet
from wred_auth import Auth
from wred_auth.sqlalchemy import SQLAlchemyStore
from wred_ratelimit import Limiter


@pytest.mark.parametrize("failure", [OSError, asyncio.CancelledError])
async def test_failed_store_cleanup_does_not_skip_owned_limiter(failure):
    closed = asyncio.Event()
    error = failure("store shutdown failed")

    class FailingStore(SQLAlchemyStore):
        async def aclose(self):
            await super().aclose()
            raise error

    class TrackedLimiter(Limiter):
        async def aclose(self):
            await super().aclose()
            closed.set()

    async def send_email(*args):
        pytest.fail("Shutdown must not send email")

    auth = Auth(
        store=FailingStore("sqlite+aiosqlite:///:memory:"),
        signing_key="test-only-key" * 4,
        encryption_key=Fernet.generate_key(),
        public_url="https://example.test",
        send_email=send_email,
        limiter=TrackedLimiter(),
    )
    with pytest.raises(failure) as caught:
        await auth.aclose()
    assert caught.value is error
    assert closed.is_set()
