import asyncio
import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from wred_ratelimit import Limiter

import wred_auth
from wred_auth import Auth
from wred_auth.sqlalchemy import SQLAlchemyStore


@pytest.fixture(params=["sqlite", "postgres", "mongodb"])
async def accounts(request, tmp_path):
    url = "sqlite+aiosqlite:///" + str(tmp_path / "accounts.db")
    if request.param == "postgres":
        url = os.getenv("WRED_TEST_POSTGRES")
        if not url:
            pytest.skip("Set WRED_TEST_POSTGRES")
    if request.param == "mongodb":
        url = os.getenv("WRED_TEST_MONGODB")
        if not url:
            pytest.skip("Set WRED_TEST_MONGODB to a replica set")
        from wred_auth.mongodb import MongoDBStore

        store = MongoDBStore(url, "wred_auth_test_" + uuid.uuid4().hex)
        await store.initialize()
    else:
        config = Config()
        config.set_main_option(
            "script_location", str(Path(wred_auth.__file__).parent / "migrations")
        )
        config.set_main_option("sqlalchemy.url", url)
        await asyncio.to_thread(command.upgrade, config, "head")
        store = SQLAlchemyStore(url)
    delivered = []

    async def mail(kind, email, url):
        delivered.append((kind, email, url))

    auth = Auth(
        store=store,
        signing_key="test-only-signing-key-" * 3,
        encryption_key=Fernet.generate_key(),
        public_url="https://example.test",
        send_email=mail,
        limiter=Limiter(),
    )
    try:
        yield auth, delivered
    finally:
        if request.param == "mongodb":
            await store.client.drop_database(store.database.name)
        await auth.aclose()
        if request.param != "mongodb":
            await asyncio.to_thread(command.downgrade, config, "base")
