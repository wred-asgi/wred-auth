import asyncio

import pytest
from test_accounts import registered

from wred_auth.storage import StoreUnavailable


async def test_independent_account_writes_and_snapshot_reads_do_not_wait(accounts):
    auth, delivered = accounts
    if getattr(getattr(auth.store, "engine", None), "dialect", None) is not None:
        if auth.store.engine.dialect.name == "sqlite":
            pytest.skip("SQLite intentionally has a single writer")
    alice = await registered(auth, delivered)
    bob = await registered(auth, delivered, "bob@example.test")
    alice_user = await auth.authenticate(alice["access_token"])
    bob_user = await auth.authenticate(bob["access_token"])
    locked, release = asyncio.Event(), asyncio.Event()

    async def hold_alice(tx):
        await tx.get("users", alice_user.id)
        await tx.update("users", alice_user.id, roles=["admin"])
        locked.set()
        await release.wait()

    pending = asyncio.create_task(auth.store.run(hold_alice))
    try:
        await asyncio.wait_for(locked.wait(), 2)
        await asyncio.wait_for(auth.set_roles(bob_user.id, ["reader"]), 2)
        # No dirty reads or waits for Alice's uncommitted change.
        assert (
            await asyncio.wait_for(auth.authenticate(alice["access_token"]), 2)
        ).roles == ()
    finally:
        release.set()
        await pending
    assert (await auth.authenticate(alice["access_token"])).roles == ("admin",)
    assert (await auth.authenticate(bob["access_token"])).roles == ("reader",)


async def test_transaction_deadline_rolls_back_and_store_recovers(accounts):
    auth, delivered = accounts
    tokens = await registered(auth, delivered)
    user = await auth.authenticate(tokens["access_token"])
    auth.store.transaction_timeout = 0.2

    async def stall(tx):
        await tx.get("users", user.id)
        await tx.update("users", user.id, roles=["uncommitted"])
        await asyncio.Event().wait()

    with pytest.raises(StoreUnavailable):
        await auth.store.run(stall)
    auth.store.transaction_timeout = 5
    assert (await auth.authenticate(tokens["access_token"])).roles == ()
    await auth.set_roles(user.id, ["committed"])
    assert (await auth.authenticate(tokens["access_token"])).roles == ("committed",)
