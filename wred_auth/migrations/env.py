"""Bundled async migration environment; applications pass sqlalchemy.url."""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from wred_auth.sqlalchemy import metadata


def run(connection):
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()


async def online():
    engine = create_async_engine(context.config.get_main_option("sqlalchemy.url"))
    async with engine.connect() as connection:
        await connection.run_sync(run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(
        url=context.config.get_main_option("sqlalchemy.url"),
        target_metadata=metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(online())
