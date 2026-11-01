"""SQLAlchemy account storage. Apply bundled Alembic migrations explicitly."""

import asyncio
import math
import random
from contextlib import asynccontextmanager

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    delete,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import create_async_engine

from .storage import StoreUnavailable

metadata = MetaData()
users = Table(
    "wred_auth_users",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("email", String(320), nullable=False, unique=True),
    Column("password", Text),
    Column("verified", Boolean, nullable=False),
    Column("active", Boolean, nullable=False),
    Column("roles", JSON, nullable=False),
    Column("totp", Text),
    Column("totp_pending", Text),
    Column("totp_step", Integer, nullable=False),
    Column("recovery", JSON, nullable=False),
)
sessions = Table(
    "wred_auth_sessions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey(users.c.id), nullable=False, index=True),
    Column("created", Float, nullable=False),
    Column("auth_time", Float, nullable=False),
    Column("expires", Float, nullable=False),
    Column("revoked", Boolean, nullable=False),
)
tokens = Table(
    "wred_auth_tokens",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey(users.c.id), index=True),
    Column("kind", String(32), nullable=False),
    Column("expires", Float, nullable=False),
    Column("used", Boolean, nullable=False),
    Column("data", JSON, nullable=False),
)
identities = Table(
    "wred_auth_identities",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey(users.c.id), nullable=False, index=True),
    Column("provider", String(32), nullable=False),
    Column("subject", String(255), nullable=False),
    UniqueConstraint("provider", "subject"),
)
TABLES = {
    "users": users,
    "sessions": sessions,
    "tokens": tokens,
    "identities": identities,
}
Index("ix_wred_auth_sessions_expires", sessions.c.expires)
Index("ix_wred_auth_tokens_expires", tokens.c.expires)
Index(
    "ix_wred_auth_sessions_live",
    sessions.c.user_id,
    sessions.c.revoked,
    sessions.c.expires,
)
Index(
    "ix_wred_auth_tokens_live",
    tokens.c.user_id,
    tokens.c.kind,
    tokens.c.used,
    tokens.c.expires,
)


def _where(target, filters):
    predicates = []
    for key, value in filters.items():
        field, _, operator = key.partition("__")
        column = target.c[field]
        if operator == "gt":
            predicates.append(column > value)
        elif operator == "lte":
            predicates.append(column <= value)
        elif not operator:
            predicates.append(column == value)
        else:
            raise ValueError("Unknown filter operator")
    return predicates


class SQLTransaction:
    def __init__(self, connection, *, read_only=False):
        self.connection = connection
        self.read_only = read_only

    def _writable(self):
        if self.read_only:
            raise ValueError("Cannot write in a read-only transaction")

    async def get(self, table, key):
        rows = await self.find(table, id=key)
        return rows[0] if rows else None

    async def find(self, table, *, limit=None, **filters):
        target = TABLES[table]
        stmt = select(target).where(*_where(target, filters)).order_by(target.c.id)
        if limit is not None:
            stmt = stmt.limit(limit)
        if not self.read_only:
            stmt = stmt.with_for_update()
        return [dict(row) for row in (await self.connection.execute(stmt)).mappings()]

    async def insert(self, table, values):
        self._writable()
        await self.connection.execute(insert(TABLES[table]).values(**values))

    async def update(self, table, key, **values):
        self._writable()
        target = TABLES[table]
        await self.connection.execute(
            update(target).where(target.c.id == key).values(**values)
        )

    async def delete(self, table, key):
        self._writable()
        target = TABLES[table]
        await self.connection.execute(delete(target).where(target.c.id == key))

    async def update_many(self, table, filters, values):
        self._writable()
        target = TABLES[table]
        await self.connection.execute(
            update(target).where(*_where(target, filters)).values(**values)
        )


class SQLAlchemyStore:
    def __init__(self, url, *, transaction_timeout=5, retries=5, **engine_options):
        if (
            not math.isfinite(transaction_timeout)
            or transaction_timeout <= 0
            or type(retries) is not int
            or retries < 0
        ):
            raise ValueError("Invalid transaction budget")
        self.transaction_timeout, self.retries = transaction_timeout, retries
        self.engine = create_async_engine(url, **engine_options)
        if self.engine.dialect.name not in ("sqlite", "postgresql"):
            raise ValueError("Supported databases: SQLite and PostgreSQL")

    @asynccontextmanager
    async def transaction(self, *, read_only=False):
        async with self.engine.connect() as connection:
            try:
                if self.engine.dialect.name == "sqlite":
                    await connection.execute(text("PRAGMA foreign_keys=ON"))
                    await connection.execute(
                        text("BEGIN" if read_only else "BEGIN IMMEDIATE")
                    )
                else:
                    await connection.execution_options(
                        isolation_level="REPEATABLE READ"
                        if read_only
                        else "SERIALIZABLE"
                    )
                    await connection.begin()
                yield SQLTransaction(connection, read_only=read_only)
                await connection.commit()
            except BaseException:
                await connection.rollback()
                raise

    async def run(self, callback, *, read_only=False):
        try:
            async with asyncio.timeout(self.transaction_timeout):
                for attempt in range(self.retries + 1):
                    try:
                        async with self.transaction(read_only=read_only) as tx:
                            result = await callback(tx)
                        return result
                    except DBAPIError as exc:
                        code = getattr(exc.orig, "sqlstate", None)
                        sqlite_code = getattr(exc.orig, "sqlite_errorcode", None)
                        if exc.connection_invalidated or (
                            code
                            and (
                                code.startswith("08")
                                or code in ("57P01", "57P02", "57P03")
                            )
                        ):
                            raise StoreUnavailable(
                                "Database connection unavailable"
                            ) from exc
                        # Unique insert races are retried so the callback sees the
                        # winner; deadlocks and serialization failures roll back.
                        if code not in (
                            "40001",
                            "40P01",
                            "23505",
                        ) and sqlite_code not in (5, 6, 517):
                            raise
                        if attempt == self.retries:
                            raise StoreUnavailable("Transaction conflicts") from exc
                        await asyncio.sleep(
                            random.uniform(0.005, 0.025) * (attempt + 1)
                        )
        except (TimeoutError, PoolTimeout, OSError) as exc:
            raise StoreUnavailable("Transaction deadline exceeded") from exc

    async def cleanup(self, *, now, batch_size=500):
        if (
            type(batch_size) is not int
            or not 1 <= batch_size <= 10000
            or not math.isfinite(now)
        ):
            raise ValueError("Invalid cleanup bounds")

        async def prune(tx):
            counts = {}
            for name in ("tokens", "sessions"):
                target = TABLES[name]
                stmt = (
                    select(target.c.id)
                    .where(target.c.expires <= now)
                    .order_by(target.c.expires)
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
                ids = list((await tx.connection.execute(stmt)).scalars())
                if ids:
                    await tx.connection.execute(
                        delete(target).where(target.c.id.in_(ids))
                    )
                counts[name] = len(ids)
            return counts

        return await self.run(prune)

    async def aclose(self):
        await self.engine.dispose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
