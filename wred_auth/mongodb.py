"""PyMongo async account store. Requires a replica set or sharded cluster."""

import asyncio
import math
import random
from contextlib import asynccontextmanager

from pymongo import AsyncMongoClient, ReadPreference, ReturnDocument
from pymongo.errors import CollectionInvalid, DuplicateKeyError, PyMongoError
from pymongo.read_concern import ReadConcern
from pymongo.write_concern import WriteConcern

from .storage import StoreUnavailable

TABLES = {
    name: "wred_auth_" + name for name in ("users", "sessions", "tokens", "identities")
}


def _query(filters):
    query = {}
    for key, value in filters.items():
        field, _, operator = key.partition("__")
        if field == "id":
            field = "_id"
        if operator in ("gt", "lte"):
            query.setdefault(field, {})["$" + operator] = value
        elif not operator:
            query[field] = value
        else:
            raise ValueError("Unknown filter operator")
    return query


def _row(document):
    if document is None:
        return None
    document["id"] = document.pop("_id")
    document.pop("_version", None)
    return document


class MongoTransaction:
    def __init__(self, database, session, *, read_only=False):
        self.database, self.session, self.read_only = database, session, read_only

    def collection(self, table):
        return self.database[TABLES[table]]

    def _writable(self):
        if self.read_only:
            raise ValueError("Cannot write in a read-only transaction")

    async def get(self, table, key):
        collection = self.collection(table)
        query = {"_id": key}
        if self.read_only:
            return _row(await collection.find_one(query, session=self.session))
        # A real write, not a no-op, prevents snapshot write skew between account
        # status/password changes and creation/rotation of dependent credentials.
        return _row(
            await collection.find_one_and_update(
                query,
                {"$inc": {"_version": 1}},
                return_document=ReturnDocument.AFTER,
                session=self.session,
            )
        )

    async def find(self, table, *, limit=None, **filters):
        cursor = (
            self.collection(table)
            .find(_query(filters), session=self.session)
            .sort("_id", 1)
        )
        if limit is not None:
            cursor = cursor.limit(limit)
        documents = await cursor.to_list(length=None)
        if self.read_only:
            return [_row(document) for document in documents]
        return [await self.get(table, document["_id"]) for document in documents]

    async def insert(self, table, values):
        self._writable()
        document = dict(values)
        document["_id"] = document.pop("id")
        await self.collection(table).insert_one(document, session=self.session)

    async def update(self, table, key, **values):
        self._writable()
        await self.collection(table).update_one(
            {"_id": key}, {"$set": values}, session=self.session
        )

    async def update_many(self, table, filters, values):
        self._writable()
        await self.collection(table).update_many(
            _query(filters), {"$set": values}, session=self.session
        )

    async def delete(self, table, key):
        self._writable()
        await self.collection(table).delete_one({"_id": key}, session=self.session)


class MongoDBStore:
    def __init__(
        self, url, database, *, transaction_timeout=5, retries=5, **client_options
    ):
        if (
            not math.isfinite(transaction_timeout)
            or transaction_timeout <= 0
            or type(retries) is not int
            or retries < 0
        ):
            raise ValueError("Invalid transaction budget")
        options = dict(
            serverSelectionTimeoutMS=2000,
            connectTimeoutMS=2000,
            socketTimeoutMS=5000,
            waitQueueTimeoutMS=1000,
            maxPoolSize=100,
        )
        options.update(client_options)
        self.client = AsyncMongoClient(url, **options)
        self.database = self.client.get_database(
            database, write_concern=WriteConcern("majority")
        )
        self.transaction_timeout, self.retries = transaction_timeout, retries

    async def initialize(self):
        """Explicit provisioning; call at deployment time, never per request."""
        hello = await self.client.admin.command("hello")
        if not hello.get("setName") and hello.get("msg") != "isdbgrid":
            raise ValueError(
                "MongoDB accounts require a replica set or sharded cluster"
            )
        for table in TABLES.values():
            try:
                await self.database.create_collection(table)
            except CollectionInvalid:
                pass  # Concurrent or repeated explicit provisioning is safe.
        users = self.database[TABLES["users"]]
        await users.create_index("email", unique=True)
        identities = self.database[TABLES["identities"]]
        await identities.create_index([("provider", 1), ("subject", 1)], unique=True)
        await identities.create_index("user_id")
        for name in ("sessions", "tokens"):
            collection = self.database[TABLES[name]]
            await collection.create_index("expires")
            await collection.create_index("user_id")
        await self.database[TABLES["sessions"]].create_index(
            [("user_id", 1), ("revoked", 1), ("expires", 1)]
        )
        await self.database[TABLES["tokens"]].create_index(
            [("user_id", 1), ("kind", 1), ("used", 1), ("expires", 1)]
        )

    def _transaction_options(self):
        return dict(
            read_concern=ReadConcern("snapshot"),
            write_concern=WriteConcern("majority"),
            read_preference=ReadPreference.PRIMARY,
            max_commit_time_ms=int(self.transaction_timeout * 1000),
        )

    @asynccontextmanager
    async def transaction(self, *, read_only=False):
        async with self.client.start_session() as session:
            async with await session.start_transaction(**self._transaction_options()):
                yield MongoTransaction(self.database, session, read_only=read_only)

    async def run(self, callback, *, read_only=False):
        try:
            async with asyncio.timeout(self.transaction_timeout):
                async with self.client.start_session() as session:
                    attempts = 0

                    async def invoke(current_session):
                        nonlocal attempts
                        attempts += 1
                        if attempts > self.retries + 1:
                            raise StoreUnavailable("Transaction conflicts")
                        return await callback(
                            MongoTransaction(
                                self.database, current_session, read_only=read_only
                            )
                        )

                    while True:
                        try:
                            # The driver retries ambiguous commits without
                            # replaying an already committed operation.
                            return await session.with_transaction(
                                invoke, **self._transaction_options()
                            )
                        except DuplicateKeyError:
                            if attempts > self.retries:
                                raise StoreUnavailable("Unique insert conflicts")
                            await asyncio.sleep(random.uniform(0.005, 0.025) * attempts)
        except (TimeoutError, PyMongoError) as exc:
            raise StoreUnavailable("MongoDB transaction unavailable") from exc

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
                collection = tx.collection(name)
                documents = (
                    await collection.find(
                        {"expires": {"$lte": now}}, {"_id": 1}, session=tx.session
                    )
                    .sort("expires", 1)
                    .limit(batch_size)
                    .to_list(length=None)
                )
                ids = [document["_id"] for document in documents]
                result = await collection.delete_many(
                    {"_id": {"$in": ids}}, session=tx.session
                )
                counts[name] = result.deleted_count
            return counts

        return await self.run(prune)

    async def aclose(self):
        await self.client.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
