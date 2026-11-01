"""Mixed multi-process account load against an isolated, disposable database.

SQL: WRED_BENCH_URL=postgresql+asyncpg://... python benchmarks/auth_load.py sql
Mongo: WRED_BENCH_URL=mongodb://... python benchmarks/auth_load.py mongodb

Creates test accounts and sessions; never point at an application database.
Measures service calls, excluding HTTP/proxy/Redis/provider/email latency.
"""

import argparse
import asyncio
import json
import multiprocessing
import os
import secrets
import time
import uuid
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet

from wred_auth import Auth, AuthError

PASSWORD = "benchmark-only password 123!"


def store_for(config):
    if config["backend"] == "mongodb":
        from wred_auth.mongodb import MongoDBStore

        return MongoDBStore(config["url"], config["database"])
    from wred_auth.sqlalchemy import SQLAlchemyStore

    return SQLAlchemyStore(config["url"])


def auth_for(config, store, mail):
    return Auth(
        store=store,
        signing_key=config["signing_key"],
        encryption_key=config["encryption_key"],
        public_url="https://benchmark.invalid",
        send_email=mail,
        max_password_jobs=config["password_jobs"],
    )


async def prepare(config):
    store = store_for(config)
    if config["backend"] == "mongodb":
        await store.initialize()
    else:
        from alembic import command
        from alembic.config import Config

        migration = Config()
        migration.set_main_option("script_location", "wred_auth:migrations")
        migration.set_main_option("sqlalchemy.url", config["url"].replace("%", "%%"))
        await asyncio.to_thread(command.upgrade, migration, "head")
    delivered = {}

    async def mail(kind, email, url):
        delivered[email] = parse_qs(urlparse(url).query)["token"][0]

    records = []
    async with auth_for(config, store, mail) as auth:
        for index in range(config["users"]):
            email = f"{config['run_id']}-{index}@benchmark.invalid"
            await auth.register(email, PASSWORD)
            await auth.verify_email(delivered[email])
            tokens = await auth.login(email, PASSWORD)
            records.append((email, tokens["access_token"]))
    return records


def worker(config, records):
    async def run():
        async def mail(*args):
            raise RuntimeError("Unexpected email during load")

        samples, statuses = [], Counter()
        gate = asyncio.Semaphore(config["concurrency"])
        async with auth_for(config, store_for(config), mail) as auth:

            async def request(index):
                async with gate:
                    email, access = records[index % len(records)]
                    operation = "login" if index % 10 == 0 else "authenticate"
                    started = time.perf_counter()
                    status = "ok"
                    try:
                        if operation == "login":
                            await auth.login(email, PASSWORD)
                        else:
                            await auth.authenticate(access)
                    except AuthError as exc:
                        status = str(exc.status)
                    except Exception as exc:
                        status = type(exc).__name__
                    samples.append((operation, (time.perf_counter() - started) * 1000))
                    statuses[operation + ":" + status] += 1

            await asyncio.gather(*(request(i) for i in range(config["requests"])))
        return samples, statuses

    return asyncio.run(run())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", choices=("sql", "mongodb"))
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=2, help="Per worker")
    parser.add_argument("--password-jobs", type=int, default=2, help="Per worker")
    parser.add_argument("--requests", type=int, default=500, help="Per worker")
    parser.add_argument("--users", type=int, default=20)
    args = parser.parse_args()
    if any(
        value < 1
        for value in (
            args.workers,
            args.concurrency,
            args.password_jobs,
            args.requests,
            args.users,
        )
    ):
        parser.error("All sizing options must be positive")
    config = vars(args) | {
        "url": os.environ["WRED_BENCH_URL"],
        "run_id": uuid.uuid4().hex,
        "database": "wred_auth_bench_" + uuid.uuid4().hex,
        "signing_key": secrets.token_urlsafe(48),
        "encryption_key": Fernet.generate_key(),
    }
    records = asyncio.run(prepare(config))
    started = time.perf_counter()
    with ProcessPoolExecutor(
        max_workers=args.workers, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        futures = [pool.submit(worker, config, records) for _ in range(args.workers)]
        results = [future.result() for future in futures]
    elapsed = time.perf_counter() - started
    statuses = Counter()
    latencies = {"login": [], "authenticate": []}
    for samples, counts in results:
        statuses.update(counts)
        for operation, duration in samples:
            latencies[operation].append(duration)
    report = {
        "backend": args.backend,
        "workers": args.workers,
        "concurrency_per_worker": args.concurrency,
        "requests": args.workers * args.requests,
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(args.workers * args.requests / elapsed, 1),
        "outcomes": dict(statuses),
    }
    for operation, values in latencies.items():
        values.sort()
        if values:
            report[operation + "_ms"] = {
                "p50": round(values[len(values) // 2], 2),
                "p95": round(values[min(len(values) - 1, int(len(values) * 0.95))], 2),
                "max": round(values[-1], 2),
            }
    print(json.dumps(report, indent=2))
    if args.backend == "mongodb":

        async def dispose():
            async with store_for(config) as store:
                await store.client.drop_database(config["database"])

        asyncio.run(dispose())


if __name__ == "__main__":
    main()
