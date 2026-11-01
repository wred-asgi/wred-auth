# wred-auth

Bearer authorization and an opt-in account service for Wred 0.13. Python 3.11+.
This package owns no UI, email service, or application account data beyond its
explicit identity tables. Version 0.1.0 APIs are not yet stable.

```sh
pip install './extensions/wred-auth[sqlalchemy]' './extensions/wred-ratelimit[redis]'
```

## Authorization without account storage

```python
from wred import App
from wred_auth import Auth, AuthError, Principal, principal


async def verify(token):
    # Replace with your token verifier/account lookup.
    if token != "development-only-token":
        raise AuthError()
    return Principal("alice", ("admin",))


auth = Auth(verifier=verify)
app = App()


@app.route("/orders/{order_id}")
@auth.require_auth()
@auth.require_role("admin")
async def order(request, order_id):
    return {"id": order_id, "user": principal(request).id}
```

`Principal(id, roles=(), session_id=None, auth_time=0)` is the verifier result.
Sync and async verifiers are supported. Raise `AuthError` for expected rejection;
unexpected failures propagate. The principal is stored at `request.scope['wred.auth']`.
Missing/invalid credentials return 401 with a Bearer challenge; missing roles return
403. `require_role` authenticates itself if no principal is present.

`JWTVerifier(key, algorithms=[...], issuer=..., audience=..., lookup=None)` verifies
external JWTs. Algorithms are application configuration, never derived from tokens.
`lookup(claims)` optionally returns a Principal and can be async; without it, the
verified subject gets no roles. This adapter does not issue tokens or infer accounts.

## Account setup

```python
import os
from wred import App
from wred_auth import Auth
from wred_auth.sqlalchemy import SQLAlchemyStore
from wred_auth.providers import Google, GitHub
from wred_ratelimit import Limiter


async def send_email(kind, email, url):
    await application_mailer(kind, email, url)  # Your implementation.


app = App()
limiter = Limiter.redis(os.environ["REDIS_URL"], namespace="my-app-auth")
auth = Auth(
    store=SQLAlchemyStore(os.environ["DATABASE_URL"]),
    signing_key=os.environ["AUTH_SIGNING_KEY"],
    encryption_key=os.environ["AUTH_ENCRYPTION_KEY"],
    issuer="my-app",
    audience="my-api",
    public_url="https://api.example.com",
    send_email=send_email,
    limiter=limiter,
    providers={
        "google": Google(
            os.environ["GOOGLE_CLIENT_ID"], os.environ["GOOGLE_CLIENT_SECRET"]
        ),
        "github": GitHub(
            os.environ["GITHUB_CLIENT_ID"], os.environ["GITHUB_CLIENT_SECRET"]
        ),
    },
)
auth.mount(app)
```

Use a randomly generated signing key of at least 32 bytes and a separate Fernet
key (`Fernet.generate_key()`). Keep them stable across workers and restarts.
Encryption protects persisted TOTP secrets. Key rotation currently requires an
application migration/re-encryption process; no automatic key ring is provided.

Account access tokens use HS256 with explicit issuer/audience and a 15-minute
lifetime. Refresh sessions expire after 30 days by default, without sliding renewal.
Every access-token authentication checks account/session state. Refresh rotates a
hashed opaque token transactionally; reuse revokes that session's entire token family.
Passwords use Argon2id and must contain 15–128 characters. Email identifiers are
case-folded; whitespace and malformed basic address structure are rejected.

SQLAlchemy supports PostgreSQL and SQLite. Use `postgresql+asyncpg://...` or
`sqlite+aiosqlite:///...`. PostgreSQL uses row locks and serializable write
transactions with bounded retries; access-token checks use non-locking repeatable
read snapshots. There is no store-wide advisory lock. SQLite uses `BEGIN IMMEDIATE`
for writes and remains intended for local/small deployments.

Password hashing and verification run outside database transactions. Password and
session state are rechecked before committing credentials. `max_password_jobs=2`
limits concurrent Argon2 jobs per `Auth` instance, with no waiting queue; excess
work returns 503. Cancellation retains the slot until its thread finishes. Size
this limit for your process memory/CPU budget (the current Argon2 defaults use
64 MiB per operation), and normally share one `Auth` instance per worker. Redis
quotas limit requests across workers; they do not replace this process-local
resource limit. Invalid reset tokens are rejected before password hashing.

Both stores accept `transaction_timeout=5` seconds and `retries=5` by default.
Retries cover database conflicts, not password hashing, email, or audit callbacks.
Deadline/retry exhaustion returns 503 through account HTTP endpoints. SQLAlchemy
engine options and PyMongo client options can be supplied to their store constructors.

## MongoDB

Install `pip install 'wred-auth[mongodb]'`. Use MongoDB 6.0+ as a replica set or
sharded cluster, including Atlas; standalone servers cannot provide the required
multi-document transactions. Use PyMongo's async driver, not Motor.

```python
from wred_auth.mongodb import MongoDBStore

store = MongoDBStore(os.environ["MONGODB_URL"], database="accounts")
await store.initialize()  # Explicit deployment step: creates collections/indexes.
# Pass store=store to Auth, with the same remaining configuration as above.
```

`initialize()` is idempotent and must complete before serving traffic. It checks
the topology and creates unique email and provider/subject indexes. Transactions
use primary reads, snapshot read concern, and majority writes. Conflicting writes
are retried; read-only access checks do not touch documents. MongoDB uses the same
account fields as SQL and separate `wred_auth_*` collections. Keep those collections
unsharded unless you design shard keys and uniqueness constraints for your deployment.

## Explicit migrations

Create an application `alembic.ini`:

```ini
[alembic]
script_location = wred_auth:migrations
sqlalchemy.url = sqlite+aiosqlite:///accounts.db
```

Then run `alembic -c alembic.ini upgrade head`. No schema is created during requests.
Revision `0001` creates users, sessions, tokens, and identities; `0002` adds live-record
and expiration indexes. Upgrade existing SQL installations before deploying this version.
Account tables are separate from application domain tables. Custom storage adapters
must now implement `run(callback, read_only=False)`, `cleanup`, filtered/paginated
reads, and bulk updates in addition to the transaction API. Callbacks can execute
more than once and must contain only transactional database work. See the contract
in `wred_auth.storage` and the bundled implementations. A context-managed
`store.transaction()` remains available for application code, but does not retry
its body automatically; use `run()` for conflict retries.

## Retention

Schedule cleanup in an application maintenance job; it is never run during requests:

```python
counts = await auth.cleanup(batch_size=500)
```

Each call removes at most 500 expired tokens and 500 expired sessions using expiration
indexes. Run additional batches with a job time budget when a backlog exists.
Used refresh tokens and revoked sessions are retained until expiry, so cleanup does
not erase replay detection for live refresh families. Revocation uses bulk database
updates. Account/user and external-identity records are not deleted by cleanup.

## HTTP endpoints

`auth.mount(app, prefix='/auth', rule='10/minute', account_rule='5/minute', key=None)` is opt-in.
It rejects existing routes. A configured limiter is required. All operations return
JSON with `Cache-Control: no-store`; requests use JSON bodies except GET operations.
Service methods also exist, but callers of those methods must apply their own rate
limits and authorization. `Principal` arguments are trusted application inputs.

With `key=None`, mount honors the configured `Limiter(key=...)`. Supply `key=...`
to override it for account routes; both synchronous and asynchronous functions work.
The default limiter uses the ASGI peer address. Behind a reverse proxy, configure
your server's trusted proxy handling to populate the real client address, or provide
a key from trusted middleware. Never trust arbitrary forwarded headers from clients.
Use Redis and a shared namespace across workers; the in-memory limiter is process-local.

| Method/path under `/auth` | Input |
|---|---|
| POST `/register` | `email`, `password` |
| POST `/verify` | `token` |
| POST `/request-verification` | `email` |
| POST `/login` | `email`, `password` |
| POST `/forgot-password` | `email` |
| POST `/reset-password` | `token`, `password` |
| POST `/refresh` | `refresh_token` |
| POST `/logout` | Bearer credentials, empty object |
| GET `/sessions` | Bearer credentials; optional `limit` (1–1000, default 100), `after` session ID |
| POST `/revoke` | Bearer credentials, `session_id` |
| POST `/change-password` | Bearer credentials, `old_password`, `password` |
| POST `/mfa-setup` | Recent Bearer credentials, empty object |
| POST `/mfa-confirm` | Recent Bearer credentials, `code` |
| POST `/mfa-login` | `challenge`, `code` |
| POST `/mfa-disable` | Recent Bearer credentials, `code` |
| GET `/oauth/{provider}/start` | Browser navigation |
| POST `/oauth/{provider}/link` | Recent Bearer credentials |
| GET `/oauth/{provider}/callback` | Provider callback query and browser cookie |

Registration/recovery return generic responses. Mail delivery is an async callback
`send_email(kind, email, url)`, where kind is `verify` or `reset`. The URL points to
`public_url/{kind}?token=...`; your frontend handles it and POSTs the token to the API.
Delivery failures propagate; users can request new verification/reset instructions.
Verification/reset tokens expire in 30 minutes. Password changes and resets revoke
existing sessions, pending MFA challenges, and outstanding password-reset tokens.
Session pages are ordered by ID; pass the last returned ID as `after` for the next page.

Successful password login returns bearer and refresh tokens, or an MFA challenge
that expires in five minutes. MFA setup returns a provisioning URI; confirmation
returns ten one-use recovery codes and revokes existing sessions. Used TOTP time
steps cannot be replayed, with one adjacent step of clock tolerance. MFA changes
and identity linking require authentication within five minutes; sign in again when
prompted. Password recovery does not disable MFA.

Google uses OIDC issuer/audience/signature/nonce checks. GitHub requires a verified
primary email. OAuth uses state, PKCE, and a Secure/HttpOnly/SameSite browser-binding
cookie. Register exact callbacks at `public_url/auth/oauth/{provider}/callback`.
Callback results return JSON tokens, never credentials in redirect URLs. No provider
refresh tokens are retained. Existing accounts are never merged by email: users must
sign in and explicitly link. One browser login flow at a time is supported.

Administrative `set_roles(user_id, roles)` and `set_active(user_id, active)` methods
are intentionally not mounted as public endpoints. Applications enforce administrator
permissions before invoking them. Optional `audit(event)` receives event, user ID,
and timestamp; it must be async and must not fail during ordinary operation.

Use `async with auth` or `await auth.aclose()` to close its store and limiter.
Handle lifespan in the hosting application. Configure request body limits at the
server/proxy; Wred buffers bodies. Credentials, mail, DNS, TLS, and live provider
configuration belong to the application.

## With wred-pydantic and wred-ratelimit

`wred-ratelimit` supplies `Limiter` for request quotas; install its `redis` extra
to share quotas across workers. `wred-pydantic` supplies the optional `body` and
`response` decorators for input validation and response conversion.

```sh
pip install wred-auth 'wred-ratelimit[redis]' wred-pydantic
```

This example defines its own app, limiter, and auth instance using external RS256
JWTs. Configure `REDIS_URL`, `AUTH_PUBLIC_KEY` (a PEM public key), `AUTH_ISSUER`, and
`AUTH_AUDIENCE` in the environment. For the built-in account service, reuse the
`app`, `auth`, and `limiter` from Account setup instead of creating them again.

```python
import os

from pydantic import BaseModel, Field
from wred import App
from wred_auth import Auth, JWTVerifier, principal
from wred_pydantic import body, response
from wred_ratelimit import Limiter

app = App()
limiter = Limiter.redis(os.environ["REDIS_URL"], namespace="my-app-auth")
auth = Auth(
    verifier=JWTVerifier(
        os.environ["AUTH_PUBLIC_KEY"],
        algorithms=["RS256"],
        issuer=os.environ["AUTH_ISSUER"],
        audience=os.environ["AUTH_AUDIENCE"],
    ),
    limiter=limiter,
)

class OrderInput(BaseModel):
    quantity: int = Field(gt=0)

class OrderOutput(BaseModel):
    user: str
    quantity: int

@app.route("/orders", methods=["POST"])
@limiter.limit("30/minute")
@auth.require_auth()
@body(OrderInput, max_bytes=4096)
@response(OrderOutput)
async def create_order(request, body):
    return {"user": principal(request).id, "quantity": body.quantity}
```

Auth decorators preserve injected keyword arguments and OpenAPI metadata.
Close `auth` during application shutdown with `await auth.aclose()`; it also closes
the supplied limiter. Authentication, authorization, validation, and quota failures
retain their HTTP statuses; the response adapter does not validate non-success payloads. All three extensions
support Wred 0.13 together with their current dependency constraints.

## Tests

```sh
pip install -e '.[test,sqlalchemy,mongodb]' '../wred-ratelimit[redis]' '../wred-pydantic'
pytest
```

SQLite tests always run. Set `WRED_TEST_POSTGRES` to an isolated PostgreSQL test
DB to exercise migrations and concurrent refresh. Tests downgrade their account
tables after each scenario; never point them at application data. Provider tests
use signed OIDC responses and simulated HTTP exchanges, not live provider accounts.
Set `WRED_TEST_MONGODB` to a test replica-set URI to run the same account contract
against MongoDB (each test creates and drops a uniquely named database).
Set `WRED_TEST_REDIS` to a test Redis URI for shared-quota integration tests.
Coverage includes transaction rollback/deadlines, independent account progress,
hash admission/cancellation, password races, retention, and decorator composition.

For a repeatable multi-process service benchmark against a disposable database:

```sh
WRED_BENCH_URL='postgresql+asyncpg://...' python benchmarks/auth_load.py sql
WRED_BENCH_URL='mongodb://...?replicaSet=rs0' python benchmarks/auth_load.py mongodb
```

The default workload runs 1,000 operations across two processes: 90% access-token
checks and 10% password logins. It reports latency percentiles and every error/503,
and excludes HTTP/proxy, Redis, email, and provider latency. SQL runs leave seeded
accounts in the supplied disposable database; MongoDB runs remove their uniquely
named benchmark database. Tune `--workers`, `--concurrency`, `--password-jobs`,
`--users`, and `--requests` for your workload. This is a local capacity probe, not
a production SLO or failover certification.
