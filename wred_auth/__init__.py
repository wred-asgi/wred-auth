"""Bearer authorization and an opt-in account service for Wred."""

import asyncio
import hashlib
import inspect
import secrets
import time
import uuid
from dataclasses import dataclass
from functools import wraps
from urllib.parse import urlencode

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.fernet import Fernet

from .storage import StoreUnavailable

__version__ = "0.1.0"


class AuthError(Exception):
    def __init__(self, detail="Not authenticated", status=401):
        self.detail, self.status = detail, status
        super().__init__(detail)

    def response(self):
        headers = [("content-type", "application/json"), ("cache-control", "no-store")]
        if self.status == 401:
            headers.append(("www-authenticate", "Bearer"))
        return {"detail": self.detail}, headers, self.status


@dataclass(frozen=True)
class Principal:
    id: str
    roles: tuple = ()
    session_id: str | None = None
    auth_time: float = 0


def principal(request):
    value = request.scope.get("wred.auth")
    if value is None:
        raise AuthError()
    return value


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _email(value):
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 320
        or value.count("@") != 1
        or value.startswith("@")
        or value.endswith("@")
        or any(c.isspace() for c in value)
    ):
        raise AuthError("Invalid email", 422)
    return value.casefold()


def _password(value):
    if not isinstance(value, str) or not 15 <= len(value) <= 128:
        raise AuthError("Password must contain 15 to 128 characters", 422)
    return value


class JWTVerifier:
    """External bearer verifier with explicit algorithms and application role lookup."""

    def __init__(self, key, *, algorithms, issuer, audience, lookup=None):
        if not algorithms or any(a.lower() == "none" for a in algorithms):
            raise ValueError("Explicit signed algorithms required")
        self.key, self.algorithms, self.issuer, self.audience, self.lookup = (
            key,
            algorithms,
            issuer,
            audience,
            lookup,
        )

    async def __call__(self, token):
        try:
            claims = jwt.decode(
                token,
                self.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["sub", "exp", "iss", "aud"]},
            )
        except jwt.InvalidTokenError as exc:
            raise AuthError() from exc
        if self.lookup:
            result = self.lookup(claims)
            result = await result if inspect.isawaitable(result) else result
            if not isinstance(result, Principal):
                raise AuthError()
            return result
        return Principal(claims["sub"])


class Auth:
    """Custom verifier alone, or full accounts with store, signing/encryption keys,
    issuer, audience, public_url, and async send_email(kind, email, url) callback.
    """

    def __init__(
        self,
        *,
        verifier=None,
        store=None,
        signing_key=None,
        encryption_key=None,
        issuer="wred-auth",
        audience="wred-api",
        public_url=None,
        send_email=None,
        audit=None,
        access_ttl=900,
        refresh_ttl=2592000,
        providers=None,
        limiter=None,
        max_password_jobs=2,
    ):
        self.verifier, self.store = verifier, store
        self.signing_key, self.issuer, self.audience = signing_key, issuer, audience
        self.public_url, self.send_email, self.audit = public_url, send_email, audit
        self.access_ttl, self.refresh_ttl = access_ttl, refresh_ttl
        self.providers = providers or {}
        self.limiter = limiter
        if type(max_password_jobs) is not int or max_password_jobs < 1:
            raise ValueError("max_password_jobs must be a positive integer")
        self._password_slots = asyncio.Semaphore(max_password_jobs)
        self._password_tasks = set()
        if store is not None:
            if (
                not signing_key
                or len(signing_key) < 32
                or not encryption_key
                or not public_url
                or not send_email
            ):
                raise ValueError(
                    "Accounts require signing/encryption keys, public_url, and send_email"
                )
            if not public_url.startswith("https://"):
                raise ValueError("Account public_url must use HTTPS")
            if access_ttl <= 0 or refresh_ttl <= access_ttl:
                raise ValueError("Invalid token lifetimes")
            self.cipher = Fernet(encryption_key)
            self.hasher = PasswordHasher()
            self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))
        if store is None and verifier is None:
            raise ValueError("Provide an account store or a verifier")

    async def _event(self, name, user_id=None):
        if self.audit:
            await self.audit({"event": name, "user_id": user_id, "time": time.time()})

    async def _run(self, callback, *, read_only=False):
        try:
            return await self.store.run(callback, read_only=read_only)
        except StoreUnavailable as exc:
            raise AuthError("Account service temporarily unavailable", 503) from exc

    async def _password_work(self, function, *args):
        # No unbounded work queue. Cancellation must not release a slot while
        # the underlying thread is still using CPU and Argon2 memory.
        if self._password_slots.locked():
            raise AuthError("Password service busy; retry later", 503)
        await self._password_slots.acquire()
        task = asyncio.create_task(asyncio.to_thread(function, *args))
        self._password_tasks.add(task)

        def completed(task):
            self._password_tasks.discard(task)
            self._password_slots.release()
            if not task.cancelled():
                task.exception()

        task.add_done_callback(completed)
        return await asyncio.shield(task)

    async def _hash_password(self, password):
        return await self._password_work(self.hasher.hash, _password(password))

    async def cleanup(self, *, batch_size=500):
        """Delete at most batch_size expired tokens and sessions per call."""
        try:
            return await self.store.cleanup(now=time.time(), batch_size=batch_size)
        except StoreUnavailable as exc:
            raise AuthError("Account service temporarily unavailable", 503) from exc

    async def _new_token(self, tx, kind, user_id=None, *, ttl=1800, data=None):
        token = secrets.token_urlsafe(32)
        await tx.insert(
            "tokens",
            {
                "id": _hash(token),
                "user_id": user_id,
                "kind": kind,
                "expires": time.time() + ttl,
                "used": False,
                "data": data or {},
            },
        )
        return token

    async def _token(self, tx, token, kind, *, consume=True):
        if not isinstance(token, str):
            raise AuthError()
        row = await tx.get("tokens", _hash(token))
        if (
            not row
            or row["kind"] != kind
            or row["used"]
            or row["expires"] <= time.time()
        ):
            raise AuthError("Invalid or expired token")
        if consume:
            await tx.update("tokens", row["id"], used=True)
        return row

    async def _verify_password(self, hashed, password):
        if not isinstance(password, str) or len(password) > 128:
            return False
        try:
            await self._password_work(
                self.hasher.verify, hashed or self.dummy_hash, password
            )
            return hashed is not None
        except VerificationError:
            return False

    def _new_user(self, email, password=None, verified=False):
        return {
            "id": uuid.uuid4().hex,
            "email": email,
            "password": password,
            "verified": verified,
            "active": True,
            "roles": [],
            "totp": None,
            "totp_pending": None,
            "totp_step": -1,
            "recovery": [],
        }

    async def register(self, email, password):
        email = _email(email)
        hashed = await self._hash_password(password)

        async def create(tx):
            if not await tx.find("users", email=email):
                user = self._new_user(email, hashed)
                await tx.insert("users", user)
                return await self._new_token(tx, "verify", user["id"])

        token = await self._run(create)
        if token:
            await self._send("verify", email, token)
        return {"detail": "If eligible, verification instructions will be sent"}

    async def _send(self, kind, email, token):
        # Application renders and sends email. The URL is a frontend landing page;
        # it must POST the token to the corresponding API operation.
        await self.send_email(
            kind,
            email,
            self.public_url.rstrip("/")
            + "/"
            + kind
            + "?"
            + urlencode({"token": token}),
        )

    async def request_token(self, email, *, kind="reset"):
        if kind not in ("reset", "verify"):
            raise ValueError("Unsupported token purpose")
        email = _email(email)

        async def issue(tx):
            users = await tx.find("users", email=email)
            if users and users[0]["active"]:
                return await self._new_token(tx, kind, users[0]["id"])

        token = await self._run(issue)
        if token:
            await self._send(kind, email, token)
        return {"detail": "If eligible, instructions will be sent"}

    async def verify_email(self, token):
        async def verify(tx):
            row = await self._token(tx, token, "verify")
            await tx.get("users", row["user_id"])
            await tx.update("users", row["user_id"], verified=True)
            return row["user_id"]

        user_id = await self._run(verify)
        await self._event("email_verified", user_id)
        return {"detail": "Email verified"}

    async def _revoke_all(self, tx, user_id, *, reset=False):
        await tx.update_many(
            "sessions", {"user_id": user_id, "revoked": False}, {"revoked": True}
        )
        for kind in ("mfa", "reset") if reset else ("mfa",):
            await tx.update_many(
                "tokens",
                {
                    "user_id": user_id,
                    "kind": kind,
                    "used": False,
                    "expires__gt": time.time(),
                },
                {"used": True},
            )

    async def reset_password(self, token, password):
        _password(password)

        async def preflight(tx):
            await self._token(tx, token, "reset", consume=False)

        await self._run(preflight, read_only=True)
        hashed = await self._hash_password(password)

        async def reset(tx):
            # Recheck after hashing: another request may have consumed or revoked
            # this token in the meantime. All changes commit atomically.
            row = await self._token(tx, token, "reset")
            account = await tx.get("users", row["user_id"])
            if not account or not account["active"]:
                raise AuthError()
            await tx.update("users", row["user_id"], password=hashed)
            await self._revoke_all(tx, row["user_id"], reset=True)
            return row["user_id"]

        user_id = await self._run(reset)
        await self._event("password_reset", user_id)
        return {"detail": "Password changed; sign in again"}

    def _access(self, user, session):
        now = int(time.time())
        return jwt.encode(
            {
                "sub": user["id"],
                "sid": session["id"],
                "iat": now,
                "exp": now + self.access_ttl,
                "iss": self.issuer,
                "aud": self.audience,
            },
            self.signing_key,
            algorithm="HS256",
        )

    async def _tokens(self, tx, user, session):
        refresh = await self._new_token(
            tx,
            "refresh",
            user["id"],
            ttl=max(1, session["expires"] - time.time()),
            data={"session_id": session["id"]},
        )
        return {
            "access_token": self._access(user, session),
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": self.access_ttl,
        }

    async def _session(self, tx, user, *, mfa=False):
        if not user["active"] or not user["verified"]:
            raise AuthError()
        if user["totp"] and not mfa:
            challenge = await self._new_token(tx, "mfa", user["id"], ttl=300)
            return {"mfa_required": True, "challenge": challenge}
        now = time.time()
        session = {
            "id": uuid.uuid4().hex,
            "user_id": user["id"],
            "created": now,
            "auth_time": now,
            "expires": now + self.refresh_ttl,
            "revoked": False,
        }
        await tx.insert("sessions", session)
        return await self._tokens(tx, user, session)

    async def login(self, email, password):
        email = _email(email)

        async def lookup(tx):
            users = await tx.find("users", email=email)
            return users[0] if users else None

        user = await self._run(lookup, read_only=True)
        valid = await self._verify_password(
            user["password"] if user else None, password
        )
        if not user or not valid:
            raise AuthError()

        async def create(tx):
            account = await tx.get("users", user["id"])
            if not account or account["password"] != user["password"]:
                raise AuthError()
            return await self._session(tx, account)

        result = await self._run(create)
        await self._event("login", user["id"])
        return result

    async def refresh(self, token):
        if not isinstance(token, str):
            raise AuthError()

        async def rotate(tx):
            row = await tx.get("tokens", _hash(token))
            if not row or row["kind"] != "refresh" or row["expires"] <= time.time():
                raise AuthError()
            session = await tx.get("sessions", row["data"]["session_id"])
            if row["used"]:
                if session:
                    await tx.update("sessions", session["id"], revoked=True)
                return None, row["user_id"]
            user = await tx.get("users", row["user_id"])
            if (
                not session
                or session["revoked"]
                or session["expires"] <= time.time()
                or not user
                or not user["active"]
                or not user["verified"]
            ):
                raise AuthError()
            await tx.update("tokens", row["id"], used=True)
            return await self._tokens(tx, user, session), row["user_id"]

        result, user_id = await self._run(rotate)
        if result is None:
            await self._event("refresh_replay", user_id)
            raise AuthError("Session revoked")
        return result

    async def authenticate(self, token):
        if self.verifier:
            value = self.verifier(token)
            value = await value if inspect.isawaitable(value) else value
            if not isinstance(value, Principal):
                raise AuthError()
            return value
        try:
            claims = jwt.decode(
                token,
                self.signing_key,
                algorithms=["HS256"],
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["sub", "sid", "exp", "iat", "iss", "aud"]},
            )
        except jwt.InvalidTokenError as exc:
            raise AuthError() from exc

        async def lookup(tx):
            session = await tx.get("sessions", claims["sid"])
            user = await tx.get("users", claims["sub"])
            if (
                not session
                or not user
                or session["user_id"] != user["id"]
                or session["revoked"]
                or session["expires"] <= time.time()
                or not user["active"]
                or not user["verified"]
            ):
                raise AuthError()
            return Principal(
                user["id"], tuple(user["roles"]), session["id"], session["auth_time"]
            )

        return await self._run(lookup, read_only=True)

    async def _request_principal(self, request):
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token or " " in token:
            raise AuthError()
        value = await self.authenticate(token)
        request.scope["wred.auth"] = value
        return value

    def require_auth(self):
        def decorate(handler):
            @wraps(handler)
            async def wrapped(request, *args, **kwargs):
                try:
                    await self._request_principal(request)
                except AuthError as exc:
                    return exc.response()
                return await handler(request, *args, **kwargs)

            metadata = dict(getattr(handler, "__wred_openapi__", {}))
            metadata.setdefault("security", [{"bearerAuth": []}])
            wrapped.__wred_openapi__ = metadata
            return wrapped

        return decorate

    def require_role(self, role):
        def decorate(handler):
            @wraps(handler)
            async def wrapped(request, *args, **kwargs):
                try:
                    value = request.scope.get(
                        "wred.auth"
                    ) or await self._request_principal(request)
                    if role not in value.roles:
                        raise AuthError("Forbidden", 403)
                except AuthError as exc:
                    return exc.response()
                return await handler(request, *args, **kwargs)

            metadata = dict(getattr(handler, "__wred_openapi__", {}))
            metadata.setdefault("security", [{"bearerAuth": []}])
            wrapped.__wred_openapi__ = metadata
            return wrapped

        return decorate

    def _recent(self, user):
        if not user.session_id or time.time() - user.auth_time > 300:
            raise AuthError("Recent authentication required", 403)

    async def _account(self, tx, principal, *, recent=False):
        if recent:
            self._recent(principal)
        session = await tx.get("sessions", principal.session_id)
        account = await tx.get("users", principal.id)
        if (
            not account
            or not account["active"]
            or not account["verified"]
            or not session
            or session["user_id"] != principal.id
            or session["revoked"]
            or session["expires"] <= time.time()
        ):
            raise AuthError()
        if recent and time.time() - session["auth_time"] > 300:
            raise AuthError("Recent authentication required", 403)
        return account

    async def sessions(self, user, *, limit=100, after=None):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise AuthError("Invalid session page size", 422)

        async def lookup(tx):
            filters = {"user_id": user.id, "revoked": False, "expires__gt": time.time()}
            if after is not None:
                filters["id__gt"] = after
            return [
                {"id": s["id"], "created": s["created"], "expires": s["expires"]}
                for s in await tx.find("sessions", limit=limit, **filters)
            ]

        return await self._run(lookup, read_only=True)

    async def revoke(self, user, session_id=None):
        async def revoke_session(tx):
            session = await tx.get("sessions", session_id or user.session_id)
            if not session or session["user_id"] != user.id:
                raise AuthError("Session not found", 404)
            await tx.update("sessions", session["id"], revoked=True)

        await self._run(revoke_session)
        await self._event("session_revoked", user.id)
        return {"detail": "Session revoked"}

    async def change_password(self, user, old_password, password):
        self._recent(user)
        _password(password)

        async def lookup(tx):
            return await self._account(tx, user, recent=True)

        account = await self._run(lookup, read_only=True)
        if not await self._verify_password(account["password"], old_password):
            raise AuthError()
        hashed = await self._hash_password(password)

        async def change(tx):
            current = await self._account(tx, user, recent=True)
            if current["password"] != account["password"]:
                raise AuthError()
            await tx.update("users", user.id, password=hashed)
            await self._revoke_all(tx, user.id, reset=True)

        await self._run(change)
        await self._event("password_changed", user.id)
        return {"detail": "Password changed; sign in again"}

    async def set_roles(self, user_id, roles):
        """Administrative service method. Never exposed as a public account endpoint."""
        roles = tuple(roles)
        if not all(isinstance(role, str) and role for role in roles):
            raise ValueError("Roles must be nonempty strings")

        async def change(tx):
            if not await tx.get("users", user_id):
                raise AuthError("Account not found", 404)
            await tx.update("users", user_id, roles=sorted(set(roles)))

        await self._run(change)
        await self._event("roles_changed", user_id)

    async def set_active(self, user_id, active):
        async def change(tx):
            if not await tx.get("users", user_id):
                raise AuthError("Account not found", 404)
            await tx.update("users", user_id, active=bool(active))
            if not active:
                await self._revoke_all(tx, user_id, reset=True)

        await self._run(change)
        await self._event("account_status_changed", user_id)

    async def setup_mfa(self, user):
        self._recent(user)
        secret = pyotp.random_base32()

        async def setup(tx):
            account = await self._account(tx, user, recent=True)
            if account["totp"]:
                raise AuthError("MFA is already enabled", 409)
            await tx.update(
                "users",
                user.id,
                totp_pending=self.cipher.encrypt(secret.encode()).decode(),
            )
            return account

        account = await self._run(setup)
        return {
            "secret": secret,
            "uri": pyotp.TOTP(secret).provisioning_uri(
                account["email"], issuer_name=self.issuer
            ),
        }

    def _totp_step(self, encrypted, code, previous=-1):
        if not encrypted or not isinstance(code, str):
            raise AuthError("Invalid MFA code")
        secret = self.cipher.decrypt(encrypted.encode()).decode()
        current = int(time.time()) // 30
        totp = pyotp.TOTP(secret)
        for step in (current, current - 1, current + 1):
            if step > previous and secrets.compare_digest(totp.at(step * 30), code):
                return step
        raise AuthError("Invalid MFA code")

    async def confirm_mfa(self, user, code):
        self._recent(user)
        recovery = [secrets.token_urlsafe(16) for _ in range(10)]

        async def confirm(tx):
            account = await self._account(tx, user, recent=True)
            step = self._totp_step(account["totp_pending"], code)
            await tx.update(
                "users",
                user.id,
                totp=account["totp_pending"],
                totp_pending=None,
                totp_step=step,
                recovery=[_hash(c) for c in recovery],
            )
            await self._revoke_all(tx, user.id)

        await self._run(confirm)
        await self._event("mfa_enabled", user.id)
        return {"recovery_codes": recovery, "detail": "MFA enabled; sign in again"}

    async def _consume_mfa(self, tx, account, code):
        hashed = _hash(code)
        if hashed in account["recovery"]:
            await tx.update(
                "users",
                account["id"],
                recovery=[c for c in account["recovery"] if c != hashed],
            )
        else:
            step = self._totp_step(account["totp"], code, account["totp_step"])
            await tx.update("users", account["id"], totp_step=step)

    async def complete_mfa(self, challenge, code):
        async def complete(tx):
            row = await self._token(tx, challenge, "mfa")
            account = await tx.get("users", row["user_id"])
            await self._consume_mfa(tx, account, code)
            result = await self._session(tx, account, mfa=True)
            return (result, account)

        result, account = await self._run(complete)
        await self._event("mfa_login", account["id"])
        return result

    async def disable_mfa(self, user, code):
        self._recent(user)

        async def disable(tx):
            account = await self._account(tx, user, recent=True)
            await self._consume_mfa(tx, account, code)
            await tx.update(
                "users",
                user.id,
                totp=None,
                totp_pending=None,
                recovery=[],
                totp_step=-1,
            )
            await self._revoke_all(tx, user.id)

        await self._run(disable)
        await self._event("mfa_disabled", user.id)
        return {"detail": "MFA disabled; sign in again"}

    async def oauth_start(self, provider, *, callback_url, user=None):
        if provider not in self.providers:
            raise AuthError("Unknown provider", 404)
        if user:
            self._recent(user)
        browser = secrets.token_urlsafe(32)
        verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(32)

        async def start(tx):
            if user:
                await self._account(tx, user, recent=True)
            state = await self._new_token(
                tx,
                "oauth",
                user.id if user else None,
                ttl=300,
                data={
                    "provider": provider,
                    "browser": _hash(browser),
                    "verifier": verifier,
                    "nonce": nonce,
                    "callback_url": callback_url,
                    "session_id": user.session_id if user else None,
                },
            )
            return state

        state = await self._run(start)
        url = self.providers[provider].authorization_url(
            state=state, nonce=nonce, verifier=verifier, redirect_uri=callback_url
        )
        return {"url": url, "browser": browser}

    async def oauth_callback(self, provider, *, state, code, browser):
        if provider not in self.providers:
            raise AuthError("Unknown provider", 404)

        # Consume before network exchange so the authorization code/state is single-use.
        async def consume(tx):
            row = await self._token(tx, state, "oauth")
            data = row["data"]
            if data["provider"] != provider or not secrets.compare_digest(
                data["browser"], _hash(browser)
            ):
                raise AuthError("Invalid OAuth state")
            return row

        row = await self._run(consume)
        data = row["data"]
        identity = await self.providers[provider].exchange(
            code=code,
            verifier=data["verifier"],
            nonce=data["nonce"],
            redirect_uri=data["callback_url"],
        )

        async def link(tx):
            existing = await tx.find(
                "identities", provider=provider, subject=identity["subject"]
            )
            if row["user_id"]:
                session = await tx.get("sessions", data["session_id"])
                user = await tx.get("users", row["user_id"])
                if (
                    not session
                    or session["revoked"]
                    or session["expires"] <= time.time()
                    or time.time() - session["auth_time"] > 300
                    or not user["active"]
                ):
                    raise AuthError("Recent authentication required", 403)
                if existing and existing[0]["user_id"] != user["id"]:
                    raise AuthError("Identity is already linked", 409)
            elif existing:
                user = await tx.get("users", existing[0]["user_id"])
            else:
                email = _email(identity["email"])
                if not identity["email_verified"]:
                    raise AuthError("Provider email must be verified", 403)
                if await tx.find("users", email=email):
                    raise AuthError(
                        "Sign in to the existing account to link this identity", 409
                    )
                user = self._new_user(email, verified=True)
                await tx.insert("users", user)
            if not existing:
                await tx.insert(
                    "identities",
                    {
                        "id": uuid.uuid4().hex,
                        "user_id": user["id"],
                        "provider": provider,
                        "subject": identity["subject"],
                    },
                )
            result = (
                {"detail": "Identity linked"}
                if row["user_id"]
                else await self._session(tx, user)
            )
            return result, user["id"]

        result, user_id = await self._run(link)
        await self._event(
            "identity_linked" if row["user_id"] else "provider_login", user_id
        )
        return result

    def mount(
        self,
        app,
        *,
        prefix="/auth",
        rule="10/minute",
        account_rule="5/minute",
        key=None,
    ):
        """Register JSON account endpoints with peer-IP and account-key throttles.

        The caller must supply a configured Limiter; use Redis across workers.
        """
        from http.cookies import SimpleCookie

        if self.store is None or self.limiter is None:
            raise ValueError("Account routes require store and limiter")
        prefix = "/" + prefix.strip("/")

        async def dispatch(request, action, provider=None):
            try:
                if action.startswith("oauth_"):
                    callback = (
                        self.public_url.rstrip("/")
                        + prefix
                        + "/oauth/"
                        + provider
                        + "/callback"
                    )
                    if action in ("oauth_start", "oauth_link"):
                        user = (
                            await self._request_principal(request)
                            if action == "oauth_link"
                            else None
                        )
                        result = await self.oauth_start(
                            provider, callback_url=callback, user=user
                        )
                        return (
                            b"",
                            [
                                ("location", result["url"]),
                                ("cache-control", "no-store"),
                                (
                                    "set-cookie",
                                    "__Host-wred_oauth="
                                    + result["browser"]
                                    + "; Path=/; Secure; HttpOnly; SameSite=Lax",
                                ),
                            ],
                            302,
                        )
                    cookie = SimpleCookie()
                    cookie.load(request.headers.get("cookie", ""))
                    browser = cookie.get("__Host-wred_oauth")
                    if not browser:
                        raise AuthError("OAuth browser binding required")
                    result = await self.oauth_callback(
                        provider,
                        state=request.query["state"],
                        code=request.query["code"],
                        browser=browser.value,
                    )
                    return (
                        result,
                        [
                            ("content-type", "application/json"),
                            ("cache-control", "no-store"),
                            (
                                "set-cookie",
                                "__Host-wred_oauth=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
                            ),
                        ],
                        200,
                    )
                payload = {} if request.method == "GET" else await request.json()
                if not isinstance(payload, dict):
                    raise AuthError("Expected a JSON object", 422)
                # Bound inputs before parsing passwords/tokens and avoid logging them.
                if any(
                    not isinstance(v, str) or len(v) > 8192 for v in payload.values()
                ):
                    raise AuthError("Invalid account input", 422)
                email = payload.get("email")
                if email:
                    email = _email(email)
                    try:
                        allowed, retry = await self.limiter.check(
                            account_rule, email, bucket="auth:account:" + action
                        )
                    except Exception:
                        return AuthError(
                            "Rate limit service unavailable", 503
                        ).response()
                    if not allowed:
                        return (
                            {"detail": "Rate limit exceeded"},
                            [
                                ("content-type", "application/json"),
                                ("retry-after", str(retry)),
                            ],
                            429,
                        )
                if action == "mfa_login":
                    try:
                        allowed, retry = await self.limiter.check(
                            account_rule,
                            payload.get("challenge", ""),
                            bucket="auth:mfa-challenge",
                        )
                    except Exception:
                        return AuthError(
                            "Rate limit service unavailable", 503
                        ).response()
                    if not allowed:
                        return (
                            {"detail": "Rate limit exceeded"},
                            [
                                ("content-type", "application/json"),
                                ("retry-after", str(retry)),
                            ],
                            429,
                        )
                if action == "register":
                    result = await self.register(payload["email"], payload["password"])
                elif action == "login":
                    result = await self.login(payload["email"], payload["password"])
                elif action == "verify":
                    result = await self.verify_email(payload["token"])
                elif action == "request_verification":
                    result = await self.request_token(payload["email"], kind="verify")
                elif action == "forgot_password":
                    result = await self.request_token(payload["email"])
                elif action == "reset_password":
                    result = await self.reset_password(
                        payload["token"], payload["password"]
                    )
                elif action == "refresh":
                    result = await self.refresh(payload["refresh_token"])
                elif action == "mfa_login":
                    result = await self.complete_mfa(
                        payload["challenge"], payload["code"]
                    )
                else:
                    user = await self._request_principal(request)
                    if action == "sessions":
                        result = {
                            "sessions": await self.sessions(
                                user,
                                limit=int(request.query.get("limit", "100")),
                                after=request.query.get("after"),
                            )
                        }
                    elif action == "logout":
                        result = await self.revoke(user)
                    elif action == "revoke":
                        result = await self.revoke(user, payload["session_id"])
                    elif action == "change_password":
                        result = await self.change_password(
                            user, payload["old_password"], payload["password"]
                        )
                    elif action == "mfa_setup":
                        result = await self.setup_mfa(user)
                    elif action == "mfa_confirm":
                        result = await self.confirm_mfa(user, payload["code"])
                    elif action == "mfa_disable":
                        result = await self.disable_mfa(user, payload["code"])
                    else:
                        raise AuthError("Not found", 404)
                return (
                    result,
                    [
                        ("content-type", "application/json"),
                        ("cache-control", "no-store"),
                    ],
                    200,
                )
            except AuthError as exc:
                return exc.response()
            except (KeyError, ValueError, UnicodeError):
                return AuthError("Invalid account input", 422).response()

        routes = []
        for action in (
            "register",
            "login",
            "verify",
            "request_verification",
            "forgot_password",
            "reset_password",
            "refresh",
            "logout",
            "revoke",
            "change_password",
            "sessions",
            "mfa_login",
            "mfa_setup",
            "mfa_confirm",
            "mfa_disable",
        ):
            routes.append(
                (
                    prefix + "/" + action.replace("_", "-"),
                    action,
                    "GET" if action == "sessions" else "POST",
                    None,
                )
            )
        for provider in self.providers:
            for action, method in (
                ("start", "GET"),
                ("callback", "GET"),
                ("link", "POST"),
            ):
                routes.append(
                    (
                        prefix + "/oauth/" + provider + "/" + action,
                        "oauth_" + action,
                        method,
                        provider,
                    )
                )
        if any(path in app.routes for path, *_ in routes):
            raise ValueError("An account route already exists")

        def make_handler(action, provider):
            async def dispatch_action(request):
                return await dispatch(request, action, provider)

            limited = self.limiter.limit(rule, key=key, bucket=prefix + ":" + action)(
                dispatch_action
            )

            async def handler(request):
                payload, headers, status = await limited(request)
                headers = [
                    (name, value)
                    for name, value in headers
                    if name.lower() != "cache-control"
                ]
                return payload, [*headers, ("cache-control", "no-store")], status

            return handler

        for path, action, method, provider in routes:
            app.route(path, methods=[method])(make_handler(action, provider))
        return self

    async def aclose(self):
        if self._password_tasks:
            await asyncio.gather(*self._password_tasks, return_exceptions=True)
        if self.store:
            await self.store.aclose()
        if self.limiter:
            await self.limiter.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()
