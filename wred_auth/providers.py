"""Google OIDC and GitHub OAuth via Authlib, without framework dependencies."""

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oidc.core import CodeIDToken

from . import AuthError


class Google:
    authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    scope = "openid email profile"

    def __init__(self, client_id, client_secret, *, transport=None):
        self.client_id, self.client_secret, self.transport = (
            client_id,
            client_secret,
            transport,
        )

    def client(self, redirect_uri):
        return AsyncOAuth2Client(
            self.client_id,
            self.client_secret,
            scope=self.scope,
            redirect_uri=redirect_uri,
            code_challenge_method="S256",
            token_endpoint_auth_method="client_secret_post",
            transport=self.transport,
            timeout=10,
        )

    def authorization_url(self, *, state, nonce, verifier, redirect_uri):
        # URL construction is local; no HTTP resources are opened here.
        with_client = self.client(redirect_uri)
        return with_client.create_authorization_url(
            self.authorize_url, state=state, nonce=nonce, code_verifier=verifier
        )[0]

    async def exchange(self, *, code, verifier, nonce, redirect_uri):
        try:
            async with self.client(redirect_uri) as client:
                token = await client.fetch_token(
                    self.token_url, code=code, code_verifier=verifier
                )
                response = await client.request(
                    "GET", self.jwks_url, withhold_token=True
                )
                response.raise_for_status()
                # Restrict algorithms before verification; never accept token-selected HS keys.
                from authlib.jose import JsonWebToken

                claims = JsonWebToken(["RS256"]).decode(
                    token["id_token"],
                    response.json(),
                    claims_cls=CodeIDToken,
                    claims_options={
                        "iss": {
                            "essential": True,
                            "values": [
                                "https://accounts.google.com",
                                "accounts.google.com",
                            ],
                        },
                        "aud": {"essential": True, "value": self.client_id},
                        "exp": {"essential": True},
                        "iat": {"essential": True},
                        "sub": {"essential": True},
                    },
                    claims_params={
                        "nonce": nonce,
                        "client_id": self.client_id,
                        "access_token": token.get("access_token"),
                    },
                )
                claims.validate(leeway=30)
                return {
                    "subject": claims["sub"],
                    "email": claims["email"],
                    "email_verified": claims.get("email_verified") is True,
                }
        except Exception as exc:
            raise AuthError("Provider authentication failed") from exc


class GitHub(Google):
    authorize_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    scope = "read:user user:email"

    async def exchange(self, *, code, verifier, nonce, redirect_uri):
        try:
            async with self.client(redirect_uri) as client:
                await client.fetch_token(
                    self.token_url,
                    code=code,
                    code_verifier=verifier,
                    headers={"Accept": "application/json"},
                )
                profile = await client.get("https://api.github.com/user")
                profile.raise_for_status()
                emails = await client.get("https://api.github.com/user/emails")
                emails.raise_for_status()
                email = next(
                    e["email"]
                    for e in emails.json()
                    if e.get("verified") and e.get("primary")
                )
                return {
                    "subject": str(profile.json()["id"]),
                    "email": email,
                    "email_verified": True,
                }
        except Exception as exc:
            raise AuthError("Provider authentication failed") from exc
