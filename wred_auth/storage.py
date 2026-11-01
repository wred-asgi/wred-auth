"""Public transaction contract for application-owned account stores."""

from typing import Any, AsyncContextManager, Awaitable, Callable, Protocol, TypeVar

T = TypeVar("T")


class StoreUnavailable(Exception):
    """Transaction deadline or conflict retry budget was exhausted."""


class Transaction(Protocol):
    async def get(self, table: str, key: str) -> dict | None: ...
    async def find(
        self, table: str, *, limit: int | None = None, **filters: Any
    ) -> list[dict]: ...
    async def insert(self, table: str, values: dict) -> None: ...
    async def update(self, table: str, key: str, **values: Any) -> None: ...
    async def delete(self, table: str, key: str) -> None: ...
    async def update_many(self, table: str, filters: dict, values: dict) -> None: ...


class AccountStore(Protocol):
    """Transactions serialize conflicting existing-record reads/writes and roll back.

    run() retries the ENTIRE callback on conflicts, within a bounded deadline.
    Callbacks must contain only database operations, without external side effects.
    Read-only callbacks use a consistent snapshot and do not lock records. Write
    callbacks lock get/find results; account mutations must read the owning user
    before inserting dependent records (including when no matches exist yet).
    Enforce uniqueness for user email and (provider, subject). Filters support
    equality and the suffixes __gt and __lte; find is ordered by id for pagination.
    Schema fields are defined in sqlalchemy.metadata; MongoDB uses the same fields.
    """

    def transaction(
        self, *, read_only: bool = False
    ) -> AsyncContextManager[Transaction]: ...
    async def run(
        self,
        callback: Callable[[Transaction], Awaitable[T]],
        *,
        read_only: bool = False,
    ) -> T: ...
    async def cleanup(self, *, now: float, batch_size: int = 500) -> dict[str, int]: ...
    async def aclose(self) -> None: ...
