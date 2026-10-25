"""An in-memory fake provider for `services.collector`/`services.scheduler` tests."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from carchive.core.errors import AuthenticationError
from carchive.core.models import DataPoint, RemoteDataRequest, RemoteDelivery, RemoteVehicle
from carchive.core.provider import (
    CredentialField,
    ParseContext,
    PayloadParser,
    ProviderCapabilities,
    SignalMapper,
    StreamSession,
)


@dataclass
class FakeParser:
    """A `PayloadParser` returning pre-set points per payload, or raising on configured ones."""

    points_by_payload: dict[bytes, list[DataPoint]] = field(default_factory=dict)
    fail_on: set[bytes] = field(default_factory=set)
    parser_version: str = "fake-parser-1"

    def parse(self, payload: bytes, context: ParseContext) -> Iterable[DataPoint]:
        """Return the configured points for `payload`, or raise if it is marked to fail."""
        if payload in self.fail_on:
            raise ValueError("broken payload")
        return self.points_by_payload.get(payload, [])


class FakeDeliverySession:
    """An in-memory `DeliverySession` for one logged-in run of `FakeProvider`."""

    def __init__(self, provider: FakeProvider) -> None:
        self._provider = provider
        self.closed = False

    async def list_vehicles(self) -> list[RemoteVehicle]:
        """Return the provider's configured vehicle list."""
        return list(self._provider.vehicles)

    async def list_data_requests(self, vin: str) -> list[RemoteDataRequest]:
        """Return the configured data requests for `vin`, or raise a queued error."""
        self._provider.discover_calls += 1
        error = self._provider._pop_error(self._provider.discover_errors, vin)
        if error is not None:
            raise error
        return list(self._provider.data_requests_by_vin.get(vin, []))

    async def list_deliveries(self, request: RemoteDataRequest) -> list[RemoteDelivery]:
        """Return the configured deliveries for `request`, or raise a queued error."""
        self._provider.list_calls += 1
        error = self._provider._pop_error(self._provider.list_errors, request.remote_id)
        if error is not None:
            raise error
        return list(self._provider.deliveries_by_remote_id.get(request.remote_id, []))

    async def download(self, request: RemoteDataRequest, delivery: RemoteDelivery) -> bytes:
        """Return the configured payload for `delivery`, or raise a queued error."""
        self._provider.download_calls += 1
        error = self._provider._pop_error(self._provider.download_errors, delivery.remote_name)
        if error is not None:
            raise error
        return self._provider.payloads[delivery.remote_name]

    async def aclose(self) -> None:
        """Mark this session closed and record the close on the owning provider."""
        self.closed = True
        self._provider.close_calls += 1


class FakeProvider:
    """A configurable in-memory provider; satisfies `core.provider.Provider`.

    Every list of per-key errors is consumed first-in-first-out: the first queued error for
    a key is raised on the first matching call, the second on the next, and so on; once a
    key's queue is empty, calls succeed normally.
    """

    id = "fake"
    brands = frozenset({"fake"})
    capabilities = ProviderCapabilities(
        delivery=True,
        stream=False,
        historical_import=False,
        catalog_import=False,
        max_listed_files=30,
        retention_days=7,
        min_request_interval_s=0.0,
    )
    credential_fields: tuple[CredentialField, ...] = (
        CredentialField(name="user", label="User", secret=False),
        CredentialField(name="password", label="Password", secret=True),
    )
    portal_home_url = "https://example.invalid/portal"

    def __init__(self, *, user: str = "user", password: str = "s3cret-password") -> None:
        self._user = user
        self._password = password
        self.login_calls = 0
        self.login_errors: list[Exception] = []
        self.vehicles: list[RemoteVehicle] = []
        self.data_requests_by_vin: dict[str, list[RemoteDataRequest]] = {}
        self.deliveries_by_remote_id: dict[str, list[RemoteDelivery]] = {}
        self.payloads: dict[str, bytes] = {}
        self.discover_errors: dict[str, list[Exception]] = {}
        self.list_errors: dict[str, list[Exception]] = {}
        self.download_errors: dict[str, list[Exception]] = {}
        self.discover_calls = 0
        self.list_calls = 0
        self.download_calls = 0
        self.close_calls = 0
        self._parser: PayloadParser | None = None
        self._mapper: SignalMapper | None = None

    def set_parser(self, parser: PayloadParser | None) -> None:
        """Set (or clear) the parser `parser()` returns."""
        self._parser = parser

    def set_mapper(self, mapper: SignalMapper | None) -> None:
        """Set (or clear) the mapper `mapper()` returns."""
        self._mapper = mapper

    def _pop_error(self, errors: dict[str, list[Exception]], key: str) -> Exception | None:
        queue = errors.get(key)
        if queue:
            return queue.pop(0)
        return None

    async def open_delivery_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> FakeDeliverySession:
        """Log in, raising a queued error or `AuthenticationError` on a credential mismatch."""
        self.login_calls += 1
        if self.login_errors:
            raise self.login_errors.pop(0)
        if credentials.get("user") != self._user or credentials.get("password") != self._password:
            raise AuthenticationError("bad credentials")
        return FakeDeliverySession(self)

    async def open_stream_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> StreamSession:
        """Not implemented: the fake provider only delivers discrete files.

        Raises:
            NotImplementedError: always.
        """
        raise NotImplementedError("fake provider has no streaming capability")

    def parser(self) -> PayloadParser:
        """Return the configured parser.

        Raises:
            NotImplementedError: if no parser was configured via `set_parser`.
        """
        if self._parser is None:
            raise NotImplementedError("no parser configured")
        return self._parser

    def mapper(self) -> SignalMapper:
        """Return the configured mapper.

        Raises:
            NotImplementedError: if no mapper was configured via `set_mapper`.
        """
        if self._mapper is None:
            raise NotImplementedError("no mapper configured")
        return self._mapper
