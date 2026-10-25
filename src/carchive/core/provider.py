"""Provider protocols: the shape every data source (VW group, later others) must implement.

`core` defines these as `typing.Protocol`s and never imports a concrete provider; providers
import `core`, not the other way round.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from carchive.core.models import (
    DataPoint,
    RemoteDataRequest,
    RemoteDelivery,
    RemoteVehicle,
    SignalValue,
)


@dataclass(frozen=True, slots=True)
class CredentialField:
    """One field a provider's setup wizard must ask for."""

    name: str
    label: str
    secret: bool


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    """What a provider can do, declared once and evaluated by the collector and monitoring."""

    delivery: bool
    stream: bool
    historical_import: bool
    catalog_import: bool
    max_listed_files: int | None
    retention_days: int | None
    min_request_interval_s: float


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Context a `PayloadParser` needs beyond the raw bytes to interpret a payload."""

    vin: str
    request_kind: str
    delivered_at: datetime | None
    fetched_at: datetime


class DeliverySession(Protocol):
    """A logged-in session with a provider that delivers data as discrete, listable files."""

    async def list_vehicles(self) -> list[RemoteVehicle]:
        """Return the vehicles visible to this session."""
        ...

    async def list_data_requests(self, vin: str) -> list[RemoteDataRequest]:
        """Return the data requests the provider resolves for `vin`."""
        ...

    async def list_deliveries(self, request: RemoteDataRequest) -> list[RemoteDelivery]:
        """Return the deliveries currently listed for `request`."""
        ...

    async def download(self, request: RemoteDataRequest, delivery: RemoteDelivery) -> bytes:
        """Download the raw payload of `delivery` belonging to `request`."""
        ...

    async def aclose(self) -> None:
        """Release any resources (connections, tokens) held by this session."""
        ...


class StreamSession(Protocol):
    """A logged-in session with a provider that pushes data as a continuous stream."""

    async def list_vehicles(self) -> list[RemoteVehicle]:
        """Return the vehicles visible to this session."""
        ...

    def stream(self) -> AsyncIterator[bytes]:
        """Yield raw payloads as they arrive."""
        ...

    async def aclose(self) -> None:
        """Release any resources (connections, tokens) held by this session."""
        ...


class PayloadParser(Protocol):
    """Turns a raw delivered payload into provider-keyed `DataPoint`s."""

    parser_version: str

    def parse(self, payload: bytes, context: ParseContext) -> Iterable[DataPoint]:
        """Parse `payload` into `DataPoint`s.

        Args:
            payload: the raw bytes of one delivery.
            context: metadata about the delivery the payload came from.

        Returns:
            An iterable of the payload's leaf values.
        """
        ...


class SignalMapper(Protocol):
    """Derives canonical `SignalValue`s from provider-keyed `DataPoint`s."""

    mapping_version: str

    def map(self, points: Sequence[DataPoint]) -> Iterable[SignalValue]:
        """Map `points` to canonical signal values.

        Args:
            points: data points, typically all belonging to one vehicle.

        Returns:
            An iterable of the canonical signal values derivable from `points`.
        """
        ...

    def preference(self, signal: str) -> tuple[str, ...]:
        """Return `signal`'s source fields in preferred order, most preferred first.

        Used by `core.signals.preferred` to pick one value among several source fields
        reporting the same signal; carries no meaning on its own without `map`'s output.

        Args:
            signal: a canonical signal name.

        Returns:
            The known source field names for `signal`, most preferred first; empty if
            this mapper does not map `signal` at all.
        """
        ...


class Provider(Protocol):
    """A data source: VW group's EU Data Act portal, and later others."""

    id: str
    brands: frozenset[str]
    capabilities: ProviderCapabilities
    credential_fields: tuple[CredentialField, ...]
    portal_home_url: str
    """The portal's own start page, linked as plain text by the setup wizard's tutorial
    step; never embedded, so the wizard never has to know anything brand-specific to show
    it."""

    async def open_delivery_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> DeliverySession:
        """Log in and return a `DeliverySession` for `brand`.

        Raises:
            NotImplementedError: if `capabilities.delivery` is False.
        """
        ...

    async def open_stream_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> StreamSession:
        """Log in and return a `StreamSession` for `brand`.

        Raises:
            NotImplementedError: if `capabilities.stream` is False.
        """
        ...

    def parser(self) -> PayloadParser:
        """Return this provider's payload parser."""
        ...

    def mapper(self) -> SignalMapper:
        """Return this provider's signal mapper."""
        ...


class ProviderRegistry:
    """Looks up providers by id or by the brand they serve."""

    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    def register(self, provider: Provider) -> None:
        """Register `provider`.

        Args:
            provider: the provider to register.

        Raises:
            ValueError: if a provider with the same `id` is already registered.
        """
        if provider.id in self._providers:
            raise ValueError(f"provider {provider.id!r} is already registered")
        self._providers[provider.id] = provider

    def get(self, provider_id: str) -> Provider:
        """Return the provider registered under `provider_id`.

        Raises:
            KeyError: if no provider with that id is registered.
        """
        try:
            return self._providers[provider_id]
        except KeyError:
            raise KeyError(f"no provider registered with id {provider_id!r}") from None

    def all(self) -> list[Provider]:
        """Return all registered providers."""
        return list(self._providers.values())

    def for_brand(self, brand: str) -> list[Provider]:
        """Return all registered providers that serve `brand` (case-insensitive)."""
        needle = brand.lower()
        return [p for p in self._providers.values() if needle in {b.lower() for b in p.brands}]
