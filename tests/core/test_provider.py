"""Tests for `carchive.core.provider`, including a protocol-conformance check."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable, Mapping, Sequence

import pytest

from carchive.core.errors import NeedsAttentionError
from carchive.core.models import (
    DataPoint,
    RemoteDataRequest,
    RemoteDelivery,
    RemoteVehicle,
    SignalValue,
)
from carchive.core.provider import (
    CredentialField,
    DeliverySession,
    ParseContext,
    PayloadParser,
    Provider,
    ProviderCapabilities,
    ProviderRegistry,
    SignalMapper,
    StreamSession,
)


class FakeDeliverySession:
    """Minimal `DeliverySession` implementation used to check protocol conformance."""

    async def list_vehicles(self) -> list[RemoteVehicle]:
        return [RemoteVehicle(vin="WVWZZZ1KZAW000001", name="Fake")]

    async def list_data_requests(self, vin: str) -> list[RemoteDataRequest]:
        return [RemoteDataRequest(vin=vin, kind="all", remote_id="r1")]

    async def list_deliveries(self, request: RemoteDataRequest) -> list[RemoteDelivery]:
        return [RemoteDelivery(remote_name="x.zip", delivered_at=None, has_content=True)]

    async def download(self, request: RemoteDataRequest, delivery: RemoteDelivery) -> bytes:
        return b""

    async def aclose(self) -> None:
        return None


class FakeStreamSession:
    """Minimal `StreamSession` implementation used to check protocol conformance."""

    async def list_vehicles(self) -> list[RemoteVehicle]:
        return []

    async def stream(self) -> AsyncIterator[bytes]:
        if False:
            yield b""

    async def aclose(self) -> None:
        return None


class FakeParser:
    """Minimal `PayloadParser` implementation used to check protocol conformance."""

    parser_version = "v1"

    def parse(self, payload: bytes, context: ParseContext) -> Iterable[DataPoint]:
        return []


class FakeMapper:
    """Minimal `SignalMapper` implementation used to check protocol conformance."""

    mapping_version = "v1"

    def map(self, points: Sequence[DataPoint]) -> Iterable[SignalValue]:
        return []

    def preference(self, signal: str) -> tuple[str, ...]:
        return ()


class FakeProvider:
    """Minimal `Provider` implementation used to check protocol conformance."""

    id = "fake"
    brands = frozenset({"fake-brand"})
    capabilities = ProviderCapabilities(
        delivery=True,
        stream=False,
        historical_import=False,
        catalog_import=False,
        max_listed_files=30,
        retention_days=7,
        min_request_interval_s=1.0,
    )
    credential_fields: tuple[CredentialField, ...] = (
        CredentialField(name="password", label="Password", secret=True),
    )
    portal_home_url = "https://example.invalid/portal"

    async def open_delivery_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> DeliverySession:
        return FakeDeliverySession()

    async def open_stream_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> StreamSession:
        raise NotImplementedError("fake provider has no stream capability")

    def parser(self) -> PayloadParser:
        return FakeParser()

    def mapper(self) -> SignalMapper:
        return FakeMapper()


_fake_provider: Provider = FakeProvider()
_fake_delivery_session: DeliverySession = FakeDeliverySession()
_fake_stream_session: StreamSession = FakeStreamSession()
_fake_parser: PayloadParser = FakeParser()
_fake_mapper: SignalMapper = FakeMapper()


def test_needs_attention_error_can_be_raised_from_a_session() -> None:
    with pytest.raises(NeedsAttentionError):
        raise NeedsAttentionError("invalid identifier")


def test_registry_register_and_get() -> None:
    registry = ProviderRegistry()
    registry.register(_fake_provider)
    assert registry.get("fake") is _fake_provider


def test_registry_rejects_duplicate_id() -> None:
    registry = ProviderRegistry()
    registry.register(_fake_provider)
    with pytest.raises(ValueError, match="fake"):
        registry.register(_fake_provider)


def test_registry_get_unknown_id_raises_key_error() -> None:
    registry = ProviderRegistry()
    with pytest.raises(KeyError, match="unknown"):
        registry.get("unknown")


def test_registry_all() -> None:
    registry = ProviderRegistry()
    registry.register(_fake_provider)
    assert registry.all() == [_fake_provider]


def test_registry_for_brand_is_case_insensitive() -> None:
    registry = ProviderRegistry()
    registry.register(_fake_provider)
    assert registry.for_brand("FAKE-BRAND") == [_fake_provider]
    assert registry.for_brand("other-brand") == []
