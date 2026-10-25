"""The VW-group EU Data Act portal, exposed through `core.provider.Provider`."""

from __future__ import annotations

from collections.abc import Mapping

import httpx

from carchive.core.provider import (
    CredentialField,
    PayloadParser,
    ProviderCapabilities,
    SignalMapper,
    StreamSession,
)
from carchive.providers.vwgroup import login
from carchive.providers.vwgroup.brands import known_brands
from carchive.providers.vwgroup.mapping import VwGroupMapper
from carchive.providers.vwgroup.parser import VwGroupParser
from carchive.providers.vwgroup.session import VwGroupDeliverySession

_REQUEST_TIMEOUT = httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)


class VwGroupProvider:
    """The VW-group EU Data Act portal; satisfies `core.provider.Provider`.

    Args:
        user_agent: sent as the `User-Agent` header on every request, so the portal can
            tell Carchive's traffic apart from a browser.
    """

    id = "vwgroup-euda"
    brands = frozenset(known_brands())
    capabilities = ProviderCapabilities(
        delivery=True,
        stream=False,
        historical_import=True,
        catalog_import=True,
        max_listed_files=30,
        retention_days=7,
        min_request_interval_s=1.0,
    )
    credential_fields: tuple[CredentialField, ...] = (
        CredentialField(name="user", label="Portal login (e-mail)", secret=False),
        CredentialField(name="password", label="Portal password", secret=True),
    )
    portal_home_url = login.PORTAL_BASE_URL

    def __init__(self, user_agent: str = "carchive") -> None:
        self._user_agent = user_agent
        self._parser = VwGroupParser()
        self._mapper = VwGroupMapper()

    async def open_delivery_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> VwGroupDeliverySession:
        """Log in to the portal as `brand` and return a ready-to-use delivery session.

        Args:
            brand: the VW-group brand to log in as, matched case-insensitively.
            credentials: must hold `"user"` and `"password"`, matching `credential_fields`.

        Returns:
            A `VwGroupDeliverySession` with a logged-in client.

        Raises:
            ValueError: if `brand` is not one of `brands`.
            AuthenticationError: if the portal rejects the credentials.
            NeedsAttentionError: if the login flow lands somewhere unexpected.
            TransientError: on a timeout, connection failure or 5xx response during login.
        """
        client = httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT,
            follow_redirects=False,
            headers={"User-Agent": self._user_agent},
        )
        user = credentials["user"]
        password = credentials["password"]

        async def relogin() -> None:
            await login.perform_login(client, brand, user, password)

        try:
            await relogin()
        except Exception:
            await client.aclose()
            raise

        return VwGroupDeliverySession(
            client, relogin, min_interval_s=self.capabilities.min_request_interval_s
        )

    async def open_stream_session(
        self, brand: str, credentials: Mapping[str, str]
    ) -> StreamSession:
        """Not implemented: the VW-group portal only delivers discrete files.

        Raises:
            NotImplementedError: always.
        """
        raise NotImplementedError("vwgroup-euda has no streaming capability")

    def parser(self) -> PayloadParser:
        """Return this provider's payload parser."""
        return self._parser

    def mapper(self) -> SignalMapper:
        """Return this provider's signal mapper."""
        return self._mapper
