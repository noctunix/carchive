"""Tests for `carchive.web.auth.client_key`."""

from __future__ import annotations

from carchive.web.auth import client_key

PEER = "203.0.113.9"


def _scope(peer: str = PEER, forwarded_for: str | None = None) -> dict[str, object]:
    headers: list[tuple[bytes, bytes]] = []
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode("latin-1")))
    return {"client": (peer, 12345), "headers": headers}


def test_default_trusted_proxies_ignores_forwarded_header() -> None:
    scope = _scope(forwarded_for="10.9.9.9")

    assert client_key(scope) == PEER


def test_trusted_peer_uses_leftmost_forwarded_address() -> None:
    scope = _scope(forwarded_for="10.0.0.5, 10.0.0.1")

    assert client_key(scope, trusted_proxies=(PEER,)) == "10.0.0.5"


def test_trusted_peer_without_header_falls_back_to_peer() -> None:
    scope = _scope(forwarded_for=None)

    assert client_key(scope, trusted_proxies=(PEER,)) == PEER


def test_trusted_peer_with_empty_header_falls_back_to_peer() -> None:
    scope = _scope(forwarded_for="")

    assert client_key(scope, trusted_proxies=(PEER,)) == PEER


def test_trusted_peer_with_invalid_header_falls_back_to_peer() -> None:
    scope = _scope(forwarded_for="not-an-ip")

    assert client_key(scope, trusted_proxies=(PEER,)) == PEER


def test_untrusted_peer_ignores_forwarded_header_even_with_other_trusted_proxies() -> None:
    scope = _scope(forwarded_for="10.0.0.5")

    assert client_key(scope, trusted_proxies=("127.0.0.1",)) == PEER


def test_trusted_network_covers_a_peer_inside_it() -> None:
    scope = _scope(peer="10.0.0.42", forwarded_for="198.51.100.1")

    assert client_key(scope, trusted_proxies=("10.0.0.0/24",)) == "198.51.100.1"


def test_no_client_in_scope_returns_placeholder() -> None:
    scope: dict[str, object] = {"headers": []}

    assert client_key(scope, trusted_proxies=(PEER,)) == "unknown"
