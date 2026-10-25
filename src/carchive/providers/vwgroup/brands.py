"""Per-brand OIDC identifiers for the VW-group EU Data Act portal.

The client ids identify a public, pre-registered identity-service client (the same one the
portal's own web frontend uses), not a per-user secret; documented by several independent
reverse-engineering projects (e.g. ioBroker.vw-connect's euDataAct module) and confirmed by
`eu_data_act_sampler.py` against a real account.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BrandIdentity:
    """A brand's OIDC client id and the state-parameter suffix the portal expects for it."""

    client_id: str
    state_suffix: str


_BRANDS: dict[str, BrandIdentity] = {
    "volkswagen": BrandIdentity(
        "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com", "VOLKSWAGEN_PASSENGER_CARS"
    ),
    "audi": BrandIdentity("cc29b87a-5e9a-4362-aecf-5adea6b01bbb@apps_vw-dilab_com", "AUDI"),
    "skoda": BrandIdentity("3ea88bf9-1d4e-4a68-b3ad-4098c1f1d246@apps_vw-dilab_com", "SKODA"),
    "seat": BrandIdentity("f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com", "SEAT"),
    "cupra": BrandIdentity("f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com", "CUPRA"),
}


def brand_identity(brand: str) -> BrandIdentity:
    """Look up the OIDC identity for `brand`.

    Args:
        brand: the brand name, matched case-insensitively.

    Returns:
        The brand's `BrandIdentity`.

    Raises:
        ValueError: if `brand` is not one of the known VW-group brands.
    """
    try:
        return _BRANDS[brand.lower()]
    except KeyError:
        raise ValueError(
            f"unknown VW-group brand {brand!r}, expected one of {known_brands()}"
        ) from None


def known_brands() -> tuple[str, ...]:
    """Return the known brand names, in their canonical lowercase form."""
    return tuple(_BRANDS)
