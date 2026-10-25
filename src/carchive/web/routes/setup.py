"""`/setup`: the wizard that walks a new user through adding a portal account and its vehicles.

Three steps on two pages: step 1 (tutorial) and step 2 (the account form) share `GET
/setup`; a successful `POST /setup` tests the login, creates the account only once that
test passes, and renders step 3 (vehicle selection) with a short-lived token
(`web.setup_state.SetupTokenStore`) standing in for the account between requests. The
account's password is read once from the submitted form and never rendered back, logged,
or carried in that token.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.core.errors import ProviderError
from carchive.core.redact import mask_vin
from carchive.services.accounts import AccountServiceError, UnknownProviderError
from carchive.services.app_services import AppServices
from carchive.web.setup_state import SetupTokenStore

router = APIRouter()


async def _setup_form_context(
    services: AppServices,
    *,
    error: str | None = None,
    provider_id: str = "",
    brand: str = "",
    label: str = "",
) -> dict[str, Any]:
    brands = services.accounts.available_brands()
    if not provider_id and brands:
        provider_id, brand = brands[0]
    return {
        "brands": brands,
        "selected_provider_id": provider_id,
        "selected_brand": brand,
        "credential_fields": services.accounts.credential_fields(provider_id)
        if provider_id
        else (),
        "portal_home_url": services.accounts.portal_home_url(provider_id) if provider_id else "",
        "label": label,
        "error": error,
        "vehicle_count": await services.vehicle_count(),
    }


@router.get("/setup")
async def setup_start(request: Request) -> Response:
    """Render the tutorial and the account form (wizard steps 1 and 2)."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    context = await _setup_form_context(services)
    return templates.TemplateResponse(request, "setup.html", context)


def _split_provider_choice(raw: str) -> tuple[str, str]:
    """Split the form's `provider_choice` field (`"<provider_id>|<brand>"`) in two."""
    provider_id, _, brand = raw.partition("|")
    return provider_id, brand


@router.post("/setup")
async def setup_account(request: Request) -> Response:
    """Test the submitted login and, only if it succeeds, create the account.

    Renders the form again with a redacted error and the password field cleared if the
    brand is unknown, the label is invalid/taken, or the login test fails; nothing is
    written in any of those cases.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    form = await request.form()
    provider_id, brand = _split_provider_choice(str(form.get("provider_choice", "")))
    label = str(form.get("label", "")).strip()

    try:
        fields = services.accounts.credential_fields(provider_id)
    except UnknownProviderError:
        context = await _setup_form_context(services, error="unknown_brand", label=label)
        return templates.TemplateResponse(request, "setup.html", context, status_code=400)

    credentials = {field.name: str(form.get(field.name, "")) for field in fields}

    check = await services.accounts.check_login(provider_id, brand, credentials)
    if not check.ok:
        context = await _setup_form_context(
            services, error=check.reason, provider_id=provider_id, brand=brand, label=label
        )
        return templates.TemplateResponse(request, "setup.html", context, status_code=400)

    try:
        account_id = await services.accounts.add_account(provider_id, brand, label, credentials)
    except AccountServiceError as exc:
        context = await _setup_form_context(
            services, error=str(exc), provider_id=provider_id, brand=brand, label=label
        )
        return templates.TemplateResponse(request, "setup.html", context, status_code=400)

    try:
        remote = await services.accounts.remote_vehicles(account_id)
    except ProviderError:
        remote = []

    token_store: SetupTokenStore = request.app.state.setup_tokens
    token = token_store.create(account_id)
    context = {
        "token": token,
        "vehicles": [(v.vin, mask_vin(v.vin), v.name) for v in remote],
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "setup_vehicles.html", context)


@router.post("/setup/vehicles")
async def setup_vehicles(request: Request) -> Response:
    """Add the selected vehicles to the account step 2 created, then show a confirmation.

    An unknown, already-used or expired token renders a dedicated error page pointing
    back to `/setup`, rather than failing the request outright: the account itself was
    already created successfully, only the vehicle step needs a fresh attempt.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    form = await request.form()
    token = str(form.get("token", ""))
    vins = [str(value) for value in form.getlist("vin")]

    token_store: SetupTokenStore = request.app.state.setup_tokens
    account_id = token_store.consume(token)
    if account_id is None:
        context = {"vehicle_count": await services.vehicle_count()}
        return templates.TemplateResponse(
            request, "setup_token_invalid.html", context, status_code=400
        )

    added = await services.accounts.add_vehicles(account_id, vins)
    context = {"added": len(added), "vehicle_count": await services.vehicle_count()}
    return templates.TemplateResponse(request, "setup_done.html", context)
