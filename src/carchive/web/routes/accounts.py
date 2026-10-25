"""`/accounts`: portal accounts overview, password replacement and deletion.

Every deletion goes through a confirmation page first (`GET .../delete`) that states
exactly what will be removed, before the `POST` that actually removes it; backups are
never touched by either page, which the confirmation and the result page both say.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.config import ConfigError, InsecureSecretsError
from carchive.core.redact import redact
from carchive.services.accounts import (
    MAX_PASSWORD_LENGTH,
    AccountNotFoundError,
    DeletionResult,
    InvalidPasswordError,
    LoginRejectedError,
    NoStoredCredentialsError,
    VehicleInfo,
)
from carchive.services.app_services import AppServices

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.get("/accounts")
async def accounts_overview(request: Request) -> Response:
    """List every account with its current state, last collector run and its vehicles."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    accounts = await services.accounts.list_accounts()
    vehicles = await services.accounts.list_vehicles()
    vehicles_by_account: dict[str, list[VehicleInfo]] = {account.label: [] for account in accounts}
    for vehicle in vehicles:
        vehicles_by_account.setdefault(vehicle.account_label, []).append(vehicle)
    context = {
        "accounts": accounts,
        "vehicles_by_account": vehicles_by_account,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "accounts.html", context)


async def _password_page(
    request: Request,
    label: str,
    *,
    status_code: int = 200,
    message: str | None = None,
    detail: str | None = None,
) -> Response:
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    account = await services.accounts.get_account_by_label(label)
    if account is None:
        raise HTTPException(status_code=404)
    context = {
        "account": account,
        "max_portal_password_length": MAX_PASSWORD_LENGTH,
        "message": message,
        "detail": detail,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(
        request, "account_password.html", context, status_code=status_code
    )


@router.get("/accounts/{label}/password")
async def account_password_form(request: Request, label: str) -> Response:
    """Show the form to replace `label`'s stored portal password.

    Raises:
        HTTPException: 404 if no account is labelled `label`.
    """
    return await _password_page(request, label)


@router.post("/accounts/{label}/password")
async def set_account_password(request: Request, label: str) -> Response:
    """Replace the stored portal password of `label`; the account and its data stay.

    The new password is tried against the portal first. The outcome is shown as a stable
    key (`message`); only a rejected login and an unusable secrets store carry free text
    (`detail`). The password itself is never rendered or logged.

    Raises:
        HTTPException: 404 if no account is labelled `label`.
    """
    services: AppServices = request.app.state.services
    form = await request.form()

    def field(name: str) -> str:
        value = form.get(name, "")
        return value[: MAX_PASSWORD_LENGTH + 1] if isinstance(value, str) else ""

    password, repeat = field("password"), field("repeat")

    if password != repeat:
        return await _password_page(request, label, status_code=400, message="mismatch")
    try:
        await services.accounts.set_password(label, password)
    except AccountNotFoundError:
        raise HTTPException(status_code=404) from None
    except InvalidPasswordError:
        return await _password_page(request, label, status_code=400, message="invalid")
    except NoStoredCredentialsError:
        return await _password_page(request, label, status_code=409, message="no_credentials")
    except LoginRejectedError as exc:
        return await _password_page(
            request, label, status_code=400, message="login_rejected", detail=exc.reason
        )
    except (ConfigError, InsecureSecretsError) as exc:
        logger.error("account.password_not_stored", account=label, error=redact(str(exc)))
        return await _password_page(
            request, label, status_code=500, message="storage_error", detail=redact(str(exc))
        )
    logger.info("account.password_replaced", account=label)
    return await _password_page(request, label, message="saved")


@router.get("/accounts/{label}/delete")
async def confirm_delete_account(request: Request, label: str) -> Response:
    """Show what deleting `label` and its vehicles would remove."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    account = await services.accounts.get_account_by_label(label)
    if account is None:
        raise HTTPException(status_code=404)
    vehicles = [v for v in await services.accounts.list_vehicles() if v.account_label == label]
    context = {
        "label": label,
        "vehicles": vehicles,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "settings_delete_account.html", context)


def _deletion_result_context(result: DeletionResult) -> dict[str, object]:
    return {
        "oldest_backup_age_days": (
            result.oldest_backup_age.days if result.oldest_backup_age is not None else None
        ),
        "has_backups": result.oldest_backup_age is not None,
    }


@router.post("/accounts/{label}/delete")
async def delete_account(request: Request, label: str) -> Response:
    """Delete `label`, its vehicles and all their data, and its stored credentials."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    try:
        result = await services.accounts.delete_account(label)
    except AccountNotFoundError:
        raise HTTPException(status_code=404) from None
    context = {**_deletion_result_context(result), "vehicle_count": await services.vehicle_count()}
    return templates.TemplateResponse(request, "settings_deleted.html", context)
