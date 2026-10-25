"""`/settings`: the dictionary catalog and the operator (web login) password.

Account and vehicle management live under `/accounts` and `/vehicles`; this page is only
the cross-cutting configuration that doesn't belong to one specific account or vehicle.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.config import Settings
from carchive.core.redact import redact
from carchive.services.app_services import AppServices
from carchive.services.catalog import CatalogError, default_catalog_version
from carchive.services.operator_auth import MIN_PASSWORD_LENGTH, PasswordPolicyError
from carchive.web.auth import (
    AUTH_ERRORS,
    attempt_password,
    is_secure_request,
    set_session_cookie,
    unavailable_response,
)
from carchive.web.uploads import UploadError, UploadTooLargeError, read_multipart_upload

router = APIRouter()
logger = structlog.get_logger(__name__)

CATALOG_IMPORT_PATH = "/settings/catalog/import"
_MAX_CATALOG_UPLOAD_BYTES = 50 * 1024 * 1024


async def _settings_page(
    request: Request,
    *,
    status_code: int = 200,
    password_message: str | None = None,
    password_detail: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    context = {
        "catalog_providers": _catalog_providers(services),
        "catalog_versions": await services.catalog.list_versions(),
        "vehicle_count": await services.vehicle_count(),
        "min_password_length": MIN_PASSWORD_LENGTH,
        "password_message": password_message,
        "password_detail": password_detail,
    }
    return templates.TemplateResponse(
        request, "settings.html", context, status_code=status_code, headers=headers
    )


@router.get("/settings")
async def settings_overview(request: Request) -> Response:
    """Show the dictionary catalog and the operator password form."""
    return await _settings_page(request)


@router.post("/settings/password")
async def change_password(request: Request) -> Response:
    """Change the operator password, end all other sessions and keep this one signed in.

    The current password is checked through the login throttle. Messages are shown as
    stable keys (`password_message`); only a password policy violation carries free text
    (`password_detail`).

    Returns:
        The settings page with the outcome. On success it also carries a fresh session
        cookie, since changing the password ended every existing session.
    """
    services: AppServices = request.app.state.services
    form = await request.form()

    def field(name: str) -> str:
        value = form.get(name, "")
        return value[:1024] if isinstance(value, str) else ""

    current, new, repeat = field("current_password"), field("new_password"), field("repeat")
    if new != repeat:
        return await _settings_page(request, status_code=400, password_message="mismatch")
    try:
        settings: Settings = request.app.state.settings
        attempt = await attempt_password(
            services.operator_auth,
            services.login_throttle,
            request.app.state.login_lock,
            request.scope,
            current,
            settings.trusted_proxies,
        )
        if attempt.outcome == "locked":
            return await _settings_page(
                request,
                status_code=429,
                password_message="locked",
                headers={"Retry-After": str(attempt.retry_after)},
            )
        if attempt.outcome == "wrong":
            return await _settings_page(request, status_code=403, password_message="wrong_current")
        try:
            await services.operator_auth.set_password(new)
        except PasswordPolicyError as exc:
            return await _settings_page(
                request, status_code=400, password_message="policy", password_detail=str(exc)
            )
        session = await services.operator_auth.create_session()
    except AUTH_ERRORS as exc:
        logger.error("operator.auth_unavailable", error=redact(str(exc)))
        return unavailable_response(request)
    logger.info("operator.password_changed")
    response = await _settings_page(request, password_message="changed")
    set_session_cookie(
        response,
        session.token,
        expires_at=session.expires_at,
        secure=is_secure_request(request.scope),
    )
    return response


def _catalog_providers(services: AppServices) -> list[str]:
    """Return every registered provider id that supports a dictionary catalog import."""
    return sorted(
        provider.id
        for provider in services.accounts.registry.all()
        if provider.capabilities.catalog_import
    )


@router.post(CATALOG_IMPORT_PATH)
async def import_catalog(request: Request) -> Response:
    """Stream an uploaded Data Dictionary PDF to disk and import it into `catalog_entries`.

    The uploaded file is always removed again once import either succeeds or fails: it is
    a one-off source for the catalog entries it describes, not something Carchive keeps
    (the dictionary is the manufacturer's document).
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    settings: Settings = request.app.state.settings
    context: dict[str, object] = {"vehicle_count": await services.vehicle_count()}

    try:
        upload = await read_multipart_upload(
            request,
            file_field="file",
            max_body_bytes=_MAX_CATALOG_UPLOAD_BYTES,
            dest_dir=settings.data_dir,
        )
    except UploadTooLargeError:
        return templates.TemplateResponse(
            request, "catalog_imported.html", {**context, "error": "too_large"}, status_code=413
        )
    except UploadError:
        return templates.TemplateResponse(
            request,
            "catalog_imported.html",
            {**context, "error": "invalid_upload"},
            status_code=400,
        )

    try:
        provider_id = upload.fields.get("provider_id", "").strip()
        catalog_version = upload.fields.get("catalog_version", "").strip()
        if not provider_id:
            raise CatalogError("no provider selected")
        if not catalog_version:
            catalog_version = default_catalog_version(upload.original_filename)
        result = await services.catalog.import_pdf(upload.path, provider_id, catalog_version)
    except CatalogError as exc:
        return templates.TemplateResponse(
            request,
            "catalog_imported.html",
            {**context, "error": "catalog_error", "message": str(exc)},
            status_code=400,
        )
    finally:
        upload.path.unlink(missing_ok=True)

    context = {**context, "result": result, "catalog_version": catalog_version}
    return templates.TemplateResponse(request, "catalog_imported.html", context)
