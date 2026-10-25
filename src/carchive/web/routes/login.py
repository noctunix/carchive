"""`/login`, `/login/setup` and `/logout`: signing in, choosing the first password, signing out.

Without a password the login page offers to choose one; whoever submits the form first
becomes the operator. After signing in the user always lands on `/`; there is deliberately
no way to name a redirect target.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse, Response

from carchive.core.redact import redact
from carchive.services.app_services import AppServices
from carchive.services.operator_auth import (
    MIN_PASSWORD_LENGTH,
    PasswordAlreadySetError,
    PasswordPolicyError,
)
from carchive.web.auth import (
    AUTH_ERRORS,
    LOGIN_PATH,
    SESSION_COOKIE_NAME,
    attempt_password,
    clear_session_cookie,
    client_key,
    is_secure_request,
    request_state,
    set_session_cookie,
    unavailable_response,
)

router = APIRouter()
logger = structlog.get_logger(__name__)

_MAX_FORM_VALUE_LENGTH = 1024


def _field(form: Any, name: str) -> str:
    value = form.get(name, "")
    return value[:_MAX_FORM_VALUE_LENGTH] if isinstance(value, str) else ""


def _login_page(
    request: Request,
    *,
    password_set: bool,
    status_code: int = 200,
    error: str | None = None,
    detail: str | None = None,
    notice: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    templates: Jinja2Templates = request.app.state.templates
    context = {
        "mode": "login" if password_set else "setup",
        "min_length": MIN_PASSWORD_LENGTH,
        "error": error,
        "detail": detail,
        "notice": notice,
        "vehicle_count": 0,
    }
    return templates.TemplateResponse(
        request, "login.html", context, status_code=status_code, headers=headers
    )


def _start_session_response(request: Request, token: str, expires_at: datetime) -> Response:
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(
        response, token, expires_at=expires_at, secure=is_secure_request(request.scope)
    )
    return response


@router.get("/login")
async def login_form(request: Request) -> Response:
    """Show the sign-in form, or the choose-a-password form while no password is set.

    Returns:
        A redirect to `/` if a valid session exists, else the form.
    """
    state = request_state(request.scope)
    if state["authenticated"]:
        return RedirectResponse("/", status_code=303)
    return _login_page(request, password_set=state["password_set"])


@router.post("/login")
async def login(request: Request) -> Response:
    """Check the password and start a session.

    A locked client (or a globally locked login) gets 429 with `Retry-After`; a wrong
    password always gets the same 401 message.

    Returns:
        A redirect to `/` with the session cookie on success, else the form again.
    """
    services: AppServices = request.app.state.services
    state = request_state(request.scope)
    if not state["password_set"]:
        return RedirectResponse(LOGIN_PATH, status_code=303)
    form = await request.form()
    try:
        attempt = await attempt_password(
            services.operator_auth,
            services.login_throttle,
            request.app.state.login_lock,
            request.scope,
            _field(form, "password"),
            request.app.state.settings.trusted_proxies,
        )
        if attempt.outcome == "ok":
            session = await services.operator_auth.create_session()
    except AUTH_ERRORS as exc:
        logger.error("operator.auth_unavailable", error=redact(str(exc)))
        return unavailable_response(request)

    if attempt.outcome == "locked":
        return _login_page(
            request,
            password_set=True,
            status_code=429,
            error="locked",
            headers={"Retry-After": str(attempt.retry_after)},
        )
    if attempt.outcome == "wrong":
        return _login_page(request, password_set=True, status_code=401, error="invalid_password")
    return _start_session_response(request, session.token, session.expires_at)


@router.get("/login/setup")
async def setup_form() -> Response:
    """Send a stray `GET` to the login page, which shows the right form."""
    return RedirectResponse(LOGIN_PATH, status_code=303)


@router.post("/login/setup")
async def setup_password(request: Request) -> Response:
    """Choose the first password and sign in.

    Of two simultaneous attempts exactly one succeeds; the other is told that a password
    exists.

    Returns:
        A redirect to `/` with the session cookie on success, else the form with the reason.
    """
    services: AppServices = request.app.state.services
    form = await request.form()
    new_password = _field(form, "new_password")
    repeat = _field(form, "new_password_repeat")
    try:
        if await asyncio.to_thread(services.operator_auth.password_is_set):
            return _login_page(request, password_set=True, status_code=409, notice="already_set")
        if new_password != repeat:
            return _login_page(request, password_set=False, status_code=400, error="mismatch")
        try:
            await services.operator_auth.set_password(new_password, only_if_unset=True)
        except PasswordPolicyError as exc:
            return _login_page(
                request, password_set=False, status_code=400, error="policy", detail=str(exc)
            )
        except PasswordAlreadySetError:
            return _login_page(request, password_set=True, status_code=409, notice="already_set")
        session = await services.operator_auth.create_session()
    except AUTH_ERRORS as exc:
        logger.error("operator.auth_unavailable", error=redact(str(exc)))
        return unavailable_response(request)
    logger.info(
        "operator.password_set",
        client=client_key(request.scope, request.app.state.settings.trusted_proxies),
    )
    return _start_session_response(request, session.token, session.expires_at)


@router.post("/logout")
async def logout(request: Request) -> Response:
    """End the current session and clear its cookie.

    Returns:
        A redirect to `/login`.
    """
    services: AppServices = request.app.state.services
    token = request.cookies.get(SESSION_COOKIE_NAME)
    try:
        if token:
            await services.operator_auth.revoke_session(token)
    except AUTH_ERRORS as exc:
        logger.error("operator.logout_failed", error=redact(str(exc)))
        return unavailable_response(request)
    response = RedirectResponse(LOGIN_PATH, status_code=303)
    clear_session_cookie(response, secure=is_secure_request(request.scope))
    return response
