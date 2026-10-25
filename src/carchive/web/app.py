"""The FastAPI application factory.

No module-level app: every call to `create_app` builds an independent instance from the
`AppServices` and `Settings` passed in, so a resource (database, scheduler) is never
reachable through an import-time singleton that tests would otherwise share by accident.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import Response

from carchive.config import Settings
from carchive.core.redact import redact
from carchive.services.app_services import AppServices
from carchive.web.auth import AuthMiddleware
from carchive.web.i18n import LanguageMiddleware, load_translations
from carchive.web.routes import (
    accounts,
    backups,
    dashboard,
    data,
    deliveries,
    health,
    lang,
    login,
    setup,
    vehicles,
)
from carchive.web.routes import settings as settings_routes
from carchive.web.routes.settings import CATALOG_IMPORT_PATH
from carchive.web.security import SecurityMiddleware
from carchive.web.setup_state import SetupTokenStore
from carchive.web.templating import build_templates

logger = structlog.get_logger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"


async def _safe_vehicle_count(services: AppServices) -> int:
    """Return `services.vehicle_count()`, or 0 if the database itself is the problem.

    An error page must render even when the failure that triggered it is the database
    being unreachable; the navigation then just defaults to showing "Set up".
    """
    try:
        return await services.vehicle_count()
    except Exception as exc:  # the error page itself must never fail because of this
        logger.warning("web.vehicle_count_unavailable", error=redact(str(exc)))
        return 0


def create_app(services: AppServices, settings: Settings, *, version: str = "dev") -> FastAPI:
    """Build the Carchive FastAPI application.

    Args:
        services: the slice of the running application the web layer may use; its
            `scheduler` is started and stopped by this app's lifespan.
        settings: the application's runtime configuration (host allowlist, among others).
        version: shown in the topbar; the `web` layer may not import `carchive.__version__`
            itself (see `tests/test_layering.py`), so the caller passes it in.

    Returns:
        A ready-to-serve FastAPI app.
    """
    translations = load_translations()
    templates = build_templates(translations)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stop = asyncio.Event()
        task = asyncio.create_task(services.scheduler.run(stop))
        services.mark_scheduler_running(True)
        try:
            yield
        finally:
            stop.set()
            services.mark_scheduler_running(False)
            await task

    app = FastAPI(
        lifespan=lifespan,
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts)),
            Middleware(
                SecurityMiddleware,
                allowed_hosts=settings.allowed_hosts,
                streaming_paths=frozenset({CATALOG_IMPORT_PATH}),
                # Browsers offer no click-through for an untrusted certificate once HSTS is
                # cached, so the self-signed certificate must never come with HSTS.
                hsts=settings.tls_certfile is not None,
            ),
            Middleware(LanguageMiddleware),
            Middleware(AuthMiddleware, operator_auth=services.operator_auth),
        ],
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.services = services
    app.state.templates = templates
    app.state.settings = settings
    app.state.app_version = version
    app.state.setup_tokens = SetupTokenStore()
    app.state.login_lock = asyncio.Lock()
    app.state.backup_lock = asyncio.Lock()

    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
    app.include_router(accounts.router)
    app.include_router(health.router)
    app.include_router(backups.router)
    app.include_router(dashboard.router)
    app.include_router(data.router)
    app.include_router(deliveries.router)
    app.include_router(lang.router)
    app.include_router(login.router)
    app.include_router(setup.router)
    app.include_router(settings_routes.router)
    app.include_router(vehicles.router)

    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(Exception, _handle_unexpected_exception)

    return app


async def _handle_http_exception(request: Request, exc: Exception) -> Response:
    """Render a plain error page for a routed HTTP error (404, 403, …).

    Never includes the exception's own detail text, the request path or a stacktrace;
    `error.html` maps the status code to a fixed, translated message.
    """
    status_code = exc.status_code if isinstance(exc, StarletteHTTPException) else 500
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    context = {"status_code": status_code, "vehicle_count": await _safe_vehicle_count(services)}
    return templates.TemplateResponse(request, "error.html", context, status_code=status_code)


async def _handle_unexpected_exception(request: Request, exc: Exception) -> Response:
    """Log an unhandled exception (redacted) and render a plain 500 page."""
    logger.error("web.unhandled_exception", error=redact(str(exc)))
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    context = {"status_code": 500, "vehicle_count": await _safe_vehicle_count(services)}
    return templates.TemplateResponse(request, "error.html", context, status_code=500)
