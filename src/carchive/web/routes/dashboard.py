"""`/`: the dashboard, and `/partials/dashboard`, its htmx auto-refresh fragment."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.services.app_services import AppServices

router = APIRouter()


@router.get("/")
async def dashboard(request: Request) -> Response:
    """Render the dashboard: one card per vehicle, monitoring notices and the status strip."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    view = await services.dashboard.overview()
    context = {"view": view, "vehicle_count": len(view.cards)}
    return templates.TemplateResponse(request, "dashboard.html", context)


@router.get("/partials/dashboard")
async def dashboard_cards(request: Request) -> Response:
    """Render only the card area, for htmx's 60-second auto-refresh."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    view = await services.dashboard.overview()
    context = {"view": view, "vehicle_count": len(view.cards)}
    return templates.TemplateResponse(request, "_dashboard_cards.html", context)
