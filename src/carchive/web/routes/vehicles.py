"""`/vehicles/{id}`: the vehicle detail and deletion pages.

Vehicles are listed grouped by account on `/accounts`, not on a page of their own.
Deletion goes through a confirmation page first (`GET .../delete`) that states exactly
what will be removed, before the `POST` that actually removes it; backups are never
touched by either page, which the confirmation and the result page both say.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.services.accounts import DeletionResult, VehicleNotFoundError
from carchive.services.app_services import AppServices
from carchive.services.dashboard import SIGNAL_PAGE_SIZES

router = APIRouter()


@router.get("/vehicles/{vehicle_id}")
async def vehicle_detail(
    request: Request, vehicle_id: UUID, signals_page: int = 1, signals_page_size: int = 0
) -> Response:
    """Show one vehicle's signals, data requests, collector history and monitoring notices.

    Args:
        request: the incoming request.
        vehicle_id: the vehicle to show.
        signals_page: the 1-based page of signal values to show.
        signals_page_size: how many signal values a page holds; any value not in
            `SIGNAL_PAGE_SIZES` falls back to the default.

    Raises:
        HTTPException: 404 if no vehicle with `vehicle_id` exists.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    detail = await services.dashboard.vehicle_detail(
        vehicle_id, signals_page=max(signals_page, 1), signals_page_size=signals_page_size
    )
    if detail is None:
        raise HTTPException(status_code=404)
    context = {
        "detail": detail,
        "signal_page_sizes": SIGNAL_PAGE_SIZES,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "vehicle_detail.html", context)


@router.get("/vehicles/{vehicle_id}/delete")
async def confirm_delete_vehicle(request: Request, vehicle_id: UUID) -> Response:
    """Show what deleting `vehicle_id` would remove."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    vehicle = await services.accounts.get_vehicle(vehicle_id)
    if vehicle is None:
        raise HTTPException(status_code=404)
    context = {"vehicle": vehicle, "vehicle_count": await services.vehicle_count()}
    return templates.TemplateResponse(request, "settings_delete_vehicle.html", context)


def _deletion_result_context(result: DeletionResult) -> dict[str, object]:
    return {
        "oldest_backup_age_days": (
            result.oldest_backup_age.days if result.oldest_backup_age is not None else None
        ),
        "has_backups": result.oldest_backup_age is not None,
    }


@router.post("/vehicles/{vehicle_id}/delete")
async def delete_vehicle(request: Request, vehicle_id: UUID) -> Response:
    """Delete `vehicle_id` and all its data."""
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    try:
        result = await services.accounts.delete_vehicle(vehicle_id)
    except VehicleNotFoundError:
        raise HTTPException(status_code=404) from None
    context = {**_deletion_result_context(result), "vehicle_count": await services.vehicle_count()}
    return templates.TemplateResponse(request, "settings_deleted.html", context)
