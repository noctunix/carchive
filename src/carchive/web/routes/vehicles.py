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

router = APIRouter()


@router.get("/vehicles/{vehicle_id}")
async def vehicle_detail(request: Request, vehicle_id: UUID, signals_q: str = "") -> Response:
    """Show one vehicle's signals, data requests, collector history and monitoring notices.

    Args:
        request: the incoming request.
        vehicle_id: the vehicle to show.
        signals_q: a substring filter over the signals section, matched against a
            signal's raw name or a source field's name.

    Raises:
        HTTPException: 404 if no vehicle with `vehicle_id` exists.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    detail = await services.dashboard.vehicle_detail(vehicle_id, signals_q=signals_q)
    if detail is None:
        raise HTTPException(status_code=404)
    context = {
        "detail": detail,
        "signals_query": signals_q,
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
