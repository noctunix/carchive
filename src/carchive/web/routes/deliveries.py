"""`/deliveries`: what arrived for a vehicle, and whether it carried new values."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.services.app_services import AppServices

router = APIRouter()


@router.get("/deliveries")
async def deliveries_list(
    request: Request, vehicle_id: UUID | None = None, page: int = 1
) -> Response:
    """List one vehicle's deliveries, newest-delivered first.

    Args:
        request: the incoming request.
        vehicle_id: the vehicle to show; defaults to the first vehicle if omitted.
        page: the 1-based page of results to show.

    Raises:
        HTTPException: 404 if `vehicle_id` is given but does not exist.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    vehicles = await services.accounts.list_vehicles()

    context: dict[str, object] = {
        "vehicles": vehicles,
        "selected_vehicle_id": vehicle_id,
        "page": max(page, 1),
        "result": None,
        "vehicle_count": await services.vehicle_count(),
    }
    if not vehicles:
        return templates.TemplateResponse(request, "deliveries.html", context)

    selected_id = vehicle_id if vehicle_id is not None else vehicles[0].id
    context["selected_vehicle_id"] = selected_id
    result = await services.deliveries.list(selected_id, page=max(page, 1))
    if result is None:
        raise HTTPException(status_code=404)

    context["result"] = result
    context["page"] = result.page
    return templates.TemplateResponse(request, "deliveries.html", context)


@router.get("/deliveries/{delivery_id}")
async def delivery_detail(
    request: Request,
    delivery_id: UUID,
    only_new: bool = False,
    q: str = "",
    page: int = 1,
) -> Response:
    """Show one delivery's values, classified as new or already known.

    Args:
        request: the incoming request.
        delivery_id: the delivery to show.
        only_new: if `True`, show only values this delivery was the first to report.
        q: a substring filter over the field name.
        page: the 1-based page of values to show.

    Raises:
        HTTPException: 404 if `delivery_id` does not exist.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    detail = await services.deliveries.detail(
        delivery_id, only_new=only_new, query=q, page=max(page, 1)
    )
    if detail is None:
        raise HTTPException(status_code=404)

    context = {
        "detail": detail,
        "only_new": only_new,
        "query": q,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "delivery_detail.html", context)
