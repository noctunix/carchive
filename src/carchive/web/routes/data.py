"""`/data`: the data explorer, listing every key a vehicle has reported."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from carchive.services.app_services import AppServices

router = APIRouter()

_PAGE_SIZE = 50


@router.get("/data")
async def data_explorer(
    request: Request,
    vehicle_id: UUID | None = None,
    q: str = "",
    cluster: str = "",
    page: int = 1,
) -> Response:
    """List every field one vehicle has reported, filtered and paginated by GET parameters.

    Args:
        request: the incoming request.
        vehicle_id: the vehicle to show; defaults to the first vehicle if omitted.
        q: a substring filter over the field name and catalog name/description.
        cluster: an exact (case-insensitive) catalog cluster filter.
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
        "query": q,
        "cluster": cluster,
        "page": page,
        "result": None,
        "vehicle_count": await services.vehicle_count(),
    }
    if not vehicles:
        return templates.TemplateResponse(request, "data.html", context)

    selected_id = vehicle_id if vehicle_id is not None else vehicles[0].id
    context["selected_vehicle_id"] = selected_id
    page = max(page, 1)
    offset = (page - 1) * _PAGE_SIZE
    result = await services.explorer.fields(
        selected_id, query=q or None, cluster=cluster or None, limit=_PAGE_SIZE, offset=offset
    )
    if result is None:
        raise HTTPException(status_code=404)

    context["result"] = result
    context["page"] = page
    context["total_pages"] = max(1, (result.total + _PAGE_SIZE - 1) // _PAGE_SIZE)
    return templates.TemplateResponse(request, "data.html", context)


@router.get("/data/{vehicle_id}/field")
async def field_history(request: Request, vehicle_id: UUID, name: str) -> Response:
    """Show one generalized field's value history as a plain table.

    Args:
        request: the incoming request.
        vehicle_id: the vehicle the field belongs to.
        name: the generalized field name (array indices collapsed to `[*]`) to show.

    Raises:
        HTTPException: 404 if `vehicle_id` does not exist.
    """
    services: AppServices = request.app.state.services
    templates: Jinja2Templates = request.app.state.templates
    values = await services.explorer.field_values(vehicle_id, name)
    if values is None:
        raise HTTPException(status_code=404)

    context = {
        "vehicle_id": vehicle_id,
        "field_generic": name,
        "values": values,
        "vehicle_count": await services.vehicle_count(),
    }
    return templates.TemplateResponse(request, "data_field.html", context)
