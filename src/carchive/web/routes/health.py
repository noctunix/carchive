"""`/healthz`: a plain JSON status check for container/systemd health probes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from carchive.services.app_services import AppServices

router = APIRouter()


@router.get("/healthz")
async def healthz(request: Request) -> JSONResponse:
    """Report database connectivity and whether the scheduler task is alive.

    Returns:
        `{"status": "ok"|"error", "db": "ok"|"error", "scheduler": "running"|"stopped"}`,
        HTTP 200 if both checks pass, else 503.
    """
    services: AppServices = request.app.state.services
    db_ok = await services.db_healthy()
    scheduler_running = services.scheduler_running()
    healthy = db_ok and scheduler_running
    body = {
        "status": "ok" if healthy else "error",
        "db": "ok" if db_ok else "error",
        "scheduler": "running" if scheduler_running else "stopped",
    }
    return JSONResponse(body, status_code=200 if healthy else 503)
