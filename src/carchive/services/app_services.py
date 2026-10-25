"""`AppServices`: the narrow slice of the running application the web layer may see.

The web layer never talks to `storage` directly (enforced by the layering test); it only
sees what this module exposes, so a future change to the storage schema cannot ripple into
routes and templates unnoticed.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

import structlog
from sqlalchemy import text

from carchive.core.redact import redact
from carchive.services.accounts import AccountService
from carchive.services.catalog import CatalogService
from carchive.services.dashboard import DashboardService
from carchive.services.deliveries import DeliveryBrowser
from carchive.services.explorer import ExplorerService
from carchive.services.operator_auth import LoginThrottle, OperatorAuth
from carchive.storage.db import Database
from carchive.storage.repositories import VehicleRepository

logger = structlog.get_logger(__name__)


class SchedulerLike(Protocol):
    """What `AppServices`/the web lifespan need from a scheduler: a stoppable run loop."""

    async def run(self, stop: asyncio.Event) -> None:
        """Run due accounts in a loop until `stop` is set."""
        ...


class AppServices:
    """Everything the web layer needs from the running application.

    `scheduler` is exposed so the web app's lifespan can start/stop its background task;
    `mark_scheduler_running` records whether that task is currently alive, for `/healthz`
    and the dashboard to report without reaching back into the lifespan closure.

    Args:
        db: the application's database.
        scheduler: the background due-time loop; not started by this class itself.
        accounts: adds, tests, lists and deletes accounts and vehicles; used by the
            setup and settings routes.
        operator_auth: password and session handling for the operator login.
        login_throttle: the process-wide brute-force throttle for login attempts.
    """

    def __init__(
        self,
        db: Database,
        scheduler: SchedulerLike,
        accounts: AccountService,
        operator_auth: OperatorAuth,
        login_throttle: LoginThrottle,
    ) -> None:
        self._db = db
        self.scheduler = scheduler
        self.accounts = accounts
        self.operator_auth = operator_auth
        self.login_throttle = login_throttle
        self.dashboard = DashboardService(
            db, accounts.registry, accounts.settings, backup=accounts.backup
        )
        self.catalog = CatalogService(db)
        self.explorer = ExplorerService(db, self.catalog, accounts.registry)
        self.deliveries = DeliveryBrowser(db, accounts.registry)
        self._scheduler_running = False
        self._vehicles = VehicleRepository()

    def mark_scheduler_running(self, running: bool) -> None:
        """Record whether the scheduler's background task is currently alive."""
        self._scheduler_running = running

    def scheduler_running(self) -> bool:
        """Return whether the scheduler's background task is currently alive."""
        return self._scheduler_running

    async def db_healthy(self) -> bool:
        """Return whether the database answers a trivial read.

        Never raises: a connection or query failure is logged (redacted) and reported as
        unhealthy, since a health endpoint that itself crashes is worse than one that
        reports `False`.
        """
        try:
            async with self._db.read() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as exc:  # the health check must report, never crash, on failure
            logger.warning("app_services.db_health_check_failed", error=redact(str(exc)))
            return False
        return True

    async def vehicle_count(self) -> int:
        """Return the number of non-archived vehicles across all accounts.

        Used by every page's navigation to decide whether to show the "Set up" link, so
        it is kept to the one cheap query that answers that, rather than reusing
        `dashboard.overview` (which also reads every vehicle's signals and monitoring state).
        """
        async with self._db.read() as conn:
            return await self._vehicles.count_active(conn)
