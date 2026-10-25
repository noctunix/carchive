"""Scheduler: an in-process due-time loop that runs the collector, one account at a time.

Due times live in the database (`data_requests.next_due_at`), not in process memory, so a
restart picks up exactly where the last run left off.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import structlog

from carchive.core.redact import redact
from carchive.services.backup import BackupService
from carchive.services.collector import AccountRunResult, Collector
from carchive.storage.db import Database
from carchive.storage.repositories import (
    AccountRepository,
    DataRequestRepository,
    DeliveryRepository,
)

logger = structlog.get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Scheduler:
    """Runs due accounts through a `Collector`, never two logins at once.

    Args:
        collector: runs one account's collection pass.
        db: the database to read due times from.
        clock: returns the current UTC time; overridable for tests.
        sleep: injectable async sleep, used to wait between polls.
        poll_cap_s: the longest the loop ever sleeps in one go, so a stop request or a
            newly due account is never delayed by more than this.
        backup: if given, creates/verifies/prunes a daily backup once `backup_time` has
            passed each day, after every pass over due accounts.
        backup_time: the local time of day (`"HH:MM"`) a backup becomes due.
        raw_payload_retention_days: how long a parsed delivery's raw payload is kept
            before being cleared; `0` clears it as soon as parsed, `None` keeps it
            forever. See `Settings.raw_payload_retention_days`.
    """

    def __init__(
        self,
        collector: Collector,
        db: Database,
        *,
        clock: Callable[[], datetime] = _utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        poll_cap_s: float = 60.0,
        backup: BackupService | None = None,
        backup_time: str = "03:30",
        raw_payload_retention_days: int | None = 30,
    ) -> None:
        self._collector = collector
        self._db = db
        self._clock = clock
        self._sleep = sleep
        self._poll_cap_s = poll_cap_s
        self._backup = backup
        self._backup_time = backup_time
        self._raw_payload_retention_days = raw_payload_retention_days
        self._accounts = AccountRepository()
        self._requests = DataRequestRepository()
        self._deliveries = DeliveryRepository()

    async def run_once(self) -> list[AccountRunResult]:
        """Run every account that currently has collection work due, one after another.

        An exception from one account's run is logged and does not stop the others.
        Afterward, creates/verifies/prunes a backup if one is configured and due.

        Returns:
            One `AccountRunResult` per account that was actually run.
        """
        now = self._clock()
        async with self._db.read() as conn:
            due_accounts = await self._accounts.list_due(conn, now)

        results: list[AccountRunResult] = []
        for account in due_accounts:
            try:
                results.append(await self._collector.run_account(account.id))
            except Exception as exc:  # one account's bug must not stop the others
                logger.error(
                    "scheduler.account_run_failed",
                    account_id=str(account.id),
                    error=redact(str(exc)),
                )

        await self._maybe_backup(now)
        await self._maybe_purge_raw_payloads(now)
        return results

    async def _maybe_purge_raw_payloads(self, now: datetime) -> None:
        """Clear raw payloads of parsed deliveries past the configured retention; never raises.

        A no-op when `raw_payload_retention_days` is `None` (keep forever). Runs every
        pass rather than on its own schedule: the `UPDATE` matches nothing once caught up,
        so it costs little, and unlike the backup it has no meaningful "once a day" semantics.
        """
        if self._raw_payload_retention_days is None:
            return
        cutoff = now - timedelta(days=self._raw_payload_retention_days)
        try:
            async with self._db.write() as conn:
                purged = await self._deliveries.purge_raw_payloads(conn, cutoff)
            if purged:
                logger.info("scheduler.raw_payloads_purged", count=purged)
        except Exception as exc:  # a broken purge run must not stop the scheduler
            logger.error("scheduler.raw_payload_purge_failed", error=redact(str(exc)))

    async def _maybe_backup(self, now: datetime) -> None:
        """Create, verify and prune a daily backup once it is due; never raises.

        A backup failure is logged and must not stop the scheduler loop, since a broken
        backup run is recoverable on the next pass but a stuck scheduler is not.
        """
        if self._backup is None:
            return
        try:
            existing = await asyncio.to_thread(self._backup.list_backups)
            last_backup_at = existing[0].created_at if existing else None
            if not BackupService.due(now, last_backup_at, self._backup_time):
                return

            path = await self._backup.create()
            await asyncio.to_thread(self._backup.verify, path)
            await asyncio.to_thread(self._backup.prune, now)
        except Exception as exc:  # a broken backup run must not stop the scheduler
            logger.error("scheduler.backup_failed", error=redact(str(exc)))

    async def run(self, stop: asyncio.Event) -> None:
        """Run due accounts in a loop until `stop` is set.

        Sleeps between passes until the next due time, capped at `poll_cap_s`; an exception
        during one pass is logged and does not end the loop.

        Args:
            stop: set by the caller to end the loop after the current sleep.
        """
        while not stop.is_set():
            try:
                await self.run_once()
            except Exception as exc:  # defends run() itself, run_once already guards per account
                logger.error("scheduler.pass_failed", error=redact(str(exc)))

            if stop.is_set():
                break

            now = self._clock()
            async with self._db.read() as conn:
                next_due = await self._requests.earliest_next_due(conn, now)
            sleep_s = self._poll_cap_s
            if next_due is not None:
                sleep_s = min(sleep_s, max(0.0, (next_due - now).total_seconds()))
            await self._sleep_until_due_or_stopped(sleep_s, stop)

    async def _sleep_until_due_or_stopped(self, seconds: float, stop: asyncio.Event) -> None:
        """Wait up to `seconds`, returning immediately once `stop` is set.

        A plain `await self._sleep(seconds)` would ignore `stop` for the whole duration,
        which is at most `poll_cap_s` (60 s by default) — long enough that systemd and
        other process supervisors would consider a shutdown hung.
        """
        sleep_task = asyncio.ensure_future(self._sleep(seconds))
        stop_task = asyncio.ensure_future(stop.wait())
        try:
            await asyncio.wait({sleep_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (sleep_task, stop_task):
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
