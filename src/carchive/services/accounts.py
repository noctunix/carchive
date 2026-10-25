"""Account and vehicle management: setup, login testing, listing and deletion.

Every write here is idempotent and leaves either the whole change or none of it: adding an
account never leaves orphaned credentials if the database write fails, and deleting a
vehicle or account removes every dependent row in one transaction. Deleting never touches
backups; callers report how long the data can still be recovered from the oldest one still
on disk.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncConnection

from carchive.config import (
    ConfigError,
    Settings,
    WriteOutcome,
    check_passwords_replaceable,
    load_secrets,
    read_credential_fields,
    remove_credentials,
    replace_password,
    replace_passwords,
    unreadable_credential_refs,
    write_credentials,
)
from carchive.core.errors import ProviderError
from carchive.core.models import RemoteVehicle
from carchive.core.provider import CredentialField, ProviderRegistry
from carchive.core.redact import redact, register_secret
from carchive.services.backup import BackupService
from carchive.storage.db import Database
from carchive.storage.records import AccountRecord
from carchive.storage.repositories import (
    AccountRepository,
    CollectorRunRepository,
    DataPointRepository,
    DataRequestRepository,
    DeliveryRepository,
    ImportBatchRepository,
    SignalValueRepository,
    VehicleRepository,
)

_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
MAX_PASSWORD_LENGTH = 1024


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AccountServiceError(ValueError):
    """Base class for account/vehicle management errors meant to be shown to the user."""


class InvalidLabelError(AccountServiceError):
    """Raised when a label fails the `[A-Za-z0-9_-]{1,40}` pattern."""


class LabelConflictError(AccountServiceError):
    """Raised when an account with the requested label, or its credential reference, exists."""


class UnknownProviderError(AccountServiceError):
    """Raised when no provider is registered for the requested provider id."""


class UnsupportedBrandError(AccountServiceError):
    """Raised when the requested provider does not serve the requested brand."""


class AccountNotFoundError(AccountServiceError):
    """Raised when an operation names an account that does not exist."""


class InvalidPasswordError(AccountServiceError):
    """Raised when a new portal password is empty or longer than `MAX_PASSWORD_LENGTH`."""


class NoStoredCredentialsError(AccountServiceError):
    """Raised when an account has no entry in the secrets file whose password could be replaced."""


class LoginRejectedError(AccountServiceError):
    """Raised when the provider does not accept a new password.

    Attributes:
        reason: the provider's redacted, human-readable reason.
    """

    def __init__(self, reason: str | None) -> None:
        super().__init__(f"the portal did not accept the login: {reason or 'unknown reason'}")
        self.reason = reason


class VehicleNotFoundError(AccountServiceError):
    """Raised when an operation names a vehicle that does not exist."""


@dataclass(frozen=True, slots=True)
class LoginCheck:
    """The result of testing credentials against a provider."""

    ok: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """One account, as shown on the settings page and by `carchive account list`."""

    id: UUID
    label: str
    brand: str
    provider_id: str
    state: str
    state_reason: str | None
    last_run_at: datetime | None
    last_run_outcome: str | None


@dataclass(frozen=True, slots=True)
class VehicleInfo:
    """One vehicle, as shown on the settings page and by `carchive vehicle list`."""

    id: UUID
    account_label: str
    vin: str
    label: str
    brand: str
    archived: bool
    last_run_at: datetime | None
    last_run_outcome: str | None


@dataclass(frozen=True, slots=True)
class RequestDescription:
    """Enough about a data request to label a fetch result for a human."""

    account_label: str
    vin: str
    kind: str


@dataclass(frozen=True, slots=True)
class DeletionResult:
    """What a deletion removed from the live database.

    Attributes:
        oldest_backup_age: how long ago the oldest backup still on disk was created, or
            `None` if there is no backup at all. The just-deleted data can still be
            recovered from that backup (and any newer one) until it ages out of
            retention; deletion itself never touches backups.
    """

    oldest_backup_age: timedelta | None


class AccountService:
    """Adds, tests, lists and deletes accounts and vehicles.

    Args:
        db: the database to read and write through.
        registry: looks up the `Provider` for an account's `provider_id`.
        settings: used for `secrets_file`.
        backup: if given, consulted by `delete_vehicle`/`delete_account` to report the
            oldest backup's age; `None` skips that (the deletion itself is unaffected).
        clock: returns the current UTC time; overridable for tests.
    """

    def __init__(
        self,
        db: Database,
        registry: ProviderRegistry,
        settings: Settings,
        *,
        backup: BackupService | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._db = db
        self._registry = registry
        self._settings = settings
        self._backup = backup
        self._clock = clock
        self._accounts = AccountRepository()
        self._vehicles = VehicleRepository()
        self._requests = DataRequestRepository()
        self._deliveries = DeliveryRepository()
        self._data_points = DataPointRepository()
        self._signal_values = SignalValueRepository()
        self._runs = CollectorRunRepository()
        self._import_batches = ImportBatchRepository()

    @property
    def registry(self) -> ProviderRegistry:
        """The provider registry this service was built with.

        Lets `AppServices` build a `services.dashboard.DashboardService` sharing the same
        registry, without a second constructor argument threaded through every caller.
        """
        return self._registry

    @property
    def settings(self) -> Settings:
        """The settings this service was built with, for the same reason as `registry`."""
        return self._settings

    @property
    def backup(self) -> BackupService | None:
        """The backup service this was built with, for the same reason as `registry`."""
        return self._backup

    def available_brands(self) -> list[tuple[str, str]]:
        """Return `(provider_id, brand)` for every brand any registered provider serves.

        For the setup wizard's brand selector.
        """
        return sorted(
            (provider.id, brand) for provider in self._registry.all() for brand in provider.brands
        )

    def credential_fields(self, provider_id: str) -> tuple[CredentialField, ...]:
        """Return the credential fields the setup wizard must ask for, for `provider_id`.

        Raises:
            UnknownProviderError: if no provider is registered under `provider_id`.
        """
        try:
            return self._registry.get(provider_id).credential_fields
        except KeyError:
            raise UnknownProviderError(f"unknown provider {provider_id!r}") from None

    def portal_home_url(self, provider_id: str) -> str:
        """Return `provider_id`'s portal home page, linked as plain text by the wizard.

        Raises:
            UnknownProviderError: if no provider is registered under `provider_id`.
        """
        try:
            return self._registry.get(provider_id).portal_home_url
        except KeyError:
            raise UnknownProviderError(f"unknown provider {provider_id!r}") from None

    async def check_login(
        self, provider_id: str, brand: str, credentials: Mapping[str, str]
    ) -> LoginCheck:
        """Try logging in with `credentials`, without storing anything.

        Used by the setup wizard to validate a login before an account is created.

        Args:
            provider_id: the provider to log in through.
            brand: the brand to log in as.
            credentials: the fields the provider's `credential_fields` declare.

        Returns:
            Whether the login succeeded, and a redacted, human-readable reason if not.

        Raises:
            UnknownProviderError: if no provider is registered under `provider_id`.
        """
        try:
            provider = self._registry.get(provider_id)
        except KeyError:
            raise UnknownProviderError(f"unknown provider {provider_id!r}") from None

        # Registered before the first network call, not after a successful `add_account`,
        # so a secret value can never leak unredacted through an error message raised
        # while only testing a login that is never actually stored.
        for field in provider.credential_fields:
            if field.secret and field.name in credentials:
                register_secret(credentials[field.name])

        try:
            session = await provider.open_delivery_session(brand, credentials)
        except ProviderError as exc:
            return LoginCheck(ok=False, reason=redact(str(exc)))
        try:
            await session.list_vehicles()
        except ProviderError as exc:
            return LoginCheck(ok=False, reason=redact(str(exc)))
        finally:
            await session.aclose()
        return LoginCheck(ok=True, reason=None)

    async def add_account(
        self, provider_id: str, brand: str, label: str, credentials: Mapping[str, str]
    ) -> UUID:
        """Create a new account with `label`, storing `credentials` in the secrets file.

        Args:
            provider_id: the provider this account belongs to.
            brand: the brand to log in as; must be one of the provider's `brands`.
            label: a unique, filesystem- and URL-safe name for this account; also used as
                its `credential_ref`.
            credentials: the fields the provider's `credential_fields` declare.

        Returns:
            The new account's id.

        Raises:
            InvalidLabelError: if `label` does not match `[A-Za-z0-9_-]{1,40}`.
            UnknownProviderError: if no provider is registered under `provider_id`.
            UnsupportedBrandError: if `provider_id` does not serve `brand`.
            LabelConflictError: if an account with `label` already exists, or the
                secrets file already has different credentials under that reference.
        """
        if not _LABEL_PATTERN.fullmatch(label):
            raise InvalidLabelError(f"label must match {_LABEL_PATTERN.pattern!r}")
        try:
            provider = self._registry.get(provider_id)
        except KeyError:
            raise UnknownProviderError(f"unknown provider {provider_id!r}") from None
        if brand.lower() not in {b.lower() for b in provider.brands}:
            raise UnsupportedBrandError(f"provider {provider_id!r} does not serve brand {brand!r}")

        async with self._db.read() as conn:
            existing = await self._accounts.get_by_label(conn, label)
        if existing is not None:
            raise LabelConflictError(f"an account labelled {label!r} already exists")

        outcome = write_credentials(
            self._settings.secrets_file, label, credentials, overwrite=False
        )
        if outcome == WriteOutcome.CONFLICT:
            raise LabelConflictError(f"credentials already exist for reference {label!r}")

        account_id = uuid4()
        try:
            async with self._db.write() as conn:
                await self._accounts.add(
                    conn,
                    id=account_id,
                    provider_id=provider_id,
                    brand=brand.lower(),
                    label=label,
                    credential_ref=label,
                    state="active",
                    state_reason=None,
                    created_at=self._clock(),
                )
        except Exception:
            # Only undo what this call itself wrote; a pre-existing, unrelated
            # credential under the same reference (outcome UNCHANGED) is left alone.
            if outcome == WriteOutcome.CREATED:
                remove_credentials(self._settings.secrets_file, label)
            raise
        return account_id

    async def test_login(self, account_id: UUID) -> LoginCheck:
        """Try logging in with an existing account's stored credentials.

        Args:
            account_id: the account to test.

        Returns:
            Whether the login succeeded, and a redacted, human-readable reason if not.

        Raises:
            AccountNotFoundError: if no account with `account_id` exists.
        """
        account = await self._require_account(account_id)
        credentials = load_secrets(self._settings.secrets_file).get(account.credential_ref)
        if credentials is None:
            return LoginCheck(ok=False, reason="no credentials stored for this account")
        return await self.check_login(account.provider_id, account.brand, credentials)

    async def _replaceable_account(self, label: str) -> AccountRecord:
        """Return the account `label` after checking its password could be replaced alone."""
        account = await self.get_account_by_label(label)
        if account is None:
            raise AccountNotFoundError(f"no account labelled {label!r}")
        check_passwords_replaceable(self._settings.secrets_file, [account.credential_ref])
        return account

    async def check_password_replaceable(self, label: str) -> None:
        """Fail early if replacing only this account's password would not work.

        Args:
            label: the account's label.

        Raises:
            AccountNotFoundError: if no account labelled `label` exists.
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file or vault key is unusable, or the key is lost
                while other accounts still hold encrypted passwords (the message names them).
        """
        await self._replaceable_account(label)

    async def check_new_password(self, label: str, password: str) -> None:
        """Try a new password for an account against the provider, storing nothing.

        Args:
            label: the account's label.
            password: the new portal password in plaintext; never logged or echoed.

        Raises:
            AccountNotFoundError: if no account labelled `label` exists.
            InvalidPasswordError: if `password` is empty or longer than `MAX_PASSWORD_LENGTH`.
            NoStoredCredentialsError: if the secrets file has no entry for the account.
            LoginRejectedError: if the provider does not accept the login.
            UnknownProviderError: if the account's provider is not registered.
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file is malformed.
        """
        self._validate_password(password)
        register_secret(password)
        account = await self.get_account_by_label(label)
        if account is None:
            raise AccountNotFoundError(f"no account labelled {label!r}")
        fields = read_credential_fields(self._settings.secrets_file, account.credential_ref)
        if fields is None:
            raise NoStoredCredentialsError(f"no credentials stored for account {label!r}")

        check = await self.check_login(
            account.provider_id, account.brand, {**fields, "password": password}
        )
        if not check.ok:
            raise LoginRejectedError(check.reason)

    async def set_password(self, label: str, password: str) -> None:
        """Replace an account's stored portal password; the account and its data stay.

        The new password is tried against the provider first and only stored if the login
        works. The old password is never read, so this also works after the vault key was
        lost, as long as no other account's password is left unreadable by that (see
        `set_passwords` for replacing several at once).

        Args:
            label: the account's label.
            password: the new portal password in plaintext; never logged or echoed.

        Raises:
            AccountNotFoundError: if no account labelled `label` exists.
            InvalidPasswordError: if `password` is empty or longer than `MAX_PASSWORD_LENGTH`.
            NoStoredCredentialsError: if the secrets file has no entry for the account.
            LoginRejectedError: if the provider does not accept the login; nothing is stored.
            UnknownProviderError: if the account's provider is not registered.
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file or vault key is unusable, or the key is lost
                while other accounts still hold encrypted passwords.
        """
        self._validate_password(password)
        account = await self._replaceable_account(label)
        await self.check_new_password(label, password)
        replace_password(self._settings.secrets_file, account.credential_ref, password)

    async def unreadable_password_labels(self) -> list[str]:
        """Return the labels of accounts whose stored password cannot be decrypted.

        Returns:
            The sorted labels, empty if every stored password is readable.

        Raises:
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file or vault key is unusable, or an unreadable
                password belongs to no account (it cannot be replaced by prompting).
        """
        unreadable = unreadable_credential_refs(self._settings.secrets_file)
        if not unreadable:
            return []
        async with self._db.read() as conn:
            accounts = await self._accounts.list_all(conn)
        by_ref = {account.credential_ref: account.label for account in accounts}
        orphans = [ref for ref in unreadable if ref not in by_ref]
        if orphans:
            raise ConfigError(
                f"unreadable passwords belong to no account: {', '.join(orphans)}; remove "
                f"those [credentials.*] entries from {self._settings.secrets_file}"
            )
        return sorted(by_ref[ref] for ref in unreadable)

    async def set_passwords(self, passwords: Mapping[str, str]) -> None:
        """Replace the stored passwords of several accounts in one atomic write.

        Nothing is tried against the provider here; callers check each password first with
        `check_new_password`. A missing vault key is only regenerated once every encrypted
        password in the file is among the replaced ones.

        Args:
            passwords: new plaintext password per account label.

        Raises:
            AccountNotFoundError: if a label names no account.
            InvalidPasswordError: if a password is empty or longer than `MAX_PASSWORD_LENGTH`.
            InsecureSecretsError: if the secrets file is group/world-accessible.
            ConfigError: if the secrets file or vault key is unusable, an account has no
                stored credentials, or encrypted passwords would remain unreadable.
        """
        by_ref: dict[str, str] = {}
        for label, password in passwords.items():
            self._validate_password(password)
            register_secret(password)
            account = await self.get_account_by_label(label)
            if account is None:
                raise AccountNotFoundError(f"no account labelled {label!r}")
            by_ref[account.credential_ref] = password
        replace_passwords(self._settings.secrets_file, by_ref)

    @staticmethod
    def _validate_password(password: str) -> None:
        if not password or len(password) > MAX_PASSWORD_LENGTH:
            raise InvalidPasswordError(
                f"the password must be 1 to {MAX_PASSWORD_LENGTH} characters long"
            )

    async def remote_vehicles(self, account_id: UUID) -> list[RemoteVehicle]:
        """List the vehicles an account's provider currently reports for it.

        Args:
            account_id: the account to list vehicles for.

        Returns:
            The vehicles the provider reports, as-is (not yet matched to local vehicles).

        Raises:
            AccountNotFoundError: if no account with `account_id` exists.
            ValueError: if the account has no credentials stored.
            ProviderError: if the login or the listing itself fails.
        """
        account = await self._require_account(account_id)
        credentials = load_secrets(self._settings.secrets_file).get(account.credential_ref)
        if credentials is None:
            raise ValueError(f"no credentials stored for account {account.label!r}")
        provider = self._registry.get(account.provider_id)
        session = await provider.open_delivery_session(account.brand, credentials)
        try:
            return await session.list_vehicles()
        finally:
            await session.aclose()

    async def get_account_by_label(self, label: str) -> AccountRecord | None:
        """Return the account labelled `label`, or `None` if there is none.

        For CLI/web code that only has a label to work with (`vehicle sync <label>`,
        a settings page link); every other method here takes the account id directly.
        """
        async with self._db.read() as conn:
            return await self._accounts.get_by_label(conn, label)

    async def add_vehicles(self, account_id: UUID, vins: Sequence[str]) -> list[UUID]:
        """Add vehicles to `account_id`, restricted to VINs the account actually reports.

        Args:
            account_id: the account the new vehicles belong to.
            vins: candidate VINs, typically picked by the user from `remote_vehicles`.

        Returns:
            The ids of the vehicles actually added; a VIN not reported by the provider,
            or already added, is silently skipped.

        Raises:
            AccountNotFoundError: if no account with `account_id` exists.
            ProviderError: if the login or the vehicle listing fails.
        """
        account = await self._require_account(account_id)
        remote_by_vin = {vehicle.vin: vehicle for vehicle in await self.remote_vehicles(account_id)}

        added: list[UUID] = []
        async with self._db.write() as conn:
            existing_vins = {
                vehicle.vin for vehicle in await self._vehicles.list_for_account(conn, account_id)
            }
            for vin in vins:
                if vin not in remote_by_vin or vin in existing_vins:
                    continue
                vehicle_id = uuid4()
                await self._vehicles.add(
                    conn,
                    id=vehicle_id,
                    account_id=account_id,
                    vin=vin,
                    label=f"{account.label} …{vin[-6:]}" if len(vin) >= 6 else account.label,
                    brand=account.brand,
                    model=None,
                    created_at=self._clock(),
                )
                added.append(vehicle_id)
                existing_vins.add(vin)
        return added

    async def list_accounts(self) -> list[AccountInfo]:
        """Return every account, with its most recent collector run."""
        async with self._db.read() as conn:
            accounts = await self._accounts.list_all(conn)
            infos = []
            for account in accounts:
                last_run = await self._runs.latest_for_account(conn, account.id)
                infos.append(
                    AccountInfo(
                        id=account.id,
                        label=account.label,
                        brand=account.brand,
                        provider_id=account.provider_id,
                        state=account.state,
                        state_reason=account.state_reason,
                        last_run_at=last_run.started_at if last_run else None,
                        last_run_outcome=last_run.outcome if last_run else None,
                    )
                )
        return infos

    async def list_vehicles(self) -> list[VehicleInfo]:
        """Return every vehicle, with its owning account's label and most recent run."""
        async with self._db.read() as conn:
            vehicles = await self._vehicles.list_all(conn)
            accounts_by_id = {
                account.id: account for account in await self._accounts.list_all(conn)
            }
            infos = []
            for vehicle in vehicles:
                latest_run = None
                for request in await self._requests.list_for_vehicle(conn, vehicle.id):
                    run = await self._runs.latest_for_request(conn, request.id)
                    if run is not None and (
                        latest_run is None or run.started_at > latest_run.started_at
                    ):
                        latest_run = run
                account = accounts_by_id.get(vehicle.account_id)
                infos.append(
                    VehicleInfo(
                        id=vehicle.id,
                        account_label=account.label if account is not None else "",
                        vin=vehicle.vin,
                        label=vehicle.label,
                        brand=vehicle.brand,
                        archived=vehicle.archived_at is not None,
                        last_run_at=latest_run.started_at if latest_run else None,
                        last_run_outcome=latest_run.outcome if latest_run else None,
                    )
                )
        return infos

    async def due_account_ids(self) -> list[UUID]:
        """Return the ids of every account that currently has collection work due.

        For `carchive fetch` (no flags): logging in is wasted work for an account with
        nothing due yet, so the CLI calls this instead of running every account.
        """
        async with self._db.read() as conn:
            due = await self._accounts.list_due(conn, self._clock())
        return [account.id for account in due]

    async def describe_request(self, request_id: UUID) -> RequestDescription | None:
        """Return the account label, VIN and kind behind a data request id.

        For labeling `carchive fetch`'s per-request output without the CLI reaching into
        `storage` itself.

        Args:
            request_id: the data request to describe.

        Returns:
            The description, or `None` if the request, its vehicle or its account no
            longer exists.
        """
        async with self._db.read() as conn:
            request = await self._requests.get(conn, request_id)
            if request is None:
                return None
            vehicle = await self._vehicles.get(conn, request.vehicle_id)
            if vehicle is None:
                return None
            account = await self._accounts.get(conn, vehicle.account_id)
            if account is None:
                return None
        return RequestDescription(account_label=account.label, vin=vehicle.vin, kind=request.kind)

    async def get_vehicle(self, vehicle_id: UUID) -> VehicleInfo | None:
        """Return one vehicle's info, or `None` if no vehicle with `vehicle_id` exists.

        For a deletion confirmation page/prompt that needs to show what a given id
        refers to before the user commits.
        """
        for info in await self.list_vehicles():
            if info.id == vehicle_id:
                return info
        return None

    async def delete_vehicle(self, vehicle_id: UUID) -> DeletionResult:
        """Delete a vehicle and every row derived from it, in one transaction.

        Args:
            vehicle_id: the vehicle to delete.

        Returns:
            The deletion result (oldest backup age).

        Raises:
            VehicleNotFoundError: if no vehicle with `vehicle_id` exists.
        """
        async with self._db.write() as conn:
            vehicle = await self._vehicles.get(conn, vehicle_id)
            if vehicle is None:
                raise VehicleNotFoundError(f"no vehicle with id {vehicle_id}")
            await self._delete_vehicle_data(conn, vehicle_id)
            await self._vehicles.delete(conn, vehicle_id)
        return DeletionResult(oldest_backup_age=await self._oldest_backup_age())

    async def delete_account(self, label: str) -> DeletionResult:
        """Delete an account, every one of its vehicles and their data, and its credentials.

        Args:
            label: the account's label.

        Returns:
            The deletion result (oldest backup age).

        Raises:
            AccountNotFoundError: if no account labelled `label` exists.
        """
        async with self._db.write() as conn:
            account = await self._accounts.get_by_label(conn, label)
            if account is None:
                raise AccountNotFoundError(f"no account labelled {label!r}")
            for vehicle in await self._vehicles.list_for_account(conn, account.id):
                await self._delete_vehicle_data(conn, vehicle.id)
                await self._vehicles.delete(conn, vehicle.id)
            await self._runs.delete_for_account(conn, account.id)
            await self._accounts.delete(conn, account.id)
        remove_credentials(self._settings.secrets_file, account.credential_ref)
        return DeletionResult(oldest_backup_age=await self._oldest_backup_age())

    async def _delete_vehicle_data(self, conn: AsyncConnection, vehicle_id: UUID) -> None:
        """Delete every row derived from `vehicle_id`, in foreign-key-safe order.

        Does not delete the vehicle row itself; callers do that once this returns.
        """
        await self._signal_values.delete_for_vehicle(conn, vehicle_id)
        await self._data_points.delete_for_vehicle(conn, vehicle_id)
        await self._deliveries.delete_for_vehicle(conn, vehicle_id)
        await self._runs.delete_for_vehicle(conn, vehicle_id)
        await self._requests.delete_for_vehicle(conn, vehicle_id)
        await self._import_batches.delete_for_vehicle(conn, vehicle_id)

    async def _require_account(self, account_id: UUID) -> AccountRecord:
        async with self._db.read() as conn:
            account = await self._accounts.get(conn, account_id)
        if account is None:
            raise AccountNotFoundError(f"no account with id {account_id}")
        return account

    async def _oldest_backup_age(self) -> timedelta | None:
        if self._backup is None:
            return None
        backups = await asyncio.to_thread(self._backup.list_backups)
        if not backups:
            return None
        oldest = min(backup.created_at for backup in backups)
        return self._clock() - oldest
