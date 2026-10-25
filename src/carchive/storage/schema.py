"""Portable SQLAlchemy Core table definitions for Carchive's local database.

Written so the same schema maps to PostgreSQL later: no SQLite-only SQL, UUID primary keys
generated in Python, UTC timestamps via `UTCDateTime`, and `CHECK` constraints only for a
fixed, known set of values rather than open-ended free text. A fixed naming convention gives
every constraint and index a stable, predictable name, which Alembic's autogenerate/compare
tooling relies on to recognize "no change" across runs.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    Uuid,
)

from carchive.storage.types import UTCDateTime

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
# `%(constraint_name)s` in the "ck" template is filled from a CheckConstraint's own `name=`,
# even when one is given explicitly (unlike "uq"/"ix", which always derive the name from
# columns and ignore `name=`). Every `CheckConstraint` below therefore gets only its short,
# table-local suffix (e.g. "valid_state"), so the convention can prefix it with "ck_<table>_"
# without doubling.

metadata = MetaData(naming_convention=NAMING_CONVENTION)

accounts = Table(
    "accounts",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("provider_id", String, nullable=False),
    Column("brand", String, nullable=False),
    Column("label", String, nullable=False),
    Column("credential_ref", String, nullable=False),
    Column("state", String, nullable=False),
    Column("state_reason", String, nullable=True),
    Column("created_at", UTCDateTime, nullable=False),
    UniqueConstraint("label", name="uq_accounts_label"),
    CheckConstraint("state IN ('active', 'needs_attention', 'disabled')", name="valid_state"),
)

vehicles = Table(
    "vehicles",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("account_id", ForeignKey("accounts.id"), nullable=False),
    Column("vin", String, nullable=False),
    Column("label", String, nullable=False),
    Column("brand", String, nullable=False),
    Column("model", String, nullable=True),
    Column("created_at", UTCDateTime, nullable=False),
    Column("archived_at", UTCDateTime, nullable=True),
    UniqueConstraint("account_id", "vin", name="uq_vehicles_account_id_vin"),
)

data_requests = Table(
    "data_requests",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("vehicle_id", ForeignKey("vehicles.id"), nullable=False),
    Column("kind", String, nullable=False),
    Column("remote_id", String, nullable=True),
    Column("interval_s", Integer, nullable=False),
    Column("next_due_at", UTCDateTime, nullable=True),
    Column("state", String, nullable=False),
    Column("state_reason", String, nullable=True),
    Column("last_success_at", UTCDateTime, nullable=True),
    UniqueConstraint("vehicle_id", "kind", name="uq_data_requests_vehicle_id_kind"),
    CheckConstraint("state IN ('active', 'needs_attention', 'disabled')", name="valid_state"),
)

import_batches = Table(
    "import_batches",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("vehicle_id", ForeignKey("vehicles.id"), nullable=False),
    Column("kind", String, nullable=False),
    Column("source_name", String, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("state", String, nullable=False),
    Column("progress", Float, nullable=False),
    Column("started_at", UTCDateTime, nullable=False),
    Column("finished_at", UTCDateTime, nullable=True),
    Column("error", String, nullable=True),
    UniqueConstraint("vehicle_id", "sha256", name="uq_import_batches_vehicle_id_sha256"),
    CheckConstraint("kind IN ('historical')", name="valid_kind"),
    CheckConstraint("state IN ('pending', 'running', 'done', 'failed')", name="valid_state"),
    CheckConstraint("progress >= 0 AND progress <= 1", name="valid_progress"),
)

deliveries = Table(
    "deliveries",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("data_request_id", ForeignKey("data_requests.id"), nullable=True),
    Column("import_batch_id", ForeignKey("import_batches.id"), nullable=True),
    Column("remote_name", String, nullable=False),
    Column("delivered_at", UTCDateTime, nullable=True),
    Column("fetched_at", UTCDateTime, nullable=False),
    Column("has_content", Boolean, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("parse_state", String, nullable=False),
    Column("parser_version", String, nullable=True),
    Column("raw_payload", LargeBinary, nullable=True),
    UniqueConstraint(
        "data_request_id", "remote_name", name="uq_deliveries_data_request_id_remote_name"
    ),
    CheckConstraint(
        "(data_request_id IS NULL) != (import_batch_id IS NULL)",
        name="exactly_one_parent",
    ),
    CheckConstraint(
        "parse_state IN ('pending', 'parsed', 'failed', 'empty')",
        name="valid_parse_state",
    ),
)

data_points = Table(
    "data_points",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("vehicle_id", ForeignKey("vehicles.id"), nullable=False),
    Column("key", String, nullable=False),
    Column("field_name", String, nullable=False),
    # Array indices in `field_name` collapsed to `[*]` (`core.fields.generic_field_name`), so
    # the data explorer can group one vehicle's charging sessions or power-curve points into
    # a single row. Nullable only because SQLite cannot add a `NOT NULL` column to an
    # existing table without rewriting it; every writer fills it unconditionally.
    Column("field_generic", String, nullable=True),
    Column("value_raw", Text, nullable=True),
    Column("value_type", String, nullable=False),
    Column("value_num", Float, nullable=True),
    Column("value_text", Text, nullable=True),
    Column("value_bool", Boolean, nullable=True),
    Column("value_time", UTCDateTime, nullable=True),
    Column("captured_at", UTCDateTime, nullable=True),
    Column("captured_at_quality", String, nullable=False),
    Column("first_delivery_id", ForeignKey("deliveries.id"), nullable=False),
    Column("first_seen_at", UTCDateTime, nullable=False),
    Column("last_seen_at", UTCDateTime, nullable=False),
    Column("seen_count", Integer, nullable=False),
    Column("dedup_key", String(64), nullable=False),
    UniqueConstraint("vehicle_id", "dedup_key", name="uq_data_points_vehicle_id_dedup_key"),
    CheckConstraint(
        "value_type IN ('num', 'text', 'bool', 'time', 'null')",
        name="valid_value_type",
    ),
    CheckConstraint(
        "captured_at_quality IN ('exact', 'report', 'delivery', 'tz_unknown', 'invalid')",
        name="valid_captured_at_quality",
    ),
)
Index(
    "ix_data_points_vehicle_id_field_name_captured_at",
    data_points.c.vehicle_id,
    data_points.c.field_name,
    data_points.c.captured_at,
)
Index(
    "ix_data_points_vehicle_id_key_captured_at",
    data_points.c.vehicle_id,
    data_points.c.key,
    data_points.c.captured_at,
)
Index(
    "ix_data_points_vehicle_id_field_generic",
    data_points.c.vehicle_id,
    data_points.c.field_generic,
)

signal_values = Table(
    "signal_values",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("vehicle_id", ForeignKey("vehicles.id"), nullable=False),
    Column("signal", String, nullable=False),
    Column("value_num", Float, nullable=True),
    Column("value_text", Text, nullable=True),
    Column("value_bool", Boolean, nullable=True),
    Column("unit", String, nullable=True),
    Column("captured_at", UTCDateTime, nullable=True),
    Column("captured_at_quality", String, nullable=False),
    Column("source_data_point_id", ForeignKey("data_points.id"), nullable=False),
    Column("mapping_version", String, nullable=False),
    UniqueConstraint(
        "source_data_point_id",
        "signal",
        "mapping_version",
        name="uq_signal_values_source_data_point_id_signal_mapping_version",
    ),
    CheckConstraint(
        "captured_at_quality IN ('exact', 'report', 'delivery', 'tz_unknown', 'invalid')",
        name="valid_captured_at_quality",
    ),
)
Index(
    "ix_signal_values_vehicle_id_signal_captured_at",
    signal_values.c.vehicle_id,
    signal_values.c.signal,
    signal_values.c.captured_at,
)

catalog_entries = Table(
    "catalog_entries",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("provider_id", String, nullable=False),
    Column("catalog_version", String, nullable=False),
    Column("key", String, nullable=False),
    Column("name", String, nullable=False),
    Column("description", Text, nullable=True),
    Column("unit", String, nullable=True),
    Column("data_type", String, nullable=True),
    Column("clusters", JSON, nullable=True),
    Column("kind", String, nullable=False),
    UniqueConstraint(
        "provider_id",
        "catalog_version",
        "key",
        name="uq_catalog_entries_provider_id_catalog_version_key",
    ),
    CheckConstraint("kind IN ('continuous', 'historical')", name="valid_kind"),
)

collector_runs = Table(
    "collector_runs",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("account_id", ForeignKey("accounts.id"), nullable=False),
    Column("data_request_id", ForeignKey("data_requests.id"), nullable=True),
    Column("started_at", UTCDateTime, nullable=False),
    Column("finished_at", UTCDateTime, nullable=False),
    Column("outcome", String, nullable=False),
    Column("listed", Integer, nullable=True),
    Column("placeholders", Integer, nullable=True),
    Column("downloaded", Integer, nullable=True),
    Column("with_content", Integer, nullable=True),
    Column("pending", Integer, nullable=True),
    Column("oldest_pending_age_s", Float, nullable=True),
    Column("message", String(300), nullable=True),
    CheckConstraint(
        "outcome IN ('ok', 'unavailable', 'rate_limited', 'error', 'login_failed')",
        name="valid_outcome",
    ),
    CheckConstraint("message IS NULL OR length(message) <= 300", name="message_length"),
)
Index(
    "ix_collector_runs_data_request_id_started_at",
    collector_runs.c.data_request_id,
    collector_runs.c.started_at,
)

backups = Table(
    "backups",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("created_at", UTCDateTime, nullable=False),
    Column("path", String, nullable=False),
    Column("size_bytes", Integer, nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("verified", Boolean, nullable=False),
    Column("error", String, nullable=True),
)

operator_sessions = Table(
    "operator_sessions",
    metadata,
    Column("id", Uuid(as_uuid=True), primary_key=True),
    Column("token_hash", String(64), nullable=False),
    Column("created_at", UTCDateTime, nullable=False),
    Column("last_seen_at", UTCDateTime, nullable=False),
    Column("expires_at", UTCDateTime, nullable=False),
    UniqueConstraint("token_hash", name="uq_operator_sessions_token_hash"),
)
