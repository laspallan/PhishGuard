"""The common record format every source is converted to (proposal Section 3.6).

One record is one URL or one email. Records are stored as Parquet files with a fixed schema.

sample_id is a UUID derived from the sample type and content hash (UUID version 5), so the
same content always gets the same id. Duplicates across sources therefore share an id, and
rebuilding the dataset from the raw files gives identical ids.
"""

import hashlib
import os
import uuid
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
from pydantic import BaseModel, ConfigDict, Field, model_validator

from phishguard.models.enums import AttackCategory, Label, Modality

SAMPLE_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "phishguard:sample")


class Source(StrEnum):
    PHISHTANK = "phishtank"
    OPENPHISH = "openphish"
    TRANCO = "tranco"
    NAZARIO = "nazario"
    SPAMASSASSIN = "spamassassin"
    ENRON = "enron"
    OWN_MAILBOX = "own_mailbox"  # recent legitimate-email check set: evaluation only


# What every source provides: (sample type, label).
SOURCE_INFO: dict[Source, tuple[Modality, Label]] = {
    Source.PHISHTANK: (Modality.URL, Label.PHISHING),
    Source.OPENPHISH: (Modality.URL, Label.PHISHING),
    Source.TRANCO: (Modality.URL, Label.LEGITIMATE),
    Source.NAZARIO: (Modality.EMAIL, Label.PHISHING),
    Source.SPAMASSASSIN: (Modality.EMAIL, Label.LEGITIMATE),
    Source.ENRON: (Modality.EMAIL, Label.LEGITIMATE),
    Source.OWN_MAILBOX: (Modality.EMAIL, Label.LEGITIMATE),
}


def content_hash(content: str) -> str:
    """SHA-256 of the (already normalised) content, as 64 hex characters."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def make_sample_id(sample_type: Modality, hash_hex: str) -> uuid.UUID:
    return uuid.uuid5(SAMPLE_ID_NAMESPACE, f"{sample_type.value}:{hash_hex}")


class SampleRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sample_id: uuid.UUID
    sample_type: Modality
    raw_content: str = Field(min_length=1)
    label: Label
    attack_category: AttackCategory | None = None
    source: Source
    source_date: date | None = None  # date given by the source, if any
    collected_at: datetime  # when we downloaded it (timezone-aware)
    group_key: str | None = None  # split grouping key (decision D4), set during cleaning
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_ref: str | None = None  # URLs only: where the snapshot is stored

    @classmethod
    def create(cls, *, source: Source, raw_content: str, hash_of: str | None = None, **fields):
        """Build a record, deriving sample_type, label, content_hash and sample_id.

        hash_of is the normalised content to hash; it defaults to raw_content.
        """
        sample_type, label = SOURCE_INFO[source]
        digest = content_hash(raw_content if hash_of is None else hash_of)
        return cls(
            sample_id=make_sample_id(sample_type, digest),
            sample_type=sample_type,
            label=label,
            source=source,
            raw_content=raw_content,
            content_hash=digest,
            **fields,
        )

    @model_validator(mode="after")
    def _check_consistency(self) -> "SampleRecord":
        if (self.sample_type, self.label) != SOURCE_INFO[self.source]:
            raise ValueError(f"{self.source} provides {SOURCE_INFO[self.source]}")
        if self.label is Label.LEGITIMATE and self.attack_category is not None:
            raise ValueError("legitimate samples have no attack category")
        if self.sample_id != make_sample_id(self.sample_type, self.content_hash):
            raise ValueError("sample_id does not match sample_type and content_hash")
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        if self.snapshot_ref is not None and self.sample_type is not Modality.URL:
            raise ValueError("only URL samples have snapshots")
        return self

    def to_row(self) -> dict[str, Any]:
        row = self.model_dump()
        row["sample_id"] = str(self.sample_id)
        for key in ("sample_type", "label", "attack_category", "source"):
            row[key] = None if row[key] is None else str(row[key])
        return row


PARQUET_SCHEMA = pa.schema(
    [
        pa.field("sample_id", pa.string(), nullable=False),
        pa.field("sample_type", pa.string(), nullable=False),
        pa.field("raw_content", pa.large_string(), nullable=False),
        pa.field("label", pa.string(), nullable=False),
        pa.field("attack_category", pa.string()),
        pa.field("source", pa.string(), nullable=False),
        pa.field("source_date", pa.date32()),
        pa.field("collected_at", pa.timestamp("us", tz="UTC"), nullable=False),
        pa.field("group_key", pa.string()),
        pa.field("content_hash", pa.string(), nullable=False),
        pa.field("snapshot_ref", pa.string()),
    ]
)


class SchemaMismatchError(ValueError):
    """Raised when a Parquet file does not have the expected record schema."""


def write_records(records: list[SampleRecord], path: Path) -> None:
    """Write records to Parquet. Writes to a temporary file first, so a crash never
    leaves a half-written file at `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist([r.to_row() for r in records], schema=PARQUET_SCHEMA)
    tmp = path.with_suffix(path.suffix + ".tmp")
    pq.write_table(table, tmp)
    os.replace(tmp, path)


def read_records(path: Path) -> list[SampleRecord]:
    table = pq.read_table(path)
    if not table.schema.equals(PARQUET_SCHEMA, check_metadata=False):
        raise SchemaMismatchError(f"{path} does not have the record schema")
    return [SampleRecord.model_validate(row) for row in table.to_pylist()]
