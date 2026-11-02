"""Database models on in-memory SQLite: ids, encryption, constraints and cascades."""

import uuid
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import Uuid, func, select, text
from sqlalchemy.exc import IntegrityError

from phishguard.core import crypto
from phishguard.models import (
    AdminUser,
    Base,
    Campaign,
    ModelVersion,
    Participant,
    Scan,
    ScanFeatures,
    SimulationEvent,
    SimulationSample,
    Template,
)
from phishguard.models.enums import (
    AttackCategory,
    Decision,
    EventType,
    Modality,
    ModelKind,
    SampleUsage,
    TemplateSplit,
)

EXPECTED_TABLES = {
    "admin_users",
    "api_clients",
    "model_versions",
    "scans",
    "scan_features",
    "scan_feedback",
    "ti_lookups",
    "participants",
    "templates",
    "campaigns",
    "simulation_events",
    "simulation_samples",
    "experiment_runs",
}
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


def make_model_version(**overrides) -> ModelVersion:
    values = dict(
        name="url-soft-voting",
        modality=Modality.URL,
        kind=ModelKind.SOFT_VOTING,
        artifact_path="data/models/x.joblib",
        data_hash="d" * 64,
        feature_set_hash="f" * 64,
        seed=42,
    )
    return ModelVersion(**{**values, **overrides})


def make_participant(email: str = "alice@example.org", code: str = "P001") -> Participant:
    return Participant(
        email=email, participant_code=code, consent_form_version="v1", consent_given_at=NOW
    )


def test_all_tables_exist():
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_every_primary_key_is_a_uuid():
    for table in Base.metadata.tables.values():
        for column in table.primary_key.columns:
            assert isinstance(column.type, Uuid), f"{table.name}.{column.name}"


def test_ids_are_generated_as_uuid4(db):
    version = make_model_version()
    db.add(version)
    db.commit()

    assert isinstance(version.id, uuid.UUID)
    assert version.id.version == 4


def test_email_is_encrypted_on_disk_and_decrypted_on_read(db):
    db.add(make_participant("Alice@Example.org"))
    db.commit()

    raw = db.execute(text("SELECT email, email_hash FROM participants")).one()
    assert "alice" not in raw.email.lower()
    assert crypto.decrypt(raw.email) == "alice@example.org"
    assert raw.email_hash == crypto.email_blind_index("alice@example.org")

    db.expire_all()
    assert db.scalars(select(Participant)).one().email == "alice@example.org"


def test_admin_can_be_found_by_blind_index(db):
    db.add(AdminUser(email="admin@uni.example", password_hash="x"))
    db.commit()

    found = db.scalars(
        select(AdminUser).where(
            AdminUser.email_hash == crypto.email_blind_index("ADMIN@uni.example")
        )
    ).one()
    assert found.email == "admin@uni.example"


def test_same_email_in_other_case_is_rejected(db):
    db.add(make_participant("alice@example.org", "P001"))
    db.commit()
    db.add(make_participant("ALICE@example.org", "P002"))

    with pytest.raises(IntegrityError):
        db.commit()


def test_enum_check_constraint_rejects_unknown_values(db):
    db.add(make_model_version())
    db.commit()
    model_id = db.scalars(select(ModelVersion.id)).one().hex

    with pytest.raises(IntegrityError):
        db.execute(
            text(
                "INSERT INTO scans (id, model_version_id, sample_type, input_hash, score,"
                " decision, used_distilbert, created_at)"
                " VALUES (:id, :mv, 'url', :h, 0.5, 'maybe', 0, :now)"
            ),
            {"id": uuid.uuid4().hex, "mv": model_id, "h": "a" * 64, "now": NOW},
        )


def make_scan(version: ModelVersion, **overrides) -> Scan:
    values = dict(
        model_version_id=version.id,
        sample_type=Modality.URL,
        input_hash="a" * 64,
        url="http://example.test/login",
        score=0.95,
        decision=Decision.BLOCK,
    )
    return Scan(**{**values, **overrides})


@pytest.mark.parametrize("bad", [{"score": 1.5}, {"score": -0.1}, {"ti_score": 101.0}])
def test_scan_scores_must_be_in_range(db, bad):
    version = make_model_version()
    db.add(version)
    db.commit()
    db.add(make_scan(version, **bad))

    with pytest.raises(IntegrityError):
        db.commit()


def test_warn_threshold_must_be_below_block(db):
    db.add(make_model_version(block_threshold=0.6, warn_threshold=0.9))

    with pytest.raises(IntegrityError):
        db.commit()


def test_scan_features_need_exactly_140_values(db):
    version = make_model_version()
    db.add(version)
    db.commit()
    scan = make_scan(version)
    db.add(scan)
    db.commit()

    with pytest.raises(ValueError, match="expected 140"):
        ScanFeatures(scan_id=scan.id, extractor_version="0.1", values=[0.0] * 139)

    db.add(ScanFeatures(scan_id=scan.id, extractor_version="0.1", values=[0.5] * 140))
    db.commit()
    assert len(db.get(ScanFeatures, scan.id).values) == 140


def test_deleting_a_participant_removes_their_events_and_samples(db):
    template = Template(
        name="Fictional payroll notice",
        attack_category=AttackCategory.CREDENTIAL_HARVEST,
        fictional_org="Northwind Learning Trust",
        split=TemplateSplit.TRAIN,
    )
    participant = make_participant()
    db.add_all([template, participant])
    db.commit()
    campaign = Campaign(name="Round 1", template_id=template.id)
    db.add(campaign)
    db.commit()
    clicked = SimulationEvent(
        campaign_id=campaign.id,
        participant_id=participant.id,
        event_type=EventType.CLICKED,
        occurred_at=NOW,
    )
    db.add(clicked)
    db.commit()
    db.add(
        SimulationSample(
            simulation_event_id=clicked.id,
            template_id=template.id,
            content_ref="data/simulation/s1.eml",
            usage=SampleUsage.TRAIN,
            collected_month=date(2026, 11, 1),
        )
    )
    db.commit()

    db.delete(participant)
    db.commit()

    assert db.scalar(select(func.count()).select_from(SimulationEvent)) == 0
    assert db.scalar(select(func.count()).select_from(SimulationSample)) == 0
    assert db.scalar(select(func.count()).select_from(Campaign)) == 1


def test_simulation_events_have_no_column_for_submitted_data():
    columns = set(SimulationEvent.__table__.columns.keys())

    assert columns == {"id", "campaign_id", "participant_id", "event_type", "occurred_at"}
