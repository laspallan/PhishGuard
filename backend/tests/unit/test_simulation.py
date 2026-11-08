"""Simulation safety rules and the GoPhish client, with GoPhish mocked. Nothing is sent."""

import json
import logging
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import select, text

from phishguard.models import Campaign, Participant, SimulationEvent, SimulationSample, Template
from phishguard.models.enums import (
    AttackCategory,
    CampaignStatus,
    EventType,
    SampleUsage,
    TemplateSplit,
)
from phishguard.services.simulation import campaigns
from phishguard.services.simulation.campaigns import SimulationNotAllowedError
from phishguard.services.simulation.gophish import GoPhishClient, GoPhishError, parse_timeline

NOW = datetime(2026, 11, 6, tzinfo=UTC)
SECRET = "hunter2-Not-A-Real-Password"
BRANDS = frozenset({"paypal"})
TIMELINE = [
    {"email": "", "time": "2026-11-06T10:00:00Z", "message": "Campaign Created", "details": ""},
    {"email": "a@test.example", "time": "2026-11-06T10:01:00Z", "message": "Email Sent",
     "details": ""},
    {"email": "A@Test.Example", "time": "2026-11-06T10:02:00Z", "message": "Clicked Link",
     "details": json.dumps({"payload": {"rid": ["x"]}, "browser": {"address": "203.0.113.9"}})},
    {"email": "a@test.example", "time": "2026-11-06T10:03:00Z", "message": "Submitted Data",
     "details": json.dumps({"payload": {"password": [SECRET], "email": [SECRET]}, "browser": {}})},
    {"email": "a@test.example", "time": "2026-11-06T10:04:00Z", "message": "Email Reported",
     "details": ""},
]  # fmt: skip


class FakeGoPhish:
    """Records requests; answers like the documented API."""

    def __init__(self, timeline=TIMELINE):
        self.requests: list[httpx.Request] = []
        self.timeline = timeline

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.endswith("/results"):
            return httpx.Response(200, json={"id": 7, "results": [], "timeline": self.timeline})
        return httpx.Response(201, json={"id": 7})

    def bodies(self, path: str) -> list[dict]:
        return [json.loads(r.content) for r in self.requests if r.url.path == f"/api/{path}"]


def _client(fake) -> GoPhishClient:
    return GoPhishClient(
        "https://gophish.test:3333/", "k", client=httpx.Client(transport=httpx.MockTransport(fake))
    )


def _participant(session, email="a@test.example", code="P1", *, withdrawn=False) -> Participant:
    participant = Participant(
        email=email,
        participant_code=code,
        consent_form_version="v1",
        consent_given_at=NOW,
        consent_withdrawn_at=NOW if withdrawn else None,
    )
    session.add(participant)
    session.flush()
    return participant


def _campaign(session, split=TemplateSplit.TRAIN, org="Northwind Bank of Testland") -> Campaign:
    template = Template(
        name=f"t-{split.value}-{org[:8]}",
        attack_category=AttackCategory.CREDENTIAL_HARVEST,
        fictional_org=org,
        split=split,
    )
    session.add(template)
    session.flush()
    campaign = Campaign(name="c", template_id=template.id)
    session.add(campaign)
    session.flush()
    return campaign


def _launch(session, fake, campaign, ids, ethics="UNI-2026-001", contact="study@test.example"):
    return campaigns.launch(
        session, _client(fake), ethics_approval_ref=ethics, campaign=campaign,
        participant_ids=ids, contact_email=contact, smtp="s", url="http://sim.test",
        real_brands=BRANDS,
    )  # fmt: skip


# --- launching ------------------------------------------------------------------------------


def test_no_launch_without_ethics_approval(db):
    fake = FakeGoPhish()
    with pytest.raises(SimulationNotAllowedError, match="ethics"):
        _launch(db, fake, _campaign(db), [_participant(db).id], ethics=None)
    assert fake.requests == []


def test_no_launch_to_someone_who_withdrew(db):
    fake = FakeGoPhish()
    with pytest.raises(SimulationNotAllowedError, match="consent"):
        _launch(db, fake, _campaign(db), [_participant(db, withdrawn=True).id])
    assert fake.requests == []


def test_no_launch_to_someone_who_is_not_a_participant(db):
    import uuid

    fake = FakeGoPhish()
    with pytest.raises(SimulationNotAllowedError, match="registered"):
        _launch(db, fake, _campaign(db), [uuid.uuid4()])
    assert fake.requests == []


@pytest.mark.parametrize("org", ["PayPal", "  paypal ", ""])
def test_no_launch_with_a_real_brand_or_no_organisation(db, org):
    fake = FakeGoPhish()
    with pytest.raises(SimulationNotAllowedError):
        _launch(db, fake, _campaign(db, org=org), [_participant(db).id])
    assert fake.requests == []


def test_launch_sends_only_to_consenting_participants(db):
    fake = FakeGoPhish()
    campaign = _launch(db, fake, _campaign(db), [_participant(db).id])

    assert campaign.status is CampaignStatus.RUNNING and campaign.gophish_campaign_id == 7
    targets = fake.bodies("groups/")[0]["targets"]
    assert [t["email"] for t in targets] == ["a@test.example"]
    assert fake.requests[0].headers["Authorization"] == "Bearer k"


def test_every_campaign_lands_on_its_own_explanation_page(db):
    fake = FakeGoPhish()
    campaign = _launch(db, fake, _campaign(db), [_participant(db).id])
    page = fake.bodies("pages/")[0]
    assert "This was a simulated phishing email" in page["html"] and "<form" not in page["html"]
    assert "Northwind Bank of Testland is not a real organisation" in page["html"]
    assert page["capture_credentials"] is False
    assert (
        fake.bodies("campaigns/")[0]["page"]
        == {"name": page["name"]}
        == {"name": f"pg-{campaign.id}"}
    )


@pytest.mark.parametrize("contact", [None, "", "not-an-address"])
def test_no_launch_without_a_contact_address_for_the_page(db, contact):
    fake = FakeGoPhish()
    with pytest.raises(SimulationNotAllowedError, match="contact"):
        _launch(db, fake, _campaign(db), [_participant(db).id], contact=contact)
    assert fake.requests == []


def test_a_campaign_is_launched_once(db):
    fake = FakeGoPhish()
    campaign = _launch(db, fake, _campaign(db), [_participant(db).id])
    with pytest.raises(SimulationNotAllowedError, match="draft"):
        campaigns.launch(
            db, _client(fake), ethics_approval_ref="UNI", campaign=campaign,
            participant_ids=[], contact_email="study@test.example", smtp="s", url="http://x",
        )  # fmt: skip


# --- no credential value anywhere -----------------------------------------------------------


def test_landing_pages_cannot_turn_capture_on():
    fake = FakeGoPhish()
    _client(fake).create_page("p", "<form></form>")
    body = fake.bodies("pages/")[0]
    assert body["capture_credentials"] is False and body["capture_passwords"] is False


def test_parsed_events_have_no_field_for_details():
    events = parse_timeline(TIMELINE)
    assert SECRET not in repr(events)
    assert [e.event_type for e in events] == [
        EventType.SENT, EventType.CLICKED, EventType.SUBMITTED, EventType.REPORTED,
    ]  # fmt: skip
    assert events[1].email == "a@test.example"


def test_a_submitted_value_reaches_neither_database_nor_logs(db, caplog):
    """The worst case: GoPhish holds a submitted password. We pull results and look everywhere."""
    caplog.set_level(logging.DEBUG)
    participant = _participant(db)
    campaign = _campaign(db)
    events = _client(FakeGoPhish()).campaign_events(7)
    assert campaigns.store_events(db, campaign, events)["saved"] == 4
    assert campaigns.convert_failures(db, campaign, content_ref="templates/t1.json") == 2

    assert SECRET not in caplog.text
    for table in ("simulation_events", "simulation_samples", "participants", "campaigns"):
        for row in db.execute(text(f"SELECT * FROM {table}")):  # noqa: S608
            assert SECRET not in str(tuple(row))
    # There is a row for the submission: the fact is kept, the value is not.
    types = db.scalars(
        select(SimulationEvent.event_type).where(SimulationEvent.participant_id == participant.id)
    ).all()
    assert EventType.SUBMITTED in types
    assert "details" not in SimulationEvent.__table__.columns


def test_errors_do_not_carry_the_response_body():
    def refuse(request):
        return httpx.Response(500, json={"message": SECRET})

    with pytest.raises(GoPhishError) as error:
        _client(refuse).campaign_events(7)
    assert SECRET not in str(error.value)


# --- storing events -------------------------------------------------------------------------


def test_events_are_saved_once(db):
    _participant(db)
    campaign = _campaign(db)
    events = parse_timeline(TIMELINE)
    assert campaigns.store_events(db, campaign, events)["saved"] == 4
    again = campaigns.store_events(db, campaign, events)
    assert again["saved"] == 0 and again["already_saved"] == 4


def test_events_of_withdrawn_or_unknown_people_are_dropped(db):
    campaign = _campaign(db)
    events = parse_timeline(TIMELINE)
    assert campaigns.store_events(db, campaign, events)["unknown_address"] == 4
    _participant(db, withdrawn=True)
    assert campaigns.store_events(db, campaign, events)["withdrawn"] == 4
    assert db.scalars(select(SimulationEvent)).all() == []


# --- samples --------------------------------------------------------------------------------


def _with_failures(db, split):
    _participant(db)
    campaign = _campaign(db, split=split)
    campaigns.store_events(db, campaign, parse_timeline(TIMELINE))
    return campaign


@pytest.mark.parametrize(
    ("split", "usage"),
    [(TemplateSplit.TRAIN, SampleUsage.TRAIN), (TemplateSplit.HOLDOUT, SampleUsage.SIM_HOLDOUT)],
)
def test_samples_follow_the_template_split(db, split, usage):
    campaign = _with_failures(db, split)
    assert campaigns.convert_failures(db, campaign, content_ref="t.json") == 2
    samples = db.scalars(select(SimulationSample)).all()
    assert {s.usage for s in samples} == {usage}
    assert all(s.collected_month.day == 1 for s in samples)


def test_samples_are_only_clicks_and_submissions_and_made_once(db):
    campaign = _with_failures(db, TemplateSplit.TRAIN)
    assert campaigns.convert_failures(db, campaign, content_ref="t.json") == 2
    assert campaigns.convert_failures(db, campaign, content_ref="t.json") == 0


def test_there_is_no_way_to_mark_a_sample_for_the_locked_test_set():
    assert {u.value for u in SampleUsage} == {"train", "sim_holdout"}
