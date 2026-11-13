"""Campaign-management endpoints on SQLite, with GoPhish faked. Nothing is sent."""

import json

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from phishguard.controllers import simulation_controller
from phishguard.core.config import Settings, get_settings
from phishguard.db.session import get_db
from phishguard.main import create_app
from phishguard.services.simulation.gophish import GoPhishClient

KEY = {"X-API-Key": "k"}
TEMPLATE = {
    "name": "library-expiry", "subject": "Your library account expires",
    "html": "<a href='{{.URL}}'>x</a>",
    "fictional_org": "Kestrelmoor Institute", "attack_category": "credential_harvest",
    "split": "train",
}  # fmt: skip
CONSENT = {"consent_form_version": "1.0", "consent_given_at": "2026-11-08T10:00:00Z"}


class FakeGoPhish:
    def __init__(self):
        self.requests: list[httpx.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        if request.url.path == "/api/groups/" and request.method == "GET":
            targets = [{"email": "private@test.example"}, {"email": "other@test.example"}]
            return httpx.Response(200, json=[
                {"id": 3, "name": "pg-x", "targets": targets},
                {"id": 4, "name": "pg-y", "targets": [{"email": "PRIVATE@test.example"}]},
                {"id": 5, "name": "someone-elses", "targets": [{"email": "private@test.example"}]},
            ])  # fmt: skip
        if request.method in ("PUT", "DELETE"):
            return httpx.Response(200, json={"success": True})
        if request.url.path.endswith("/results"):
            timeline = [
                {"email": "private@test.example", "time": "2026-11-08T11:00:00Z",
                 "message": "Clicked Link", "details": ""},
            ]  # fmt: skip
            return httpx.Response(200, json={"timeline": timeline})
        return httpx.Response(201, json={"id": 7})

    def paths(self):
        return [r.url.path for r in self.requests]


def _app(sqlite_engine, tmp_path, monkeypatch, fake, **settings):
    config = Settings(
        _env_file=None, environment="test", api_key="k", data_dir=tmp_path, **settings
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: config

    def session():
        with Session(sqlite_engine) as db:
            yield db

    app.dependency_overrides[get_db] = session

    def client(_settings):  # a new client per request, like the real one (each is closed after)
        transport = httpx.MockTransport(fake)
        return GoPhishClient("https://gophish.test", "g", client=httpx.Client(transport=transport))

    monkeypatch.setattr(simulation_controller, "_client", client)
    return TestClient(app)


@pytest.fixture
def fake():
    return FakeGoPhish()


@pytest.fixture
def approved(sqlite_engine, crypto_keys, tmp_path, monkeypatch, fake):
    return _app(
        sqlite_engine, tmp_path, monkeypatch, fake,
        ethics_approval_ref="UNI-2026-001", simulation_contact_email="study@test.example",
    )  # fmt: skip


@pytest.fixture
def not_approved(sqlite_engine, crypto_keys, tmp_path, monkeypatch, fake):
    return _app(
        sqlite_engine, tmp_path, monkeypatch, fake, simulation_contact_email="s@test.example"
    )


def _draft(api):
    template = api.post("/admin/simulation/templates", json=TEMPLATE, headers=KEY).json()["id"]
    person = api.post(
        "/admin/simulation/participants",
        json={"email": "private@test.example", "participant_code": "P1", **CONSENT}, headers=KEY,
    ).json()["id"]  # fmt: skip
    campaign = api.post(
        "/admin/simulation/campaigns", json={"name": "c1", "template_id": template}, headers=KEY
    ).json()
    assert campaign["status"] == "draft"
    return campaign["id"], person


def _launch(api, campaign, people):
    return api.post(
        f"/admin/simulation/campaigns/{campaign}/launch",
        json={"participant_ids": people, "smtp": "s", "url": "http://sim.test"}, headers=KEY,
    )  # fmt: skip


def test_every_endpoint_needs_the_key(approved):
    assert approved.post("/admin/simulation/templates", json=TEMPLATE).status_code == 401


def test_a_whole_campaign_and_no_answer_names_a_participant(approved, fake):
    campaign, person = _draft(approved)
    launched = _launch(approved, campaign, [person])
    assert launched.status_code == 200 and launched.json()["status"] == "running"
    page = json.loads(next(r.content for r in fake.requests if r.url.path == "/api/pages/"))
    assert "This was a simulated phishing email" in page["html"]
    synced = approved.post(f"/admin/simulation/campaigns/{campaign}/sync", headers=KEY)
    assert synced.json()["saved"] == 1
    done = approved.post(f"/admin/simulation/campaigns/{campaign}/complete", headers=KEY)
    assert done.json()["status"] == "completed"
    summary = approved.get("/admin/campaigns", headers=KEY)
    assert summary.json()[0]["participants_by_event"] == {"clicked": 1}
    for response in (launched, synced, done, summary):
        assert "private@" not in response.text and "P1" not in response.text


def test_nothing_is_sent_without_ethics_approval(not_approved, fake):
    campaign, person = _draft(not_approved)
    sent_before = list(fake.paths())
    response = _launch(not_approved, campaign, [person])
    assert response.status_code == 403 and "ethics" in response.json()["detail"]
    assert fake.paths() == sent_before  # only the template was created, nothing launched


def test_withdrawn_participants_cannot_be_targeted(approved):
    campaign, person = _draft(approved)
    assert (
        approved.post(f"/admin/simulation/participants/{person}/withdraw", headers=KEY).json()[
            "status"
        ]
        == "withdrawn"
    )
    response = _launch(approved, campaign, [person])
    assert response.status_code == 403 and "consent" in response.json()["detail"]


def test_real_brands_and_duplicates_are_refused(approved, fake):
    real = approved.post(
        "/admin/simulation/templates", json={**TEMPLATE, "fictional_org": "PayPal"}, headers=KEY
    )
    assert real.status_code == 422 and fake.requests == []
    _draft(approved)
    again = approved.post(
        "/admin/simulation/participants",
        json={"email": "PRIVATE@test.example", "participant_code": "P2", **CONSENT}, headers=KEY,
    )  # fmt: skip
    assert again.status_code == 409
    assert "private@" not in again.text.lower()


def test_the_lists_give_ids_and_never_an_email_address(approved):
    campaign, person = _draft(approved)
    approved.post(f"/admin/simulation/participants/{person}/withdraw", headers=KEY)
    templates = approved.get("/admin/simulation/templates", headers=KEY)
    people = approved.get("/admin/simulation/participants", headers=KEY)
    found = approved.get("/admin/simulation/campaigns", headers=KEY)
    assert templates.json()[0]["fictional_org"] == "Kestrelmoor Institute"
    assert people.json()[0]["participant_code"] == "P1" and people.json()[0]["withdrawn"] is True
    assert found.json()[0] == {
        "id": campaign, "name": "c1", "template_name": "library-expiry", "status": "draft",
        "launched_at": None, "completed_at": None,
    }  # fmt: skip
    for response in (templates, people, found):
        assert "private@" not in response.text and "email" not in response.json()[0]
    assert approved.get("/admin/simulation/participants").status_code == 401


def test_a_withdrawn_participant_is_deleted_here_and_from_phishguards_gophish_groups(
    approved, fake, sqlite_engine
):
    campaign, person = _draft(approved)
    _launch(approved, campaign, [person])
    url = f"/admin/simulation/participants/{person}/delete"
    assert approved.post(url, headers=KEY).status_code == 409  # not withdrawn yet
    approved.post(f"/admin/simulation/participants/{person}/withdraw", headers=KEY)
    answer = approved.post(url, headers=KEY)
    assert answer.status_code == 200
    assert answer.json() == {
        "deleted": True, "gophish_groups_changed": 2, "gophish_campaigns_still_holding_results": 1
    }  # fmt: skip
    put = next(r for r in fake.requests if r.method == "PUT")
    assert put.url.path == "/api/groups/3"
    assert json.loads(put.content)["targets"] == [{"email": "other@test.example"}]
    deleted = [r.url.path for r in fake.requests if r.method == "DELETE"]
    assert deleted == ["/api/groups/4"]  # emptied; "someone-elses" was never touched
    assert approved.get("/admin/simulation/participants", headers=KEY).json() == []
    assert "private@" not in answer.text


def test_gophish_results_are_erased_only_for_a_completed_campaign(approved, fake):
    campaign, person = _draft(approved)
    _launch(approved, campaign, [person])
    url = f"/admin/simulation/campaigns/{campaign}/erase-gophish"
    assert approved.post(url, headers=KEY).status_code == 409  # still running
    approved.post(f"/admin/simulation/campaigns/{campaign}/complete", headers=KEY)
    assert approved.post(url, headers=KEY).json()["status"] == "gophish_results_erased"
    assert [r.url.path for r in fake.requests if r.method == "DELETE"] == ["/api/campaigns/7"]
    assert approved.post(url, headers=KEY).status_code == 409  # nothing left to erase


def test_deleting_before_any_launch_needs_no_gophish(not_approved, fake, monkeypatch):
    _, person = _draft(not_approved)
    monkeypatch.setattr(simulation_controller, "_client", lambda _s: pytest.fail("no GoPhish"))
    not_approved.post(f"/admin/simulation/participants/{person}/withdraw", headers=KEY)
    answer = not_approved.post(f"/admin/simulation/participants/{person}/delete", headers=KEY)
    assert answer.json()["deleted"] is True and answer.json()["gophish_groups_changed"] == 0


def test_the_gophish_certificate_is_always_checked(tmp_path, monkeypatch):
    seen = []
    real = httpx.Client
    monkeypatch.setattr(
        simulation_controller.httpx, "Client", lambda **kw: seen.append(kw["verify"]) or real()
    )
    base = {"_env_file": None, "gophish_url": "https://gophish.test", "gophish_api_key": "g"}
    simulation_controller._client(Settings(**base)).close()
    assert seen == [True]
    missing = Settings(**base, gophish_ca_file=tmp_path / "missing.crt")
    with pytest.raises(HTTPException) as refused:
        simulation_controller._client(missing)
    assert refused.value.status_code == 503 and "certificate" in refused.value.detail


def test_unknown_ids_and_unlaunched_campaigns(approved):
    campaign, _ = _draft(approved)
    missing = "00000000-0000-4000-8000-000000000000"
    assert (
        approved.post(f"/admin/simulation/campaigns/{missing}/sync", headers=KEY).status_code == 404
    )
    assert (
        approved.post(f"/admin/simulation/campaigns/{campaign}/sync", headers=KEY).status_code
        == 409
    )
    assert (
        approved.post(f"/admin/simulation/campaigns/{campaign}/complete", headers=KEY).status_code
        == 409
    )
