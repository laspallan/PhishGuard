"""Managing simulations from the dashboard. Every safety rule stays in services/simulation:
this controller only looks things up, calls those services and turns refusals into HTTP errors."""

import ssl
import uuid
from datetime import UTC, datetime

import httpx
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phishguard.core.config import Settings
from phishguard.core.crypto import email_blind_index
from phishguard.models import Campaign, Participant, Template
from phishguard.models.enums import CampaignStatus
from phishguard.schemas.simulation import CampaignIn, LaunchIn, ParticipantIn, TemplateIn
from phishguard.services.simulation import campaigns
from phishguard.services.simulation.campaigns import SimulationNotAllowedError
from phishguard.services.simulation.gophish import GoPhishClient, GoPhishError


def _client(settings: Settings) -> GoPhishClient:
    """Certificates are always checked: against PHISHGUARD_GOPHISH_CA_FILE when it is set."""
    if not (settings.gophish_url and settings.gophish_api_key):
        raise HTTPException(503, "GoPhish is not configured")
    verify: ssl.SSLContext | bool = True
    if settings.gophish_ca_file is not None:
        try:
            verify = ssl.create_default_context(cafile=str(settings.gophish_ca_file))
        except (OSError, ssl.SSLError):
            raise HTTPException(503, "the GoPhish certificate file cannot be read") from None
    return GoPhishClient(
        settings.gophish_url,
        settings.gophish_api_key.get_secret_value(),
        client=httpx.Client(timeout=30, verify=verify),
    )


def _get(session: Session, model, item_id: uuid.UUID):
    item = session.get(model, item_id)
    if item is None:
        raise HTTPException(404, f"{model.__name__.lower()} not found")
    return item


class SimulationController:
    def templates(self, session: Session) -> list[dict]:
        rows = session.scalars(select(Template).order_by(Template.created_at.desc()))
        return [
            {
                "id": t.id,
                "name": t.name,
                "fictional_org": t.fictional_org,
                "attack_category": t.attack_category.value,
                "split": t.split.value,
            }  # fmt: skip
            for t in rows
        ]

    def participants(self, session: Session) -> list[dict]:
        rows = session.scalars(select(Participant).order_by(Participant.participant_code))
        return [
            {
                "id": p.id,
                "participant_code": p.participant_code,
                "consent_form_version": p.consent_form_version,
                "consent_given_at": p.consent_given_at,
                "withdrawn": p.consent_withdrawn_at is not None,
            }  # fmt: skip
            for p in rows
        ]

    def campaigns(self, session: Session) -> list[dict]:
        rows = session.execute(
            select(Campaign, Template.name)
            .join(Template, Campaign.template_id == Template.id)
            .order_by(Campaign.created_at.desc())
        )
        return [
            {
                "id": c.id,
                "name": c.name,
                "template_name": name,
                "status": c.status.value,
                "launched_at": c.launched_at,
                "completed_at": c.completed_at,
            }  # fmt: skip
            for c, name in rows
        ]

    def create_template(self, session: Session, settings: Settings, body: TemplateIn) -> dict:
        template = Template(
            name=body.name, attack_category=body.attack_category,
            fictional_org=body.fictional_org.strip(), split=body.split,
        )  # fmt: skip
        try:
            campaigns.check_template(template, campaigns.REAL_BRANDS)
        except SimulationNotAllowedError as error:
            raise HTTPException(422, str(error)) from None
        if session.scalar(select(Template.id).where(Template.name == body.name)):
            raise HTTPException(409, "a template with this name exists")
        client = _client(settings)
        try:
            created = client.create_template(body.name, body.subject, body.html, body.text)
        except GoPhishError as error:
            raise HTTPException(502, str(error)) from None
        finally:
            client.close()
        template.gophish_template_id = created["id"]
        session.add(template)
        session.commit()
        return {"id": template.id}

    def add_participant(self, session: Session, body: ParticipantIn) -> dict:
        exists = select(Participant.id).where(
            (Participant.email_hash == email_blind_index(body.email))
            | (Participant.participant_code == body.participant_code)
        )
        if session.scalar(exists):
            raise HTTPException(409, "this participant is already registered")
        participant = Participant(
            email=body.email, participant_code=body.participant_code,
            consent_form_version=body.consent_form_version,
            consent_given_at=body.consent_given_at,
        )  # fmt: skip
        session.add(participant)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            raise HTTPException(409, "this participant is already registered") from None
        return {"id": participant.id}

    def withdraw(self, session: Session, participant_id: uuid.UUID) -> dict:
        """From now on: no new campaign can target them, and their events are dropped."""
        participant = _get(session, Participant, participant_id)
        if participant.consent_withdrawn_at is None:
            participant.consent_withdrawn_at = datetime.now(UTC)
            session.commit()
        return {"id": participant.id, "status": "withdrawn"}

    def create_campaign(self, session: Session, body: CampaignIn) -> dict:
        _get(session, Template, body.template_id)
        campaign = Campaign(name=body.name, template_id=body.template_id)
        session.add(campaign)
        session.commit()
        return {"id": campaign.id, "status": campaign.status.value}

    def launch(
        self, session: Session, settings: Settings, campaign_id: uuid.UUID, body: LaunchIn
    ) -> dict:
        campaign = _get(session, Campaign, campaign_id)
        client = _client(settings)
        try:
            campaigns.launch(
                session, client, ethics_approval_ref=settings.ethics_approval_ref,
                campaign=campaign, participant_ids=body.participant_ids,
                contact_email=settings.simulation_contact_email, smtp=body.smtp, url=body.url,
            )  # fmt: skip
        except SimulationNotAllowedError as error:
            raise HTTPException(403, str(error)) from None
        except GoPhishError as error:
            raise HTTPException(502, str(error)) from None
        finally:
            client.close()
        return {"id": campaign.id, "status": campaign.status.value}

    def sync(self, session: Session, settings: Settings, campaign_id: uuid.UUID) -> dict:
        campaign = _get(session, Campaign, campaign_id)
        if campaign.gophish_campaign_id is None:
            raise HTTPException(409, "this campaign has not been launched")
        client = _client(settings)
        try:
            events = client.campaign_events(campaign.gophish_campaign_id)
        except GoPhishError as error:
            raise HTTPException(502, str(error)) from None
        finally:
            client.close()
        return campaigns.store_events(session, campaign, events)

    def complete(self, session: Session, settings: Settings, campaign_id: uuid.UUID) -> dict:
        campaign = _get(session, Campaign, campaign_id)
        if campaign.status is not CampaignStatus.RUNNING:
            raise HTTPException(409, "only a running campaign can be completed")
        client = _client(settings)
        try:
            client.complete_campaign(campaign.gophish_campaign_id)
        except GoPhishError as error:
            raise HTTPException(502, str(error)) from None
        finally:
            client.close()
        campaign.status = CampaignStatus.COMPLETED
        campaign.completed_at = datetime.now(UTC)
        session.commit()
        return {"id": campaign.id, "status": campaign.status.value}
