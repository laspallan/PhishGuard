"""Launching campaigns and storing what happened (Phase 6).

The rules that keep simulations safe are checked here, before GoPhish is contacted:
- no launch unless the university's ethics approval reference is set in the configuration;
- every target must be a participant with recorded consent that has not been withdrawn;
- the template must name a fictional organisation, and it must not be a real brand's name;
- the landing page is always the explanation page (`debrief.py`), made here for each campaign, so
  no campaign can use another page (promised in the ethics request).

Events of participants who withdrew are dropped, and an email address unknown to PhishGuard is
ignored (and only counted): the address is never logged.
"""

import logging
import uuid
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.core.crypto import email_blind_index
from phishguard.models import Campaign, Participant, SimulationEvent, SimulationSample, Template
from phishguard.models.enums import CampaignStatus, EventType, SampleUsage, TemplateSplit
from phishguard.services.features.lexicons import BRAND_DOMAINS
from phishguard.services.simulation.debrief import debrief_page
from phishguard.services.simulation.gophish import GoPhishClient, TimelineEvent

REAL_BRANDS = frozenset(BRAND_DOMAINS)

log = logging.getLogger(__name__)

FAILED_EVENTS = (EventType.CLICKED, EventType.SUBMITTED)


class SimulationNotAllowedError(RuntimeError):
    """A safety rule forbids this campaign."""


def active_participants(session: Session, participant_ids: list[uuid.UUID]) -> list[Participant]:
    """The participants, or an error if any of them has not consented or has withdrawn."""
    found = session.scalars(select(Participant).where(Participant.id.in_(participant_ids))).all()
    if len(found) != len(set(participant_ids)):
        raise SimulationNotAllowedError("a target is not a registered participant")
    if any(p.consent_withdrawn_at is not None or p.consent_given_at is None for p in found):
        raise SimulationNotAllowedError("a target has no active consent")
    return list(found)


def check_template(template: Template, real_brands: frozenset[str]) -> None:
    org = template.fictional_org.strip().lower()
    if not org:
        raise SimulationNotAllowedError("the template names no fictional organisation")
    if org in real_brands or template.name.strip().lower() in real_brands:
        raise SimulationNotAllowedError("the template uses a real brand's name")


def launch(
    session: Session,
    client: GoPhishClient,
    *,
    ethics_approval_ref: str | None,
    campaign: Campaign,
    participant_ids: list[uuid.UUID],
    contact_email: str | None,
    smtp: str,
    url: str,
    real_brands: frozenset[str] = REAL_BRANDS,
) -> Campaign:
    if not ethics_approval_ref:
        raise SimulationNotAllowedError("no ethics approval reference is configured")
    if campaign.status is not CampaignStatus.DRAFT:
        raise SimulationNotAllowedError("only a draft campaign can be launched")
    if not contact_email or "@" not in contact_email:
        raise SimulationNotAllowedError("the explanation page needs a contact address")
    template = session.get(Template, campaign.template_id)
    check_template(template, real_brands)
    participants = active_participants(session, participant_ids)
    emails = [p.email for p in participants]
    name = f"pg-{campaign.id}"
    client.create_page(name, debrief_page(template.fictional_org, contact_email))
    client.create_group(name, emails)
    created = client.create_campaign(
        campaign.name, template=template.name, page=name, smtp=smtp, url=url, group=name
    )
    campaign.gophish_campaign_id = created["id"]
    campaign.status = CampaignStatus.RUNNING
    campaign.launched_at = datetime.now(UTC)
    session.commit()
    return campaign


def store_events(session: Session, campaign: Campaign, events: list[TimelineEvent]) -> dict:
    """Saves new events once; safe to call again with the same results."""
    counts = {"saved": 0, "already_saved": 0, "unknown_address": 0, "withdrawn": 0}
    for event in events:
        participant = session.scalar(
            select(Participant).where(Participant.email_hash == email_blind_index(event.email))
        )
        if participant is None:
            counts["unknown_address"] += 1
            continue
        if participant.consent_withdrawn_at is not None:
            counts["withdrawn"] += 1
            continue
        exists = session.scalar(
            select(SimulationEvent.id).where(
                SimulationEvent.campaign_id == campaign.id,
                SimulationEvent.participant_id == participant.id,
                SimulationEvent.event_type == event.event_type,
                SimulationEvent.occurred_at == event.occurred_at,
            )
        )
        if exists is not None:
            counts["already_saved"] += 1
            continue
        session.add(
            SimulationEvent(
                campaign_id=campaign.id,
                participant_id=participant.id,
                event_type=event.event_type,
                occurred_at=event.occurred_at,
            )
        )
        counts["saved"] += 1
    session.commit()
    return counts


def sample_usage(template: Template) -> SampleUsage:
    """Holdout templates become the simulation-holdout set, never training data. There is no
    value for the locked test set: it is a frozen file outside the database."""
    return SampleUsage.SIM_HOLDOUT if template.split is TemplateSplit.HOLDOUT else SampleUsage.TRAIN


def convert_failures(session: Session, campaign: Campaign, *, content_ref: str) -> int:
    """One sample per failed event (click or submission) of this campaign. The sample is the
    template's own content (`content_ref`): the same text for everyone, no participant data."""
    template = session.get(Template, campaign.template_id)
    failed = session.scalars(
        select(SimulationEvent)
        .join(Participant, SimulationEvent.participant_id == Participant.id)
        .where(
            SimulationEvent.campaign_id == campaign.id,
            SimulationEvent.event_type.in_(FAILED_EVENTS),
            Participant.consent_withdrawn_at.is_(None),
        )
    ).all()
    made = 0
    for event in failed:
        if session.scalar(
            select(SimulationSample.id).where(SimulationSample.simulation_event_id == event.id)
        ):
            continue
        session.add(
            SimulationSample(
                simulation_event_id=event.id,
                template_id=template.id,
                content_ref=content_ref,
                usage=sample_usage(template),
                collected_month=date(event.occurred_at.year, event.occurred_at.month, 1),
            )
        )
        made += 1
    session.commit()
    return made
