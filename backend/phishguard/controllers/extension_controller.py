"""What the browser extension needs besides scans: hosts to block before they load."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.models import Scan
from phishguard.models.enums import Modality
from phishguard.services import blocklist


class ExtensionController:
    def blocked_hosts(self, session: Session, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        rows = session.execute(
            select(Scan.url, Scan.decision, Scan.created_at).where(
                Scan.sample_type == Modality.URL,
                Scan.url.is_not(None),
                Scan.created_at >= now - timedelta(days=blocklist.SAFE_DAYS),
            )
        ).all()
        return {
            "hosts": blocklist.blocked_hosts(rows, now),
            "block_days": blocklist.BLOCK_DAYS,
            "generated_at": now,
        }
