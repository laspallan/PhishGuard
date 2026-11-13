"""GoPhish API client (Phase 6). Only endpoints checked on 2026-11-06 against the official docs
(docs.getgophish.com/api-documentation) and, for event names and capture, the source of v0.12.1.

Safety, enforced here and tested:
- Landing pages are always created with `capture_credentials` and `capture_passwords` off. GoPhish
  then removes the `name` of every form input, so the browser does not send the values at all,
  and the fact of a submission is still recorded as a "Submitted Data" event.
- Results are reduced to (email, event, time) as soon as they arrive. `details` of a timeline
  event can hold submitted form values, so it is never read, returned or logged.
- Nothing is sent by this module on its own: `create_campaign` is reachable only through
  `campaigns.launch`, which checks ethics approval and each participant's consent first.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from phishguard.models.enums import EventType

# The exact `message` strings of GoPhish (models/models.go).
EVENT_TYPES: Mapping[str, EventType] = {
    "Email Sent": EventType.SENT,
    "Email Opened": EventType.OPENED,
    "Clicked Link": EventType.CLICKED,
    "Submitted Data": EventType.SUBMITTED,
    "Email Reported": EventType.REPORTED,
}


class GoPhishError(RuntimeError):
    """GoPhish refused the request or could not be reached. Never holds a response body."""


@dataclass(frozen=True)
class TimelineEvent:
    """Everything PhishGuard keeps from a GoPhish event; there is no field for `details`."""

    email: str
    event_type: EventType
    occurred_at: datetime


def parse_timeline(timeline: list[Mapping[str, Any]] | None) -> list[TimelineEvent]:
    """Events about a participant. Others (e.g. "Campaign Created") have no type here."""
    events = []
    for item in timeline or []:
        event_type = EVENT_TYPES.get(item.get("message", ""))
        email = item.get("email")
        if event_type is None or not email:
            continue
        occurred_at = datetime.fromisoformat(str(item["time"]).replace("Z", "+00:00"))
        events.append(TimelineEvent(str(email).strip().lower(), event_type, occurred_at))
    return events


class GoPhishClient:
    def __init__(self, base_url: str, api_key: str, *, client: httpx.Client | None = None):
        self._client = client or httpx.Client(timeout=30)
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"}

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._client.request(
                method, f"{self._base}/api/{path}", headers=self._headers, **kwargs
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as error:
            # Only the status: a response body could carry participant data.
            status = error.response.status_code
            raise GoPhishError(f"{method} {path} failed: status {status}") from None
        except (httpx.HTTPError, ValueError) as error:
            raise GoPhishError(f"{method} {path} failed: {type(error).__name__}") from None

    def create_template(self, name: str, subject: str, html: str, text: str = "") -> dict:
        body = {"name": name, "subject": subject, "html": html, "text": text}
        return self._request("POST", "templates/", json=body)

    def create_page(self, name: str, html: str, redirect_url: str = "") -> dict:
        """Capture is off and cannot be turned on through this client."""
        body = {
            "name": name,
            "html": html,
            "capture_credentials": False,
            "capture_passwords": False,
            "redirect_url": redirect_url,
        }
        return self._request("POST", "pages/", json=body)

    def create_group(self, name: str, emails: list[str]) -> dict:
        """Targets carry only the address: GoPhish does not need names to send."""
        targets = [{"email": e, "first_name": "", "last_name": "", "position": ""} for e in emails]
        return self._request("POST", "groups/", json={"name": name, "targets": targets})

    def groups(self) -> list[dict]:
        return self._request("GET", "groups/")

    def update_group(self, group: dict) -> dict:
        """Replaces the group's targets; GoPhish needs at least one."""
        return self._request("PUT", f"groups/{group['id']}", json=group)

    def delete_group(self, group_id: int) -> dict:
        return self._request("DELETE", f"groups/{group_id}")

    def delete_campaign(self, campaign_id: int) -> dict:
        """Deletes the campaign and its results (addresses, IPs, browsers) from GoPhish."""
        return self._request("DELETE", f"campaigns/{campaign_id}")

    def create_sending_profile(self, name: str, *, host: str, from_address: str) -> dict:
        """`from_address` must be a bare address: real GoPhish 0.12.1 answered 500 to
        "Name <a@b.com>" and to addresses under .invalid (checked 2026-11-06)."""
        body = {
            "name": name,
            "host": host,
            "from_address": from_address,
            "interface_type": "SMTP",
            "ignore_cert_errors": False,
        }
        return self._request("POST", "smtp/", json=body)

    def create_campaign(
        self, name: str, *, template: str, page: str, smtp: str, url: str, group: str
    ) -> dict:
        body = {
            "name": name,
            "template": {"name": template},
            "page": {"name": page},
            "smtp": {"name": smtp},
            "url": url,
            "groups": [{"name": group}],
        }
        return self._request("POST", "campaigns/", json=body)

    def complete_campaign(self, campaign_id: int) -> dict:
        return self._request("GET", f"campaigns/{campaign_id}/complete")

    def campaign_events(self, campaign_id: int) -> list[TimelineEvent]:
        data = self._request("GET", f"campaigns/{campaign_id}/results")
        return parse_timeline(data.get("timeline"))

    def close(self) -> None:
        self._client.close()
