"""IMAP gateway (Phase 7): scans new emails through the PhishGuard API, quarantines or flags.

Use only with mailboxes you control or whose owners consented (CLAUDE.md safety rules).

- Messages are fetched with BODY.PEEK[], so the gateway never marks the user's mail as read.
- The last scanned UID (per UIDVALIDITY) is kept in a state file, so each email is scanned
  once, also across restarts.
- Fail safe: if the API is down, answers an error, or has no trained model yet (503), the
  gateway stops this round and retries the same email next time. It never acts on a guess.
- block -> moved to the quarantine folder; warn -> \\Flagged; allow -> left alone.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from config import GatewaySettings

log = logging.getLogger("phishguard.gateway")
ACTIONS = ("block", "warn", "allow")


class ScanUnavailableError(RuntimeError):
    """The API could not give a verdict; retry this email later."""


class IMAPGateway:
    def __init__(
        self,
        settings: GatewaySettings,
        *,
        imap_factory: Callable[[GatewaySettings], Any] | None = None,
        http: httpx.Client | None = None,
    ):
        self.settings = settings
        self.imap_factory = imap_factory or _imapclient_factory
        self.http = http or httpx.Client(timeout=30)

    # --- state -----------------------------------------------------------------------------
    def _load_state(self) -> dict[str, Any]:
        try:
            return json.loads(self.settings.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, state: dict[str, Any]) -> None:
        self.settings.state_file.write_text(json.dumps(state), encoding="utf-8")

    # --- scanning --------------------------------------------------------------------------
    def scan(self, raw: bytes) -> str:
        headers = {}
        if self.settings.api_key.get_secret_value():
            headers["X-API-Key"] = self.settings.api_key.get_secret_value()
        try:
            response = self.http.post(
                f"{self.settings.api_base_url}/scan/email",
                json={"raw_email": raw.decode("utf-8", errors="replace")},
                headers=headers,
            )
        except httpx.HTTPError as error:
            raise ScanUnavailableError(f"API not reachable: {type(error).__name__}") from error
        if response.status_code != 200:
            raise ScanUnavailableError(f"API answered HTTP {response.status_code}")
        verdict = (response.json() or {}).get("verdict")
        if verdict not in ACTIONS:
            raise ScanUnavailableError(f"unexpected verdict {verdict!r}")
        return verdict

    def run_once(self) -> dict[str, int]:
        """Scan every email that arrived since the last round. Returns counts per action."""
        counts = {action: 0 for action in ACTIONS}
        state = self._load_state()
        with self.imap_factory(self.settings) as client:
            client.login(self.settings.imap_user, self.settings.imap_password.get_secret_value())
            selected = client.select_folder(self.settings.mailbox, readonly=False)
            validity = str(selected.get(b"UIDVALIDITY", b""))
            key = f"{self.settings.mailbox}:{validity}"
            last_uid = int(state.get(key, 0))
            # "n:*" also returns the last UID when nothing is newer (IMAP rule), hence the filter
            found = client.search(["UID", f"{last_uid + 1}:*"])
            uids = sorted(uid for uid in found if uid > last_uid)
            if uids and not client.folder_exists(self.settings.quarantine_folder):
                client.create_folder(self.settings.quarantine_folder)
            for uid in uids:
                raw = client.fetch([uid], ["BODY.PEEK[]"])[uid][b"BODY[]"]
                try:
                    verdict = self.scan(raw)
                except ScanUnavailableError as error:
                    log.warning("UID %s not scanned (%s); retrying next round", uid, error)
                    break
                if verdict == "block":
                    client.move([uid], self.settings.quarantine_folder)
                elif verdict == "warn":
                    client.add_flags([uid], [b"\\Flagged"])
                counts[verdict] += 1
                log.info("UID %s: %s", uid, verdict)
                state[key] = uid
                self._save_state(state)
        return counts

    def run(self) -> None:
        while True:
            try:
                log.info("round: %s", self.run_once())
            except Exception:  # keep the service alive; the error is logged, not hidden
                log.exception("gateway round failed")
            time.sleep(self.settings.check_interval_seconds)


def _imapclient_factory(settings: GatewaySettings):
    from imapclient import IMAPClient

    return IMAPClient(settings.imap_host, port=settings.imap_port, ssl=settings.imap_use_ssl)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    IMAPGateway(GatewaySettings()).run()
