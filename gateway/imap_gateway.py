"""IMAP gateway: polls mailbox, scans emails via API, quarantines/warns."""
from __future__ import annotations

import email
import time

import httpx
from imapclient import IMAPClient

from config import GatewaySettings


class IMAPGateway:
    def __init__(self, settings: GatewaySettings):
        self.settings = settings

    def run_once(self):
        with IMAPClient(self.settings.imap_host, port=self.settings.imap_port, ssl=self.settings.imap_use_ssl) as client:
            client.login(self.settings.imap_user, self.settings.imap_password)
            client.select_folder("INBOX")
            messages = client.search(["UNSEEN"])
            for uid in messages:
                raw = client.fetch([uid], ["RFC822"])[uid][b"RFC822"]
                msg = email.message_from_bytes(raw)
                # Extract and scan
                try:
                    headers = self.settings
                    resp = httpx.post(
                        f"{self.settings.api_base_url}/scan/email",
                        json={"raw_email": raw.decode(errors="ignore")},
                        headers={"X-API-Key": self.settings.api_key} if self.settings.api_key else {},
                        timeout=30,
                    )
                    verdict = resp.json().get("verdict", "allow")
                    if verdict == "block":
                        client.move(uid, self.settings.quarantine_folder)
                    elif verdict == "warn":
                        client.add_flags(uid, [b"\\Flagged"])
                except Exception:
                    pass

    def run(self):
        while True:
            try:
                self.run_once()
            except Exception:
                pass
            time.sleep(self.settings.check_interval_seconds)


if __name__ == "__main__":
    settings = GatewaySettings()
    gw = IMAPGateway(settings)
    gw.run()
