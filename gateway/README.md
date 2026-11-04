# PhishGuard IMAP email gateway

Polls a test mailbox over IMAP, sends each new message to the PhishGuard API
(`POST /scan/email`), and acts on the verdict: block → quarantine folder, warn → `\Flagged`,
allow → leave it. Phase 7.

**Only mailboxes I control, or whose owners consented, are ever connected** (CLAUDE.md).

- Messages are read with `BODY.PEEK[]`, so they stay unread for the user.
- The last scanned UID (per UIDVALIDITY) is stored in `gateway_state.json`: each email is
  scanned once, also after a restart.
- If the API is down, rejects the key, or has no trained model yet (503), the gateway stops
  the round and retries the same email next time. It never acts on a guess.

Settings (environment, prefix `PHISHGUARD_GATEWAY_`): `IMAP_HOST`, `IMAP_PORT`,
`IMAP_USE_SSL`, `IMAP_USER`, `IMAP_PASSWORD`, `MAILBOX`, `API_BASE_URL`, `API_KEY`,
`QUARANTINE_FOLDER`, `CHECK_INTERVAL_SECONDS`, `STATE_FILE`.

```powershell
python -m pip install -r requirements.txt
python -m pytest            # offline: fake IMAP server, mocked API
python imap_gateway.py      # run (needs the settings above)
```

Dependencies: httpx (BSD-3-Clause), IMAPClient 4.1 (BSD-3-Clause), pydantic-settings (MIT).
