# PhishGuard IMAP email gateway

Polls a test mailbox over IMAP, sends each new message to the PhishGuard API, and acts on
the verdict: block → quarantine folder, warn → tag the message, allow → leave it. Attachment
handling is limited to file type and hash. Built in Phase 7.

Only mailboxes I control are ever connected. Credentials come from environment variables
(see `../.env.example`).
