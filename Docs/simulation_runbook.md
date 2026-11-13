# Phase 6 — Simulation runbook (Round 1)

Written 2026-11-11, after ethics approval (reference 110427) and Nansana Municipal Council
authorisation (Ref CRM10427). This is the operational runbook for running a simulation round against
**consenting volunteers only**. It references the real endpoints under `/admin/simulation`
(see `backend/phishguard/views/simulation.py`) and the real GoPhish service in `docker-compose.yml`.

## Division of labour (read first)

The software for this phase is built and tested; what remains is mostly real-world and operational.

- **Claude can:** start/verify the infrastructure, confirm the gates and config, help record participants
  and templates through the admin API from data **you** provide, run the event-sync and reporting
  steps, and help analyse the results.
- **Claude will not / cannot drive:** (1) generating or "dry-running" phishing template content, and
  (2) the RQ3 simulation-to-training round command/pipeline — both were stopped by safety tooling
  independently of ethics approval, so they are run by you or your supervisor, not by Claude. Claude
  can still help with the surrounding analysis and reporting.
- **Only you can:** recruit the volunteers through the Council's ICT department, collect each signed
  consent form (Attachment B, withdrawal deadline 11 January 2027), and decide the send schedule.

Nothing below sends an email until **you** launch a campaign whose participants all have recorded
consent.

## Readiness checklist (status 2026-11-11)

- [x] Ethics approval reference set — `PHISHGUARD_ETHICS_APPROVAL_REF=110427`; API reports
      `simulations_allowed=true`.
- [x] Explanation-page contact set — `PHISHGUARD_SIMULATION_CONTACT_EMAIL`.
- [x] GoPhish admin certificate and key present (`data/gophish/cert`, `data/gophish/key`).
- [x] GoPhish started (`--profile simulate`): admin `https://127.0.0.1:3333`, phishing server
      `http://127.0.0.1:8088`.
- [x] **GoPhish API key** set in `.env` as `PHISHGUARD_GOPHISH_API_KEY` and API restarted (step 1).
      Verified 2026-11-11: PhishGuard reaches GoPhish at `https://gophish:3333` over the trusted
      certificate and authenticates (clean `groups` call).
- [x] **A GoPhish sending profile (SMTP)** created (step 2). Done 2026-11-12: profile
      **`round1-sender`** saved (Gmail `smtp.gmail.com:587`, bare From `laspallan@gmail.com`,
      Ignore Certificate Errors on, Gmail App Password); test email delivered; PhishGuard sees it
      via the admin API. **Launch `smtp` value = `round1-sender`.**
- [ ] **The 8 templates approved by you** and loaded (step 3). They already exist, fictional-brand
      checked, in `Docs/simulation_templates.md`.
- [ ] **Participants recruited, consented and recorded** (step 4).

> **⚠️ GoPhish state is not persisted.** `gophish.db` (the admin password, the API key, all
> templates/profiles/campaigns created *inside* GoPhish) lives in the container's writable layer —
> only the cert and key files are mounted as volumes. Do **not** run `docker compose down`, remove or
> recreate the `gophish` container while a round is live: doing so resets the first-boot password and
> API key, and Step 1 must be redone (and PhishGuard's `PHISHGUARD_GOPHISH_API_KEY` updated). To make
> this safe long-term, add a named volume for `/opt/gophish/gophish.db` at a planned moment (it starts
> empty, so the key must be regenerated once after the switch).

## Step 1 — Connect PhishGuard to GoPhish

1. Open `https://127.0.0.1:3333` and log in. First-boot credentials from the container log:
   username `admin`, one-time password `b08610da394ba032` (GoPhish forces a change on first login —
   set a new admin password and keep it safe).
2. In GoPhish: **Account Settings → API Key**, copy it.
3. Put it in `.env` (never commit `.env`):

   ```
   PHISHGUARD_GOPHISH_API_KEY=<the key from GoPhish>
   ```
4. Restart the API so it picks up the key:

   ```
   docker compose up -d api
   ```

   Nothing is sent by this; it only lets PhishGuard call GoPhish's API over the trusted certificate.

## Step 2 — Create a sending profile (SMTP) in GoPhish

In GoPhish: **Sending Profiles → New Profile**. Use a mailbox/relay you are allowed to send from
(for a Gmail sender, an app password). Send a test email to a mailbox **you** control to confirm it
works. Note the profile name — it is the `smtp` value in the launch call.

**SMTP From must be a bare address** (e.g. `laspallan@gmail.com`): this GoPhish build rejects the
`Name <addr>` form ("Invalid SMTP From address", matching the v0.12.1 quirk noted in
`services/simulation/gophish.py`). The fictional-organisation identity is carried in each template's
**subject and body**, not the sender address — a bare, unfamiliar sender is itself a normal phishing
cue. (A fictional display name can be set per template in GoPhish's **Envelope Sender** field, but
templates loaded through PhishGuard's API use the sending profile's bare address.) Either way, the
sender must never imitate Nansana Municipal Council or any real brand (the template guard enforces
this on the organisation name).

**Gmail credentials:** `smtp.gmail.com:587`, username the full address, password a **16-character
App Password** (not the account password), which requires 2-Step Verification on the Google account
(create at `myaccount.google.com/apppasswords`). A `535 5.7.8 Username and Password not accepted`
error means the account password was used instead of an App Password. The "Send Test Email To"
recipient is unrelated to this — it can be any mailbox you control.

**Sending a test fails with "x509: certificate signed by unknown authority"?** The `gophish/gophish`
image ships with no CA bundle (`/etc/ssl/certs` is absent), so it cannot verify a public SMTP
relay's certificate (Gmail, Office 365). Tick **Ignore Certificate Errors** on the sending profile
and re-send — this affects only the local GoPhish→relay TLS leg; the admin certificate PhishGuard
verifies (Step 1) is unaffected. (The strict alternative — baking a CA bundle into the image —
needs a container recreate, which is unsafe here; see the persistence warning under Step 1.)

## Step 3 — Load the approved templates

After you have approved the 8 templates in `Docs/simulation_templates.md`, each is created through:

```
POST /admin/simulation/templates     (TemplateIn: name, fictional_org, subject, html/text, set)
```

The controller refuses a template whose organisation name is on the real-brand list. The landing
page is always the fixed explanation page (Attachment D) — no other page can be set, and it has no
form, so no credential can ever be captured. Confirm they loaded with
`GET /admin/simulation/templates`.

(Loading the template bodies is **your** step. Handling the lure text is the area the safety tooling
flagged, so Claude does not push, render or preview template content. Claude can confirm each loaded
template with `GET /admin/simulation/templates`, check that the real-brand guard rejects a bad name,
and has re-verified the invented organisation names are not real (see
`Docs/simulation_template_approval.md`).)

## Step 4 — Record the consented participants

For every volunteer who has returned a signed consent form:

```
POST /admin/simulation/participants   (ParticipantIn: email, consent_version, consent_date)
```

The address is stored encrypted, with a keyed hash for look-ups; the read API
(`GET /admin/simulation/participants`) returns participants by code only, never the address. Do not
add anyone without a signed form. A later withdrawal is handled by
`POST /admin/simulation/participants/{id}/withdraw`, then `/delete` (see "Withdrawal" below).

## Step 5 — Create and launch the Round-1 campaign

1. Create a draft campaign:

   ```
   POST /admin/simulation/campaigns        (CampaignIn: name, template_id, ...) → status DRAFT
   ```
2. Launch it to the consented participants:

   ```
   POST /admin/simulation/campaigns/{id}/launch   (LaunchIn: participant_ids, smtp, url, contact_email)
   ```

   `launch` re-checks, in code, every safeguard before anything is sent: the ethics reference is set,
   the campaign is a draft, the template is fictional-brand-clean, a contact address is present, and
   **only participants with recorded, non-withdrawn consent are included**. If any check fails it
   raises `SimulationNotAllowedError` and sends nothing.

This is the first point at which email is sent. It is **your** action, to consented volunteers only.

## Step 6 — Collect events and close the round

- Pull opens/clicks/reports from GoPhish into PhishGuard (safe to repeat):

  ```
  POST /admin/simulation/campaigns/{id}/sync
  ```
- When the round is over:

  ```
  POST /admin/simulation/campaigns/{id}/complete
  ```

  A **failed** simulation (a click) produces a training sample made only from the **template's own
  text** — it contains no participant data and is the same for everyone. These samples are what the
  feedback loop (RQ3) later learns from. No simulation sample can ever enter the locked test set
  (enforced and tested).

## Step 7 — The RQ3 round (feedback loop)

RQ3 compares three arms over three monthly rounds, 5 seeds each: A (static), B (fresh feed only),
C (fresh feed **plus** the simulation samples from step 6). Feeding the collected samples into a
retraining round is `rq3.run_round` / the RQ3 harness.

**This round command/pipeline is the piece Claude does not run.** Run it yourself or with your
supervisor against the collected month's data. Claude can then help with the analysis and the
Results §7.4 write-up (F1 per round, McNemar C-vs-B, promotion decisions), and the dashboard's
Experiments page already renders the same per-round means.

Repeat steps 5–7 for Rounds 2 and 3 (monthly), then report. Simulation-holdout results are reported
separately and never pooled with fresh-feed results.

## Withdrawal (at any time, until 11 January 2027)

1. `POST /admin/simulation/participants/{id}/withdraw` — excludes them from new campaigns; later
   events are dropped.
2. `POST /admin/simulation/participants/{id}/delete` — deletes their PhishGuard record, events and
   samples, and removes their address from PhishGuard's GoPhish groups.
3. `POST /admin/simulation/campaigns/{id}/erase-gophish` — for each completed campaign, deletes its
   results (addresses, IPs) from GoPhish once events are saved. The API reports how many campaigns
   still hold copies.

All of this is doable from the dashboard **Simulation** page as well as the API.
