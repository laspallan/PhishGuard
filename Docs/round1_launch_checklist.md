# Round 1 — launch checklist (click-by-click)

A short, do-this-then-that sheet for running Round 1 from the dashboard **Simulation** page.
It assumes Steps 1–2 of `Docs/simulation_runbook.md` are done (they are: GoPhish API key in `.env`,
sending profile **`round1-sender`** saved and test-mailed). Nothing here sends an email until the
**Launch** button at step D, and only to participants with recorded consent.

**Key facts to have ready**
- Dashboard: http://localhost:5173 → sign in with `PHISHGUARD_API_KEY` → **Simulation**.
- Sending profile name (the `smtp` value at launch): **`round1-sender`**.
- Landing page address (the GoPhish phishing server, the `url` value at launch): the base URL where
  GoPhish's **phishing server (port 8088)** is reachable **by the participants' browsers**. The fixed
  explanation page is served there automatically; you do not build it.
  - Same machine only (a local test with a mailbox you control): `http://127.0.0.1:8088`.
  - **Real Council staff clicking from their own devices:** `127.0.0.1` will NOT work for them — use
    the address of the host running GoPhish as they can reach it (its LAN IP/hostname, or a public
    name), with port 8088 exposed to them, e.g. `http://<server-ip>:8088`. Decide this with Kitonsa's
    ICT team before launch; it is the one network detail Round 1 depends on.
- Consent withdrawal deadline on the form: **11 January 2027**.

---

## A. Templates (Step 3 — may already be done)

1. Simulation → **Templates** → the **New template** form.
2. Load all 8 (metadata below; paste subject + HTML body from `Docs/simulation_templates.md`,
   with `{{.URL}}` where the link goes). Each appears in the "Saved templates" table.

| Name | Set | Organisation | Category |
|---|---|---|---|
| `library-expiry` | train | Kestrelmoor Institute | credential_harvest |
| `parcel-redelivery` | train | Parcelwren | brand_impersonation |
| `shared-invoice` | train | Lumacloud | malware |
| `room-booking` | train | Kestrelmoor Institute | spear |
| `mailbox-quota` | holdout | Kestrelmoor Institute | credential_harvest |
| `parcel-customs` | holdout | Parcelwren | brand_impersonation |
| `shared-agenda` | holdout | Lumacloud | malware |
| `lecture-seat` | holdout | Kestrelmoor Institute | spear |

> For Round 1 you launch a **train** template (e.g. `library-expiry`). Holdout templates are kept
> for the separate holdout measurement (Results §7.4) and are not used for training.

---

## B. Participants (Step 4) — only people who signed a consent form

For **each** returned, signed consent form, in Simulation → **Participants** → the
**New participant** form:

1. **Email address** — the volunteer's address (stored encrypted; never shown again).
2. **Participant code** — a short code you choose (e.g. `P001`). This is the only identifier any
   screen or report shows; actions are never tied back to a name.
3. **Consent form version** — the version string on the form they signed (e.g. `v1`).
4. **Consent given on** — the date they signed.
5. **Register participant** → it appears in the "Registered participants" table as **Active**.

Rules:
- Do **not** register anyone without a signed form.
- A person who later withdraws: **Withdraw** (excludes them from new campaigns; later events
  dropped), then, if they ask for erasure, **Delete** (removes their record, events, samples and
  their address from GoPhish's groups).

---

## C. Create the draft campaign (Step 5a)

1. Simulation → **Campaigns** → the **New campaign** form (appears once at least one template
   exists).
2. **Campaign name** — e.g. `round1`.
3. **Template** — pick a **train** template (e.g. `library-expiry (Kestrelmoor Institute, train)`).
4. **Create draft** → the campaign appears in the list with status **draft** and a launch form.

---

## D. Launch (Step 5b) — THIS SENDS REAL EMAIL

In the draft campaign's launch form:

1. **Participants (active only)** — tick each consented participant to include.
2. **GoPhish sending profile** — type **`round1-sender`**.
3. **Landing page address** — type **`http://127.0.0.1:8088`**.
4. **Launch** → confirm the "sends real emails" prompt.

What happens in code before anything is sent (all re-checked; any failure sends nothing and shows
the reason): ethics reference is set, the campaign is a draft, the template is fictional-brand-clean,
a contact address is present, and **only non-withdrawn consented participants are included**.

> The Launch button is disabled with "Locked until the ethics approval reference is set" if
> `simulations_allowed` is false. It is currently **true**, so launch is enabled.

---

## E. During and after the round (Step 6)

1. **Fetch events** (safe to repeat) — pulls opens/clicks/reports from GoPhish into PhishGuard. The
   message tells you how many new events were saved.
2. When the round is over: **Complete** — GoPhish stops tracking it. A click produces a training
   sample made only from the **template's own text** (no participant data); these feed RQ3 later and
   can never enter the locked test set.
3. After events are saved, optionally **Erase GoPhish results** — deletes the addresses/IPs from
   GoPhish while PhishGuard keeps the events it already fetched.

---

## F. What Claude does around this (not the lure, not the launch)

- Confirms the 8 templates loaded (`GET /admin/simulation/templates`) and that the real-brand guard
  rejects a disallowed organisation name.
- Helps read the aggregate results on the **Campaigns** page (per-campaign sent/clicked/
  submitted/reported — never an individual's actions).
- Does the Results §7.4 analysis and write-up.
- Does **not** push/render template bodies, and does **not** run the RQ3 round command
  (`rq3.run_round`) — those are yours/your supervisor's, by design (safety tooling, independent of
  ethics approval). See `Docs/simulation_runbook.md` "Division of labour".

---

## One-line sanity checks (optional, from a terminal)

```
# templates loaded (expect 8):
curl -s -H "X-API-Key: <KEY>" http://127.0.0.1:8000/admin/simulation/templates | python -c "import sys,json;print(len(json.load(sys.stdin)),'templates')"
# participants registered (by code only):
curl -s -H "X-API-Key: <KEY>" http://127.0.0.1:8000/admin/simulation/participants | python -c "import sys,json;print(len(json.load(sys.stdin)),'participants')"
# simulations unlocked (expect true):
curl -s -H "X-API-Key: <KEY>" http://127.0.0.1:8000/admin/status | python -c "import sys,json;print('allowed:',json.load(sys.stdin)['simulations_allowed'])"
```
