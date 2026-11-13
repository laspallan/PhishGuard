# Template approval sheet (Phase 6, before Round 1)

For the researcher (and supervisor) to formally approve the 8 simulation templates before they are
loaded. **The full template text is in `Docs/simulation_templates.md` — read each one there**; this
sheet is the catalogue and the checklist, not a copy of the lure content.

## The 8 templates (metadata only)

| # | Name | Set | Category | Invented organisation |
|---|---|---|---|---|
| T1 | library-expiry | train | credential_harvest | Kestrelmoor Institute |
| T2 | parcel-redelivery | train | brand_impersonation | Parcelwren |
| T3 | shared-invoice | train | malware | Lumacloud |
| T4 | room-booking | train | spear | Kestrelmoor Institute |
| H1 | mailbox-quota | holdout | credential_harvest | Kestrelmoor Institute |
| H2 | parcel-customs | holdout | brand_impersonation | Parcelwren |
| H3 | shared-agenda | holdout | malware | Lumacloud |
| H4 | lecture-seat | holdout | spear | Kestrelmoor Institute |

Four attack categories × a training and a holdout version. The holdout set is never used in training
— it only tests, so its results stay separate (Results §7.4).

## Criteria to confirm for every template (ethics request §3–4)

Tick each, reading the body in `Docs/simulation_templates.md`:

- [ ] **Fictional organisation only.** Named org is one of the three invented names, and the sender
      display name imitates neither Nansana Municipal Council nor any real brand.
      *(Names re-checked 2026-11-11 — none is a real organisation; see `decisions.md`.)*
- [ ] **Low-harm lure.** No mention of grades, assessment, pay, jobs, health, money owed, discipline
      or security incidents; the pretext is mildly inconvenient, not frightening.
- [ ] **Phishing cues left visible.** Ordinary signs (urgency, a vague sender, a "confirm" link)
      remain spottable by a careful reader — the study measures detection, not how well people can
      be tricked.
- [ ] **No personal data.** Generic greeting; the only link is `{{.URL}}`, which opens the fixed
      explanation page; the email ends with the organisation name only — no real addresses, phone
      numbers or logos.
- [ ] **Landing page.** The explanation page (Attachment D) is the only page; it has no form, so no
      credential can be entered or captured (enforced in `campaigns.check_template` and by GoPhish
      capture-off).

## Global checks (once)

- [ ] All four categories represented in both sets (table above).
- [ ] The three invented names re-searched immediately before Round 1 (repeat if the round slips).
- [ ] Each template's `set` (train / holdout) is correct, so no holdout template is ever used in
      training.

## Sign-off

I have read all 8 templates in `Docs/simulation_templates.md` and confirm they meet the criteria
above. They may be loaded for the study.

Researcher: Luswata Allan   Signature: ____________________   Date: ____________

Supervisor (optional): Christopher Ayesiga   Signature: ____________________   Date: ____________

## After sign-off

You load each approved template through `POST /admin/simulation/templates` (or the dashboard
**Simulation** page). Claude does not push the template bodies, but will confirm they loaded
(`GET /admin/simulation/templates`) and that the real-brand guard still rejects a disallowed name.
