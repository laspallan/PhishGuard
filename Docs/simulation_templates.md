# Simulation templates (draft, for approval)

Eight templates for the RQ3 rounds: one per attack category in each set. **Training** templates
make the samples arm C learns from; **holdout** templates are kept out of training and used only to
test (simulation-holdout set). Not yet loaded into PhishGuard or GoPhish, and not to be used before
the university approves them with the study.

## Rules these templates follow

- **Fictional organisations only.** Kestrelmoor Institute, Parcelwren (parcel delivery) and Lumacloud
  (file sharing) are invented. A web search on 2026-11-08 found no organisation using any of the three
  exact names. Near names exist: "Kestrel Institute" (a research centre), and "LumiCloud" and
  "Lumencloud" (security-camera and lighting services, not file sharing). CONFIRM before submitting,
  and search again before the first round. PhishGuard also refuses names on its real-brand list
  (checked: all three pass).
- **Low-harm lures.** Because the researcher's own students or staff may take part, no template
  mentions grades, assessment, pay, jobs, health, money owed, discipline or security incidents. Each
  is something mildly inconvenient to ignore, not frightening.
- **Ordinary phishing cues kept visible** (urgency, a vague sender, a link to "confirm"), so a careful
  reader can spot them; the study measures detection, not how well we can trick people.
- **No personal data.** PhishGuard sends GoPhish only the address, so templates greet generically.
- `{{.URL}}` is where GoPhish puts the simulation link; it always opens the explanation page.
- Every email ends with the organisation name only: no real addresses, phone numbers or logos.

| # | Name | Set | Category | Organisation |
|---|---|---|---|---|
| T1 | library-expiry | train | credential_harvest | Kestrelmoor Institute |
| T2 | parcel-redelivery | train | brand_impersonation | Parcelwren |
| T3 | shared-invoice | train | malware | Lumacloud |
| T4 | room-booking | train | spear | Kestrelmoor Institute |
| H1 | mailbox-quota | holdout | credential_harvest | Kestrelmoor Institute |
| H2 | parcel-customs | holdout | brand_impersonation | Parcelwren |
| H3 | shared-agenda | holdout | malware | Lumacloud |
| H4 | lecture-seat | holdout | spear | Kestrelmoor Institute |

Training and holdout templates in one category use a different pretext, so the holdout set tests
whether the model learnt the category, not the wording.

## Training set

### T1 library-expiry (credential_harvest)

**From:** Kestrelmoor Institute Library
**Subject:** Your library account expires in 3 days

Dear member,

Your Kestrelmoor Institute library account expires in 3 days. To keep access to your loans and
e-books, please confirm your account details here:

{{.URL}}

Library Services, Kestrelmoor Institute

### T2 parcel-redelivery (brand_impersonation)

**From:** Parcelwren Delivery
**Subject:** We could not deliver your parcel

Hello,

Our courier tried to deliver your parcel today but nobody was available. Choose a new delivery day
within 48 hours, or the parcel will be returned to the sender:

{{.URL}}

Parcelwren Customer Service

### T3 shared-invoice (malware)

**From:** Lumacloud
**Subject:** A document has been shared with you: Invoice_0427.pdf

Hello,

A colleague has shared a document with you on Lumacloud.

Invoice_0427.pdf (212 KB)

Open the document: {{.URL}}

This link expires in 7 days. Lumacloud file sharing

### T4 room-booking (spear)

**From:** Kestrelmoor Institute Facilities
**Subject:** Action needed: your room booking for next week

Hello,

A room booking made under your department for next Tuesday has a conflict with another event. Please
confirm whether you still need the room by tomorrow, or it will be released:

{{.URL}}

Facilities Office, Kestrelmoor Institute

## Holdout set

### H1 mailbox-quota (credential_harvest)

**From:** Kestrelmoor Institute IT Service Desk
**Subject:** Your mailbox is almost full

Dear user,

Your mailbox has reached 96% of its storage limit. New messages may not be delivered. Sign in to
request more storage:

{{.URL}}

IT Service Desk, Kestrelmoor Institute

### H2 parcel-customs (brand_impersonation)

**From:** Parcelwren
**Subject:** Your parcel is waiting: details needed

Hello,

Your international parcel is being held at our depot until the delivery details are confirmed.
Please check the details within 3 days:

{{.URL}}

Parcelwren International

### H3 shared-agenda (malware)

**From:** Lumacloud
**Subject:** Meeting_agenda.docx was shared with you

Hello,

You have been given access to a file on Lumacloud.

Meeting_agenda.docx (48 KB)

View the file: {{.URL}}

Lumacloud file sharing

### H4 lecture-seat (spear)

**From:** Kestrelmoor Institute Events
**Subject:** Your seat at the annual lecture has been reserved

Hello,

A seat at the Kestrelmoor Institute annual lecture has been reserved in your name. Please view your
ticket by Friday, or the seat will be released:

{{.URL}}

Events Office, Kestrelmoor Institute

## Loading them (after approval)

Dashboard, **Simulation**, New template: name, organisation, subject, category and set as in the
table; HTML body is the text above with each paragraph in `<p>` and the link as
`<a href="{{.URL}}">{{.URL}}</a>`; the plain-text body is the text as written. The categories "malware"
and "spear" describe the lure only: no file is attached or downloaded, and the link opens the
explanation page like every other.
