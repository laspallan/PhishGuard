# Ethics approval request: PhishGuard phishing simulation study

**Status: approved.** The Research Ethics Committee approved this study on 2026-11-11 (reference
110427; chair Male Henry Kenneth), with supervisor sign-off by Christopher Ayesiga, and Nansana
Municipal Council authorised it (Ref CRM10427, Office of the Town Clerk). The number of simulated
emails per participant is set to 30 (sections 3, A and the debrief). One operational detail remains to
fill in section 5 before the first round: where GoPhish runs. If the university has its own form, copy
these sections into it.

---

**To:** Research Ethics Committee, International Business, Science and Technology University (IBSTU)
**Copy:** Christopher Ayesiga (supervisor), christopherayesiga@gmail.com
**From:** Luswata Allan, MSc student, Master of Science in Cyber Security and Forensics, student number 011250360
**Date:** [date you send]
**Subject:** Ethics approval request: phishing simulation with consenting volunteers (MSc thesis)

Dear Committee,

I request ethics approval for the simulation part of my MSc thesis, PhishGuard, a phishing detection
system. The study sends simulated phishing emails to adult volunteers who have consented in advance.
It uses a fictional organisation and does not collect passwords. No participant has been contacted,
and the software will not launch a campaign until an approval reference from the university is
entered into it.

## 1. Purpose

The study answers this research question: does retraining with data from failed simulations improve
detection over time, compared with a static model and with a model retrained on the same amount of
fresh feed data without simulation data?

The study tests the detection models. It does not assess individuals, and results are reported only
as totals.

## 2. Participants

- About 50 adult volunteers, staff of Nansana Municipal Council, recruited by an open invitation sent
  through the Council's IT department.
- Test mailboxes controlled by the researcher are also used.
- Nobody is included without recorded consent, and real third parties are never targeted.
- Because the participants are staff of an organisation, these safeguards apply:
  - The invitation is open and goes to everyone in the group, so nobody is singled out. It is sent by
    the IT department, not by the researcher directly.
  - Taking part, declining or withdrawing has no effect on employment, assessment or the working
    relationship.
  - The researcher does not look at any individual's results, and does not use them for any purpose
    other than this study.

## 3. What participants experience

1. They read an information sheet and sign a consent form. They know that simulated emails will
   arrive during the study, but not when, or which emails they will be.
2. Over 3 monthly rounds, they receive about 30 simulated emails from a fictional organisation.
3. If they follow the link, they immediately see a page explaining that this was a simulation. The
   page has no form and asks for nothing, so they are never invited to enter a password.
4. All participants get a full debrief at the end of the study (Attachment D).

The study involves limited deception, because participants are not told when an email is a
simulation. This is necessary because announcing each email would invalidate the behaviour being
measured. Possible harms are mild embarrassment or annoyance, and wasted time. The controls below
and the debrief are intended to limit these.

The simulated emails come from a **fictional, invented organisation**, not from Nansana Municipal
Council or any real body. This is a deliberate safeguard: the study never imitates the participants'
real employer or any real brand.

## 4. Safeguards built into the software

These are enforced in code and covered by automated tests:

- **No approval, no launch.** A campaign is refused unless the university's approval reference is
  configured.
- **Consent required.** A campaign is refused if any target has no recorded consent or has withdrawn.
- **Fictional branding only.** A template must name a fictional organisation, and a template using a
  name on the list of real brands is refused. The landing page does not imitate any real site.
- **No passwords collected.** The landing page has no form. As a second control, GoPhish landing pages
  are always created with capture off. This was tested on GoPhish 0.12.1 in a local container with no
  outgoing email: a password submitted through a test form did not reach GoPhish.
- **Totals only.** The dashboard shows campaign totals, not individuals.

## 5. Data collected

| Data | Where it is held | Protection or note |
|---|---|---|
| Email address | PhishGuard database | Encrypted (Fernet), with a keyed hash used for look-ups |
| Consent form version and date, withdrawal date | PhishGuard database | Linked to the participant record |
| Events: sent, opened, clicked, reported, and time | PhishGuard database | Linked to the participant record |
| Email address, IP address and browser for each event | GoPhish's own database | Stored by GoPhish; PhishGuard does not copy IP address or browser. Access is limited to the researcher, on [where GoPhish runs] |

**Not collected:** passwords or any other typed values, and the content of participants' own mailboxes.

**Training data:** a failed simulation produces a training sample made from the template's own text.
It is the same for everyone and contains no participant data.

**Retention:** the researcher proposes to keep study data with no planned deletion date, except where
a participant withdraws (section 6). The committee is asked whether this is acceptable (section 7).

**Publication:** only totals appear in the thesis. No participant can be identified.

**Legal basis:** the study is designed to comply with Uganda's Data Protection and Privacy Act, 2019
and the Data Protection and Privacy Regulations, 2021 (overseen by the Personal Data Protection Office
under NITA-U), and follows the principles of the EU General Data Protection Regulation (Regulation (EU)
2016/679) as an international reference.

## 6. Withdrawal

Participants may withdraw at any time, without giving a reason, by contacting laspallan@gmail.com. From
that point they are excluded from new campaigns and their later events are dropped. Their data is then
deleted, within 30 days, in two steps built into the software:

1. **Their record:** their PhishGuard record, events and samples are deleted, and their address is
   removed from every simulation group in GoPhish.
2. **GoPhish's copies:** GoPhish also keeps a copy of each recipient (address, IP address, browser) in
   the results of campaigns already sent. Once such a campaign has finished and its events have been
   saved in PhishGuard, its results are deleted from GoPhish as a whole.

Only step 2 waits for the campaign to finish; the software reports how many campaigns still hold
copies.

Withdrawal is possible until 11 January 2027. After that, models already trained cannot be changed,
although they contain only template text, never participant data.

## 7. Questions for the committee

1. Is advance consent to unannounced simulated emails acceptable, and is the debrief described above
   sufficient?
2. Does the Council's or the university's IT or security team need to be told, or to approve the
   sending domain?
3. May this data, including email and IP addresses, be kept with no planned deletion date under
   university policy, the Data Protection and Privacy Act, 2019 and the Regulations, 2021? If not, what
   period applies?
4. What further safeguards are needed given that the participants are all staff of one organisation?

## 8. Attachments

- A. Information sheet (below)
- B. Consent form, version 1.0 (below)
- C. Example simulation templates (below)
- D. Explanation page and end-of-study debrief (below)

Please let me know if you need anything further.

Kind regards,
Luswata Allan
laspallan@gmail.com
0704837308, IT Assistant

---

## Supervisor approval

To be completed by the supervisor to confirm the study and this request.

I have reviewed this ethics approval request and the attached study materials, and I approve its
submission to the Research Ethics Committee.

Supervisor name: Christopher Ayesiga

Signature: ______________________   Date: ____________

---

## Attachment A: information sheet

**Study:** Testing phishing detection software with simulated emails (PhishGuard)
**Researcher:** Luswata Allan, MSc student, Master of Science in Cyber Security and Forensics,
International Business, Science and Technology University (IBSTU). **Supervisor:** Christopher Ayesiga,
christopherayesiga@gmail.com

**Why am I being asked?** The study needs adult volunteers to receive simulated phishing emails. It is
testing software, not you.

**What will happen?** Over about 3 months you will receive about 30 simulated emails at
the address you give. They will not be announced. They come from an invented organisation. If you open
a link in one, a page tells you straight away that it was a simulation. It does not ask you for anything.

**What is recorded?** Your email address, your consent, and when an email was sent, opened, clicked or
reported. The simulation software (GoPhish) also stores your IP address and browser details when you
open an email or link. No passwords or typed values are collected, and your mailbox is not read.

**Who sees it?** Only the researcher has access to data about individuals. Only totals are published.

**How long is it kept?** There is no planned deletion date, unless you withdraw. The Research Ethics
Committee approved the study on this basis (reference 110427).

**Must I take part?** No. You can refuse or withdraw at any time without giving a reason, by writing to
laspallan@gmail.com. Your records are then deleted. Withdrawal is possible until 11 January 2027.
Trained models cannot be changed afterwards, but they contain only the text of the simulated emails,
nothing about you. Taking part, declining or withdrawing has no effect on your employment, assessment or
working relationship with the researcher.

**Risks and benefits:** you may feel annoyed or embarrassed, and it takes a little of your time. There
is no direct benefit to you, but the study helps improve phishing detection.

**Questions or complaints:** the researcher at laspallan@gmail.com, the supervisor Christopher Ayesiga
(christopherayesiga@gmail.com), or the Research Ethics Committee at +256 705 582192. Ethics approval
reference: 110427.

## Attachment B: consent form (version 1.0)

Study: Testing phishing detection software with simulated emails (PhishGuard)

Please tick each box:

- [ ] I have read the information sheet and could ask questions.
- [ ] I am 18 or older.
- [ ] I agree to receive simulated phishing emails without being told in advance which emails they are.
- [ ] I understand that my email address, the events listed in the information sheet, and my IP address
  and browser details will be recorded.
- [ ] I understand that only totals will be published.
- [ ] I understand how long the data will be kept, as stated in the information sheet.
- [ ] I understand that taking part is voluntary, and that I can withdraw until 11 January 2027 without
  giving a reason and without any effect on me.

Email address for the study: ______________________

Name: ______________________ Signature: ______________________ Date: ____________

## Attachment C: example templates

The full proposed set (8 templates: 4 attack categories, each with a training and a holdout version,
from three invented organisations) is in `Docs/simulation_templates.md`, reproduced in the accompanying
Word document. Two of them are shown below.

"Kestrelmoor Institute" is an invented name. A web search on 2026-11-08 found no organisation using it;
it will be searched again before the first round and changed if a real organisation is found. `{{.URL}}`
is the simulation link. Each template belongs to either the training set or the simulation-holdout set,
so one is kept out of training and used only for testing.

### Example 1 (training set)

**From:** Kestrelmoor Institute Library
**Subject:** Your library account expires in 3 days

Dear member,

Your Kestrelmoor Institute library account expires in 3 days. To keep access to your loans, please
confirm your details here: {{.URL}}

Library Services, Kestrelmoor Institute

### Example 2 (simulation-holdout set)

**From:** Kestrelmoor Institute Events
**Subject:** Your seat at the annual lecture has been reserved

Hello,

A seat at the Kestrelmoor Institute annual lecture has been reserved in your name. Please view your
ticket by Friday, or the seat will be released: {{.URL}}

Events Office, Kestrelmoor Institute

### Landing page (both examples)

The explanation page in Attachment D. It has no form, logo or styling from any real organisation.

## Attachment D: explanation page and debrief

### Explanation page, shown as soon as a link is opened

> **This was a simulated phishing email**
>
> You are safe. It was sent as part of the PhishGuard research study you agreed to join. Kestrelmoor
> Institute is not a real organisation.
>
> Nothing was installed on your device, and this page does not ask you for anything.
>
> The study recorded that this link was opened. Results are reported only as totals, and this is not a
> judgement of you. The aim is to test phishing detection software.
>
> Before you open a link in a real email, check who sent it and where the link goes, and be wary of
> pressure to act quickly.
>
> Questions, or to withdraw from the study: laspallan@gmail.com

### Debrief email, sent to all participants at the end of the study

**Subject:** PhishGuard study finished: thank you

Dear participant,

The study has finished, and you will receive no more simulated emails. Thank you for taking part.

During the study you received 30 simulated phishing emails from an invented organisation,
Kestrelmoor Institute. They were not announced because announcing them would have changed how people
responded. No passwords or typed values were collected, and your individual results will not be
published or used to judge you.

The study tested whether retraining phishing detection software with simulation data improves it over
time. A summary of the results is available from me on request once the thesis is complete.

You can still withdraw until 11 January 2027 by writing to me. If anything about the study concerned
you, please contact me, my supervisor Christopher Ayesiga (christopherayesiga@gmail.com), or the
Research Ethics Committee at +256 705 582192.

Luswata Allan
