"""The landing page of a simulation: it explains the simulation at once (decisions.md, 2026-11-07).

It has no form and loads nothing from elsewhere, so a participant has nowhere to type a password.
GoPhish records "Clicked Link" when this page is opened.
"""

from html import escape


def debrief_page(fictional_org: str, contact_email: str) -> str:
    org, contact = escape(fictional_org), escape(contact_email)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>This was a simulation</title>
</head>
<body style="font-family: sans-serif; max-width: 40rem; margin: 2rem auto; padding: 0 1rem">
<h1>This was a simulated phishing email</h1>
<p>You are safe. It was sent as part of the PhishGuard research study you agreed to join.
{org} is not a real organisation.</p>
<p>Nothing was installed on your device, and this page does not ask you for anything.</p>
<p>The study recorded that this link was opened. Results are reported only as totals, and this is
not a judgement of you. The aim is to test phishing detection software.</p>
<p>Before you open a link in a real email, check who sent it and where the link goes, and be wary
of pressure to act quickly.</p>
<p>Questions, or to withdraw from the study: {contact}</p>
</body>
</html>
"""
