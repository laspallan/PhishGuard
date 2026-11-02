from phishguard_ml.data.email_normalise import normalise_time_clues

RAW = (
    "Received: from mail.example.org (mail.example.org [10.0.0.1])\n"
    "\tby mx.uni.example; Mon, 4 Mar 2002 10:00:00 -0800\n"
    "From: Bob <bob@example.org>\n"
    "Date: Mon, 4 Mar 2002 10:00:00 -0800\n"
    "Subject: Q3 2002 budget\n"
    "X-Mailer: Microsoft Outlook Express 6.00.2600.0000\n"
    "X-MimeOLE: Produced By Microsoft MimeOLE V6.00\n"
    "User-Agent: Mutt/1.2.5i\n"
    "Message-ID: <123@example.org>\n"
    "\n"
    "Copyright 1999-2002. Call 555-2002-12 or see order 120021.\n"
)


def test_date_mailer_and_received_timestamps_are_replaced():
    out = normalise_time_clues(RAW)

    assert "Date: <DATE>\n" in out
    assert "X-Mailer: <MAILER>\n" in out
    assert "X-MimeOLE: <MAILER>\n" in out
    assert "User-Agent: <MAILER>\n" in out
    assert "\tby mx.uni.example; <DATE>\n" in out
    assert "Outlook" not in out and "Mutt" not in out


def test_years_in_subject_and_body_are_replaced_but_other_numbers_kept():
    out = normalise_time_clues(RAW)

    assert "Subject: Q3 <YEAR> budget" in out
    assert "Copyright <YEAR>-<YEAR>." in out
    assert "120021" in out  # part of a longer number, not a year
    assert "555-<YEAR>-12" in out  # a standalone 4-digit year-like group is replaced


def test_other_headers_and_structure_are_unchanged():
    out = normalise_time_clues(RAW)

    assert "From: Bob <bob@example.org>\n" in out
    assert "Message-ID: <123@example.org>\n" in out
    assert out.count("\n\n") == 1


def test_crlf_emails_and_emails_without_body():
    crlf = "Date: Tue, 1 Jan 2019 00:00:00 +0000\r\nSubject: 2019\r\n\r\nin 2019\r\n"
    assert normalise_time_clues(crlf) == "Date: <DATE>\r\nSubject: <YEAR>\r\n\r\nin <YEAR>\r\n"
    assert normalise_time_clues("Date: x 2002") == "Date: <DATE>"


def test_normalising_twice_changes_nothing():
    once = normalise_time_clues(RAW)
    assert normalise_time_clues(once) == once
