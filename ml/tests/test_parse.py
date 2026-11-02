from phishguard.models.enums import Label, Modality
from phishguard_ml.data import parse
from phishguard_ml.data.records import Source
from tests.fixtures import (
    email_bytes,
    mbox,
    phishtank_csv,
    tar_archive,
    tranco_zip,
    write_download,
)


def test_phishtank_rows_become_phishing_url_records(tmp_path):
    csv_bytes = phishtank_csv(
        [
            ("http://paypa1.example/login", "2026-11-01T10:00:00+00:00", "yes"),
            ("not a url", "2026-11-01T10:00:00+00:00", "yes"),
            ("http://pending.example/", "2026-11-01T10:00:00+00:00", "no"),
        ]
    )
    folder = write_download(tmp_path / "pt", {"online-valid.csv": csv_bytes}, "phishtank")
    rejects = parse.RejectCounter()

    records = list(parse.parse_phishtank(folder, rejects))

    assert len(records) == 1
    assert records[0].label is Label.PHISHING
    assert records[0].source_date.isoformat() == "2026-11-01"
    assert records[0].group_key == "domain:paypa1.example"
    assert rejects == {"phishtank:bad_url": 1, "phishtank:not_verified": 1}


def test_openphish_lines_become_records(tmp_path):
    folder = write_download(
        tmp_path / "op", {"feed.txt": b"https://a.example/x\n\nhttps://b.example/\n"}, "openphish"
    )
    assert len(list(parse.parse_openphish(folder, parse.RejectCounter()))) == 2


def test_tranco_domains_become_home_page_urls_up_to_limit(tmp_path):
    zipped = tranco_zip(["google.com", "example.org", "third.example"])
    folder = write_download(tmp_path / "tr", {"top-1m.csv.zip": zipped}, "tranco")

    records = list(parse.parse_tranco(folder, parse.RejectCounter(), limit=2))

    assert [r.raw_content for r in records] == ["https://google.com/", "https://example.org/"]
    assert all(r.label is Label.LEGITIMATE and r.sample_type is Modality.URL for r in records)


def test_nazario_mbox_messages_become_phishing_emails(tmp_path):
    box = mbox([email_bytes(subject="Verify your account"), email_bytes(subject="Second")])
    folder = write_download(tmp_path / "nz", {"phishing-2024": box}, "nazario")

    records = list(parse.parse_nazario(folder, parse.RejectCounter()))

    assert len(records) == 2
    assert records[0].label is Label.PHISHING
    assert records[0].group_key == "sender:bob@example.org"
    assert "Verify your account" in records[0].raw_content


def test_spamassassin_skips_cmds_file(tmp_path):
    archive = tar_archive(
        {
            "easy_ham/00001.abc": email_bytes(subject="One"),
            "easy_ham/00002.def": email_bytes(subject="Two"),
            "easy_ham/cmds": b"mv 00001 00001.abc\n",
        },
        "w:bz2",
    )
    folder = write_download(tmp_path / "sa", {"20030228_easy_ham.tar.bz2": archive}, "spamassassin")

    records = list(parse.parse_spamassassin(folder, parse.RejectCounter()))

    assert sorted(r.raw_content.split("Subject: ")[1][:3] for r in records) == ["One", "Two"]


def test_enron_groups_by_owner_and_skips_sent_folders(tmp_path):
    archive = tar_archive(
        {
            "maildir/allen-p/inbox/1.": email_bytes(subject="Inbox mail"),
            "maildir/allen-p/sent_items/1.": email_bytes(subject="Sent mail"),
            "maildir/allen-p/all_documents/1.": email_bytes(subject="Copy"),
        },
        "w:gz",
    )
    folder = write_download(tmp_path / "en", {"enron_mail_20150507.tar.gz": archive}, "enron")
    rejects = parse.RejectCounter()

    records = list(parse.parse_enron(folder, rejects, fraction=1.0))

    assert len(records) == 1
    assert records[0].group_key == "enron:allen-p"
    assert rejects["enron:skipped_folder"] == 2


def test_enron_selection_is_deterministic():
    names = [f"maildir/u/inbox/{i}." for i in range(2000)]
    first = [n for n in names if parse.enron_selected(n, 0.1)]

    assert first == [n for n in names if parse.enron_selected(n, 0.1)]
    assert 120 < len(first) < 280


def test_email_without_sender_is_its_own_group(tmp_path):
    raw = b"Subject: no sender\n\nbody\n"
    folder = write_download(tmp_path / "nz", {"x": mbox([raw])}, "nazario")

    (record,) = parse.parse_nazario(folder, parse.RejectCounter())

    assert record.group_key == f"sample:{record.content_hash}"


def test_parsers_exist_for_every_source():
    assert set(parse.PARSERS) == set(Source)


def test_phishtank_targets_unescaped_and_other_left_out(tmp_path):
    day = "2026-11-01T10:00:00+00:00"
    csv_bytes = phishtank_csv(
        [
            ("http://allegro.shop-x.example/", day, "yes"),
            ("http://att-login.example/", day, "yes"),
            ("http://plain.example/", day, "yes"),
        ],
        targets=["Allegro", "AT&amp;T", "Other"],  # as written in the real file
    )
    folder = write_download(tmp_path / "pt", {"online-valid.csv": csv_bytes}, "phishtank")

    targets = parse.phishtank_targets([folder])

    assert targets == {
        "http://allegro.shop-x.example/": "Allegro",
        "http://att-login.example/": "AT&T",
    }
