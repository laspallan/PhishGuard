import mailbox

import pytest

from phishguard_ml.data.records import SampleRecord, Source
from phishguard_ml.evaluation import baseline

T = "2026-11-02T00:00Z"


def _email(text, i):
    return SampleRecord.create(source=Source.NAZARIO, raw_content=text, collected_at=T,
                               group_key=f"sender:{i}@x-test.com")  # fmt: skip


def test_export_escapes_from_lines_and_tags_each_email(isolated_data_dir):
    records = [
        _email("Subject: a\n\nhello\nFrom the team\n", 1),  # body line that starts with "From "
        _email("Subject: b\n\nCafé\n", 2),
    ]
    path = baseline.export(records)
    messages = list(mailbox.mbox(path, create=False))
    assert len(messages) == 2  # the body "From " line did not start a new message
    assert [m[baseline.ID_HEADER] for m in messages] == [str(r.sample_id) for r in records]
    assert ">From the team" in messages[0].get_payload()


def _scored(path, rows):
    with path.open("w", encoding="utf-8") as out:
        for sample_id, score in rows:
            out.write("From phishguard@localhost Thu Jan  1 00:00:00 1970\n")
            out.write(
                f"X-Spam-Status: {'Yes' if score >= 5 else 'No'}, score={score} required=5.0\n"
            )
            out.write("\ttests=MSGID_SHORT,NO_RECEIVED autolearn=no\n")  # folded, as SA writes it
            out.write(f"{baseline.ID_HEADER}: {sample_id}\nSubject: x\n\nbody\n\n")


def test_import_matches_by_id_in_any_order(isolated_data_dir):
    records = [_email("Subject: a\n\nx\n", 1), _email("Subject: b\n\ny\n", 2)]
    baseline.work_dir().mkdir(parents=True)
    _scored(
        baseline.work_dir() / "scored.mbox",
        [(records[1].sample_id, 7.2), (records[0].sample_id, -0.1)],
    )
    (baseline.work_dir() / "version.txt").write_text("SpamAssassin version 4.0.1\n")

    assert baseline.import_scores(records) == {"emails": 2, "detected": 1}
    assert baseline.load() == {str(records[0].sample_id): False, str(records[1].sample_id): True}


def test_import_refuses_missing_results(isolated_data_dir):
    records = [_email("Subject: a\n\nx\n", 1), _email("Subject: b\n\ny\n", 2)]
    baseline.work_dir().mkdir(parents=True)
    _scored(baseline.work_dir() / "scored.mbox", [(records[0].sample_id, 1.0)])
    with pytest.raises(ValueError):
        baseline.import_scores(records)
