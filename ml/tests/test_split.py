from collections import Counter

import pytest

from phishguard.models.enums import AttackCategory, Label, Modality
from phishguard_ml.data import split
from phishguard_ml.data.records import SampleRecord, Source

T = "2026-11-02T00:00Z"
CATEGORIES = [AttackCategory.CREDENTIAL_HARVEST, AttackCategory.BRAND_IMPERSONATION]


def make_records(n_phish_url=600, n_legit_url=600, n_phish_mail=200, n_legit_mail=200):
    records = []
    for i in range(n_phish_url):
        records.append(
            SampleRecord.create(
                source=Source.PHISHTANK,
                raw_content=f"http://p{i}.d{i % 150}.example/login",
                collected_at=T,
                snapshot_ref=f"snapshots/{i}",
                group_key=f"domain:d{i % 150}.example",
                attack_category=CATEGORIES[i % 2],
            )
        )
    for i in range(n_legit_url):
        records.append(
            SampleRecord.create(
                source=Source.TRANCO,
                raw_content=f"https://site{i}.example/",
                collected_at=T,
                snapshot_ref=f"snapshots/{i}",
                group_key=f"domain:site{i}.example",
            )
        )
    for i in range(n_phish_mail):
        records.append(
            SampleRecord.create(
                source=Source.NAZARIO,
                raw_content=f"Subject: verify {i}\n\nbody",
                collected_at=T,
                group_key=f"sender:s{i % 40}@x.example",
                attack_category=AttackCategory.CREDENTIAL_HARVEST,
            )
        )
    for i in range(n_legit_mail):
        records.append(
            SampleRecord.create(
                source=Source.ENRON,
                raw_content=f"Subject: meeting {i}\n\nbody",
                collected_at=T,
                group_key=f"enron:user{i % 30}",
            )
        )
    return records


def test_sample_is_balanced_per_modality_and_stratified():
    dataset = split.sample_dataset(make_records(), n_url=800, n_email=300)

    counts = Counter((r.sample_type, r.label) for r in dataset)
    assert counts[(Modality.URL, Label.PHISHING)] == 400
    assert counts[(Modality.URL, Label.LEGITIMATE)] == 400
    assert counts[(Modality.EMAIL, Label.PHISHING)] == 150
    categories = Counter(r.attack_category for r in dataset if r.sample_type is Modality.URL)
    assert categories[AttackCategory.CREDENTIAL_HARVEST] == 200


def test_sampling_is_reproducible_and_order_independent():
    records = make_records()
    a = split.sample_dataset(records, n_url=800, n_email=300)
    b = split.sample_dataset(list(reversed(records)), n_url=800, n_email=300)

    assert [r.sample_id for r in a] == [r.sample_id for r in b]


def test_asking_for_more_than_available_fails():
    with pytest.raises(split.InsufficientDataError, match="email phishing"):
        split.sample_dataset(make_records(), n_url=800, n_email=1000)


def test_own_mailbox_never_enters_the_dataset():
    records = make_records() + [
        SampleRecord.create(
            source=Source.OWN_MAILBOX,
            raw_content=f"Subject: n{i}\n\nx",
            collected_at=T,
            group_key="g",
        )
        for i in range(500)
    ]
    dataset = split.sample_dataset(records, n_url=800, n_email=300)

    assert all(r.source is not Source.OWN_MAILBOX for r in dataset)


def test_split_is_15_percent_test_groups_never_cross_and_folds_cover_dev():
    dataset = split.sample_dataset(make_records(), n_url=800, n_email=300)
    rows = split.make_split(dataset)

    test_share = sum(r["set"] == "test" for r in rows) / len(rows)
    assert 0.11 < test_share < 0.19
    group_of = {str(r.sample_id): r.group_key for r in dataset}
    test_groups = {group_of[r["sample_id"]] for r in rows if r["set"] == "test"}
    dev_groups = {group_of[r["sample_id"]] for r in rows if r["set"] == "dev"}
    assert test_groups.isdisjoint(dev_groups)
    folds = Counter(r["fold"] for r in rows if r["set"] == "dev")
    assert set(folds) == {0, 1, 2, 3, 4}
    for k in range(5):
        fold_groups = {group_of[r["sample_id"]] for r in rows if r["fold"] == k}
        other = {group_of[r["sample_id"]] for r in rows if r["set"] == "dev" and r["fold"] != k}
        assert fold_groups.isdisjoint(other)


def test_split_is_reproducible():
    dataset = split.sample_dataset(make_records(), n_url=800, n_email=300)
    assert split.make_split(dataset) == split.make_split(dataset)


def test_split_is_written_once_and_any_change_is_detected(isolated_data_dir):
    dataset = split.sample_dataset(make_records(), n_url=800, n_email=300)
    rows = split.make_split(dataset)

    manifest = split.write_split(dataset, rows, {"n_url": 800, "n_email": 300})
    assert manifest["samples"] == 1100
    assert split.verify_split()["sha256"] == manifest["sha256"]

    with pytest.raises(split.SplitExistsError):
        split.write_split(dataset, rows, {})

    loaded, loaded_rows = split.load_split()
    assert len(loaded) == 1100 and len(loaded_rows) == 1100

    with (isolated_data_dir / "splits" / "split.parquet").open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(split.SplitChangedError):
        split.verify_split()


def test_records_without_group_key_cannot_be_split():
    record = SampleRecord.create(
        source=Source.TRANCO, raw_content="https://a.example/", collected_at=T
    )
    with pytest.raises(ValueError, match="group_key"):
        split.make_split([record])


def test_urls_without_a_snapshot_are_never_sampled():
    unfetched = [
        SampleRecord.create(
            source=Source.TRANCO,
            raw_content=f"https://unfetched{i}.example/",
            collected_at=T,
            group_key=f"domain:unfetched{i}.example",
        )
        for i in range(2000)
    ]
    dataset = split.sample_dataset(make_records() + unfetched, n_url=800, n_email=300)

    urls = [r for r in dataset if r.sample_type is Modality.URL]
    assert len(urls) == 800 and all(r.snapshot_ref is not None for r in urls)
    with pytest.raises(split.InsufficientDataError):
        split.sample_dataset(make_records(n_legit_url=300) + unfetched, n_url=800, n_email=300)


def _phish(url, i=0):
    return SampleRecord.create(
        source=Source.PHISHTANK,
        raw_content=url,
        collected_at=T,
        group_key="domain:old",
        snapshot_ref=f"snapshots/p{i}",
        attack_category=AttackCategory.UNKNOWN,
    )


POPULAR = {"google.com", "qrco.de", "pages.dev"}


def test_phishing_on_hosting_platforms_is_grouped_by_customer_site():
    assert split.phishing_url_group(_phish("https://evil.pages.dev/a"), POPULAR) == (
        "domain:evil.pages.dev"
    )
    assert split.phishing_url_group(_phish("http://login-bad.example/x"), POPULAR) == (
        "domain:login-bad.example"
    )


def test_phishing_on_popular_sites_is_one_group_per_link_unless_it_redirects():
    form = _phish("https://docs.google.com/forms/d/abc/viewform")
    assert split.phishing_url_group(form, POPULAR).startswith("link:https://docs.google.com/")
    qr = _phish("https://qrco.de/bX1")
    # redirected to an attacker site: grouped with it, so links to one site stay together
    assert split.phishing_url_group(qr, POPULAR, "https://a.evil-site.com/login") == (
        "domain:evil-site.com"
    )
    # redirected to another popular site (e.g. a takedown page): still one group per link
    assert split.phishing_url_group(qr, POPULAR, "https://www.google.com/").startswith("link:")


def test_regroup_changes_only_phishing_urls():
    records = make_records(n_phish_url=2, n_legit_url=2, n_phish_mail=1, n_legit_mail=1)
    out = split.regroup_phishing_urls(records, POPULAR, lambda r: None)
    for before, after in zip(records, out, strict=True):
        changed = before.sample_type is Modality.URL and before.label is Label.PHISHING
        assert (before.group_key != after.group_key) == changed


def test_each_modality_is_split_on_its_own():
    dataset = split.sample_dataset(make_records(), n_url=800, n_email=300)
    rows = split.make_split(dataset)
    assert [row["sample_id"] for row in rows] == [str(r.sample_id) for r in dataset]
    for modality in Modality:
        part = [r for r in dataset if r.sample_type is modality]
        own = split.make_split(part)
        by_id = {row["sample_id"]: row for row in rows}
        assert all(by_id[row["sample_id"]] == row for row in own)
