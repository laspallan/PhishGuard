"""IMAP gateway, offline: a fake IMAP server and a mocked PhishGuard API."""

import httpx
import pytest
from pydantic import SecretStr

from config import GatewaySettings
from imap_gateway import IMAPGateway


class FakeIMAP:
    """Just the IMAPClient calls the gateway uses; records what happened."""

    def __init__(self, messages: dict[int, bytes], validity: int = 7):
        self.messages = messages
        self.validity = validity
        self.moved: list[tuple[list[int], str]] = []
        self.flagged: list[int] = []
        self.fetch_items: list[list[str]] = []
        self.folders = {"INBOX"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, user, password):
        self.login_args = (user, password)

    def select_folder(self, folder, readonly=False):
        return {b"UIDVALIDITY": self.validity}

    def search(self, criteria):
        first = int(criteria[1].split(":")[0])
        found = [uid for uid in self.messages if uid >= first]
        return found or [max(self.messages)]  # IMAP returns the last UID for "n:*" past the end

    def fetch(self, uids, items):
        self.fetch_items.append(items)
        return {uid: {b"BODY[]": self.messages[uid]} for uid in uids}

    def folder_exists(self, folder):
        return folder in self.folders

    def create_folder(self, folder):
        self.folders.add(folder)

    def move(self, uids, folder):
        self.moved.append((uids, folder))

    def add_flags(self, uids, flags):
        self.flagged += uids


def api(verdicts: dict[bytes, object], seen: list):
    """Mocked /scan/email: the verdict is chosen by a marker in the email text."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = request.content
        for marker, answer in verdicts.items():
            if marker in body:
                if isinstance(answer, int):
                    return httpx.Response(answer)
                return httpx.Response(200, json={"verdict": answer, "score": 0.5, "ti_score": 0})
        return httpx.Response(200, json={"verdict": "allow", "score": 0.1, "ti_score": 0})

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def settings(tmp_path):
    return GatewaySettings(
        _env_file=None,
        imap_user="test@mailbox",
        imap_password=SecretStr("pw"),
        api_key=SecretStr("key"),
        state_file=tmp_path / "state.json",
    )


MAILS = {1: b"Subject: a\n\nPHISH", 2: b"Subject: b\n\nSUSPECT", 3: b"Subject: c\n\nhello"}


def test_actions_peek_and_api_key(settings):
    imap, seen = FakeIMAP(dict(MAILS)), []
    gateway = IMAPGateway(
        settings,
        imap_factory=lambda s: imap,
        http=api({b"PHISH": "block", b"SUSPECT": "warn"}, seen),
    )

    assert gateway.run_once() == {"block": 1, "warn": 1, "allow": 1}
    assert imap.moved == [([1], "PhishGuard/Quarantine")]
    assert "PhishGuard/Quarantine" in imap.folders  # created when missing
    assert imap.flagged == [2]
    assert all(items == ["BODY.PEEK[]"] for items in imap.fetch_items)  # never marks as read
    assert seen[0].headers["X-API-Key"] == "key"


def test_each_email_is_scanned_once_across_rounds(settings):
    imap, seen = FakeIMAP(dict(MAILS)), []
    gateway = IMAPGateway(settings, imap_factory=lambda s: imap, http=api({}, seen))
    gateway.run_once()
    assert gateway.run_once() == {"block": 0, "warn": 0, "allow": 0}
    assert len(seen) == 3

    imap.messages[4] = b"Subject: d\n\nnew"
    assert gateway.run_once()["allow"] == 1 and len(seen) == 4


@pytest.mark.parametrize("failure", [503, 500])
def test_api_errors_stop_the_round_and_retry_the_same_email(settings, failure):
    imap, seen = FakeIMAP(dict(MAILS)), []
    gateway = IMAPGateway(
        settings, imap_factory=lambda s: imap, http=api({b"SUSPECT": failure}, seen)
    )
    assert gateway.run_once() == {"block": 0, "warn": 0, "allow": 1}  # stopped at UID 2
    assert imap.moved == [] and imap.flagged == []  # nothing done on a guess

    gateway.http = api({}, seen)  # the API works again
    assert gateway.run_once()["allow"] == 2  # UIDs 2 and 3, UID 1 not scanned again


def test_unreachable_api_does_nothing(settings):
    def down(request):
        raise httpx.ConnectError("refused")

    imap = FakeIMAP(dict(MAILS))
    client = httpx.Client(transport=httpx.MockTransport(down))
    gateway = IMAPGateway(settings, imap_factory=lambda s: imap, http=client)
    assert gateway.run_once() == {"block": 0, "warn": 0, "allow": 0}
    assert not settings.state_file.exists()


def test_new_uidvalidity_starts_again(settings):
    imap, seen = FakeIMAP(dict(MAILS)), []
    gateway = IMAPGateway(settings, imap_factory=lambda s: imap, http=api({}, seen))
    gateway.run_once()
    imap.validity = 8  # the server renumbered the mailbox
    gateway.run_once()
    assert len(seen) == 6
