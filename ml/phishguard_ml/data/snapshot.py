"""Step 5: snapshot collector. Runs only inside its container (docker compose --profile collect).

For each URL it stores, under data/snapshots/<sample_id>/:
  meta.json  request outcome (status, redirects, content type, size, why skipped)
  page.html  the HTML, only if the response is HTML (max 2 MB)
  dns.json   A / AAAA / MX / NS records and TTLs
  tls.json   certificate details and whether it verified

Safety rules (CLAUDE.md): plain HTTP GET only; no JavaScript is ever run (httpx does not run
scripts); no forms are submitted; bodies that are not HTML are never downloaded; no cookies are
kept. In addition, every hop is checked so a URL cannot reach private or local addresses.

Registration data (RDAP) is collected separately by rdap.py: it is not time-critical and the
registries rate-limit it, so it must not slow down capturing pages before they go offline.
"""

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlsplit

import dns.resolver
import httpcore
import httpx
from cryptography import x509

from phishguard.models.enums import Label, Modality
from phishguard_ml import paths
from phishguard_ml.data.clean import normalise_url, registered_domain
from phishguard_ml.data.download import user_agent
from phishguard_ml.data.records import SampleRecord, Source

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = httpx.Timeout(10.0)
HTML_TYPES = ("text/html", "application/xhtml+xml")
DNS_TYPES = ("A", "AAAA", "MX", "NS")
_HREF = re.compile(r"""<a\s[^>]*?href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
NON_PAGE_SUFFIXES = frozenset(
    {
        ".pdf",
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".svg",
        ".webp",
        ".mp4",
        ".mp3",
        ".zip",
        ".exe",
        ".dmg",
        ".apk",
        ".css",
        ".js",
        ".xml",
        ".json",
        ".rss",
        ".ico",
        ".woff",
        ".woff2",
    }
)


CONTAINER_FLAG = "PHISHGUARD_IN_SNAPSHOT_CONTAINER"  # set only by ml/Dockerfile


class UnsafeTargetError(Exception):
    """The URL would make the collector contact a private, local or reserved address."""


class NotInSnapshotContainerError(RuntimeError):
    """Snapshots were requested outside the snapshot container."""


def resolve(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return []


def safe_addresses(host: str, resolver: Callable[[str], list[str]] | None = None) -> list[str]:
    """Resolve the host once; return its addresses only if every one of them is public."""
    addresses = (resolver or resolve)(host)
    if not addresses:
        raise UnsafeTargetError(f"host does not resolve: {host}")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global:
            raise UnsafeTargetError(f"{host} resolves to non-public address {ip}")
    return addresses


def check_safe_target(url: str, resolver: Callable[[str], list[str]] | None = None) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTargetError(f"not an http(s) URL: {url}")
    safe_addresses(parts.hostname, resolver)


class PinnedBackend(httpcore.NetworkBackend):
    """Connects only to an address it has just checked (decision D11f: no DNS rebinding).

    check_safe_target alone is not enough: the HTTP library would resolve the host again when
    it connects, and a hostile name server can answer a public address the first time and a
    private one the second. Here the lookup, the check and the connection use the same
    addresses. TLS still uses the host name (httpcore passes it for SNI and certificate checks).
    """

    def __init__(
        self,
        resolver: Callable[[str], list[str]] | None = None,
        inner: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.resolver = resolver
        self.inner = inner or httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        last_error: Exception | None = None
        for address in safe_addresses(host, self.resolver):
            try:
                return self.inner.connect_tcp(address, port, timeout, local_address, socket_options)
            except httpcore.ConnectError as error:
                last_error = error
        raise last_error  # type: ignore[misc]  # safe_addresses never returns an empty list

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise UnsafeTargetError("unix sockets are never used by the collector")

    def sleep(self, seconds: float) -> None:
        self.inner.sleep(seconds)


class PinnedTransport(httpx.HTTPTransport):
    """httpx transport whose connections go through PinnedBackend.

    httpx does not take a network backend directly, so the connection pool is rebuilt with
    httpcore's public constructor; test_pinned_transport_connects_to_the_checked_ip checks the
    wiring, so an httpx upgrade that changes it fails the tests instead of silently unpinning.
    """

    def __init__(
        self,
        resolver: Callable[[str], list[str]] | None = None,
        inner: httpcore.NetworkBackend | None = None,
    ) -> None:
        super().__init__()
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(),
            network_backend=PinnedBackend(resolver, inner),
        )


def pinned_client(**kwargs) -> httpx.Client:
    """The collector's HTTP client. trust_env=False: no proxy from the environment can bypass
    the pinned transport."""
    return httpx.Client(transport=PinnedTransport(), trust_env=False, **kwargs)


def fetch_page(
    url: str,
    client: httpx.Client,
    resolver: Callable[[str], list[str]] | None = None,
    *,
    deadline: float | None = None,
) -> tuple[dict, bytes | None]:
    """GET the URL, following redirects one hop at a time. Returns (meta, html or None).

    `deadline` (time.monotonic() value, live scans only) stops the whole fetch, all hops and
    the body included; a late page is dropped, not cut, since a part of it would give other
    feature values than the page. The batch collector passes none and is unchanged."""
    meta: dict = {"url": url, "redirects": [], "fetched_at": datetime.now(UTC).isoformat()}
    current = url
    for hop in range(MAX_REDIRECTS + 1):
        if deadline is not None and time.monotonic() >= deadline:
            meta["skipped"] = "deadline"
            return meta, None
        try:
            check_safe_target(current, resolver)
        except UnsafeTargetError as error:
            meta["skipped"] = str(error)
            # The URL's own host is unsafe (never contacted again) unless it simply does not
            # resolve: then DNS is still recorded, since "no DNS records" is a feature (F53).
            meta["unsafe_host"] = hop == 0 and "does not resolve" not in str(error)
            return meta, None
        client.cookies.clear()
        try:
            limit = {} if deadline is None else {"timeout": max(deadline - time.monotonic(), 0.1)}
            with client.stream("GET", current, follow_redirects=False, **limit) as response:
                meta["status"] = response.status_code
                meta["final_url"] = current
                if response.is_redirect and "location" in response.headers:
                    current = urljoin(current, response.headers["location"])
                    meta["redirects"].append(current)
                    continue
                content_type = response.headers.get("content-type", "").lower()
                meta["content_type"] = content_type
                if not content_type.startswith(HTML_TYPES):
                    meta["skipped"] = "not HTML: body not downloaded"
                    return meta, None
                body = bytearray()
                for chunk in response.iter_bytes():
                    if deadline is not None and time.monotonic() >= deadline:
                        meta["skipped"] = "deadline"
                        return meta, None
                    body.extend(chunk)
                    if len(body) > MAX_BYTES:
                        meta["truncated"] = True
                        break
                meta["bytes"] = min(len(body), MAX_BYTES)
                return meta, bytes(body[:MAX_BYTES])
        except UnsafeTargetError as error:  # the host changed its answer since the check above
            meta["skipped"] = str(error)
            meta["unsafe_host"] = hop == 0
            return meta, None
        # httpx.InvalidURL is not an HTTPError; ValueError comes from urljoin on a broken
        # Location header (e.g. "Invalid IPv6 URL"). Both seen in the first real run.
        except (httpx.HTTPError, httpx.InvalidURL, ValueError) as error:
            meta["error"] = f"{type(error).__name__}: {error}"
            return meta, None
    meta["skipped"] = f"more than {MAX_REDIRECTS} redirects"
    return meta, None


def dns_info(host: str, lifetime: float = 5.0) -> dict:
    result: dict = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    for kind in DNS_TYPES:
        try:
            answer = resolver.resolve(host, kind)
            result[kind] = {"records": sorted(r.to_text() for r in answer), "ttl": answer.rrset.ttl}
        except Exception as error:  # NXDOMAIN, NoAnswer, timeouts: recorded, not raised
            result[kind] = {"error": type(error).__name__}
    return result


def _cert_summary(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    return {
        "issuer": cert.issuer.rfc4514_string(),
        "subject": cert.subject.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "san": names,
    }


def _connect_checked(
    host: str, port: int, resolver: Callable[[str], list[str]] | None, timeout: float = 10
):
    """A TCP connection to one of the host's checked public addresses (D11f)."""
    last_error: OSError | None = None
    for address in safe_addresses(host, resolver):
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as error:
            last_error = error
    raise last_error  # type: ignore[misc]  # safe_addresses never returns an empty list


def tls_info(
    host: str,
    port: int = 443,
    resolver: Callable[[str], list[str]] | None = None,
    timeout: float = 10,
) -> dict:
    """Certificate details. 'verified' is True only if the chain and hostname both check out.

    Connects to the checked address, but sends the host name for SNI and checks the
    certificate against it."""
    for verify in (True, False):
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with _connect_checked(host, port, resolver, timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
            return {"verified": verify, **_cert_summary(der)}
        except ssl.SSLCertVerificationError as error:
            last_error = f"verify failed: {error.verify_message}"
            continue
        except (OSError, ValueError, UnsafeTargetError) as error:
            return {"error": f"{type(error).__name__}: {error}"}
    return {"error": last_error}


class RunCache:
    """Per-run cache so each host gets one DNS and one TLS lookup."""

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()

    def get(self, kind: str, key: str, compute: Callable[[], dict]) -> dict:
        with self._lock:
            if (kind, key) in self._values:
                return self._values[(kind, key)]
        value = compute()
        with self._lock:
            return self._values.setdefault((kind, key), value)


def same_site_links(html: str, page_url: str, limit: int = 1) -> list[str]:
    """Up to `limit` deeper pages of the same site linked from this page (decision D10a).

    Chosen by hash, not by position, so the choice is deterministic but not biased towards
    menus at the top of the page. File downloads and the home page itself are skipped.
    """
    domain = registered_domain(urlsplit(page_url).hostname or "")
    found = set()
    for href in _HREF.findall(html):
        try:
            url = normalise_url(urljoin(page_url, href.strip()))
        except ValueError:  # broken href, e.g. "http://[" -> "Invalid IPv6 URL"
            continue
        if url is None:
            continue
        parts = urlsplit(url)
        if registered_domain(parts.hostname or "") != domain:
            continue
        if parts.path in ("", "/") and not parts.query:
            continue
        if PurePosixPath(parts.path.lower()).suffix in NON_PAGE_SUFFIXES:
            continue
        found.add(url)
    return sorted(found, key=lambda u: hashlib.sha256(u.encode()).hexdigest())[:limit]


def _is_home_page(record: SampleRecord) -> bool:
    return record.source is Source.TRANCO and urlsplit(record.raw_content).path in ("", "/")


def take_snapshot(
    record: SampleRecord, client: httpx.Client, cache: RunCache | None = None, links: int = 0
) -> tuple[str, list[str]]:
    """Snapshot one URL record. Returns (snapshot_ref, same-site links for Tranco home pages)."""
    cache = cache or RunCache()
    folder = paths.snapshots_dir() / str(record.sample_id)
    folder.mkdir(parents=True, exist_ok=True)
    meta, html = fetch_page(record.raw_content, client)
    host = urlsplit(record.raw_content).hostname or ""
    if html is not None:
        (folder / "page.html").write_bytes(html)
    if not meta.get("unsafe_host"):
        # DNS queries go to resolvers, not the host. TLS connects to the host, which passed the
        # safety check above.
        dns_data = cache.get("dns", host, lambda: dns_info(host))
        tls_data = cache.get("tls", host, lambda: tls_info(host))
        (folder / "dns.json").write_text(json.dumps(dns_data, indent=1))
        (folder / "tls.json").write_text(json.dumps(tls_data, indent=1))
    found: list[str] = []
    if links and html is not None and _is_home_page(record):
        page_url = meta.get("final_url", record.raw_content)
        found = same_site_links(html.decode("utf-8", errors="replace"), page_url, links)
        meta["same_site_links"] = found
    # meta.json is written last: its presence means the snapshot is complete (used to resume).
    _write_meta(folder, meta)
    return f"snapshots/{record.sample_id}", found


def _write_meta(folder: Path, meta: dict) -> None:
    """Atomic write: a run killed mid-write must not leave an empty meta.json marked complete."""
    tmp = folder / "meta.json.tmp"
    tmp.write_text(json.dumps(meta, indent=1))
    os.replace(tmp, folder / "meta.json")


def _read_meta(record: SampleRecord) -> dict | None:
    """The finished snapshot's meta.json, or None if missing or unreadable (fetch again)."""
    try:
        return json.loads((paths.snapshots_dir() / str(record.sample_id) / "meta.json").read_text())
    except (OSError, ValueError):
        return None


def _safe_snapshot(
    record: SampleRecord, client: httpx.Client, cache: RunCache, links: int
) -> tuple[str, list[str]]:
    """take_snapshot, but one URL's unexpected error is recorded instead of stopping the run."""
    try:
        return take_snapshot(record, client, cache, links)
    except Exception as error:
        folder = paths.snapshots_dir() / str(record.sample_id)
        folder.mkdir(parents=True, exist_ok=True)
        meta = {"url": record.raw_content, "error": f"crash: {type(error).__name__}: {error}"}
        _write_meta(folder, meta)
        return f"snapshots/{record.sample_id}", []


def _link_record(link: str, parent: SampleRecord) -> SampleRecord:
    return SampleRecord.create(
        source=Source.TRANCO,
        raw_content=link,
        hash_of=normalise_url(link),
        collected_at=datetime.now(UTC),
        group_key=parent.group_key,  # same registered domain as its home page
    )


def snapshot_records(
    records: list[SampleRecord],
    *,
    workers: int = 48,
    limit: int | None = None,
    only: Label | None = None,
    links: int = 1,
) -> list[SampleRecord]:
    """Snapshot URL records that do not have one yet, phishing first; returns all records.

    Tranco home pages also contribute `links` same-site pages as new legitimate records
    (decision D10a), which are snapshotted in a second pass. A record whose snapshot folder is
    already complete (meta.json present) is not fetched again, so an interrupted run resumes.
    """
    if os.environ.get(CONTAINER_FLAG) != "1":
        raise NotInSnapshotContainerError(
            "Phishing pages are fetched only inside the snapshot container "
            "(docker compose --profile collect run --rm snapshot)."
        )
    known = {r.sample_id for r in records}
    new_records: list[SampleRecord] = []

    def add_links(parent: SampleRecord, found: list[str]) -> None:
        for link in found:
            child = _link_record(link, parent)
            if child.sample_id not in known:
                known.add(child.sample_id)
                new_records.append(child)

    refs: dict = {}
    todo = []
    for r in records:
        if r.sample_type is not Modality.URL or (only is not None and r.label is not only):
            continue
        meta = _read_meta(r)
        if meta is not None:
            # Already snapshotted (e.g. before a rebuild): keep it, and re-create the D10a
            # link records it found, which a rebuild from the raw files does not contain.
            refs[r.sample_id] = f"snapshots/{r.sample_id}"
            if links and _is_home_page(r):
                add_links(r, meta.get("same_site_links", [])[:links])
        else:
            todo.append(r)
    todo.sort(key=lambda r: r.label is not Label.PHISHING)  # phishing pages die fastest
    todo = todo[:limit]

    cache = RunCache()
    headers = {"User-Agent": user_agent(Source.TRANCO)}
    with pinned_client(timeout=TIMEOUT, headers=headers) as client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = pool.map(lambda r: _safe_snapshot(r, client, cache, links), todo)
            for record, (ref, found) in zip(todo, results, strict=True):
                refs[record.sample_id] = ref
                add_links(record, found)
            done = {r.sample_id for r in new_records if _read_meta(r) is not None}
            pending = [r for r in new_records if r.sample_id not in done]
            list(pool.map(lambda r: _safe_snapshot(r, client, cache, 0), pending))
            new_records = [
                r.model_copy(update={"snapshot_ref": f"snapshots/{r.sample_id}"})
                for r in new_records
            ]
    updated = [
        r.model_copy(update={"snapshot_ref": refs[r.sample_id]}) if r.sample_id in refs else r
        for r in records
    ]
    return updated + new_records


def load_snapshot(record: SampleRecord, name: str) -> bytes | None:
    if record.snapshot_ref is None:
        return None
    path = paths.data_dir() / record.snapshot_ref / name
    return path.read_bytes() if path.exists() else None


def snapshot_dir_for(record: SampleRecord) -> Path:
    return paths.snapshots_dir() / str(record.sample_id)
