"""Hosts the extension blocks before they load (Phase 7, option C in
Docs/extension_precheck_proposal.md).

Only host names are shared, never URLs: a phishing URL's path or query often carries the victim's
address or a token, and the host alone is enough to stop the page. A host is shared when this API
rated a URL on it **block** in the last BLOCK_DAYS days, unless anything on the same registered
domain was rated **allow** in the last SAFE_DAYS days: that protects shared hosting (one phishing
page on a site-builder host must not block every site on it).
"""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from phishguard.models.enums import Decision
from phishguard.services.features.hosts import split_host

BLOCK_DAYS = 7
SAFE_DAYS = 30
MAX_HOSTS = 1000


def host_of(url: str | None) -> str | None:
    try:
        parts = urlsplit(url or "")
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    return host.rstrip(".")


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def blocked_hosts(
    rows: Iterable[tuple[str | None, Decision, datetime]], now: datetime
) -> list[str]:
    """`rows`: (url, decision, scanned at) of URL scans. Newest blocks first, at most MAX_HOSTS."""
    latest_block: dict[str, datetime] = {}
    safe_domains: set[str] = set()
    for url, decision, at in rows:
        host, at = host_of(url), _utc(at)
        if host is None:
            continue
        if decision is Decision.ALLOW and at >= now - timedelta(days=SAFE_DAYS):
            safe_domains.add(split_host(host).registered_domain)
        elif decision is Decision.BLOCK and at >= now - timedelta(days=BLOCK_DAYS):
            latest_block[host] = max(at, latest_block.get(host, at))
    hosts = [h for h in latest_block if split_host(h).registered_domain not in safe_domains]
    hosts.sort(key=lambda h: latest_block[h], reverse=True)
    return hosts[:MAX_HOSTS]
