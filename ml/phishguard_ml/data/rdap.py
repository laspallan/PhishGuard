"""Registration data (RDAP, the JSON successor of WHOIS) for every registered domain.

Separate from the snapshot collector because registration data is not time-critical and the
registries rate-limit it. Queries go directly to each top-level domain's own RDAP server, found
in IANA's bootstrap file (RFC 9224, https://data.iana.org/rdap/dns.json), never to the domain's
web server, so this step may run anywhere.

Politeness: one request at a time per registry with a pause between requests (different
registries run in parallel); on HTTP 429 or a server error the request is retried with
increasing waits (honouring Retry-After). Results go to data/rdap/<domain>.json; a domain with a
final answer (200 or 404) is never queried again, so a stopped run resumes.
"""

import json
import os
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from phishguard.models.enums import Modality
from phishguard_ml import paths
from phishguard_ml.data.clean import registered_domain
from phishguard_ml.data.download import DEFAULT_USER_AGENT
from phishguard_ml.data.records import SampleRecord

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
FINAL_STATUSES = (200, 404)
RETRY_STATUSES = (429, 500, 502, 503, 504)


def rdap_dir() -> Path:
    return paths.data_dir() / "rdap"


def rdap_path(domain: str) -> Path:
    return rdap_dir() / f"{domain}.json"


def load_bootstrap(client: httpx.Client) -> dict[str, str]:
    """TLD -> RDAP base URL. The downloaded file is kept in data/rdap/ for the record."""
    cached = rdap_dir() / "bootstrap.json"
    if cached.exists():
        data = json.loads(cached.read_text())
    else:
        response = client.get(BOOTSTRAP_URL)
        response.raise_for_status()
        data = response.json()
        rdap_dir().mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps(data))
    table = {}
    for tlds, urls in data["services"]:
        base = next((u for u in urls if u.startswith("https://")), urls[0])
        for tld in tlds:
            table[tld.lower()] = base if base.endswith("/") else base + "/"
    return table


def base_for(domain: str, table: dict[str, str]) -> str | None:
    labels = domain.lower().split(".")
    for i in range(len(labels)):  # longest suffix first (some entries have dots)
        base = table.get(".".join(labels[i:]))
        if base:
            return base
    return None


def domains_of(records: Iterable[SampleRecord]) -> list[str]:
    """Registered domains of all URL records (IP addresses have no registration data)."""
    found = set()
    for record in records:
        if record.sample_type is not Modality.URL:
            continue
        domain = registered_domain(urlsplit(record.raw_content).hostname or "")
        if domain and not domain.replace(".", "").isdigit() and ":" not in domain:
            found.add(domain)
    return sorted(found)


def fetch(
    domain: str,
    base: str,
    client: httpx.Client,
    *,
    retries: int = 4,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    url = f"{base}domain/{domain}"
    for attempt in range(retries + 1):
        try:
            response = client.get(url, follow_redirects=True)
        except httpx.HTTPError as error:
            result = {"error": f"{type(error).__name__}: {error}"}
        else:
            if response.status_code == 200:
                try:
                    return {"status": 200, "response": response.json()}
                except ValueError:
                    return {"status": 200, "error": "not JSON"}
            if response.status_code in FINAL_STATUSES:
                return {"status": response.status_code}
            result = {"status": response.status_code, "error": f"HTTP {response.status_code}"}
            if response.status_code not in RETRY_STATUSES:
                return result
            retry_after = response.headers.get("retry-after", "")
            if retry_after.isdigit():
                sleep(min(int(retry_after), 300))
                continue
        if attempt < retries:
            sleep(5 * 2**attempt)
    return result


def _is_final(path: Path) -> bool:
    if not path.exists():
        return False
    return json.loads(path.read_text()).get("status") in FINAL_STATUSES


def collect(
    domains: Iterable[str],
    client: httpx.Client,
    *,
    interval: float = 0.5,
    workers: int = 16,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, int]:
    """Query every domain without a final answer yet. Returns counts of outcomes."""
    table = load_bootstrap(client)
    by_registry: dict[str, list[str]] = defaultdict(list)
    outcome: dict[str, int] = defaultdict(int)
    for domain in domains:
        if _is_final(rdap_path(domain)):
            outcome["already_done"] += 1
            continue
        base = base_for(domain, table)
        if base is None:
            rdap_path(domain).parent.mkdir(parents=True, exist_ok=True)
            rdap_path(domain).write_text(json.dumps({"status": 404, "error": "no RDAP server"}))
            outcome["no_rdap_server"] += 1
            continue
        by_registry[base].append(domain)

    def run_registry(base: str) -> list[int | None]:
        statuses = []
        for domain in by_registry[base]:
            result = fetch(domain, base, client, sleep=sleep)
            result["queried_at"] = datetime.now(UTC).isoformat()
            tmp = rdap_path(domain).with_suffix(".json.tmp")
            tmp.write_text(json.dumps(result))
            os.replace(tmp, rdap_path(domain))
            statuses.append(result.get("status"))
            sleep(interval)
        return statuses

    rdap_dir().mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for statuses in pool.map(run_registry, list(by_registry)):
            for status in statuses:
                outcome[f"http_{status}" if status else "network_error"] += 1
    return dict(outcome)


def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(20.0),
        headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/rdap+json"},
    )
