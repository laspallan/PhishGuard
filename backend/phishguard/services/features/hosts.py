"""Splitting a hostname into subdomain / registered domain / public suffix.

Uses only the Public Suffix List snapshot bundled with tldextract (no network), the same setup
as the dataset pipeline in ml/, so training and the live API split hosts identically.
"""

import ipaddress
from dataclasses import dataclass

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(frozen=True)
class HostParts:
    subdomain: str  # "" if none, e.g. "login.secure" for login.secure.example.co.uk
    registered_domain: str  # eTLD+1, e.g. "example.co.uk"; the host itself if unknown suffix
    suffix: str  # public suffix, e.g. "co.uk"; "" for IP addresses


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def split_host(host: str) -> HostParts:
    host = host.lower().rstrip(".")
    if is_ip(host):
        return HostParts(subdomain="", registered_domain=host, suffix="")
    result = _extract(host)
    registered = result.top_domain_under_public_suffix or host
    return HostParts(subdomain=result.subdomain, registered_domain=registered, suffix=result.suffix)
