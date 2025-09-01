from urllib.parse import urlparse
import tldextract
import re

# Domain related helper functions
def host_from_url(url: str) -> str:
    return urlparse(url).hostname or ""


def registrable_domain(host_or_url: str) -> str:
    host = host_from_url(host_or_url) if "://" in host_or_url else host_or_url
    ext = tldextract.extract(host)
    if not ext.registered_domain:
        return host
    return ext.registered_domain

def is_third_party(request_url: str, page_url: str) -> bool:
    return registrable_domain(request_url) != registrable_domain(page_url)

def is_blocklisted_host(host: str, tracking_set: set) -> bool:
    etld1 = registrable_domain(host)
    return (
        host in tracking_set
        or etld1 in tracking_set
        or any(host.endswith("." + d) for d in tracking_set)
    )