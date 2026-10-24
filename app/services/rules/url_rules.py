from urllib.parse import urlparse
import ipaddress
from app.services.detection_engine import RuleContext, Finding


def check_ip_urls(ctx: RuleContext) -> Finding | None:
    ip_urls = []
    for url in ctx.iocs.urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                ipaddress.ip_address(parsed.hostname)
                ip_urls.append(url)
        except ValueError:
            pass
    if ip_urls:
        return Finding(
            rule_id="URL-001",
            title="URL uses raw IP address",
            description="Links point directly to IP addresses instead of domains.",
            severity="high",
            confidence="high",
            weight=15,
            evidence={"urls": ip_urls},
        )
    return None


def check_insecure_scheme(ctx: RuleContext) -> Finding | None:
    http_urls = [u for u in ctx.iocs.urls if u.startswith("http://")]
    if http_urls:
        return Finding(
            rule_id="URL-002",
            title="Insecure HTTP links found",
            description="Contains URLs using unencrypted HTTP.",
            severity="low",
            confidence="high",
            weight=5,
            evidence={"urls": http_urls[:5]},
        )
    return None


def check_suspicious_tlds(ctx: RuleContext) -> Finding | None:
    suspicious_tlds = {".xyz", ".top", ".club", ".online", ".site", ".zip", ".mov"}
    bad_domains = [
        d for d in ctx.iocs.domains if any(d.endswith(tld) for tld in suspicious_tlds)
    ]
    if bad_domains:
        return Finding(
            rule_id="URL-003",
            title="Suspicious TLD",
            description="Domains use TLDs frequently abused for phishing.",
            severity="medium",
            confidence="medium",
            weight=10,
            evidence={"domains": bad_domains},
        )
    return None


def check_url_subdomain_depth(ctx: RuleContext) -> Finding | None:
    deep_domains = set()
    for url in ctx.iocs.urls:
        try:
            parsed = urlparse(url)
            if parsed.hostname and parsed.hostname.count(".") > 3:
                deep_domains.add(parsed.hostname)
        except Exception:
            pass
    if deep_domains:
        return Finding(
            rule_id="URL-004",
            title="Excessive subdomain depth",
            description="Deeply nested subdomains can be used to spoof brands.",
            severity="medium",
            confidence="high",
            weight=10,
            evidence={"hostnames": list(deep_domains)[:5]},
        )
    return None


URL_RULES = [
    check_ip_urls,
    check_insecure_scheme,
    check_suspicious_tlds,
    check_url_subdomain_depth,
]
