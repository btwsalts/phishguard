import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "password", "wallet", "bank", "unlock"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly",
    "ow.ly", "buff.ly", "shorturl.at"
}

def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def analyze_url(raw_url):
    candidate = raw_url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url) else "http://" + raw_url
    parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("The URL does not contain a valid hostname.")

    indicators = []
    def add(name, status, detail, severity):
        indicators.append({"name": name, "status": status, "detail": detail, "severity": severity})

    https = parsed.scheme == "https"
    add("HTTPS", "pass" if https else "warning",
        "Encrypted transport detected." if https else "The URL uses plain HTTP.",
        0 if https else 15)

    ip_url = _is_ip(host)
    add("IP-based host", "warning" if ip_url else "pass",
        "The hostname is a raw IP address." if ip_url else "A domain hostname is used.",
        25 if ip_url else 0)

    userinfo = parsed.username is not None
    add("Embedded credentials", "warning" if userinfo else "pass",
        "The URL contains username information before the host." if userinfo else "No embedded username was detected.",
        25 if userinfo else 0)

    suspicious = sorted({w for w in SUSPICIOUS_WORDS if w in (parsed.path + "?" + parsed.query).lower()})
    add("Sensitive keywords", "warning" if suspicious else "pass",
        ("Found: " + ", ".join(suspicious)) if suspicious else "No common credential-related keywords found.",
        min(30, len(suspicious) * 7))

    host_labels = host.split(".")
    subdomain_depth = max(0, len(host_labels) - 2) if not ip_url else 0
    add("Deep subdomain", "warning" if subdomain_depth >= 3 else "pass",
        f"{subdomain_depth} subdomain level(s) detected." if subdomain_depth else "No unusually deep subdomain structure detected.",
        15 if subdomain_depth >= 3 else 0)

    unicode_host = any(ord(ch) > 127 for ch in host)
    punycode = "xn--" in host
    add("Lookalike / IDN host", "warning" if unicode_host or punycode else "pass",
        "Internationalized or punycode hostname detected." if unicode_host or punycode else "No IDN/punycode indicator detected.",
        20 if unicode_host or punycode else 0)

    shortened = host in SHORTENERS
    add("URL shortener", "warning" if shortened else "pass",
        "Known URL-shortening service detected." if shortened else "No common URL shortener detected.",
        15 if shortened else 0)

    long_url = len(candidate) > 180
    add("Unusually long URL", "warning" if long_url else "pass",
        f"URL length: {len(candidate)} characters." + (" This is unusually long." if long_url else ""),
        10 if long_url else 0)

    encoded = bool(re.search(r"%[0-9a-fA-F]{2}", parsed.path + parsed.query))
    add("Encoded characters", "info" if encoded else "pass",
        "Percent-encoded characters are present." if encoded else "No percent-encoded characters detected.",
        5 if encoded else 0)

    score = min(100, sum(i["severity"] for i in indicators))
    if score >= 60:
        risk, risk_class = "HIGH", "high"
    elif score >= 30:
        risk, risk_class = "MEDIUM", "medium"
    else:
        risk, risk_class = "LOW", "low"

    return {
        "input": raw_url,
        "normalized": candidate,
        "hostname": host,
        "risk": risk,
        "risk_class": risk_class,
        "score": score,
        "indicators": indicators,
        "note": "This is a heuristic analysis, not proof that a site is malicious."
    }
