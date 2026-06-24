# src/engine/heuristics.py
import re
from urllib.parse import urlparse
from Levenshtein import distance as lev_distance

# Top 30 brands to check typosquatting against
TRUSTED_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft",
    "netflix", "paypal", "instagram", "twitter", "linkedin",
    "youtube", "whatsapp", "telegram", "dropbox", "github",
    "adobe", "spotify", "zoom", "slack", "reddit",
    "ebay", "walmart", "chase", "wellsfargo", "bankofamerica",
    "citibank", "hdfc", "icici", "sbi", "axis"
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rb.gy", "is.gd", "buff.ly", "dlvr.it"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "payment", "credential", "password",
    "free", "prize", "winner", "claim", "urgent", "suspended",
    "unusual", "activity", "recover", "unlock", "limited"
]


def analyse(url: str) -> dict:
    """
    Run full heuristic analysis on a URL.
    Returns a dict with: score (0-100), reasons, flags
    """
    try:
        parsed   = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = parsed.path.lower()
        full     = url.lower()
    except Exception:
        return {"score": 100, "reasons": ["Could not parse URL"], "flags": ["parse_error"]}

    score   = 0
    reasons = []
    flags   = []

    # ── 1. URL Length ─────────────────────────────────────
    if len(url) > 100:
        score += 20
        reasons.append(f"URL is very long ({len(url)} chars)")
        flags.append("long_url")
    elif len(url) > 75:
        score += 10
        reasons.append(f"URL is longer than usual ({len(url)} chars)")
        flags.append("medium_url")

    # ── 2. IP address as host ─────────────────────────────
    if hostname and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        score += 30
        reasons.append("IP address used instead of domain name")
        flags.append("ip_host")

    # ── 3. HTTPS check ────────────────────────────────────
    if parsed.scheme != "https":
        score += 15
        reasons.append("URL does not use HTTPS encryption")
        flags.append("no_https")

    # ── 4. Excessive subdomains ───────────────────────────
    if hostname:
        parts = hostname.split(".")
        if len(parts) > 4:
            score += 20
            reasons.append(f"Excessive subdomain depth ({len(parts)} levels)")
            flags.append("excessive_subdomains")
        elif len(parts) > 3:
            score += 8
            reasons.append("Multiple subdomains detected")
            flags.append("multi_subdomains")

    # ── 5. @ symbol ───────────────────────────────────────
    if "@" in url:
        score += 20
        reasons.append("@ symbol present — browser ignores everything before it")
        flags.append("at_symbol")

    # ── 6. Double slash in path ───────────────────────────
    if "//" in path:
        score += 10
        reasons.append("Double slash in URL path detected")
        flags.append("double_slash")

    # ── 7. URL shortener ─────────────────────────────────
    if hostname in URL_SHORTENERS:
        score += 15
        reasons.append(f"URL shortening service detected ({hostname})")
        flags.append("shortener")

    # ── 8. Suspicious keywords ────────────────────────────
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if found_kw:
        kw_score = min(len(found_kw) * 8, 25)
        score += kw_score
        reasons.append(f"Suspicious keywords found: {', '.join(found_kw[:4])}")
        flags.append("suspicious_keywords")

    # ── 9. Typosquatting detection ────────────────────────
    if hostname:
        base_domain = hostname.split(".")[0]
        for brand in TRUSTED_BRANDS:
            dist = lev_distance(base_domain, brand)
            if 0 < dist <= 2 and base_domain != brand:
                score += 35
                reasons.append(
                    f"Possible typosquatting: '{base_domain}' closely resembles '{brand}'"
                )
                flags.append("typosquatting")
                break

    # ── 10. Hyphen in domain ──────────────────────────────
    if hostname and hostname.count("-") > 2:
        score += 10
        reasons.append("Excessive hyphens in domain name")
        flags.append("hyphens")

    # ── 11. Path depth ────────────────────────────────────
    depth = len([p for p in path.split("/") if p])
    if depth > 5:
        score += 8
        reasons.append(f"Deep URL path ({depth} levels)")
        flags.append("deep_path")

    # ── 12. Numeric-heavy domain ─────────────────────────
    if hostname:
        digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
        if digit_ratio > 0.4:
            score += 12
            reasons.append("Domain name is heavily numeric")
            flags.append("numeric_domain")

    return {
        "score":   min(score, 100),
        "reasons": reasons if reasons else ["No suspicious patterns detected"],
        "flags":   flags
    }