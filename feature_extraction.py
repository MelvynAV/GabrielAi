# feature_extraction.py - GabrielAI v2.0
# ────────────────────────────────────────────────────────
# Extracts 22 features from a raw URL string.
# All features are lexical (text-only) — no network calls.
# This ensures the ML model is fast and reproducible.
# ────────────────────────────────────────────────────────

import re
import math
from urllib.parse import urlparse

# Phishing-associated keywords in URL paths/queries (generic action words only).
# Brand names are intentionally excluded here to avoid false positives on
# legitimate brand-owned domains (e.g., google.com, paypal.com).
# Brand impersonation (e.g., paypal-secure.evil.com) is caught by other
# features: hyphen-in-domain, subdomain_count, entropy, etc.
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'alert',
    'suspended', 'unusual', 'activity', 'webscr', 'ebayisapi',
    'redirect', 'validate', 'recover', 'authenticate'
]

# Brand impersonation keywords — only checked at inference in the FULL URL
# (not used in model features to avoid false positives on legitimate domains)
BRAND_IMPERSONATION_KEYWORDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'facebook', 'netflix', 'instagram', 'twitter', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'dropbox'
]

URL_SHORTENERS = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd',
    'ow.ly', 'buff.ly', 'short.link', 'rb.gy', 'clck.ru'
]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string. High entropy → likely random/obfuscated."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def extract_features(url: str) -> list:
    """
    Extract 22 numerical features from a raw URL.

    Feature vector (in order):
      0  have_ip           – IP address used instead of domain name
      1  have_at           – '@' symbol in URL (tricks browser auth parsing)
      2  url_length        – Binary: 1 if URL ≥ 54 chars (phishing threshold)
      3  url_depth         – Number of path segments (subdirectories)
      4  redirection       – '//' in path (suspicious redirect)
      5  https_domain      – 1 = HTTPS, 0 = HTTP
      6  tinyurl           – Known URL shortener service
      7  prefix_suffix     – Hyphen in domain (e.g. paypal-secure.com)
      8  dns_record        – Placeholder (set to 1; real DNS done in app)
      9  web_traffic       – Placeholder (set to 1)
     10  domain_age        – Placeholder (set by WHOIS in app)
     11  domain_end        – Placeholder (set by WHOIS in app)
     12  iframe            – Placeholder (static page analysis)
     13  mouse_over        – Placeholder
     14  right_click       – Placeholder
     15  web_forwards      – Placeholder

    ── NEW IN v2.0 ──
     16  subdomain_count   – Number of subdomains (e.g. a.b.c.com = 2 subdomains)
     17  domain_entropy    – Shannon entropy of the domain name (high = obfuscated)
     18  digit_ratio       – Ratio of digits in the domain name
     19  special_char_count– Count of special chars: ~ % ! & = + $ # in the full URL
     20  phishing_keywords – Count of phishing keywords found in the full URL
     21  punycode          – 1 if domain contains 'xn--' (homograph/IDN spoofing)

    Returns: list of 22 float values
    """
    if not url or not isinstance(url, str):
        return [0.0] * 22

    # Normalize
    url_norm = url.strip()
    if not url_norm.startswith(('http://', 'https://')):
        url_norm = 'http://' + url_norm

    parsed = urlparse(url_norm)
    scheme   = parsed.scheme.lower()
    netloc   = parsed.netloc.lower()
    path     = parsed.path.lower()
    query    = parsed.query.lower()
    full     = url_norm.lower()

    # Strip port, strip www
    hostname = netloc.split(':')[0]
    domain_no_www = hostname[4:] if hostname.startswith('www.') else hostname

    # ── Core 16 features (matching training CSV encoding) ──────────────────────
    f = [0.0] * 22

    # 0 – Have IP
    f[0] = 1.0 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0.0

    # 1 – Have @
    f[1] = 1.0 if '@' in full else 0.0

    # 2 – URL Length (binary threshold: 54 chars is the standard phishing cutoff)
    f[2] = 1.0 if len(url_norm) >= 54 else 0.0

    # 3 – URL Depth (count non-empty path segments)
    f[3] = float(len([p for p in path.split('/') if p]))

    # 4 – Redirection (double-slash in path or query)
    f[4] = 1.0 if '//' in path[1:] or '//' in query else 0.0

    # 5 – HTTPS
    f[5] = 1.0 if scheme == 'https' else 0.0

    # 6 – TinyURL / shortener
    f[6] = 1.0 if any(s in domain_no_www for s in URL_SHORTENERS) else 0.0

    # 7 – Prefix/Suffix (hyphen in domain = e.g. secure-paypal.com)
    f[7] = 1.0 if '-' in domain_no_www else 0.0

    # 8–15: Placeholders (DNS/page-content features — overridden in app.py)
    f[8]  = 1.0   # dns_record  (assume OK; real check in app)
    f[9]  = 1.0   # web_traffic (assume OK)
    f[10] = 1.0   # domain_age  (assume old; real check in app)
    f[11] = 0.0   # domain_end  (assume not expiring; real check in app)
    f[12] = 0.0   # iframe
    f[13] = 0.0   # mouse_over
    f[14] = 0.0   # right_click
    f[15] = 0.0   # web_forwards

    # ── New v2.0 features ───────────────────────────────────────────────────────

    # 16 – Subdomain count (parts of domain minus TLD + SLD)
    parts = domain_no_www.split('.')
    subdomain_count = max(0, len(parts) - 2)  # e.g. a.b.evil.com → 2 subdomains
    f[16] = float(subdomain_count)

    # 17 – Shannon entropy of domain (random-looking names are suspicious)
    f[17] = round(_shannon_entropy(domain_no_www), 4)

    # 18 – Digit ratio in domain
    if domain_no_www:
        digit_count = sum(c.isdigit() for c in domain_no_www)
        f[18] = round(digit_count / len(domain_no_www), 4)
    else:
        f[18] = 0.0

    # 19 – Special character count in full URL
    special_chars = set('~%!&=+$#^*|{}[]<>')
    f[19] = float(sum(c in special_chars for c in full))

    # 20 – Phishing keywords in path+query only (avoids false positives on brand domains)
    path_query = (path + ("?" + query if query else "")).lower()
    f[20] = float(sum(kw in path_query for kw in PHISHING_KEYWORDS))

    # 21 – Punycode / IDN homograph attack (xn-- prefix)
    f[21] = 1.0 if 'xn--' in hostname else 0.0

    return f


def get_feature_names() -> list:
    """Return human-readable names for all 22 features."""
    return [
        "Have IP Address",        # 0
        "Have @ Symbol",          # 1
        "Long URL (≥54 chars)",   # 2
        "URL Depth",              # 3
        "Double Redirection",     # 4
        "HTTPS Protocol",         # 5
        "URL Shortener",          # 6
        "Hyphen in Domain",       # 7
        "DNS Record (live)",      # 8
        "Web Traffic (live)",     # 9
        "Domain Age (live)",      # 10
        "Domain Expiring (live)", # 11
        "iFrame",                 # 12
        "MouseOver Handler",      # 13
        "Right-Click Disabled",   # 14
        "Web Forwards",           # 15
        "Subdomain Count",        # 16
        "Domain Entropy",         # 17
        "Digit Ratio in Domain",  # 18
        "Special Char Count",     # 19
        "Phishing Keyword Count", # 20
        "Punycode (IDN spoofing)",# 21
    ]
