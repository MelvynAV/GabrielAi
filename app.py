# app.py - GabrielAI v2.0
# ─────────────────────────────────────────────────────────────────────────────
# Phishing URL Detection with Supervised ML + Live Enrichment Signals
# ─────────────────────────────────────────────────────────────────────────────

import streamlit as st
import pickle
import numpy as np
import re
import math
import ssl
import socket
import datetime
from datetime import timezone
from urllib.parse import urlparse

from feature_extraction import extract_features, get_feature_names, PHISHING_KEYWORDS

# ── Optional runtime packages (graceful fallback if not installed) ─────────────
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GabrielAI v2 — Phishing Detection",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Load model ────────────────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    try:
        with open('gabriel_phishing_model.pkl', 'rb') as f:
            obj = pickle.load(f)
        # Support both v1 (raw model) and v2 (dict)
        if isinstance(obj, dict):
            return obj['model'], obj.get('feature_cols', []), obj
        else:
            return obj, [], {}
    except FileNotFoundError:
        return None, [], {}

model, feature_cols, model_meta = load_model()

if model is None:
    st.error("⚠️ Model not found. Please run `train_model.py` first.")
    st.stop()

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    .stApp {
        background: linear-gradient(135deg, #0a0a1a 0%, #0d1f3c 50%, #0a0a1a 100%);
        font-family: 'Inter', sans-serif;
    }
    .main .block-container {
        background: rgba(10, 18, 40, 0.92);
        border: 1px solid rgba(212, 175, 55, 0.2);
        padding: 2.5rem 3rem;
        border-radius: 20px;
        box-shadow: 0 0 60px rgba(212, 175, 55, 0.08), 0 20px 40px rgba(0,0,0,0.6);
        margin-top: 1rem;
    }
    h1 {
        background: linear-gradient(90deg, #d4af37, #f7e98e, #d4af37);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        font-size: 2.8rem;
        font-weight: 700;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 0;
    }
    .subtitle {
        text-align: center;
        color: #8899aa;
        font-size: 0.95rem;
        font-style: italic;
        margin-top: 0.3rem;
        margin-bottom: 1.5rem;
    }
    .badge {
        display: inline-block;
        background: rgba(212,175,55,0.12);
        border: 1px solid rgba(212,175,55,0.35);
        color: #d4af37;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin: 2px;
    }
    div.stButton > button {
        background: linear-gradient(90deg, #b8860b 0%, #d4af37 50%, #f7e98e 100%);
        color: #0a0a1a;
        border: none;
        padding: 12px 24px;
        border-radius: 50px;
        font-size: 1rem;
        font-weight: 700;
        letter-spacing: 1px;
        width: 100%;
        transition: all 0.3s;
        box-shadow: 0 4px 20px rgba(212, 175, 55, 0.3);
    }
    div.stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(212, 175, 55, 0.5);
    }
    .stTextInput > div > div > input {
        background: rgba(255,255,255,0.05) !important;
        border: 1px solid rgba(212,175,55,0.3) !important;
        border-radius: 12px !important;
        color: #e8e8e8 !important;
        padding: 12px 20px !important;
        font-size: 1rem !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #d4af37 !important;
        box-shadow: 0 0 0 2px rgba(212,175,55,0.2) !important;
    }
    .result-safe {
        background: linear-gradient(135deg, rgba(0,200,100,0.12), rgba(0,150,80,0.08));
        border: 1px solid rgba(0,200,100,0.4);
        border-left: 6px solid #00c864;
        padding: 20px 24px;
        border-radius: 12px;
        text-align: center;
        margin: 1rem 0;
    }
    .result-threat {
        background: linear-gradient(135deg, rgba(220,30,30,0.15), rgba(180,0,0,0.08));
        border: 1px solid rgba(220,30,30,0.5);
        border-left: 6px solid #dc1e1e;
        padding: 20px 24px;
        border-radius: 12px;
        text-align: center;
        margin: 1rem 0;
    }
    .result-warn {
        background: linear-gradient(135deg, rgba(255,165,0,0.12), rgba(200,120,0,0.08));
        border: 1px solid rgba(255,165,0,0.4);
        border-left: 6px solid #ffa500;
        padding: 20px 24px;
        border-radius: 12px;
        text-align: center;
        margin: 1rem 0;
    }
    .signal-card {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 14px 16px;
        margin: 6px 0;
    }
    .signal-label {
        color: #8899aa;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    .signal-value {
        color: #e8e8e8;
        font-size: 1rem;
        font-weight: 600;
        margin-top: 3px;
    }
    .ok { color: #00c864; }
    .warn { color: #ffa500; }
    .bad { color: #ff4444; }
    .section-title {
        color: #d4af37;
        font-size: 0.85rem;
        font-weight: 600;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        border-bottom: 1px solid rgba(212,175,55,0.2);
        padding-bottom: 6px;
        margin: 1.2rem 0 0.8rem 0;
    }
    .stExpander {
        background: rgba(255,255,255,0.03) !important;
        border: 1px solid rgba(255,255,255,0.08) !important;
        border-radius: 10px !important;
    }
    .stMetric { background: transparent; }
    .feature-bar-bg {
        background: rgba(255,255,255,0.06);
        border-radius: 4px;
        height: 6px;
        margin-top: 4px;
    }
    .feature-bar-fill {
        height: 6px;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

# ── Known safe domains (whitelist for well-known legitimate sites) ─────────────
SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'gstatic.com', 'googleapis.com',
    'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
    'twitter.com', 'x.com', 'twimg.com',
    'amazon.com', 'cloudfront.net', 'apple.com', 'icloud.com',
    'microsoft.com', 'live.com', 'office.com', 'bing.com',
    'linkedin.com', 'netflix.com', 'reddit.com', 'redd.it',
    'paypal.com', 'github.com', 'stackoverflow.com', 'bankofamerica.com',
    'wikipedia.org', 'discord.com', 'spotify.com', 'zoom.us',
    'adobe.com', 'salesforce.com', 'slack.com', 'dropbox.com',
    'uottawa.ca', 'canada.ca', 'gc.ca', 'cloudflare.com',
    'vercel.app', 'netlify.app', 'streamlit.app', 'streamlit.io',
}

# ── SSL Certificate check ─────────────────────────────────────────────────────
def get_ssl_info(hostname: str) -> dict:
    """
    Retrieve SSL certificate metadata.
    Returns: issuer, valid_from, valid_to, cert_duration_days, days_remaining, error.
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        def parse_cert_date(s):
            return datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        valid_from = parse_cert_date(cert['notBefore'])
        valid_to   = parse_cert_date(cert['notAfter'])
        now        = datetime.datetime.now(timezone.utc)

        duration_days   = (valid_to - valid_from).days
        days_remaining  = (valid_to - now).days

        # Extract issuer org
        issuer_map = {k: v for k, v in (x for sublist in cert.get('issuer', []) for x in sublist)}
        issuer_org = issuer_map.get('organizationName', issuer_map.get('commonName', 'Unknown'))

        return {
            'issuer':          issuer_org,
            'valid_from':      valid_from.strftime('%Y-%m-%d'),
            'valid_to':        valid_to.strftime('%Y-%m-%d'),
            'duration_days':   duration_days,
            'days_remaining':  days_remaining,
            'error':           None,
        }
    except ssl.SSLCertVerificationError:
        return {'error': 'Certificate verification failed (self-signed or invalid)'}
    except socket.timeout:
        return {'error': 'Connection timeout (no HTTPS or host unreachable)'}
    except Exception as e:
        return {'error': f'SSL check unavailable: {str(e)[:60]}'}

# ── DNS lookup ────────────────────────────────────────────────────────────────
def get_dns_info(hostname: str) -> dict:
    if not DNS_AVAILABLE:
        return {'available': False, 'note': 'dnspython not installed'}
    try:
        answers = dns.resolver.resolve(hostname, 'A', lifetime=4)
        return {'available': True, 'a_records': [str(r) for r in answers], 'has_dns': True}
    except Exception as e:
        return {'available': True, 'has_dns': False, 'error': str(e)[:60]}

# ── WHOIS lookup ──────────────────────────────────────────────────────────────
def get_whois_info(hostname: str) -> dict:
    if not WHOIS_AVAILABLE:
        return {'available': False, 'note': 'python-whois not installed'}
    try:
        w = whois.whois(hostname)
        now = datetime.datetime.now(timezone.utc)

        def normalize(dt):
            if isinstance(dt, list): dt = dt[0]
            if isinstance(dt, datetime.datetime):
                return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
            return None

        creation   = normalize(w.creation_date)
        expiration = normalize(w.expiration_date)

        age_days      = (now - creation).days   if creation   and creation < now   else None
        days_to_expiry= (expiration - now).days if expiration and expiration > now else None

        return {
            'available':     True,
            'registrar':     getattr(w, 'registrar', 'Unknown'),
            'creation_date': creation.strftime('%Y-%m-%d')   if creation   else 'Unknown',
            'expiry_date':   expiration.strftime('%Y-%m-%d') if expiration else 'Unknown',
            'age_days':      age_days,
            'days_to_expiry':days_to_expiry,
        }
    except Exception as e:
        return {'available': True, 'error': str(e)[:80]}

# ── UI: Header ────────────────────────────────────────────────────────────────
st.markdown("<h1>⚔ Gabriel AI</h1>", unsafe_allow_html=True)
st.markdown(
    "<p class='subtitle'>Phishing URL Detection Engine &nbsp;·&nbsp; "
    "<span class='badge'>v2.0</span> "
    "<span class='badge'>Random Forest · 22 Features</span> "
    "<span class='badge'>95.7% Accuracy</span></p>",
    unsafe_allow_html=True
)

st.markdown(
    "<p style='text-align:center; color:#8899aa; font-size:0.88rem;'>"
    "Paste any URL below — the engine will analyze its structural, lexical, and network signals in real-time.</p>",
    unsafe_allow_html=True
)

st.markdown("---")

# ── Input ─────────────────────────────────────────────────────────────────────
url_input = st.text_input(
    "URL",
    placeholder="https://suspicious-login.paypal-secure.com/verify?account=...",
    label_visibility="collapsed"
)

col_btn, col_ex = st.columns([3, 1])
with col_btn:
    analyze_btn = st.button("🛡️  ANALYZE URL", use_container_width=True)
with col_ex:
    demo_btn = st.button("📋 Demo", use_container_width=True)

if demo_btn:
    st.session_state['demo_url'] = "http://paypal-secure-update.com/login?user=victim&token=abc123"
    st.rerun()

if 'demo_url' in st.session_state:
    url_input = st.session_state.pop('demo_url')
    analyze_btn = True

# ── Analysis ──────────────────────────────────────────────────────────────────
if analyze_btn:
    if not url_input.strip():
        st.warning("⚠️ Please paste a URL to analyze.")
        st.stop()

    url_str = url_input.strip()
    url_norm = url_str if url_str.startswith(('http://', 'https://')) else 'http://' + url_str

    parsed   = urlparse(url_norm)
    netloc   = parsed.netloc.lower()
    hostname = netloc.split(':')[0]
    domain   = hostname[4:] if hostname.startswith('www.') else hostname

    # ── Whitelist check ────────────────────────────────────────────────────────
    is_whitelisted = (
        domain in SAFE_DOMAINS or
        any(domain.endswith('.' + s) for s in SAFE_DOMAINS)
    )

    # ── Feature extraction ─────────────────────────────────────────────────────
    features = extract_features(url_str)

    # ── Live signal collection (SSL, DNS, WHOIS) ───────────────────────────────
    ssl_info, dns_info, whois_info = {}, {}, {}

    with st.spinner("🔍 Running analysis…"):

        # SSL (pure stdlib — always available)
        if parsed.scheme == 'https' or url_norm.startswith('https'):
            ssl_info = get_ssl_info(domain)
        else:
            # Try anyway in case the site does redirect to HTTPS
            ssl_info = get_ssl_info(domain)

        # DNS & WHOIS (optional packages)
        if DNS_AVAILABLE:
            dns_info = get_dns_info(domain)
        if WHOIS_AVAILABLE:
            whois_info = get_whois_info(domain)
            # Feed WHOIS results back into features for model
            if whois_info.get('available') and 'age_days' in whois_info:
                if whois_info['age_days'] is not None:
                    features[10] = 1.0 if whois_info['age_days'] > 365 else 0.0
                if whois_info.get('days_to_expiry') is not None:
                    features[11] = 1.0 if 0 < whois_info['days_to_expiry'] < 30 else 0.0

    # ── Model prediction ───────────────────────────────────────────────────────
    if is_whitelisted:
        prediction, confidence = 0, 99.5
    else:
        X = np.array([features], dtype=float)
        prediction = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        confidence = proba[1] * 100 if prediction == 1 else proba[0] * 100

    # ── Result banner ──────────────────────────────────────────────────────────
    st.markdown("---")
    if is_whitelisted:
        st.markdown(f"""
        <div class='result-safe'>
            <h2 style='color:#00c864; margin:0;'>✅ SAFE — WHITELISTED DOMAIN</h2>
            <p style='color:#aaa; margin:4px 0 0;'>This is a well-known, trusted domain.</p>
        </div>""", unsafe_allow_html=True)
    elif prediction == 1:
        risk_label = "CRITICAL" if confidence > 85 else "HIGH"
        st.markdown(f"""
        <div class='result-threat'>
            <h2 style='color:#ff4444; margin:0;'>🚨 THREAT DETECTED — {risk_label} RISK</h2>
            <p style='color:#ffaaaa; margin:4px 0 0;'>This URL exhibits strong indicators of a phishing attack.</p>
        </div>""", unsafe_allow_html=True)
    else:
        warn_note = " — Low confidence, exercise caution." if confidence < 75 else ""
        st.markdown(f"""
        <div class='result-safe'>
            <h2 style='color:#00c864; margin:0;'>🛡️ LIKELY SAFE</h2>
            <p style='color:#aaa; margin:4px 0 0;'>No strong phishing indicators detected.{warn_note}</p>
        </div>""", unsafe_allow_html=True)

    # ── Confidence meter ────────────────────────────────────────────────────────
    mc1, mc2, mc3 = st.columns(3)
    if prediction == 1 and not is_whitelisted:
        mc1.metric("🔴 Risk Score",    f"{confidence:.1f}%")
        mc2.metric("🔬 Features Used", f"{len(features)}")
        mc3.metric("🤖 Model",         "Random Forest v2")
    else:
        mc1.metric("🟢 Safety Score",  f"{confidence:.1f}%" if not is_whitelisted else "99.5%")
        mc2.metric("🔬 Features Used", f"{len(features)}")
        mc3.metric("🤖 Model",         "Random Forest v2")

    # ── SECTION 1: Structural Signals ──────────────────────────────────────────
    st.markdown("<p class='section-title'>🔍 Structural Signals</p>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)

    def sig(label, value, css_class=""):
        return f"""<div class='signal-card'>
            <div class='signal-label'>{label}</div>
            <div class='signal-value {css_class}'>{value}</div>
        </div>"""

    feature_names = get_feature_names()
    scheme_used = "HTTPS ✅" if features[5] == 1 else "HTTP ⚠️"
    has_ip      = "Yes 🚨" if features[0] == 1 else "No ✅"
    has_at      = "Yes 🚨" if features[1] == 1 else "No ✅"
    long_url    = "Yes ⚠️" if features[2] == 1 else "No ✅"
    has_hyphen  = "Yes ⚠️" if features[7] == 1 else "No ✅"
    shortener   = "Yes 🚨" if features[6] == 1 else "No ✅"
    redirect    = "Yes 🚨" if features[4] == 1 else "No ✅"
    punycode    = "Yes 🚨" if features[21] == 1 else "No ✅"

    with c1:
        st.markdown(sig("Protocol",            scheme_used),  unsafe_allow_html=True)
        st.markdown(sig("IP Address Used",     has_ip),       unsafe_allow_html=True)
        st.markdown(sig("@ Symbol in URL",     has_at),       unsafe_allow_html=True)
        st.markdown(sig("URL Too Long (≥54c)", long_url),     unsafe_allow_html=True)
    with c2:
        st.markdown(sig("Hyphen in Domain",    has_hyphen),   unsafe_allow_html=True)
        st.markdown(sig("URL Shortener",       shortener),    unsafe_allow_html=True)
        st.markdown(sig("Double Redirect //",  redirect),     unsafe_allow_html=True)
        st.markdown(sig("Punycode / IDN",      punycode),     unsafe_allow_html=True)

    # ── SECTION 2: Lexical Intelligence (new v2 features) ─────────────────────
    st.markdown("<p class='section-title'>🧬 Lexical Intelligence (v2.0)</p>", unsafe_allow_html=True)
    lc1, lc2, lc3 = st.columns(3)

    subdomain_c = int(features[16])
    entropy_val = round(features[17], 2)
    digit_r     = round(features[18] * 100, 1)
    kw_count    = int(features[20])
    spec_count  = int(features[19])
    url_depth   = int(features[3])

    subdomain_cls = "bad" if subdomain_c >= 3 else ("warn" if subdomain_c >= 2 else "ok")
    entropy_cls   = "bad" if entropy_val > 3.8 else ("warn" if entropy_val > 3.2 else "ok")
    digit_cls     = "bad" if digit_r > 30 else ("warn" if digit_r > 15 else "ok")
    kw_cls        = "bad" if kw_count >= 2 else ("warn" if kw_count == 1 else "ok")

    with lc1:
        st.markdown(sig("Subdomain Depth",    f"{subdomain_c}", subdomain_cls), unsafe_allow_html=True)
        st.markdown(sig("URL Depth",          f"/{url_depth} levels"),          unsafe_allow_html=True)
    with lc2:
        st.markdown(sig("Domain Entropy",     f"{entropy_val} / 5.0", entropy_cls), unsafe_allow_html=True)
        st.markdown(sig("Digit Ratio",        f"{digit_r}%", digit_cls),           unsafe_allow_html=True)
    with lc3:
        st.markdown(sig("Phishing Keywords",  f"{kw_count} found", kw_cls), unsafe_allow_html=True)
        st.markdown(sig("Special Chars",      f"{spec_count}"),               unsafe_allow_html=True)

    # ── SECTION 3: Live Network Signals ───────────────────────────────────────
    st.markdown("<p class='section-title'>🌐 Live Network Signals</p>", unsafe_allow_html=True)
    nc1, nc2 = st.columns(2)

    with nc1:
        st.markdown("**🔒 SSL Certificate**")
        if ssl_info.get('error'):
            err = ssl_info['error']
            st.markdown(sig("SSL Status",
                "⚠️ No valid cert" if "invalid" in err.lower() or "fail" in err.lower() else "⚠️ N/A",
                "warn"),
            unsafe_allow_html=True)
            st.caption(f"_{err}_")
        else:
            dur   = ssl_info.get('duration_days', 0)
            rem   = ssl_info.get('days_remaining', 0)
            issuer= ssl_info.get('issuer', 'Unknown')
            # Short-lived certs (< 90 days) are a phishing signal
            dur_cls  = "bad" if dur < 90 else ("warn" if dur < 180 else "ok")
            rem_cls  = "bad" if rem < 7  else ("warn" if rem < 30  else "ok")
            st.markdown(sig("Issuer",               issuer),                    unsafe_allow_html=True)
            st.markdown(sig("Cert Validity",        f"{dur} days", dur_cls),    unsafe_allow_html=True)
            st.markdown(sig("Valid From → To",
                f"{ssl_info.get('valid_from','?')} → {ssl_info.get('valid_to','?')}"),
            unsafe_allow_html=True)
            st.markdown(sig("Days Remaining",       f"{rem} days", rem_cls),    unsafe_allow_html=True)

    with nc2:
        st.markdown("**📋 Domain Registration**")
        if not WHOIS_AVAILABLE:
            st.markdown(sig("WHOIS",  "Install python-whois for live data", "warn"), unsafe_allow_html=True)
        elif whois_info.get('error'):
            st.markdown(sig("WHOIS Error", whois_info['error'][:50], "warn"), unsafe_allow_html=True)
        else:
            age  = whois_info.get('age_days')
            left = whois_info.get('days_to_expiry')
            age_cls  = "bad" if age is not None and age < 90  else ("warn" if age is not None and age < 365 else "ok")
            left_cls = "bad" if left is not None and left < 30 else "ok"
            st.markdown(sig("Registrar",    whois_info.get('registrar', 'Unknown')[:35]), unsafe_allow_html=True)
            st.markdown(sig("Created",      whois_info.get('creation_date', 'Unknown')), unsafe_allow_html=True)
            st.markdown(sig("Expires",      whois_info.get('expiry_date', 'Unknown')),   unsafe_allow_html=True)
            age_str  = f"{age} days"  if age  is not None else "Unknown"
            left_str = f"{left} days" if left is not None else "Unknown"
            st.markdown(sig("Domain Age",       age_str,  age_cls),  unsafe_allow_html=True)
            st.markdown(sig("Expires In",       left_str, left_cls), unsafe_allow_html=True)

    # ── SECTION 4: Recommendation ─────────────────────────────────────────────
    st.markdown("---")
    if prediction == 1 and not is_whitelisted:
        st.error(
            "🚫 **RECOMMENDATION:** Do NOT click this link. "
            "Block the domain immediately and report it to your security team or [Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/)."
        )
    elif not is_whitelisted and confidence < 75:
        st.warning(
            "⚠️ **RECOMMENDATION:** Proceed with caution. "
            "Verify the domain ownership independently before entering any credentials."
        )
    else:
        st.success(
            "✅ **RECOMMENDATION:** This URL appears safe. "
            "Always verify the domain matches what you expect before entering sensitive data."
        )

    # ── Technical report (expander) ───────────────────────────────────────────
    with st.expander("📊 Technical Report — Feature Vector & Raw Data"):
        st.markdown("**Model Feature Vector (22 dimensions)**")
        names = get_feature_names()
        col_a, col_b = st.columns(2)
        for i, (name, val) in enumerate(zip(names, features)):
            col = col_a if i < 11 else col_b
            icon = "🔴" if val > 0 and i not in [3, 5, 8, 9, 10, 17, 18] else ("🟡" if val > 0 else "🟢")
            col.markdown(f"`{i:02d}` {icon} **{name}**: `{round(val, 3)}`")

        if ssl_info and not ssl_info.get('error'):
            st.markdown("**SSL Certificate (raw)**")
            st.json(ssl_info)
        if whois_info and whois_info.get('available'):
            st.markdown("**WHOIS Data (raw)**")
            st.json(whois_info)
        if dns_info and dns_info.get('available'):
            st.markdown("**DNS Records**")
            st.json(dns_info)

# ── Footer ─────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:#445566; font-size:0.78rem;'>"
    "GabrielAI v2.0 · Melvyn Avoa · uOttawa Computer Science · "
    "Random Forest · 22-feature lexical + network analysis · "
    "95.7% test accuracy on 10,000-sample balanced dataset</p>",
    unsafe_allow_html=True
)
