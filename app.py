import streamlit as st
import pickle
import numpy as np
import os
import re
import datetime
from datetime import timezone
from urllib.parse import urlparse
import dns.resolver   # pip install dnspython
import whois          # pip install python-whois

# ─── Load model ────────────────────────────────────────────────────────────────
try:
    model = pickle.load(open('gabriel_phishing_model.pkl', 'rb'))
except FileNotFoundError:
    st.error("⚠️ Model not found. Please run 'train_model.py' first.")
    st.stop()

# ─── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GabrielAI - Phishing Detection",
    page_icon="🛡️",
    layout="centered"
)

# ─── CSS (unchanged) ───────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-image: url("https://images.unsplash.com/photo-1504608524841-42fe6f032b4b?q=80&w=3165&auto=format&fit=crop"); background-size: cover; background-position: center; background-attachment: fixed; }
    .main .block-container { background-color: rgba(255, 255, 255, 0.92); padding: 3rem; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2); margin-top: 1rem; }
    h1 { color: #B8860B; text-align: center; font-family: 'Helvetica Neue', sans-serif; text-transform: uppercase; letter-spacing: 1px; }
    h3 { color: #555; font-weight: 300; font-style: italic; }
    div.stButton > button { background: linear-gradient(90deg, #d4af37 0%, #f7e98e 100%); color: #4a3b2a; border: none; padding: 10px 20px; border-radius: 50px; font-size: 18px; font-weight: bold; box-shadow: 0 4px 10px rgba(212, 175, 55, 0.3); width: 100%; transition: all 0.3s; }
    div.stButton > button:hover { transform: scale(1.02); box-shadow: 0 6px 15px rgba(212, 175, 55, 0.5); }
    .stTextInput > div > div > input { border-radius: 50px; padding-left: 20px; border: 1px solid #d4af37; }
    .st-emotion-cache-12fm5qf { width: 100vw !important; position: relative !important; margin-left: calc(-50vw + 50%) !important; overflow: hidden !important; }
    [data-testid="stImage"] { width: 100vw !important; position: relative !important; overflow: hidden; background: transparent !important; }
    [data-testid="stImage"] img { max-height: 250px !important; width: 100% !important; object-fit: contain !important; object-position: center center !important; border-radius: 0; }
</style>
""", unsafe_allow_html=True)

# ─── Header image ──────────────────────────────────────────────────────────────
if os.path.exists("angel3.jpg"):
    st.image("angel3.jpg", caption="Guardian of the Network", use_container_width=True)
else:
    st.image(
        "https://images.unsplash.com/photo-1542259681-d41907cb3874?q=80&w=1200&h=250&auto=format&fit=crop",
        caption="Archangel Gabriel - Guardian of the Message",
        use_container_width=True
    )

st.markdown("<h1>Gabriel AI</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center;'>The Digital Archangel guarding your network.</h3>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #FFF;'>This AI engine analyzes URL structures to detect phishing threats in real-time.</p>", unsafe_allow_html=True)
st.markdown("---")

# ─── Input ─────────────────────────────────────────────────────────────────────
st.markdown("### 🔍 Analyze a Link")
url_input = st.text_input("URL", placeholder="Paste the suspicious URL here...", label_visibility="collapsed")
analyze_btn = st.button("🛡️ ANALYZE URL")

# ─── Very large safe domains list ──────────────────────────────────────────────
SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
    'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'meta.com',
    'twitter.com', 'x.com', 't.co', 'twimg.com',
    'amazon.com', 'awsstatic.com', 'a2z.com', 'cloudfront.net',
    'apple.com', 'icloud.com', 'mzstatic.com', 'apple.news',
    'microsoft.com', 'live.com', 'office.com', 'azureedge.net', 'bing.com',
    'linkedin.com', 'licdn.com',
    'netflix.com', 'nflxvideo.net',
    'reddit.com', 'redd.it',
    'paypal.com', 'venmo.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'citi.com', 'capitalone.com', 'usbank.com', 'pnc.com', 'td.com', 'rbc.com',
    'scotiabank.com', 'bmo.com', 'hsbc.com', 'barclays.co.uk', 'lloydsbank.com',
    'uottawa.ca', 'utoronto.ca', 'ubc.ca', 'mcgill.ca', 'ualberta.ca', 'ucalgary.ca',
    'queensu.ca', 'sfu.ca', 'yorku.ca', 'carleton.ca',
    'bankofcanada.ca', 'canada.ca', 'gc.ca', 'cra-arc.gc.ca',
    'edu', '.gov', 'harvard.edu', 'stanford.edu', 'mit.edu', 'berkeley.edu',
    'ox.ac.uk', 'cam.ac.uk', 'london.ac.uk',
    'ebay.com', 'etsy.com', 'shopify.com', 'walmart.com', 'target.com',
    'bestbuy.com', 'costco.com', 'homedepot.com',
    'wikipedia.org', 'discord.com', 'spotify.com', 'twitch.tv', 'zoom.us',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com', 'github.com',
    'stackoverflow.com', 'medium.com', 'nytimes.com', 'bbc.com', 'cnn.com',
    'theguardian.com', 'washingtonpost.com', 'forbes.com', 'bloomberg.com',
    'cloudflare.com', 'akamai.net', 'fastly.net', 'vercel.app', 'netlify.app',
    'pages.dev', 'herokuapp.com', 'firebaseapp.com'
}

# ─── Feature extraction with DNS + WHOIS ───────────────────────────────────────
def extract_features(url_str: str):
    if not url_str:
        return [0] * 16, {"error": "No URL"}, {"error": "No URL"}

    # Add protocol if missing
    if not url_str.startswith(('http://', 'https://')):
        url_str = 'http://' + url_str

    parsed = urlparse(url_str)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = url_str.lower()

    hostname = netloc.split(':')[0].replace('www.', '')

    features = [0] * 16

    # 1. have_ip
    features[0] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0

    # 2. have_at
    features[1] = 1 if '@' in full else 0

    # 3. url_length
    features[2] = len(url_str)

    # 4. url_depth
    features[3] = len([p for p in path.split('/') if p])

    # 5. redirection
    features[4] = 1 if '//' in path[1:] or '//' in query else 0

    # 6. https_domain
    features[5] = 1 if scheme == 'https' else 0

    # 7. tinyurl
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly']
    features[6] = 1 if any(s in hostname for s in shorteners) else 0

    # 8. prefix/suffix (hyphen)
    features[7] = 1 if '-' in hostname else 0

    dns_info = {}
    whois_info = {}

    # DNS lookup
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        dns_info['A_records'] = len(answers)
        dns_info['has_dns'] = 1
    except Exception as e:
        dns_info['has_dns'] = 0
        dns_info['error'] = str(e)

    # WHOIS
    try:
        w = whois.whois(hostname)
        creation = w.creation_date
        expiration = w.expiration_date

        if isinstance(creation, list): creation = creation[0]
        if isinstance(expiration, list): expiration = expiration[0]

        # Make now timezone-aware (UTC)
        now = datetime.datetime.now(timezone.utc)

        if creation and isinstance(creation, datetime.datetime):
            # Make creation aware if naive
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            else:
                creation = creation.astimezone(timezone.utc)

            age_days = (now - creation).days if creation < now else 0
            whois_info['domain_age_days'] = age_days
            features[10] = 1 if age_days > 365 else 0

        if expiration and isinstance(expiration, datetime.datetime):
            # Make expiration aware if naive
            if expiration.tzinfo is None:
                expiration = expiration.replace(tzinfo=timezone.utc)
            else:
                expiration = expiration.astimezone(timezone.utc)

            days_left = (expiration - now).days if expiration > now else -1
            whois_info['days_to_expire'] = days_left
            features[11] = 1 if 0 < days_left < 30 else 0

    except Exception as e:
        whois_info['error'] = str(e)
        features[10] = 0
        features[11] = 0

    # Fill remaining placeholders
    features[8] = 1   # dns_record
    features[9] = 1   # web_traffic
    features[12] = 0  # iframe
    features[13] = 0  # mouse_over
    features[14] = 0  # right_click
    features[15] = 0  # web_forwards

    return features, dns_info, whois_info

# ─── Main logic ────────────────────────────────────────────────────────────────
if analyze_btn:
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL to analyze.")
    else:
        with st.spinner("Performing DNS + WHOIS checks + model prediction..."):
            try:
                # Parse domain
                parsed = urlparse(url_input if url_input.startswith(('http://', 'https://')) else 'http://' + url_input)
                domain = parsed.netloc.lower().replace('www.', '')

                # Whitelist check
                is_safe = domain in SAFE_DOMAINS or any(domain.endswith('.' + s) for s in SAFE_DOMAINS)

                # Extract features & metadata
                features, dns_info, whois_info = extract_features(url_input)

                if is_safe:
                    prediction = 0
                    confidence = 99.5
                    st.markdown("---")
                    st.markdown(f"""
                    <div style='background-color: #e6f7ff; padding: 20px; border-radius: 10px; border-left: 6px solid #00bfff; text-align: center;'>
                        <h2 style='color: #007acc; margin:0;'>🛡️ SAFE LINK</h2>
                        <p style='color: #005f73; font-size: 1.1em;'>Well-known legitimate domain (whitelisted).</p>
                    </div>
                    """, unsafe_allow_html=True)
                    st.metric("Safety Confidence", f"{confidence:.2f}%", delta="VERY SAFE")
                    st.success("RECOMMENDATION: You may proceed.")
                else:
                    features_array = np.array([features], dtype=float)
                    prediction = model.predict(features_array)[0]
                    proba = model.predict_proba(features_array)[0]

                    st.markdown("---")

                    if prediction == 1:
                        confidence = proba[1] * 100
                        st.markdown("""
                        <div style='background-color: #ffe6e6; padding: 20px; border-radius: 10px; border-left: 6px solid #ff4d4d; text-align: center;'>
                            <h2 style='color: #cc0000; margin:0;'>👹 THREAT DETECTED</h2>
                            <p style='color: #a30000; font-size: 1.1em;'>This URL shows signs of Phishing.</p>
                        </div>
                        """, unsafe_allow_html=True)
                        st.metric("Risk Level", f"{confidence:.2f}%", delta="HIGH RISK")
                        st.error("RECOMMENDATION: Do NOT click. Block this domain.")
                    else:
                        confidence = proba[0] * 100
                        st.markdown("""
                        <div style='background-color: #e6f7ff; padding: 20px; border-radius: 10px; border-left: 6px solid #00bfff; text-align: center;'>
                            <h2 style='color: #007acc; margin:0;'>🛡️ SAFE LINK</h2>
                            <p style='color: #005f73; font-size: 1.1em;'>The URL structure appears legitimate.</p>
                        </div>
                        """, unsafe_allow_html=True)
                        st.metric("Safety Confidence", f"{confidence:.2f}%", delta="SAFE")
                        st.success("RECOMMENDATION: You may proceed.")

                # ─── Technical report ──────────────────────────────────────────────
                with st.expander("📜 View Technical Report"):
                    st.write("**DNS Information**")
                    st.json(dns_info)

                    st.write("**WHOIS Information**")
                    st.json(whois_info)

                    if not is_safe:
                        st.write("**Model Input Features (16 values)**")
                        feature_names = [
                            "Have IP", "Have @", "URL Length", "URL Depth", "Redirection",
                            "HTTPS Domain", "TinyURL", "Prefix/Suffix", "DNS Record",
                            "Web Traffic", "Domain Age", "Domain End", "iFrame",
                            "Mouse Over", "Right Click", "Web Forwards"
                        ]
                        feat_dict = dict(zip(feature_names, features))
                        c1, c2 = st.columns(2)
                        with c1:
                            st.json({k: v for k, v in list(feat_dict.items())[:8]})
                        with c2:
                            st.json({k: v for k, v in list(feat_dict.items())[8:]})

            except Exception as e:
                st.error(f"Analysis failed: {str(e)}")