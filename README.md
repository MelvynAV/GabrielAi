# ⚔ GabrielAI v2.0 — Phishing URL Detection

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-app.streamlit.app)

> **A machine learning–powered heuristic engine for real-time phishing URL detection.**  
> Built by Melvyn Avoa · uOttawa Computer Science (3rd Year) · Cybersecurity & AI/ML

---

## 🎓 Project Abstract

This project explores the application of **Supervised Machine Learning** in cybersecurity threat detection, specifically targeting **URL-based phishing attacks**.

Rather than relying on static blacklists (which fail against zero-day attacks), GabrielAI uses a **22-feature heuristic engine** to classify URLs based on their structural and lexical properties — the same methodology used in enterprise IAM and SIEM systems.

---

## 🔬 Methodology & Feature Engineering

Raw URLs cannot be fed directly into an ML algorithm. The core of this project is the **feature extraction pipeline** (`feature_extraction.py`), which converts a URL string into a numerical vector representing **Indicators of Compromise (IOCs)**.

### Core Lexical Features (16)
| Feature | Description | Phishing Signal |
|---|---|---|
| `have_ip` | IP address used instead of domain | Bypasses DNS blocklists |
| `have_at` | `@` symbol in URL | Tricks browser auth parsing |
| `url_length` | URL ≥ 54 characters | Obfuscation through padding |
| `url_depth` | Number of path segments | Payload hidden deep in structure |
| `redirection` | `//` in path/query | Redirect chain obfuscation |
| `https_domain` | Protocol is HTTPS | Note: HTTPS ≠ safe (see below) |
| `tinyurl` | Known URL shortener | Hides true destination |
| `prefix_suffix` | Hyphen in domain | e.g., `paypal-secure.com` |

### New v2.0 Lexical Features (6)
| Feature | Description | Why It Matters |
|---|---|---|
| `subdomain_count` | Number of subdomain levels | e.g., `login.verify.evil.com` → 2 |
| `domain_entropy` | Shannon entropy of domain name | High randomness = likely auto-generated |
| `digit_ratio` | Proportion of digits in domain | e.g., `p4yp4l.com` |
| `special_char_count` | `~%!&=+$#` in URL | Obfuscation characters |
| `phishing_keywords` | Count of keywords (login, verify…) | Semantic social engineering signals |
| `punycode` | `xn--` in domain | IDN homograph attacks (е vs e) |

### Live Network Enrichment (not in ML model)
- **SSL Certificate Analysis**: Issuer, validity duration (< 90 days = suspicious), days remaining
- **WHOIS Domain Age**: Burner domains registered < 90 days ago
- **DNS Record Lookup**: A-record resolution check

---

## 🤖 Model Selection & Performance

**Algorithm:** `RandomForestClassifier` (scikit-learn)

**Why Random Forest?**
- Aggregates votes from 500 decision trees → resists overfitting vs. single DT
- Handles non-linear feature relationships (URL features are not linearly separable)
- Provides `predict_proba()` for confidence scoring, not just binary output
- Feature importance ranking for explainability (critical for security review)

**Training Data:** 10,000 URLs (5,000 legitimate / 5,000 phishing) — balanced dataset

| Metric | Value |
|---|---|
| Training Accuracy | 96.86% |
| **Test Accuracy** | **95.75%** |
| Precision (Phishing) | 0.99 |
| Recall (Phishing) | 0.93 |
| F1-Score | 0.96 |

**Top Features by Importance:**
1. `url_length` (binary threshold) — 29.8%
2. `domain_entropy` (Shannon) — 28.4%
3. `url_depth` — 11.1%
4. `subdomain_count` — 9.0%
5. `prefix/suffix` — 4.9%

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Core Logic | Python 3.10+ |
| ML Engine | scikit-learn (Random Forest) |
| Data Pipeline | Pandas, NumPy |
| Frontend | Streamlit |
| Network Analysis | dnspython, python-whois, stdlib ssl |
| Deployment | Streamlit Community Cloud |

---

## 🚀 Deployment

### Local
```bash
git clone https://github.com/YOUR_USERNAME/GabrielAI.git
cd GabrielAI
pip install -r requirements.txt
python train_model.py      # Trains and saves model
streamlit run app.py
```

### Streamlit Community Cloud (Free)
1. Push to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repo → Deploy

### GitHub Student (Free Custom Domain)
1. Enable GitHub Pages in repo Settings
2. Use `namecheap.com` (free `.me` domain with GitHub Education Pack)
3. Point your DNS to Streamlit's custom domain feature

---

## 📚 Key Learnings & Challenges

1. **Feature–Model Mismatch (v1 → v2 Bug Fix):** The original model was trained on pre-extracted binary features from a CSV, but `url_length` at inference was using raw character count instead of the binary threshold (≥54). This caused silent prediction errors — fixing it improved real-world accuracy significantly.

2. **HTTPS ≠ Safe:** Modern phishing sites routinely use HTTPS to appear legitimate. The model treats HTTPS as one signal among 22, not a safety guarantee.

3. **Entropy as a Signal:** Domain names like `xf3k2p.com` have very high Shannon entropy compared to `google.com`. This feature alone has 28% importance in the trained model.

4. **False Positive Balance:** High recall (catching all threats) vs. high precision (not blocking legit sites) is the core tuning challenge. The current model achieves 0.99 precision with 0.93 recall on phishing — acceptable for a detection aid.

---

## 🗺️ Roadmap (v3.0)

- [ ] Upgrade to **XGBoost** and benchmark against Random Forest
- [ ] Expand dataset to 50,000+ samples (PhishTank, OpenPhish)
- [ ] Add **BERT-based URL tokenizer** for semantic analysis
- [ ] Integrate **VirusTotal API** for live reputation scoring
- [ ] Add **MITRE ATT&CK** technique tagging for detected threats

---

*Author: Melvyn Avoa · [LinkedIn](https://linkedin-in.com/in/melvyn-avoa-487032384/) · [GitHub](https://github.com/melvynav) · uOttawa CSI*
