# train_model.py - GabrielAI v2.0
# ─────────────────────────────────────────────────────────────────────────────
# Retrains the phishing classifier on the original dataset (phishing_site_urls.csv)
# and augments it with 6 new lexical features computed from the domain column.
# ─────────────────────────────────────────────────────────────────────────────

import pandas as pd
import numpy as np
import pickle
import math
import re
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import sys

LOCAL_CSV = "phishing_site_urls.csv"

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'banking', 'confirm', 'password', 'credential', 'alert',
    'suspended', 'unusual', 'activity', 'webscr', 'ebayisapi',
    'redirect', 'validate', 'recover', 'authenticate'
]

URL_SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'ow.ly']


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def augment_domain_features(domain: str) -> dict:
    """Compute 6 new lexical features from a bare domain string."""
    domain = str(domain).lower().strip()
    domain_no_www = domain[4:] if domain.startswith('www.') else domain

    parts = domain_no_www.split('.')
    subdomain_count = max(0, len(parts) - 2)
    entropy = shannon_entropy(domain_no_www)
    digit_ratio = sum(c.isdigit() for c in domain_no_www) / max(len(domain_no_www), 1)
    special_count = sum(c in '~%!&=+$#^*' for c in domain_no_www)
    keyword_count = sum(kw in domain_no_www for kw in PHISHING_KEYWORDS)
    punycode = 1 if 'xn--' in domain_no_www else 0

    return {
        'subdomain_count':    subdomain_count,
        'domain_entropy':     round(entropy, 4),
        'digit_ratio':        round(digit_ratio, 4),
        'special_char_count': special_count,
        'phishing_keywords':  keyword_count,
        'punycode':           punycode,
    }


def train():
    print("=" * 65)
    print("  GabrielAI v2.0 — Model Training")
    print("=" * 65)

    # ── Load dataset ────────────────────────────────────────────────────────────
    try:
        data = pd.read_csv(LOCAL_CSV)
    except FileNotFoundError:
        print(f"❌ Dataset not found: {LOCAL_CSV}")
        sys.exit(1)

    data.columns = [c.strip().lower() for c in data.columns]
    print(f"\n✅ Loaded {len(data):,} samples, {len(data.columns)} columns")
    print(f"   Columns: {list(data.columns)}")

    # ── Augment with new v2.0 domain features ───────────────────────────────────
    print("\n🔬 Extracting 6 new lexical features from domain column...")
    augmented = data['domain'].apply(augment_domain_features).apply(pd.Series)
    data = pd.concat([data, augmented], axis=1)
    print(f"   New features added: {list(augmented.columns)}")

    # ── Define feature columns ───────────────────────────────────────────────────
    exclude = ['label', 'domain']
    feature_cols = [c for c in data.columns if c not in exclude]
    print(f"\n📐 Total features for training: {len(feature_cols)}")
    print(f"   {feature_cols}")

    X = data[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    y = data['label']

    # Standardize labels: 0 = legitimate, 1 = phishing
    if y.min() < 0:
        y = np.where(y == -1, 1, 0)

    print(f"\n📊 Class distribution:")
    print(f"   Legitimate (0): {(y == 0).sum():,}")
    print(f"   Phishing   (1): {(y == 1).sum():,}")

    # ── Train / Test split ───────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ── Train Random Forest ──────────────────────────────────────────────────────
    print("\n🔥 Training Random Forest (500 trees)...")
    rf = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    rf.fit(X_train, y_train)

    train_acc = rf.score(X_train, y_train)
    test_acc  = rf.score(X_test,  y_test)

    print("\n" + "─" * 65)
    print(f"  Random Forest Results")
    print(f"  Training Accuracy : {train_acc * 100:.2f}%")
    print(f"  Test Accuracy     : {test_acc  * 100:.2f}%")
    print("─" * 65)
    print("\n📋 Classification Report (Test Set):")
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    print("\n🔍 Top 10 Most Important Features:")
    importances = sorted(
        zip(feature_cols, rf.feature_importances_),
        key=lambda x: -x[1]
    )
    for name, imp in importances[:10]:
        bar = '█' * int(imp * 100)
        print(f"  {name:<30} {imp:.4f}  {bar}")

    # ── Save model + metadata ───────────────────────────────────────────────────
    model_data = {
        'model': rf,
        'feature_cols': feature_cols,
        'version': '2.0',
        'test_accuracy': test_acc,
        'train_accuracy': train_acc,
        'n_features': len(feature_cols),
    }

    with open('gabriel_phishing_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)

    print(f"\n💾 Model saved: gabriel_phishing_model.pkl")
    print(f"   Features: {len(feature_cols)}")
    print(f"   Test accuracy: {test_acc * 100:.2f}%")
    print("\n✅ Training complete — ready to deploy!\n")


if __name__ == "__main__":
    train()
