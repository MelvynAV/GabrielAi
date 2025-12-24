# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import sys

LOCAL_CSV = "phishing_site_urls.csv"

def train():
    print("📥 Loading Pre-extracted Phishing Dataset...")
    print(f"File: {LOCAL_CSV}\n")

    try:
        data = pd.read_csv(LOCAL_CSV)
        data.columns = [c.strip().lower() for c in data.columns]
        print(f"✅ Loaded {len(data):,} samples | {len(data.columns)} columns")
        print("Columns:", list(data.columns), "\n")

        label_col = 'label'
        if label_col not in data.columns:
            label_col = data.columns[-1]
        print(f"Label column: '{label_col}' (values: {sorted(data[label_col].unique())})\n")

        # IMPORTANT: Exclude non-numeric / string columns like 'domain'
        exclude_cols = [label_col, 'domain']  # add any other string columns if more appear
        feature_cols = [c for c in data.columns if c not in exclude_cols]

        print(f"Using {len(feature_cols)} numeric features: {feature_cols}\n")

        X = data[feature_cols].copy()

        # Convert to numeric, coerce errors to NaN
        X = X.apply(pd.to_numeric, errors='coerce')

        # Handle missing/invalid values (common: -1 = missing)
        X = X.replace(-1, np.nan)
        X = X.fillna(X.median(numeric_only=True))  # median imputation

        # Final check: ensure all numeric
        if not np.all(np.isfinite(X)):
            print("Warning: Non-finite values remain in X. Cleaning...")
            X = X[np.isfinite(X).all(axis=1)]

        y = data[label_col]

        # Standardize label: assume 0=legitimate, 1=phishing (adjust if reversed)
        # If labels are -1/1, map -1 → 1 (phish), 1 → 0 (legit)
        if y.min() < 0:
            y = np.where(y == -1, 1, 0)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        print(f"Training set: {len(X_train):,} samples")
        print(f"Test set:     {len(X_test):,} samples\n")

        print("🔥 Training Random Forest...")
        model = RandomForestClassifier(
            n_estimators=500,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train, y_train)

        train_acc = model.score(X_train, y_train)
        test_acc  = model.score(X_test, y_test)

        print("\n" + "═" * 60)
        print(f"  Gabriel AI - Training Complete")
        print(f"  Training Accuracy: {train_acc*100:.2f}%")
        print(f"  Test Accuracy:     {test_acc*100:.2f}%")
        print("═" * 60 + "\n")

        with open('gabriel_phishing_model.pkl', 'wb') as f:
            pickle.dump(model, f)

        print("💾 Model saved as gabriel_phishing_model.pkl")
        print("Note: For inference in app.py, you need to extract the same 17 features from new URLs.")

    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc(file=sys.stdout)


if __name__ == "__main__":
    train()