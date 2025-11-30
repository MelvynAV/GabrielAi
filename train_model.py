# train_model.py (Version 3 - Blindée)

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import requests
import io
from feature_extraction import extract_features 

# --- FONCTION DE SECOURS (Si internet plante) ---
def get_backup_data():
    print("⚠️ Utilisation du Dataset de SECOURS (Interne)...")
    data = {
        'url': [
            'http://google.com', 'https://www.youtube.com', 'https://github.com', 'https://uottawa.ca', 'https://stackoverflow.com',
            'http://192.168.1.1/login', 'http://paypal-secure-account-login.com', 'http://apple-id-verify.cf', 'http://secure-bank.com.update.info', 'http://netflix-payment-declined.net'
        ],
        'label': ['good', 'good', 'good', 'good', 'good', 'bad', 'bad', 'bad', 'bad', 'bad']
    }
    return pd.DataFrame(data)

# --- ÉTAPE 1 : ACQUISITION DES DONNÉES ---
print("📥 Tentative de téléchargement du dataset...")

# Lien très stable (bitsofgray)
url_dataset = "https://raw.githubusercontent.com/bitsofgray/phishing-data/master/phishing_data.csv"

try:
    response = requests.get(url_dataset)
    if response.status_code == 200:
        data = pd.read_csv(io.StringIO(response.content.decode('utf-8')))
        print("✅ Téléchargement réussi !")
    else:
        print(f"❌ Erreur lien (Status {response.status_code}).")
        data = get_backup_data()
except Exception as e:
    print(f"❌ Erreur connexion : {e}")
    data = get_backup_data()

# --- NETTOYAGE ---
# On s'assure que les colonnes sont propres
data.columns = data.columns.str.strip().str.lower()

# Si le téléchargement a marché mais qu'on a beaucoup de données, on échantillonne pour aller vite
if len(data) > 2000:
    data_phishing = data[data['label'] == 'bad'].sample(500)
    data_legit = data[data['label'] == 'good'].sample(500)
    data_sample = pd.concat([data_phishing, data_legit]).reset_index(drop=True)
else:
    data_sample = data

print(f"📊 Dataset prêt : {len(data_sample)} URLs à analyser.")

# --- ÉTAPE 2 : TRANSFORMATION ---
print("🧠 Extraction des caractéristiques via GabrielAI...")
features = []
labels = []

for index, row in data_sample.iterrows():
    try:
        url_features = extract_features(row['url'])
        features.append(url_features)
        # 1 pour 'bad', 0 pour 'good'
        labels.append(1 if row['label'] == 'bad' else 0)
    except:
        continue

if not features:
    print("❌ Erreur : Aucune feature extraite. Vérifie feature_extraction.py")
    exit()

# --- ÉTAPE 3 : ENTRAÎNEMENT ---
print("🔥 Entraînement du modèle RandomForest...")
X = np.array(features)
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, max_depth=10)
model.fit(X_train, y_train)

# --- ÉTAPE 4 : RÉSULTATS ---
predictions = model.predict(X_test)
# Si le dataset est trop petit (mode secours), l'accuracy peut être bizarre, c'est normal.
if len(y_test) > 0:
    accuracy = accuracy_score(y_test, predictions)
    print(f"\n✅ TERMINÉ ! Précision du modèle : {accuracy * 100:.2f}%")
else:
    print("\n✅ TERMINÉ ! (Pas assez de données pour le test, mais le modèle est créé)")

# --- ÉTAPE 5 : SAUVEGARDE ---
with open('gabriel_model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("💾 Modèle sauvegardé sous 'gabriel_model.pkl'")