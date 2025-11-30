import streamlit as st
import pickle
import numpy as np
from feature_extraction import extract_features

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="GabrielAI - Phishing Detection", page_icon="🛡️", layout="centered")

# --- CHARGEMENT DU MODÈLE ---
# On charge le cerveau qu'on a entraîné juste avant
try:
    with open('gabriel_model.pkl', 'rb') as file:
        model = pickle.load(file)
except FileNotFoundError:
    st.error("❌ Modèle introuvable ! Lancez d'abord 'train_model.py'.")
    st.stop()

# --- HEADER / TITRE ---
st.title("🛡️ GabrielAI")
st.subheader("Intelligent Phishing URL Detection System")
st.markdown("---")

# --- ZONE DE SAISIE ---
st.markdown("#### 🔍 Entrez l'URL suspecte à analyser :")
url_input = st.text_input("", placeholder="ex: http://paypal-secure-login.com...")

# --- LOGIQUE D'ANALYSE ---
if st.button("Analyser le lien", type="primary"):
    if not url_input:
        st.warning("Veuillez entrer une URL.")
    else:
        # 1. Extraction des features (Le traducteur)
        features = extract_features(url_input)
        
        # 2. Prédiction (Le cerveau)
        # On doit remodeler les données pour que le modèle les accepte (1 ligne, X colonnes)
        features_array = np.array(features).reshape(1, -1)
        
        prediction = model.predict(features_array)[0] # 0 = Safe, 1 = Phishing
        probability = model.predict_proba(features_array) # ex: [0.1, 0.9] (10% safe, 90% phishing)
        
        # 3. Affichage des résultats
        st.markdown("### Résultat de l'analyse :")
        
        # Colonnes pour organiser l'affichage
        col1, col2 = st.columns([1, 2])
        
        if prediction == 1:
            # CAS : PHISHING
            with col1:
                st.image("https://cdn-icons-png.flaticon.com/512/564/564619.png", width=100) # Icone Alerte
            with col2:
                st.error(f"🚨 DANGER DÉTECTÉ : PHISHING")
                confidence = probability[0][1] * 100
                st.metric("Niveau de confiance", f"{confidence:.2f}%")
                st.markdown("**Action recommandée :** Ne cliquez pas. Bloquez ce domaine.")
        else:
            # CAS : SAFE
            with col1:
                st.image("https://cdn-icons-png.flaticon.com/512/1161/1161388.png", width=100) # Icone Shield
            with col2:
                st.success(f"✅ SITE LÉGITIME (SAFE)")
                confidence = probability[0][0] * 100
                st.metric("Niveau de confiance", f"{confidence:.2f}%")
                st.markdown("**Analyse :** La structure de l'URL semble normale.")

        # --- DÉTAILS TECHNIQUES (XAI - Explainable AI) ---
        # C'est ce qui impressionne les recruteurs : montrer POURQUOI l'IA a décidé ça.
        st.markdown("---")
        with st.expander("Voir les détails techniques (Features)"):
            st.write("Voici ce que GabrielAI a extrait de l'URL :")
            st.json({
                "Contient une IP": "Oui" if features[0] == 1 else "Non",
                "Longueur URL": f"{features[1]} caractères",
                "Profondeur": features[2],
                "Présence '@'": "Oui" if features[3] > 0 else "Non",
                "Nombre de points": features[4],
                "HTTPS": "Oui" if features[5] == 1 else "Non"
            })