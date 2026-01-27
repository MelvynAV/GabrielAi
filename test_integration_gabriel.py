import pytest
import pickle
import numpy as np
import os
from feature_extraction import extract_features

# Fixture pour charger le modèle une seule fois pour tous les tests
@pytest.fixture
def model():
    model_path = 'gabriel_phishing_model.pkl'
    if not os.path.exists(model_path):
        pytest.skip("Fichier modèle pkl introuvable")
    with open(model_path, 'rb') as f:
        return pickle.load(f)

def test_pipeline_end_to_end(model):
    """Vérifie le flux complet : URL -> Features -> Prédiction"""
    
    # 1. Préparation de la donnée (Arrange)
    url_suspecte = "http://amazone-security-update.com/login"
    
    # 2. Extraction des caractéristiques (Act - Partie 1)
    features = extract_features(url_suspecte)
    
    # 3. Conversion pour le modèle Scikit-Learn (Act - Partie 2)
    # Le modèle attend un tableau 2D (une matrice)
    features_np = np.array(features).reshape(1, -1)
    
    # 4. Prédiction (Act - Partie 3)
    prediction = model.predict(features_np)
    
    # 5. Validation (Assert)
    # On vérifie que le modèle retourne bien un résultat binaire (0 ou 1)
    assert len(prediction) == 1
    assert prediction[0] in [0, 1], "Le modèle doit retourner 0 (sain) ou 1 (phishing)"

def test_integration_feature_count(model):
    """Vérifie que le nombre de features extraites correspond aux attentes du modèle"""
    url = "google.com"
    features = extract_features(url)
    
    # Récupération du nombre de features attendues par le modèle RandomForest
    expected_count = model.n_features_in_
    
    assert len(features) == expected_count, f"Le modèle attend {expected_count} features, mais l'extracteur en donne {len(features)}"