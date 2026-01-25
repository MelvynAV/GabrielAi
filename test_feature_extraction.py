import pytest
import re
from feature_extraction import extract_features

# --- TESTS DE LOGIQUE MÉTIER (HAPPY PATH) ---

def test_ip_detection():
    """Vérifie que la détection d'adresse IP fonctionne dans le domaine"""
    # Cas positif
    url_ip = "192.168.1.1/login"
    features = extract_features(url_ip)
    assert features[0] == 1, "Échec : L'adresse IP n'a pas été détectée"

    # Cas négatif
    url_normal = "google.com"
    features_normal = extract_features(url_normal)
    assert features_normal[0] == 0, "Échec : Un domaine normal a été marqué comme IP"

def test_url_depth():
    """Vérifie le calcul de la profondeur des répertoires"""
    url = "https://example.com/api/v1/users"
    features = extract_features(url)
    # L'index 3 correspond à URL_Depth
    assert features[3] == 3, f"Échec : Profondeur attendue 3, reçue {features[3]}"

def test_security_features():
    """Vérifie les indicateurs HTTPS et les raccourcisseurs d'URL"""
    # Test HTTPS (index 5)
    assert extract_features("https://secure.com")[5] == 1
    assert extract_features("http://unsafe.com")[5] == 0

    # Test TinyURL (index 6)
    assert extract_features("bit.ly/123")[6] == 1
    assert extract_features("github.com")[6] == 0

def test_domain_hyphen():
    """Vérifie la détection de tiret dans le nom de domaine (index 7)"""
    assert extract_features("my-bank-secure.com")[7] == 1
    assert extract_features("amazon.ca")[7] == 0

# --- TESTS DE ROBUSTESSE (EDGE CASES) ---

@pytest.mark.parametrize("url, expected_depth", [
    ("", 0),                          # Chaîne vide
    ("https://", 0),                  # Protocole seul
    ("google.com/////", 0),           # Slashes superflus
    ("http://domain.com/a/b/c/d/e", 5) # Profondeur élevée
])
def test_url_robustness(url, expected_depth):
    """S'assure que la fonction ne crashe jamais, peu importe l'entrée"""
    try:
        features = extract_features(url)
        assert len(features) >= 16
        assert features[3] == expected_depth
    except Exception as e:
        pytest.fail(f"La fonction a levé une exception inattendue : {e}")

# --- TEST DE CONFORMITÉ MACHINE LEARNING ---

def test_ml_compatibility():
    """Vérifie que la sortie est compatible avec un modèle ML (uniquement des nombres)"""
    features = extract_features("https://intact.ca/fr/mon-dossier")
    
    # Vérification que le résultat est une liste
    assert isinstance(features, list)
    
    # Vérification que chaque élément est un entier ou un flottant (pas de strings)
    for i, f in enumerate(features):
        assert isinstance(f, (int, float)), f"Erreur à l'index {i} : la valeur {f} n'est pas un nombre"