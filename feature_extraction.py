# feature_extraction.py
import re
from urllib.parse import urlparse, urlsplit

def extract_features(url: str) -> list:
    """
    Extract 17 features matching your training dataset.
    Returns list of 16 numerical values + domain (but domain not used for prediction).
    """
    features = []

    # Normalize
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = url.lower()

    hostname = netloc.split(':')[0].replace('www.', '')

    # 1. Have_IP
    features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0)

    # 2. Have_At
    features.append(1 if '@' in full else 0)

    # 3. URL_Length
    features.append(len(url))

    # 4. URL_Depth (number of subdirectories)
    features.append(len([p for p in path.split('/') if p]))

    # 5. Redirection (double slash in path or many redirects – simplified)
    features.append(1 if '//' in path[1:] or '//' in query else 0)

    # 6. https_Domain (1 = https, 0 = http)
    features.append(1 if scheme == 'https' else 0)

    # 7. TinyURL (shortener domains)
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd']
    features.append(1 if any(s in hostname for s in shorteners) else 0)

    # 8. Prefix/Suffix (hyphen in domain)
    features.append(1 if '-' in hostname else 0)

    # 9. DNS_Record (always assume 1 for simplicity; real check needs DNS lib)
    features.append(1)  # placeholder - set to 0 if you detect no DNS later

    # 10. Web_Traffic (placeholder: high for known domains, low otherwise)
    features.append(1)  # assume good traffic; improve with Alexa-like list if needed

    # 11. Domain_Age (placeholder: assume old)
    features.append(1)  # 1 = old domain

    # 12. Domain_End (placeholder)
    features.append(0)  # 0 = not expiring soon

    # 13. iFrame (check for iframe src in page – but since no page fetch, assume 0)
    features.append(0)

    # 14. Mouse_Over (event handler – assume 0 without page)
    features.append(0)

    # 15. Right_Click (disable right-click – assume 0)
    features.append(0)

    # 16. Web_Forwards (meta refresh or many redirects – simplified)
    features.append(0)

    return features