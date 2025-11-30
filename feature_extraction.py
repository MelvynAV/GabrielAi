# feature_extraction.py

import re
from urllib.parse import urlparse

# --- 1. IP Address Detection ---
def has_ip_address(url):
    # CYBER LOGIC: Legitimate sites have domain names (e.g., google.com).
    # If a URL uses an IP address (e.g., http://123.45.67.89/...), it is suspicious.
    # Attackers do this to bypass DNS filters or because the domain was banned.
    match = re.search(
        r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'  # IPv4
        r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' # Hexadecimal
        r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url) # IPv6
    return 1 if match else 0

# --- 2. URL Length ---
def get_url_length(url):
    # CYBER LOGIC: Phishing URLs are often very long to hide the suspicious part
    # on mobile devices or to obfuscate the real destination.
    return len(url)

# --- 3. URL Depth ---
def get_depth(url):
    # CYBER LOGIC: Counts the number of '/' after the domain.
    # e.g., .com/folder/sub-folder/file/login.php
    # Compromised sites often hide phishing kits deep inside the file structure
    # to avoid detection by the site admin.
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth+1
    return depth

# --- 4. The '@' Symbol ---
def count_at_symbol(url):
    # CYBER LOGIC: Everything before an '@' in a URL is ignored by the browser 
    # and considered a user ID.
    # e.g., http://google.com@evil-site.com -> The browser goes to evil-site.com.
    # This is an old trick, but it still exists.
    return url.count('@')

# --- 5. Number of Dots (.) ---
def count_dots(url):
    # CYBER LOGIC: A high number of dots can indicate infinite subdomains.
    # e.g., www.paypal.com.secure.login.account-update.com
    # The attacker tries to drown the real domain (account-update.com) with trusted words.
    return url.count('.')

# --- 6. HTTPS ---
def has_https(url):
    # Note: Today, 80% of phishing sites also use HTTPS (green padlock).
    # However, it remains a feature that the AI can use in combination with others.
    return 1 if "https" in url else 0

# --- MAIN FUNCTION ---
def extract_features(url):
    features = []
    # We stack the results into a list
    features.append(has_ip_address(url))
    features.append(get_url_length(url))
    features.append(get_depth(url))
    features.append(count_at_symbol(url))
    features.append(count_dots(url))
    features.append(has_https(url))
    
    return features