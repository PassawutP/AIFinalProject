# feature_extractor.py

import re
import socket
import urllib.parse
import requests
import tldextract
from bs4 import BeautifulSoup

# -------------------------
# Helper functions
# -------------------------

def is_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

def get_domain(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

def get_html_content(url):
    try:
        response = requests.get(url, timeout=5)
        return response.text if response.status_code == 200 else ""
    except:
        return ""

def google_index_check(domain):
    try:
        query = f"https://www.google.com/search?q=site:{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(query, headers=headers, timeout=5)
        return int("did not match any documents" not in response.text)
    except:
        return 0

# -------------------------
# Feature Extractors
# -------------------------

def extract_lexical_features(url):
    features = {}
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features["f01_url_length"] = len(url)
    features["f02_num_dots"] = url.count('.')
    features["f03_num_hyphens"] = url.count('-')
    features["f04_num_underscores"] = url.count('_')
    features["f05_num_slashes"] = url.count('/')
    features["f06_num_percent"] = url.count('%')
    features["f07_num_query_components"] = len(parsed.query.split('&')) if parsed.query else 0
    features["f08_num_at"] = url.count('@')
    features["f09_num_equals"] = url.count('=')
    features["f10_num_ampersand"] = url.count('&')
    features["f11_num_hash"] = url.count('#')
    features["f12_has_ip"] = int(is_ip_address(domain))
    features["f13_domain_length"] = len(domain)
    features["f14_path_length"] = len(path)
    features["f15_num_subdomains"] = domain.count('.') - 1
    features["f16_is_https"] = int(parsed.scheme == "https")
    features["f17_domain_in_path"] = int(get_domain(url) in path)
    features["f18_num_digits"] = sum(c.isdigit() for c in url)
    features["f19_num_letters"] = sum(c.isalpha() for c in url)
    features["f20_url_entropy"] = round(sum(-url.count(c) / len(url) * (url.count(c) / len(url)).bit_length()
                                        for c in set(url) if c), 4) if url else 0

    return features

def extract_domain_features(url):
    features = {}
    domain = get_domain(url)

    features["f21_tld_length"] = len(domain.split('.')[-1])
    features["f22_domain_is_ip"] = int(is_ip_address(domain))
    features["f23_num_vowels_in_domain"] = sum(1 for c in domain if c.lower() in "aeiou")
    features["f24_num_consonants_in_domain"] = sum(1 for c in domain if c.isalpha() and c.lower() not in "aeiou")
    features["f25_num_digits_in_domain"] = sum(1 for c in domain if c.isdigit())
    features["f26_num_special_chars_in_domain"] = sum(1 for c in domain if not c.isalnum() and c != '.')
    features["f27_num_subdomain_tokens"] = len(domain.split('.')) - 1
    features["f28_domain_has_www"] = int('www' in domain)
    features["f29_is_com_tld"] = int(domain.endswith('.com'))
    features["f30_is_country_tld"] = int(domain.endswith(('.cn', '.ru', '.in', '.br', '.id')))
    
    return features

def extract_content_features(url):
    features = {}
    html = get_html_content(url)
    soup = BeautifulSoup(html, "html.parser")

    features["f31_num_links"] = len(soup.find_all('a'))
    features["f32_num_images"] = len(soup.find_all('img'))
    features["f33_num_scripts"] = len(soup.find_all('script'))
    features["f34_num_iframes"] = len(soup.find_all('iframe'))
    features["f35_num_forms"] = len(soup.find_all('form'))
    features["f36_has_login_form"] = int(bool(soup.find('input', {'type': 'password'})))
    features["f37_external_scripts"] = int(any('src' in tag.attrs and not tag.attrs['src'].startswith(url)
                                              for tag in soup.find_all('script') if 'src' in tag.attrs))
    features["f38_num_meta_tags"] = len(soup.find_all('meta'))
    features["f39_contains_mailto"] = int('mailto:' in html)
    features["f40_contains_tel"] = int('tel:' in html)

    return features

def extract_external_features(url):
    features = {}
    domain = get_domain(url)

    # Placeholder example — use verified APIs or pre-downloaded data sources
    features["f41_in_top_1m"] = 0  # Example placeholder
    features["f42_has_ssl"] = int(url.startswith("https"))
    features["f43_dns_resolvable"] = int(True)  # Replace with DNS check if desired
    features["f44_google_indexed"] = google_index_check(domain)
    
    return features

# -------------------------
# Main Function
# -------------------------

def extract_features(url):
    features = {}
    features.update(extract_lexical_features(url))
    features.update(extract_domain_features(url))
    features.update(extract_content_features(url))
    features.update(extract_external_features(url))

    # Padding to simulate 86 features
    for i in range(len(features) + 1, 87):
        features[f"f{i:02d}_placeholder"] = 0

    return features
