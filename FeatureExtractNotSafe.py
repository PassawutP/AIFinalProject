import re
from urllib.parse import urlparse
import tldextract
import socket
import requests
from bs4 import BeautifulSoup
import whois
import datetime
import os
from dotenv import load_dotenv
import csv
import logging

# Load environment variables
load_dotenv()
api_key = os.getenv("OR_api_key")

# Set up logging to both console and a file
log_file = os.path.join("PhishingLink", "process.log")
os.makedirs(os.path.dirname(log_file), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

def normalize_url(url):
    """Ensure URL has a proper protocol."""
    return url if url.startswith("http://") or url.startswith("https://") else "https://" + url

def check_redirects(url):
    try:
        url = normalize_url(url)
        original_domain = tldextract.extract(url).registered_domain
        response = requests.get(url, timeout=10, allow_redirects=True)
        final_url = response.url
        final_domain = tldextract.extract(final_url).registered_domain
        redirected = len(response.history) > 0
        internal_redirect = redirected and (original_domain == final_domain)
        external_redirect = redirected and (original_domain != final_domain)
        return {
            "f38_redirect_count": len(response.history),
            "f39_external_redirect": int(external_redirect),
        }
    except Exception as e:
        logging.error(f"check_redirects error for {url}: {e}")
        return {
            "f38_redirect_count": 0,
            "f39_external_redirect": 0,
            "redirect_error": str(e),
        }

def extract_url_features(url):
    url = normalize_url(url)
    features = {}
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    full_url = url
    hostname = parsed.hostname if parsed.hostname else ""

    # f1-2: URL and hostname length
    features["url_length"] = full_url
    features["f1_url_length"] = len(full_url)
    features["f2_hostname_length"] = len(hostname)

    # f3: IP in hostname
    try:
        socket.inet_aton(hostname)
        features["f3_ip_in_url"] = 1
    except:
        features["f3_ip_in_url"] = int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", hostname)))

    # f4–f20: special characters
    special_chars = [".", "-", "@", "?", "&", "|", "=", "_", "~", "%", "/", "*", ":", ",", ";", "$", " "]
    for i, char in enumerate(special_chars, start=4):
        features[f"f{i}_count_{repr(char)}"] = full_url.count(char)

    # f21–f24: common phishing terms
    features["f21_www_count"] = full_url.lower().count("www")
    features["f22_com_count"] = full_url.lower().count(".com")
    features["f23_http_count"] = full_url.lower().count("http://")
    features["f24_double_slash"] = full_url.count("//")

    # f25: HTTPS token
    features["f25_https"] = int(url.startswith("https://"))

    # f26–f27: ratio of digits
    num_digits_url = sum(c.isdigit() for c in url)
    num_digits_host = sum(c.isdigit() for c in hostname)
    features["f26_digit_ratio_url"] = num_digits_url / len(url) if url else 0
    features["f27_digit_ratio_host"] = (num_digits_host / len(hostname)) if hostname else 0

    # f28: punycode
    features["f28_punycode"] = int("xn--" in hostname)

    # f29: port present
    features["f29_port_in_url"] = int(":" in hostname)

    # f30–f31: TLD in path/subdomain
    tld = ext.suffix
    features["f30_tld_in_path"] = int(tld in parsed.path)
    features["f31_tld_in_subdomain"] = int(tld in ext.subdomain)

    # f32: abnormal subdomain
    features["f32_abnormal_subdomain"] = int(bool(re.match(r"w[w\d]{1,}\d+", ext.subdomain)))

    # f33: number of subdomains
    features["f33_num_subdomains"] = (len(ext.subdomain.split(".")) if ext.subdomain else 0)

    # f34: prefix/suffix in domain
    features["f34_prefix_suffix"] = int("-" in ext.domain)

    # f35: random-looking domain (simple consonant cluster rule)
    features["f35_random_domain"] = int(bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{4,}", ext.domain.lower())))

    # f36: shortening service
    shortening_services = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "t.co"]
    features["f36_shortening_service"] = int(any(service in hostname for service in shortening_services))

    # f37: Suspicious file extensions
    path = parsed.path.lower()
    features["f37_suspicious_extension"] = int(any(ext in path for ext in [".txt", ".exe", ".js"]))

    # f38–f39: Redirects
    redirect_info = check_redirects(full_url)
    features["f38_redirect_count"] = redirect_info.get("f38_redirect_count", 0)
    features["f39_external_redirect"] = redirect_info.get("f39_external_redirect", 0)

    # f40–f50: NLP features (stub only)
    words = re.findall(r"\w+", full_url)
    features["f40_word_count"] = len(words)
    features["f41_char_repeat"] = max((full_url.count(c) for c in set(full_url)), default=0)
    features["f42_shortest_word_url"] = min((len(w) for w in words), default=0)
    features["f43_shortest_word_host"] = min((len(w) for w in hostname.split(".")), default=0)
    features["f44_shortest_word_path"] = min((len(w) for w in parsed.path.split("/") if w), default=0)
    features["f45_longest_word_url"] = max((len(w) for w in words), default=0)
    features["f46_longest_word_host"] = max((len(w) for w in hostname.split(".")), default=0)
    features["f47_longest_word_path"] = max((len(w) for w in parsed.path.split("/") if w), default=0)
    features["f48_avg_word_url"] = (sum(len(w) for w in words) / len(words)) if words else 0
    features["f49_avg_word_host"] = (sum(len(w) for w in hostname.split(".")) / len(hostname.split("."))) if hostname else 0
    path_words = [w for w in parsed.path.split("/") if w]
    features["f50_avg_word_path"] = (sum(len(w) for w in path_words) / len(path_words)) if path_words else 0

    # f51: Sensitive keywords (phishing hints)
    hints = ["verify", "update", "account", "secure", "bank", "signin", "login"]
    features["f51_phish_hints"] = sum(hint in full_url.lower() for hint in hints)

    # f52–f54: Brand domains
    brand_list = ["paypal", "apple", "amazon", "facebook", "google", "netflix"]
    features["f52_brand_in_domain"] = int(any(brand in ext.domain for brand in brand_list))
    features["f53_brand_in_subdomain"] = int(any(brand in ext.subdomain for brand in brand_list))
    features["f54_brand_in_path"] = int(any(brand in parsed.path for brand in brand_list))

    # f55: Suspicious TLDs
    suspicious_tlds = ["tk", "ml", "ga", "cf", "gq", "cn", "ru"]
    features["f55_suspicious_tld"] = int(tld in suspicious_tlds)

    # f56: Statistical report (placeholder)
    try:
        with open("PhishingLink/knownip.txt", "r") as f:
            known_malicious_ips = [line.strip() for line in f if line.strip()]
        features["f56_known_malicious_ip"] = int(hostname in known_malicious_ips)
    except Exception as e:
        logging.error(f"Error reading known IPs for {hostname}: {e}")
        features["f56_known_malicious_ip"] = 0

    return features

def extract_full_feature_set(url):
    url = normalize_url(url)
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")
        domain = tldextract.extract(url).domain

        links = soup.find_all("a", href=True)
        total_links = len(links)
        internal_links = 0
        external_links = 0
        null_links = 0
        safe_anchors = 0

        for link in links:
            href = link["href"]
            if href.startswith("#") or "void" in href:
                null_links += 1
                safe_anchors += 1
            elif "javascript" in href or "mailto:" in href:
                safe_anchors += 1
            elif domain in href:
                internal_links += 1
            else:
                external_links += 1

        internal_redirects = html.count("location.href") + html.count("window.location")
        external_redirects = html.count("window.open")

        stylesheets = soup.find_all("link", rel="stylesheet")
        external_css = sum(1 for s in stylesheets if domain not in s.get("href", ""))

        link_tags = soup.find_all("link", href=True)
        links_in_tags = sum(1 for tag in link_tags if domain in tag["href"])

        media_tags = soup.find_all(["img", "audio", "video"])
        internal_media = sum(1 for m in media_tags if domain in m.get("src", ""))
        external_media = len(media_tags) - internal_media

        login_forms = sum(1 for f in soup.find_all("form") if any(k in f.get("action", "").lower() for k in ["login", "signin", "verify"]))
        empty_forms = sum(1 for f in soup.find_all("form") if f.get("action", "") in ["", "about:blank"])
        submit_to_email = sum(1 for f in soup.find_all("form") if "mailto:" in f.get("action", ""))

        title = soup.title.string.strip() if soup.title else ""
        has_domain_in_title = int(domain in title)
        empty_title = int(title == "")
        domain_in_copyright = int(domain in soup.get_text().lower())

        invisible_iframes = sum(1 for i in soup.find_all("iframe") if "display:none" in i.get("style", "") or "visibility:hidden" in i.get("style", ""))
        disable_right_click = int("onmousedown" in html)
        onmouseover_right_click = int("event.button==2" in html)

        favicons = soup.find_all("link", rel=lambda x: x and "icon" in x)
        external_favicon = sum(1 for f in favicons if domain not in f.get("href", ""))

        return {
            "f57_total_links": total_links,
            "f58_ratio_internal_links": (internal_links / total_links if total_links else 0),
            "f59_ratio_external_links": (external_links / total_links if total_links else 0),
            "f60_ratio_null_links": (null_links / total_links if total_links else 0),
            "f61_external_css": external_css,
            "f62_internal_redirects": internal_redirects,
            "f63_external_redirects": external_redirects,
            "f64_internal_errors": 0,  # Placeholder, if you later want to track errors in link processing
            "f65_external_errors": 0,
            "f66_login_forms": login_forms,
            "f67_external_favicon": int(external_favicon > 0),
            "f68_links_in_tags": (links_in_tags / len(link_tags) if link_tags else 0),
            "f69_submit_to_email": submit_to_email,
            "f70_internal_media": internal_media,
            "f71_external_media": external_media,
            "f72_empty_forms": empty_forms,
            "f73_invisible_iframes": invisible_iframes,
            "f74_popups": html.count("window.alert"),
            "f75_safe_anchors": safe_anchors,
            "f76_disable_right_click": disable_right_click,
            "f77_onmouseover_rightclick": onmouseover_right_click,
            "f78_empty_title": empty_title,
            "f79_domain_in_title": has_domain_in_title,
            "f80_domain_in_copyright": domain_in_copyright,
            "error": False
        }
    except Exception as e:
        logging.error(f"Error processing full features for {url}: {e}")
        # Return a dictionary with expected keys and default values so that the CSV structure remains consistent.
        return {
            "f57_total_links": 0,
            "f58_ratio_internal_links": 0,
            "f59_ratio_external_links": 0,
            "f60_ratio_null_links": 0,
            "f61_external_css": 0,
            "f62_internal_redirects": 0,
            "f63_external_redirects": 0,
            "f64_internal_errors": 0,
            "f65_external_errors": 0,
            "f66_login_forms": 0,
            "f67_external_favicon": 0,
            "f68_links_in_tags": 0,
            "f69_submit_to_email": 0,
            "f70_internal_media": 0,
            "f71_external_media": 0,
            "f72_empty_forms": 0,
            "f73_invisible_iframes": 0,
            "f74_popups": 0,
            "f75_safe_anchors": 0,
            "f76_disable_right_click": 0,
            "f77_onmouseover_rightclick": 0,
            "f78_empty_title": 0,
            "f79_domain_in_title": 0,
            "f80_domain_in_copyright": 0,
            "error": True
        }

def extract_external_features(url, openpagerank_api_key=api_key):
    url = normalize_url(url)
    features = {}
    try:
        hostname = urlparse(url).hostname
        if hostname is None:
            return {"error": "Invalid URL"}

        try:
            w = whois.whois(hostname)
            features["f81_whois_registered"] = int(w.domain_name is not None)
        except:
            features["f81_whois_registered"] = 0

        try:
            expiration = w.expiration_date
            creation = w.creation_date
            if isinstance(expiration, list):
                expiration = expiration[0]
            if isinstance(creation, list):
                creation = creation[0]
            delta = (expiration - creation).days / 365 if expiration and creation else 0
            features["f82_registration_years"] = round(delta, 2)
        except:
            features["f82_registration_years"] = 0

        try:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            domain_age = (datetime.datetime.now() - creation).days
            features["f83_domain_age_days"] = domain_age
        except:
            features["f83_domain_age_days"] = 0

        features["f84_web_traffic"] = -1

        try:
            socket.gethostbyname(hostname)
            features["f85_dns_record"] = 1
        except socket.error:
            features["f85_dns_record"] = 0

        google_query = f"https://www.google.com/search?q=site:{hostname}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(google_query, headers=headers, timeout=5)
        features["f86_google_indexed"] = int("did not match any documents" not in response.text.lower())

        if openpagerank_api_key:
            pr_response = requests.get(
                "https://openpagerank.com/api/v1.0/getPageRank",
                headers={"API-OPR": openpagerank_api_key},
                params={"domains[]": hostname},
            )
            if pr_response.status_code == 200:
                rank = pr_response.json()["response"][0].get("page_rank_integer", -1)
                features["f87_pagerank"] = rank
            else:
                features["f87_pagerank"] = -1
        else:
            features["f87_pagerank"] = -1

    except Exception as e:
        logging.error(f"Error processing external features for {url}: {e}")
        features["error"] = str(e)

    return features

totalfeat = []

# Process Whitelist URLs
whitelist_path = os.path.join("PhishingLink", "Whitelist.txt")
try:
    with open(whitelist_path, "r") as white:
        white_list = white.readlines()
except Exception as e:
    logging.error(f"Failed to open {whitelist_path}: {e}")
    white_list = []

for idx, i in enumerate(white_list[:2000]):
    url = i.strip()
    try:
        urlfeat = extract_url_features(url)
        Htmlfeat = extract_full_feature_set(url)
        Exfeat = extract_external_features(url)
        result = {"isPhishing": False}
        combined = {**urlfeat, **Htmlfeat, **Exfeat, **result}
        totalfeat.append(combined)
        if idx % 5 == 0:
            logging.info(f"[+] Processed whitelist URL {idx}")
    except Exception as e:
        logging.error(f"Error processing whitelist URL {url}: {e}")
logging.info("Finished processing whitelist.")

blacklist_path = os.path.join("PhishingLink", "Blacklist.txt")
try:
    with open(blacklist_path, "r") as black:
        black_list = black.readlines()
except Exception as e:
    logging.error(f"Failed to open {blacklist_path}: {e}")
    black_list = []

for idx, i in enumerate(black_list[:2000]):
    url = i.strip()
    try:
        urlfeat = extract_url_features(url)
        Htmlfeat = extract_full_feature_set(url)
        Exfeat = extract_external_features(url)
        result = {"isPhishing": True}
        combined = {**urlfeat, **Htmlfeat, **Exfeat, **result}
        totalfeat.append(combined)
        if idx % 5 == 0:
            logging.info(f"[+] Processed blacklist URL {idx}")
    except Exception as e:
        logging.error(f"Error processing blacklist URL {url}: {e}")
logging.info("Finished processing blacklist.")


# Write results to CSV
csv_path = os.path.join("PhishingLink", "FeaturesColumn.csv")
if totalfeat:
    try:
        # Use all keys from the first record; you may want to use a union of keys if records differ.
        fieldnames = list(totalfeat[0].keys())
        with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(totalfeat)
        logging.info(f"CSV successfully written to {csv_path}")
    except Exception as e:
        logging.error(f"Error writing CSV: {e}")
else:
    logging.error("No features were extracted; CSV not written.")
