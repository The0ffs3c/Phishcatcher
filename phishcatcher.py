import requests
import re
import tldextract
import whois
from urllib.parse import urlparse

# List of known suspicious domains (this list can be expanded)
phishing_blacklist = ["example.com", "suspicious-site.com"]

# Function to check if a URL is from a suspicious domain
def is_suspicious_domain(url):
    # Extract the domain from the URL
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix

    # Check if domain is on the blacklist
    if domain in phishing_blacklist:
        return True
    return False

# Function to check if the URL is using HTTPS
def is_https(url):
    return url.lower().startswith('https://')

# Function to check for unusual URL length
def is_unusually_long(url):
    return len(url) > 100  # You can adjust this threshold as needed

# Function to check for suspicious characters or patterns in the URL
def has_suspicious_patterns(url):
    suspicious_patterns = ['@', '%', '..', 'php', 'index', 'login', 'secure','trycloudflare.com']
    for pattern in suspicious_patterns:
        if pattern in url:
            return True
    return False

# Function to check if the domain was registered recently (possible red flag)
def is_newly_registered(url):
    ext = tldextract.extract(url)
    domain = ext.domain + '.' + ext.suffix
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            delta = (requests.utils.parse_http_date(requests.utils.format_date_time(requests.utils.now())) - creation_date).days
            # Flag if domain was created within the past 30 days
            return delta < 30
    except:
        return False
    return False

# Main function to scan and assess the phishing risk of a link
def scan_phishing_link(url):
    print(f"Scanning URL: {url}")

    # Check for HTTPS
    if not is_https(url):
        print("Warning: URL is not using HTTPS!")

    # Check for suspicious domain
    if is_suspicious_domain(url):
        print("Warning: URL has a suspicious domain!")

    # Check for unusual URL length
    if is_unusually_long(url):
        print("Warning: URL is unusually long!")

    # Check for suspicious patterns
    if has_suspicious_patterns(url):
        print("Warning: URL contains suspicious patterns!")

    # Check for newly registered domains
    if is_newly_registered(url):
        print("Warning: Domain was registered recently, which might be a red flag.")

    # If everything is clear
    print("Scanning complete!")

# Example Usage
if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    scan_phishing_link(url)

