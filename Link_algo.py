import re
import whois
import datetime
import Levenshtein
from urllib.parse import urlparse

class ScamDetector:
    def __init__(self):
        # 1. The "Protected Brands" list (Add more relevant ones for your demo)
        self.target_brands = ["google", "facebook", "amazon", "paypal", "apple", "netflix", "bankofamerica"]
        
        # 2. Suspicious keywords often used in scam URLs
        self.suspicious_keywords = ["login", "verify", "secure", "account", "update", "banking", "signin", "confirm"]

    def analyze_url(self, url):
        score = 0
        reasons = []

        # CLEANUP: Ensure URL has a scheme for parsing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            domain_info = urlparse(url)
            domain = domain_info.netloc
            path = domain_info.path
        except:
            return 100, ["Invalid URL format"]

        print(f"🔍 Analyzing: {domain}...")

        # --- CHECK 1: IP Address Check (+80%) ---
        # Scammers often use raw IPs (e.g., http://192.168.1.5) instead of domains
        # Regex to look for IP address format
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            score += 80
            reasons.append("URL uses an IP address instead of a domain name.")

        # --- CHECK 2: Typosquatting (+70%) ---
        # Checks if the domain looks T00 similar to a famous brand
        for brand in self.target_brands:
            # Check if brand is IN the domain but slightly different
            # We strip the TLD (.com) to compare the core name
            domain_name = domain.split('.')[0] 
            
            if brand == domain_name:
                continue # It is the real site

            # Calculate distance (How many letters different?)
            distance = Levenshtein.distance(domain_name, brand)
            
            # If distance is small (1-2 chars) and the brand is longer than 3 chars
            if 0 < distance <= 2 and len(brand) > 3:
                score += 70
                reasons.append(f"Typosquatting detected! Mimics '{brand}' (Distance: {distance})")

        # --- CHECK 3: Suspicious Keywords (+15% each) ---
        # Looks for words like 'secure-login-paypal.com'
        for word in self.suspicious_keywords:
            if word in domain or word in path:
                score += 15
                reasons.append(f"Contains suspicious security keyword: '{word}'")

        # --- CHECK 4: Domain Age (+50%) ---
        # Real banks have domains from the 90s. Scams are from yesterday.
        # Note: WHOIS can sometimes fail or timeout, so we wrap in try/except
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            # Handle cases where WHOIS returns a list of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                # Calculate age in days
                age_days = (datetime.datetime.now() - creation_date).days
                print(f"   ℹ️  Domain Age: {age_days} days")
                
                if age_days < 30: # Less than 1 month old
                    score += 50
                    reasons.append(f"Domain is brand new ({age_days} days old).")
                elif age_days < 365: # Less than 1 year
                    score += 10
                    reasons.append(f"Domain is relatively new ({age_days} days old).")
        except:
            # If WHOIS fails (common for privacy protected domains), add a small penalty
            score += 10
            reasons.append("Could not verify domain age (Hidden or Private WHOIS).")

        # --- CHECK 5: Length & Complexity (+10%) ---
        # Scammers use long subdomains: 'verify-account.security.amazon.com.badsite.com'
        if len(domain) > 50:
            score += 20
            reasons.append("URL is suspiciously long.")
        if domain.count('.') > 3:
            score += 10
            reasons.append("Excessive subdomains detected.")

        # --- FINAL SCORE CALCULATION ---
        final_percentage = min(score, 100) # Cap at 100%
        return final_percentage, reasons

# --- RUNNING THE TEST ---
if __name__ == "__main__":
    detector = ScamDetector()
    
    # Test Cases to show the judges
    test_urls = [
        "https://www.google.com",                  # Real
        "http://paypa1.com",                       # Typosquatting (l -> 1)
        "http://192.168.1.1/login",                # IP Address
        "https://secure-verify-account-update.com", # Keywords
        "https://amazon.com.security-check.xyz"    # Subdomain trick
    ]

    print("\n--- 🛡️ SCAM DETECTOR PROTOTYPE 🛡️ ---\n")
    
    for link in test_urls:
        percent, log = detector.analyze_url(link)
        
        # Visual Formatting
        color = "🟢" if percent < 30 else "🔴"
        if 30 <= percent < 70: color = "🟠"

        print(f"{color} Link: {link}")
        print(f"   Risk Score: {percent}%")
        if log:
            print(f"   Reasons: {log}")
        print("-" * 40)