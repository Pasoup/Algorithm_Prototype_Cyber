import re
import whois
import datetime
import Levenshtein
from urllib.parse import urlparse

class ScamDetector:
    def __init__(self):
        self.target_brands = ["google", "facebook", "amazon", "paypal", "apple", "netflix", "scb"]
        
        self.suspicious_keywords = ["login", "verify", "secure", "account", "update", "banking", "signin", "confirm"]

    def analyze_url(sefl, link):
        pass

    
if __name__ == "__main__":
    detector = ScamDetector()

    test_urls = [
        "https://www.google.com",                 
        "http://paypa1.com",                       
        "http://192.168.1.1/login",               
        "https://secure-verify-account-update.com", 
        "https://amazon.com.security-check.xyz"    
    ]

    for link in test_urls:
        percent, log = detector.analyze_url(link)
        print(f" Link: {link}")
        print(f" Risk Score: {percent}%")