import re, ssl, socket, whois, datetime, Levenshtein
from urllib.parse import urlparse
from datetime import datetime,UTC,timezone

class ScamDetector:
    def __init__(self):
        self.target_brands = ["google", "facebook", "amazon", "paypal", "apple", "netflix", "scb"]
        self.suspicious_keywords = ["login", "verify", "secure", "account", "update", "banking", "signin", "confirm"]

    def analyze_url(self, link):
        pass

    def SSL_analyze(self, url):
        parse = urlparse(url)
        root = parse.hostname
        context = ssl.create_default_context()
        try:
            with socket.create_connection((root, 443), timeout=3.0) as sock:
                with context.wrap_socket(sock, server_hostname=root) as ssock:
                    #Handshake done
                    cert = ssock.getpeercert()
                    #Extracting detail
                    subject = list(cert['subject'])
                    issuer = list(cert['issuer'])
                    expire = cert['notAfter']
                    expire_date = datetime.strptime(expire, r"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expire_date - datetime.now(UTC)).days
                    print(f"Host name : {root}")
                    print(f"Issued by : {issuer}")
                    print(f"Expire date : {expire_date}")
                    print(f"Day till expire : {days_left}")
        except ssl.SSLCertVerificationError as e:
            #This is bad, SSLCert expired
            print(f"SSL ERROR: The certificate is invalid! ({e.verify_message})")
        except socket.gaierror:
            #Could not find server address
            print(f"DNS ERROR: Could not find server {root}")
        except Exception as e:
            #Could be a misconfiguration
            print(f"ERROR: {e}")

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
        detector.SSL_analyze(link)