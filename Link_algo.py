import re, ssl, socket, whois, datetime, Levenshtein
from urllib.parse import urlparse
from datetime import datetime,UTC,timezone

class  ScamDetector:
    def __init__(self):
        self.target_brands = ["google", "facebook", "amazon", "paypal", "apple", "netflix", "scb"]
        self.suspicious_keywords = ["login", "verify", "secure", "account", "update", "banking", "signin", "confirm"]

    def SSL_analyze(self, url):
#------------------------------ getting the host name --------------------------------------------------------------
        parse = urlparse(url)
        root = parse.hostname
#----------------------- getting certificate authority from OS  ----------------------------------------------------
        context = ssl.create_default_context()
#--------------------------test connection on port 443 -------------------------------------------------------------
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
                    print("-" * 30)
                    print(f"Host name : {root}")
                    print(f"Issued by : {issuer}")
                    print(f"Expire date : {expire_date}")
                    print(f"Day till expire : {days_left}")
                    #Got the certificate, reachable, valid, and exist
                    return 0, "SSL certificate valid, server reachable and exist"
#----------------------------- return risk score based on exception -------------------------------------------------
        except ssl.SSLCertVerificationError as e:
            #This is bad, SSLCert expired which could mean phishing risk, data exposure, etc.
            print(f"SSL ERROR: The certificate is invalid! ({e.verify_message})")
            return 100, "SSL certificate expired"
        except socket.gaierror:
            #Could not find server address, could be phishing attempt
            print(f"DNS ERROR: Could not find server {root}")
            return 100, "Server does not exist"
        except socket.timeout:
            #The server is either slow or blocked, doesn't necessary mean it's dangerous
            #Perhaps it's some company private server which weren't meant for public
            print("Timeout Error (Server slow/blocked)")
            return 50, "Server could be slow or blocked"
        except ConnectionRefusedError:
            print("Connection refused (Port close)")
            return 80, "Connection refused"
        except Exception as e:
            #Unknown error be assess as risky
            print(f"ERROR: {e}")
            return 100, "Unknown Error"

    def get_domain_from_url(self, url):
        #extract keywords from url
        try:
          
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # strip out www. since whois isn't good with it
            if domain.startswith('www.'):
                domain = domain[4:]
                
            return domain
        except Exception:
            return None

    def get_creation_date(self, url):
        domain_name = self.get_domain_from_url(url)
        if not domain_name:
            return "Invalid URL"
        try:
            domain_info = whois.whois(domain_name)
            creation_date = domain_info.creation_date
            if creation_date is None:
                return "Date hidden or not found"
            if isinstance(creation_date, list):
                creation_date = creation_date[0] #if more than 1 return fo date get the first one
            # Calculate Age
            now = datetime.now()
            if creation_date.tzinfo: #incase there's differ in timezone
                now = datetime.now(timezone.utc)
            age = now - creation_date
            return age.days
        except Exception as e:
            return f"Error: {str(e)}"

    def analyze_url_algo(self,url):
        risk_score = 0
        SSL_riskScore, SSL_riskMessage = self.SSL_analyze(url)
        risk_score += SSL_riskScore
    #calculatnig only for days -----------
        age_result = self.get_creation_date(url)
        age_riskMessage = ""
        if isinstance(age_result, int):
            days_created = age_result
            if days_created < 30:
                risk_score += 30  
                age_riskMessage = "Domain is extremely new!"
            elif days_created < 100:
                risk_score += 10 
                age_riskMessage = "Domain is recent"
            elif days_created < 365:
                risk_score += 5 
                age_riskMessage = "Domain is established"
            else:
                age_riskMessage = "Domain is ancient"
                risk_score += 0  
        else:
            # can't verify age, give 10 suspecious meter
            age_riskMessage = "Can't verify age"
            risk_score += 10
        RiskFactor = [age_riskMessage,SSL_riskMessage]


#-------------------- this is where we calculate risk to give out
        if risk_score >= 80:
            return f"HIGH THREAT ({risk_score}% Risk)",RiskFactor
        elif risk_score >= 40:
            return f"Medium Threat ({risk_score}% Risk)",RiskFactor
        else:
            return f"Low Threat ({risk_score}% Risk)",RiskFactor


# --- Testing ---
if __name__ == "__main__":
    checker = ScamDetector()
    
    test_urls = [
        "https://www.google.com",
        "http://paypa1.com",  
        "https://amazon.com.security-check.xyz", 
        "apple.com",
        "vercel.com"
    ]

    for link in test_urls:
        print(f"Checking: {link}")
        RiskLevel,RiskFactor = checker.analyze_url_algo(link)
        print(f"Result: {RiskLevel}")
        print(f"Risk Factor: {RiskFactor}")
        print("-" * 30)
