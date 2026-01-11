import ssl, socket, whois, datetime, requests
from urllib.parse import urlparse
from datetime import datetime,UTC,timezone
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from bs4 import BeautifulSoup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1",
        "chrome-extension://kbbpbmflbdfgiicegcefhgdocoeodcbh"
        ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LinkRequest(BaseModel):
    url:str

@app.post("/checkURL")
def checkURL(request:LinkRequest):
    checker = ScamDetector()
    RiskLevel,RiskFactor = checker.analyze_url_algo(request.url)
    return {"RiskLevel":RiskLevel,"RiskFactor":RiskFactor}

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
            return 30, "SSL certificate expired"
        except socket.gaierror:
            #Could not find server address, could be phishing attempt
            print(f"DNS ERROR: Could not find server {root}")
            return 30, "Server does not exist"
        except socket.timeout:
            #The server is either slow or blocked, doesn't necessary mean it's dangerous
            #Perhaps it's some company private server which weren't meant for public
            print("Timeout Error (Server slow/blocked)")
            return 15, "Server could be slow or blocked"
        except ConnectionRefusedError:
            print("Connection refused (Port close)")
            return 24, "Connection refused"
        except Exception as e:
            #Unknown error be assess as risky
            print(f"ERROR: {e}")
            return 30, "Unknown Error"
        
#----------------------------- Check age from first SSL certificate  ------------------------------------------------
    def age_alternative(self,domain):
        url = f"https://crt.sh/?q={domain}&output=json"
        ua = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        try:
            req = requests.get(url, headers={'User-Agent': ua},timeout=10)
            if req.ok:
                res = req.json()
                #If no result return None
                if not res:
                    return None
                dates = []
                for SSL in res:
                    date_str = SSL.get('entry_timestamp')
                    dt = datetime.strptime(date_str.split('T')[0],"%Y-%m-%d").replace(tzinfo=timezone.utc)
                    dates.append(dt)
                first_cert = min(dates)
                age = (datetime.now(UTC) - first_cert).days
                return age
        except Exception as e:
            error = f"Encountered unexpected error : {e}"
            print(error)
            return error
                    

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

        #---checking for redirect
    def Redirect_analyze(self, url):
        try:
            response = requests.get(url, allow_redirects=True, stream=True, timeout=5)
            history = response.history
            final_url = response.url
            hops = len(history)
            
            risk_score = 0
            details = []
            
            # Check for hops
            if hops == 0:
                return 0, "No redirects"
            
            if hops > 3:
                risk_score += 10
                details.append(f"High redirect count ({hops} hops)")
            else:
                details.append(f"{hops} redirect(s)")

            initial_domain = self.get_domain_from_url(url)
            final_domain = self.get_domain_from_url(final_url)

            if initial_domain != final_domain:
                # We allow legitimate sub-domain redirects
                if final_domain not in initial_domain and initial_domain not in final_domain:
                    risk_score += 10
                    details.append(f"Destination mismatch ({initial_domain} -> {final_domain})")
            
            risk_message = "; ".join(details)
            return risk_score, risk_message
        except requests.exceptions.RequestException as e:
            return 0, "Connection Failed during redirect check"
        
    def fetch_page_text(self,url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=3)
            
            if response.status_code != 200:
                return "" 
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            clean_text = soup.get_text(separator=' ').lower()
            
            return clean_text

        except Exception as e:
            print(f"Error fetching text: {e}")
            return ""
    
#--------checking for TLD-----------
    def checking_tld(self,url, page_text):
        risk_score = 0
        reasons = []
        domain = url.split("//")[-1].split("/")[0].lower()

        gambling_tlds = [
            ".cc", ".vip", ".pro", ".asia", ".club", 
            ".fun", ".live", ".bet", ".game", ".win", ".me"
        ]
        
        for tld in gambling_tlds:
            if domain.endswith(tld):
                risk_score += 30
                reasons.append(f"Suspicious TLD ({tld}) common in gambling")

        bad_domain_patterns = [
            "ufa", "pg", "168", "888", "777", "joker", 
            "slot", "auto", "wallet", "bet", "xo"
        ]
        
        matches = [pat for pat in bad_domain_patterns if pat in domain]
        if matches:
            risk_score += 50
            reasons.append(f"Domain contains gambling network keywords: {matches}")

        if page_text:
            thai_keywords = [
                "สล็อต", "บาคาร่า", "คาสิโน", "ฝากถอน", 
                "ไม่มีขั้นต่ำ", "เว็บตรง", "เครดิตฟรี", "แทงบอล"
            ]
            english_keywords = [
                "casino", "sportsbook", "betting", "wager", 
                "jackpot", "slots", "roulette", "blackjack", 
                "poker", "deposit bonus", "free spins", "live dealer",
                "odds", "payout", "rollover", "welcome bonus"
            ]
            all_keywords = thai_keywords + english_keywords

            found_keywords = [word for word in all_keywords if word in page_text]
            if len(found_keywords) >= 3:
                risk_score += 30
                reasons.append(f"Found gambling keywords: {found_keywords}")


        return min(risk_score, 100),reasons
    def analyze_url_algo(self,url):
        risk_score = 0
        SSL_riskScore, SSL_riskMessage = self.SSL_analyze(url)
        risk_score += SSL_riskScore

        redirect_score, redirect_msg = self.Redirect_analyze(url)
        risk_score += redirect_score

        page_contect = self.fetch_page_text(url)
        tld_score,tld_riskmsg = self.checking_tld(url,page_contect)
        risk_score += tld_score
    #calculatnig only for days -----------
    
        age_result = self.get_creation_date(url)
        ssl_age = self.age_alternative(url)
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
        elif isinstance(ssl_age, int):
            #Because we can't get the age directly
            #We check the first SSLCertificate of 
            #the domain, since server would need
            #certificate to be flag as 'safe'
            if ssl_age < 30:
                risk_score += 30  
                age_riskMessage = "Domain is extremely new!"
            elif ssl_age < 100:
                risk_score += 10 
                age_riskMessage = "Domain is recent"
            elif ssl_age < 365:
                risk_score += 5 
                age_riskMessage = "Domain is established"
            else:
                age_riskMessage = "Domain is ancient"
                risk_score += 0  
        else:
            # can't verify age, give 10 suspecious meter
            age_riskMessage = "Can't verify age"
            risk_score += 10
        RiskFactor = [age_riskMessage,SSL_riskMessage,redirect_msg,tld_riskmsg]

#-------------------- this is where we calculate risk to give out

        risk_score = min(risk_score, 100)
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
        "https://www.ufabet168.menu/",
        "https://ufabet.date/",

    ]

    for link in test_urls:
        print(f"Checking: {link}")
        RiskLevel,RiskFactor = checker.analyze_url_algo(link)
        print(f"Result: {RiskLevel}")
        print(f"Risk Factor: {RiskFactor}")
        print("-" * 30)