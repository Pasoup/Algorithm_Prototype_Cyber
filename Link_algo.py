import whois
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

class  ScamDetector:
    def __init__(self):
        self.target_brands = ["google", "facebook", "amazon", "paypal", "apple", "netflix", "scb"]
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

    #calculatnig only for days -----------
        age_result = self.get_creation_date(url)
        if isinstance(age_result, int):
            days_created = age_result
            if days_created < 30:
                risk_score += 30  
            elif days_created < 100:
                risk_score += 10 
            elif days_created < 365:
                risk_score += 5 
            else:
                risk_score += 0  
        else:
            # can't verify age, give 10 suspecious meter
            risk_score += 10



#-------------------- this is where we calculate risk to give out
        if risk_score >= 80:
            return f"HIGH THREAT ({risk_score}% Risk) - Domain is extremely new!"
        elif risk_score >= 40:
            return f"Medium Threat ({risk_score}% Risk) - Domain is recent."
        else:
            return f"Low Threat ({risk_score}% Risk) - Domain is established."


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
        print(f"Result: {checker.analyze_url_algo(link)}")
        print("-" * 30)