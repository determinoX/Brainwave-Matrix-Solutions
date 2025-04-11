import tldextract
from Levenshtein import distance as lev
import ssl
import whois
from datetime import datetime
from colorama import Fore, Style, init
import json
import idna

# Initialize colorama for colored text in the terminal
init(autoreset=True)

# ======================= HELPER FUNCTIONS =======================
def domain_similarity(url, trusted_domains=["google.com", "paypal.com", "microsoft.com"]):
    extracted = tldextract.extract(url)
    target_domain = f"{extracted.domain}.{extracted.suffix}"
    # Lower Levenshtein threshold and include homograph detection
    return any(lev(target_domain, trusted) <= 1 for trusted in trusted_domains) or detect_homograph(url)

def check_https(url):
    hostname = tldextract.extract(url).registered_domain
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(ssl.SSLSocket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            return True  # Valid HTTPS connection
    except Exception:
        return False  # Invalid or no HTTPS connection

def check_domain_age(url):
    domain = tldextract.extract(url).registered_domain
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days if creation_date else 0
    except Exception:
        return 0

def check_subdomain(url):
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    keywords = ['login', 'secure', 'verify', 'account']
    return any(kw in subdomain for kw in keywords)

def check_keywords(url):
    keywords = ['login', 'verify', 'secure', 'account']
    return any(kw in url for kw in keywords)

def detect_homograph(url):
    try:
        decoded_url = idna.decode(tldextract.extract(url).fqdn)
        return decoded_url != url  # If decoded URL differs, it's likely a homograph attack
    except idna.IDNAError:
        return False

# ======================= CORE FUNCTIONALITY =======================
def phishing_scan(url):
    results = {
        'Domain Spoofing': domain_similarity(url),
        'HTTPS Valid': check_https(url),
        'Domain Age (days)': check_domain_age(url),
        'Suspicious Subdomain': check_subdomain(url),
        'Suspicious Keywords': check_keywords(url),
        'Homograph Attack': detect_homograph(url)
    }
    return results

# ======================= RISK CALCULATION & REPORTING =======================
SEVERITY_WEIGHTS = {
    'Domain Spoofing': 30,
    'HTTPS Valid': 25,
    'Domain Age (days)': 20,
    'Suspicious Subdomain': 15,
    'Suspicious Keywords': 10,
    'Homograph Attack': 50  # Increased weight for homograph attacks due to their severity
}

RECOMMENDATIONS = {
    'Domain Spoofing': "Avoid this site - possible impersonation of trusted brand",
    'HTTPS Valid': "Connection not secure - do not enter sensitive information",
    'Domain Age (days)': "Newly registered domain - exercise caution",
    'Suspicious Subdomain': "Suspicious subdomain detected - may be fraudulent",
    'Suspicious Keywords': "Contains phishing keywords - verify legitimacy",
    'Homograph Attack': "Detected homograph attack - verify legitimacy of the domain"
}

def calculate_risk_score(results):
    score = 0
    for check, value in results.items():
        if isinstance(value, bool) and value:
            score += SEVERITY_WEIGHTS.get(check, 0)
        elif check == "Domain Age (days)" and value < 365:  # Flag domains less than a year old
            score += SEVERITY_WEIGHTS.get(check, 0)
    return min(score, 100)

def generate_report(results, risk_score, url):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = {
        "scan_date": timestamp,
        "url": url,
        "results": results,
        "risk_score": risk_score,
        "recommendations": [RECOMMENDATIONS[k] for k, v in results.items() 
                           if (isinstance(v, bool) and v) or 
                           (k == 'Domain Age (days)' and v < 365)]
    }
    return report

# ======================= USER INTERFACE =======================
def display_header():
    print(Fore.CYAN + Style.BRIGHT + """
 ______  ______  _     ____  
|  _ \ \/ /  _ \| |   / ___| 
| | | \  /| |_) | |   \___ \ 
| |_| /  \|  __/| |___ ___) |
|____/_/\_\_|   |_____|____/ 
""")
    print(Fore.YELLOW + Style.BRIGHT + "Terminal Phishing Link Scanner v4.1")
    print(Fore.YELLOW + "=" * 60)

def main():
    display_header()
    
    while True:
        print(Fore.GREEN + "\nOptions:")
        print(Fore.GREEN + "1. Scan a URL")
        print(Fore.GREEN + "2. Generate JSON Report")
        print(Fore.GREEN + "3. Exit")
        
        choice = input(Fore.YELLOW + "Select an option: ").strip()
        
        if choice == "1":
            url = input(Fore.CYAN + "\nEnter the URL to scan: ").strip()
            results = phishing_scan(url)
            risk_score = calculate_risk_score(results)
            
            print(Fore.YELLOW + "\nScan Results:")
            print(Fore.YELLOW + "=" * 40)
            
            for check, result in results.items():
                status_color = Fore.RED if (isinstance(result, bool) and result) or \
                    (check == 'Domain Age (days)' and result < 365) else Fore.GREEN
                
                explanation = ""
                if check == 'Domain Spoofing':
                    explanation = "(Compares with trusted domains using Levenshtein distance)"
                elif check == 'HTTPS Valid':
                    explanation = "(Valid SSL certificate check)"
                elif check == 'Domain Age (days)':
                    explanation = "(Days since domain registration)"
                elif check == 'Homograph Attack':
                    explanation = "(Checks for Unicode-based homographs)"
                
                print(f"{Fore.CYAN}{check:<20}: {status_color}{result} {explanation}")

            print(Fore.YELLOW + "\n" + "=" * 40)
            print(Fore.MAGENTA + f"Phishing Risk Score: {risk_score}/100")
            
            print(Fore.YELLOW + "\nRecommendations:")
            for k, v in results.items():
                if (isinstance(v, bool) and v) or (k == 'Domain Age (days)' and v < 365):
                    print(f"{Fore.RED}» {RECOMMENDATIONS[k]}")
            
            print(Fore.YELLOW + "\nScan completed successfully!")
        
        elif choice == "2":
            url = input(Fore.CYAN + "\nEnter the URL to scan: ").strip()
            results = phishing_scan(url)
            risk_score = calculate_risk_score(results)
            report = generate_report(results, risk_score, url)
            
            filename = f"phishing_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(Fore.GREEN + f"\nReport saved as {filename}")
        
        elif choice == "3":
            print(Fore.RED + "\nExiting the tool. Stay safe online!")
            break
        
        else:
            print(Fore.RED + "\nInvalid option. Please try again.")

if __name__ == "__main__":
    main()
