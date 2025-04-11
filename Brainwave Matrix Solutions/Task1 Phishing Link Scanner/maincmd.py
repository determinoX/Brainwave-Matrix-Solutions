import tldextract
from Levenshtein import distance as lev
import ssl
import whois
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored text in the terminal
init(autoreset=True)

# ASCII Art for the Tool Header
def display_header():
    print(Fore.CYAN + Style.BRIGHT + """
 ______  ______  _     ____  
|  _ \ \/ /  _ \| |   / ___| 
| | | \  /| |_) | |   \___ \ 
| |_| /  \|  __/| |___ ___) |
|____/_/\_\_|   |_____|____/ 
""")
    print(Fore.YELLOW + Style.BRIGHT + "Terminal Phishing Link Scanner v2.0")
    print(Fore.YELLOW + "=" * 60)


# Function to check for domain similarity (typosquatting detection)
def domain_similarity(url, trusted_domains=["google.com", "paypal.com", "microsoft.com"]):
    extracted = tldextract.extract(url)
    target_domain = f"{extracted.domain}.{extracted.suffix}"
    return any(lev(target_domain, trusted) <= 2 for trusted in trusted_domains)

# Function to validate SSL certificate
def check_https(url):
    hostname = tldextract.extract(url).registered_domain
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(ssl.SSLSocket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            return True
    except Exception:
        return False

# Function to check domain age using WHOIS lookup
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

# Function to check for suspicious subdomains
def check_subdomain(url):
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    keywords = ['login', 'secure', 'verify', 'account']
    return any(kw in subdomain for kw in keywords)

# Function to check for phishing-related keywords in the URL
def check_keywords(url):
    keywords = ['login', 'verify', 'secure', 'account']
    return any(kw in url for kw in keywords)

# Main function to perform phishing scan
def phishing_scan(url):
    results = {
        'Domain Spoofing': domain_similarity(url),
        'HTTPS Valid': check_https(url),
        'Domain Age (days)': check_domain_age(url),
        'Suspicious Subdomain': check_subdomain(url),
        'Suspicious Keywords': check_keywords(url)
    }
    return results

# Menu-driven interface for the scanner with colored output
def main():
    display_header()
    
    while True:
        print(Fore.GREEN + "\nOptions:")
        print(Fore.GREEN + "1. Scan a URL")
        print(Fore.GREEN + "2. Exit")
        
        choice = input(Fore.YELLOW + "Select an option: ").strip()
        
        if choice == "1":
            url = input(Fore.CYAN + "\nEnter the URL to scan: ").strip()
            results = phishing_scan(url)
            
            print(Fore.YELLOW + "\nScan Results:")
            print(Fore.YELLOW + "=" * 40)
            
            for check, result in results.items():
                if isinstance(result, bool):
                    status = Fore.RED + "⚠️ Suspicious" if result else Fore.GREEN + "✅ Safe"
                    print(f"{Fore.CYAN}{check:<20}: {status}")
                else:
                    print(f"{Fore.CYAN}{check:<20}: {result} days old" if check == "Domain Age (days)" else f"{Fore.CYAN}{check:<20}: {result}")
            
            print(Fore.YELLOW + "\nScan completed successfully!")
        
        elif choice == "2":
            print(Fore.RED + "\nExiting the tool. Stay safe online!")
            break
        
        else:
            print(Fore.RED + "\nInvalid option. Please try again.")

if __name__ == "__main__":
    main()
