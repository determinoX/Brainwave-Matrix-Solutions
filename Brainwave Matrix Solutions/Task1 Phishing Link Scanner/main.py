import tkinter as tk
from tkinter import messagebox
import tldextract
from Levenshtein import distance as lev
import ssl
import whois
from datetime import datetime

# Function to perform phishing scan
def phishing_scan(url):
    def domain_similarity(url, trusted_domains=["google.com", "paypal.com", "microsoft.com"]):
        extracted = tldextract.extract(url)
        target_domain = f"{extracted.domain}.{extracted.suffix}"
        return any(lev(target_domain, trusted) <= 2 for trusted in trusted_domains)

    def check_https(url):
        hostname = tldextract.extract(url).registered_domain
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(ssl.SSLSocket(), server_hostname=hostname) as s:
                s.connect((hostname, 443))
                return True
        except Exception:
            return False

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
        return any(keyword in subdomain for keyword in ['login', 'secure', 'verify', 'account'])

    results = {
        'Domain Spoofing': domain_similarity(url),
        'HTTPS Valid': check_https(url),
        'Domain Age (days)': check_domain_age(url),
        'Suspicious Subdomain': check_subdomain(url),
        'Suspicious Keywords': any(kw in url for kw in ['login', 'verify', 'secure', 'account'])
    }
    return results

# Function to handle the scan button click
def scan_url():
    url = url_entry.get()
    if not url:
        messagebox.showerror("Error", "Please enter a URL to scan.")
        return
    
    try:
        results = phishing_scan(url)
        
        # Display results in a message box
        result_message = "\n".join(
            [f"{key}: {'⚠️ Suspicious' if value else '✅ Normal'}" if isinstance(value, bool) 
             else f"{key}: {value} days" for key, value in results.items()]
        )
        messagebox.showinfo("Scan Results", result_message)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main application window
app = tk.Tk()
app.title("Phishing Link Scanner")
app.geometry("400x250")

# URL input label and entry field
url_label = tk.Label(app, text="Enter URL to Scan:")
url_label.pack(pady=10)

url_entry = tk.Entry(app, width=50)
url_entry.pack(pady=5)

# Scan button
scan_button = tk.Button(app, text="Scan", command=scan_url)
scan_button.pack(pady=20)

# Run the application
app.mainloop()
