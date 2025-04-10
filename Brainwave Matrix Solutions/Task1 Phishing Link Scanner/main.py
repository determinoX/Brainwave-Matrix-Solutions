import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import tldextract
from Levenshtein import distance as lev
import ssl
import whois
from datetime import datetime

class PhishingScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Phishing Link Scanner")
        master.geometry("800x600")
        master.configure(bg='#f0f0f0')
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10, 'bold'))
        self.style.configure('Red.TLabel', foreground='red')
        self.style.configure('Green.TLabel', foreground='green')
        
        # Create main container
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # URL Input Section
        self.input_frame = ttk.Frame(self.main_frame)
        self.input_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(self.input_frame, text="Enter URL to Scan:", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(self.input_frame, width=50, font=('Arial', 12))
        self.url_entry.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Control Buttons
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.pack(pady=10)
        
        ttk.Button(self.btn_frame, text="Scan", command=self.scan_url).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.btn_frame, text="Clear", command=self.clear_fields).pack(side=tk.LEFT, padx=5)
        
        # Results Display
        self.results_frame = ttk.Labelframe(self.main_frame, text="Scan Results", padding=10)
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Result Items
        self.result_items = {
            'Domain Spoofing': self.create_result_row("Domain Spoofing"),
            'HTTPS Valid': self.create_result_row("HTTPS Valid"),
            'Domain Age': self.create_result_row("Domain Age"),
            'Suspicious Subdomain': self.create_result_row("Suspicious Subdomain"),
            'Suspicious Keywords': self.create_result_row("Suspicious Keywords")
        }
        
        # Detailed Log
        self.log_area = scrolledtext.ScrolledText(self.results_frame, height=8, wrap=tk.WORD)
        self.log_area.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Status Bar
        self.status_bar = ttk.Label(master, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_result_row(self, title):
        frame = ttk.Frame(self.results_frame)
        frame.pack(fill=tk.X, pady=2)
        
        label = ttk.Label(frame, text=title, width=20, anchor=tk.W)
        label.pack(side=tk.LEFT)
        
        status = ttk.Label(frame, text="Pending", width=15)
        status.pack(side=tk.LEFT, padx=10)
        
        details = ttk.Label(frame, text="", width=40)
        details.pack(side=tk.LEFT)
        
        return {'frame': frame, 'status': status, 'details': details}
    
    def update_result(self, key, is_suspicious, details):
        item = self.result_items[key]
        status_text = "⚠️ Suspicious" if is_suspicious else "✅ Safe"
        color_style = 'Red.TLabel' if is_suspicious else 'Green.TLabel'
        
        item['status'].configure(text=status_text, style=color_style)
        item['details'].configure(text=details)
    
    def clear_fields(self):
        self.url_entry.delete(0, tk.END)
        self.log_area.delete(1.0, tk.END)
        for item in self.result_items.values():
            item['status'].configure(text="Pending", style='TLabel')
            item['details'].configure(text="")
        self.status_bar.configure(text="Fields cleared")
    
    def log_message(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
    
    def phishing_scan(self, url):
        def domain_similarity():
            trusted_domains = ["google.com", "paypal.com", "microsoft.com"]
            extracted = tldextract.extract(url)
            target_domain = f"{extracted.domain}.{extracted.suffix}"
            return {
                'result': any(lev(target_domain, trusted) <= 2 for trusted in trusted_domains),
                'trusted_domains': trusted_domains
            }

        def check_https():
            hostname = tldextract.extract(url).registered_domain
            try:
                context = ssl.create_default_context()
                with context.wrap_socket(ssl.SSLSocket(), server_hostname=hostname) as s:
                    s.connect((hostname, 443))
                return {'result': True}
            except Exception:
                return {'result': False}

        def check_domain_age():
            domain = tldextract.extract(url).registered_domain
            try:
                info = whois.whois(domain)
                creation_date = info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age = (datetime.now() - creation_date).days if creation_date else 0
                return {'result': age, 'days': age}
            except Exception:
                return {'result': 0, 'days': 0}

        def check_subdomain():
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain
            keywords = ['login', 'secure', 'verify', 'account']
            return {'result': any(kw in subdomain for kw in keywords)}

        def check_keywords():
            keywords = ['login', 'verify', 'secure', 'account']
            return {'result': any(kw in url for kw in keywords)}

        return {
            'Domain Spoofing': domain_similarity()['result'],
            'Trusted Domains': domain_similarity()['trusted_domains'],
            'HTTPS Valid': check_https()['result'],
            'Domain Age': check_domain_age()['days'],
            'Suspicious Subdomain': check_subdomain()['result'],
            'Suspicious Keywords': check_keywords()['result']
        }

    def scan_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to scan.")
            return
        
        try:
            self.status_bar.configure(text="Scanning...")
            self.master.update()
            
            results = self.phishing_scan(url)
            
            # Update GUI elements
            self.update_result('Domain Spoofing', results['Domain Spoofing'], 
                            f"Compared to {len(results['Trusted Domains'])} trusted domains")
            self.update_result('HTTPS Valid', not results['HTTPS Valid'], 
                            "Valid SSL" if results['HTTPS Valid'] else "Invalid SSL")
            self.update_result('Domain Age', results['Domain Age'] < 365, 
                            f"{results['Domain Age']} days old")
            self.update_result('Suspicious Subdomain', results['Suspicious Subdomain'], 
                            "Suspicious keywords found" if results['Suspicious Subdomain'] else "No issues")
            self.update_result('Suspicious Keywords', results['Suspicious Keywords'], 
                            "Suspicious keywords found" if results['Suspicious Keywords'] else "No issues")
            
            # Add detailed log
            self.log_message(f"Scan completed for: {url}")
            self.log_message("-" * 50)
            for key, value in results.items():
                self.log_message(f"{key}: {value}")
            
            self.status_bar.configure(text="Scan completed successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_bar.configure(text="Error occurred during scanning")

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingScannerGUI(root)
    root.mainloop()
