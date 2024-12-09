import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog
import threading
import requests
from bs4 import BeautifulSoup
import socket
import ssl
from urllib.parse import urlparse, urljoin
import re
import logging
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from fpdf import FPDF

# Configure logging for GUI
logger = logging.getLogger()
log_format = '%(message)s'  # No date/time
logging.basicConfig(level=logging.INFO, format=log_format)

# Create the main GUI class
class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kṣetra-jñam - The knower of the field")
        self.root.geometry("800x600")
        self.root.config(bg="#1e1e1e")
        root.iconbitmap('ksetra_jnam.ico')
        
        # Disable maximize button
        self.root.resizable(False, False)

        # Set the theme using ttk styles
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#4CAF50", font=("Helvetica", 12, 'bold'), foreground="white")
        self.style.configure("TLabel", font=("Helvetica", 12), foreground="white", background="#1e1e1e")
        self.style.configure("TCheckbutton", font=("Helvetica", 12), foreground="white", background="#1e1e1e")
        self.style.configure("TEntry", font=("Helvetica", 12), padding=10, relief="flat")

        # Create a central frame to hold everything and center it
        self.frame = tk.Frame(self.root, bg="#1e1e1e")
        self.frame.pack(expand=True)

        # Create target URL entry row (Centered)
        self.url_label = tk.Label(self.frame, text="Enter Target URL:")
        self.url_label.grid(row=0, column=0, pady=20, sticky="e", padx=10)

        self.url_entry = tk.Entry(self.frame, width=50, font=("Helvetica", 12))
        self.url_entry.grid(row=0, column=1, pady=5)

        # Create checkboxes for options (verbose and generate PDF) on the same row and centered
        self.verbose_var = tk.BooleanVar()
        self.report_var = tk.BooleanVar()

        # Creating checkboxes in the same row
        self.verbose_checkbox = tk.Checkbutton(self.frame, text="Verbose Mode", variable=self.verbose_var)
        self.report_checkbox = tk.Checkbutton(self.frame, text="Generate PDF Report", variable=self.report_var, command=self.toggle_browse_button)

        self.verbose_checkbox.grid(row=1, column=0, columnspan=2, pady=10, sticky="w")
        self.report_checkbox.grid(row=1, column=2, columnspan=2, pady=10, sticky="e")

        # File path selection for saving report (Centered)
        self.report_path_label = tk.Label(self.frame, text="Save Report to:")
        self.report_path_label.grid(row=2, column=0, pady=10, sticky="e", padx=10)

        self.report_path_entry = tk.Entry(self.frame, width=50, font=("Helvetica", 12))
        self.report_path_entry.grid(row=2, column=1, pady=5)

        self.browse_button = tk.Button(self.frame, text="Browse", command=self.browse_file, state=tk.DISABLED)
        self.browse_button.grid(row=2, column=2, padx=10)

        # Scan button (Centered)
        self.scan_button = tk.Button(self.frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, columnspan=3, pady=30)

        # Output log text box (Centered)
        self.log_text = tk.Text(self.frame, width=80, height=15, wrap=tk.WORD, state=tk.DISABLED,
                                font=("Courier", 10), bg="#333333", fg="white", padx=10, pady=10, relief="flat")
        self.log_text.grid(row=4, column=0, columnspan=3, pady=20)

        # Developer Label (Centered at the bottom)
        self.developer_label = tk.Label(self.frame, text="Developed by Asim Tara Pathak", font=("Helvetica", 10), fg="white", bg="#1e1e1e")
        self.developer_label.grid(row=5, column=0, columnspan=3, pady=20, sticky="s")

    def log_message(self, message):
        """ Log a message in the output box """
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + '\n')
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.yview(tk.END)  # Scroll to the bottom

    def browse_file(self):
        """ Open file dialog to choose where to save the report """
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
        if file_path:
            self.report_path_entry.delete(0, tk.END)  # Clear current entry
            self.report_path_entry.insert(0, file_path)  # Insert selected file path

    def toggle_browse_button(self):
        """ Enable or disable the Browse button based on the Generate PDF Report checkbox """
        if self.report_var.get():  # If the "Generate PDF Report" checkbox is checked
            self.browse_button.config(state=tk.NORMAL)
        else:  # If unchecked, disable the Browse button and show a message
            self.browse_button.config(state=tk.DISABLED)
            self.report_path_entry.delete(0, tk.END)  # Clear the entry if the checkbox is unchecked

    def start_scan(self):
        """ Start the vulnerability scan in a separate thread to keep the GUI responsive """
        target_url = self.url_entry.get()
        verbose = self.verbose_var.get()
        generate_report = self.report_var.get()
        report_path = self.report_path_entry.get()  # Get the file path to save the report

        if not target_url:
            messagebox.showerror("Input Error", "Please enter a valid URL format.")
            return

        if generate_report and not report_path:
            messagebox.showerror("Input Error", "Please choose a location to save the report.")
            return

        # Start the scan in a separate thread
        threading.Thread(target=self.run_scan, args=(target_url, verbose, generate_report, report_path), daemon=True).start()

    def run_scan(self, target_url, verbose, generate_report, report_path):
        """ Run the actual scan in a background thread """
        self.log_message("Starting scan on: " + target_url)
        try:
            # Validate the URL
            if not self.validate_url(target_url):
                self.log_message("Invalid URL format.")
                return

            # Configure logging based on verbose mode
            self.configure_logging(verbose)

            # Start the vulnerability scan
            self.log_message("Running vulnerability scan...")
            session = self.get_session_with_retries()
            vulnerabilities = self.vulnerability_scan(target_url, session)

            # Optionally generate report
            if generate_report:
                self.generate_pdf_report(vulnerabilities, target_url, report_path)

            self.log_message("Scan completed!")
            messagebox.showinfo("Scan Complete", "The scan has completed successfully.")

        except Exception as e:
            self.log_message(f"Error: {e}")
            messagebox.showerror("Scan Error", f"An error occurred during the scan: {e}")

    def validate_url(self, url):
        """ Validate the format of the URL """
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            try:
                socket.inet_aton(url)
                return True
            except socket.error:
                return False
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)

    def configure_logging(self, verbose):
        """ Configure logging level """
        log_level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=log_level, format=log_format)

    def get_session_with_retries(self):
        """ Retry configuration for network requests """
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        return session

    def vulnerability_scan(self, url, session):
        """ Run all vulnerability checks """
        vulnerabilities = []

        # Placeholder vulnerability check functions
        check_functions = [
            self.check_broken_access_control,
            self.check_cryptographic_failures,
            self.check_sql_injection,
            self.check_command_injection,
            self.check_insecure_design,
            self.check_security_misconfiguration,
            self.check_outdated_components,
            self.check_authentication_failures,
            self.check_data_integrity,
            self.check_logging,
            self.check_ssrf,
            self.check_http_headers
        ]

        # Run each check in a separate thread
        threads = []
        for check_func in check_functions:
            thread = threading.Thread(target=self.run_check, args=(check_func, url, session, vulnerabilities))
            threads.append(thread)
            thread.start()

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        return vulnerabilities

    def run_check(self, check_func, url, session, vulnerabilities):
        """ Run a vulnerability check and store the result """
        result = check_func(url, session)
        vulnerabilities.append(result)
        self.log_message(f"\n[{result['check_name']}] {result['details']}")

    # Define placeholder vulnerability check functions
    def check_broken_access_control(self, url, session):
        logger.info(f"\n[Broken Access Control Check] Testing {url} for access control issues...")
        try:
            response = session.get(url + "/admin", timeout=10)
            if response.status_code == 200:
                return {"check_name": "Broken Access Control", "result": "Vulnerable", "details": f"Access control issue detected on {url}/admin"}
            else:
                return {"check_name": "Broken Access Control", "result": "Safe", "details": "Access control seems intact."}
        except Exception as e:
            logger.error(f"[Broken Access Control Check] Error: {e}")
            return {"check_name": "Broken Access Control", "result": "Error", "details": f"Error: {e}"}


    def check_cryptographic_failures(self, url, session):
        logger.info(f"\n[Cryptographic Failures Check] Testing {url} for cryptographic issues...")
        if not url.startswith("https://"):
            return {"check_name": "Cryptographic Failures", "result": "Vulnerable", "details": "Website does not use HTTPS for secure communication."}
        else:
            return {"check_name": "Cryptographic Failures", "result": "Safe", "details": "Website is using HTTPS for secure communication."}

    def check_sql_injection(self, url, session):
        logger.info(f"\n[SQL Injection Check] Testing {url} for SQL Injection vulnerabilities...")
        try:
            response = session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')

                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        payload = "' OR 1=1 --"
                        full_url = urljoin(url, action) if action else url
                        if method == 'get':
                            vulnerable_url = f"{full_url}?{name}={payload}"
                        else:
                            vulnerable_url = full_url
                        response = session.get(vulnerable_url, timeout=10)
                        if "error" in response.text or "syntax" in response.text or "mysql" in response.text:
                            return {"check_name": "SQL Injection", "result": "Vulnerable", "details": f"SQL Injection detected in input: {name} (URL: {vulnerable_url})"}
            return {"check_name": "SQL Injection", "result": "Safe", "details": "No SQL Injection vulnerabilities detected."}
        except Exception as e:
            logger.error(f"[SQL Injection Check] Error: {e}")
            return {"check_name": "SQL Injection", "result": "Error", "details": f"Error: {e}"}

    def check_command_injection(self, url, session):
        logger.info(f"\n[Command Injection Check] Testing {url} for Command Injection...")
        try:
            payload = "; ls"
            vulnerable_url = f"{url}{payload}"
            response = session.get(vulnerable_url, timeout=10)

            if "bin" in response.text or "ls" in response.text:
                return {"check_name": "Command Injection", "result": "Vulnerable", "details": f"Command Injection detected (URL: {vulnerable_url})"}
            else:
                return {"check_name": "Command Injection", "result": "Safe", "details": "No Command Injection vulnerabilities detected."}
        except Exception as e:
            logger.error(f"[Command Injection Check] Error: {e}")
            return {"check_name": "Command Injection", "result": "Error", "details": f"Error: {e}"}

    def check_insecure_design(self, url, session):
        logger.info(f"\n[Insecure Design Check] Testing {url} for insecure design...")
        try:
            response = session.get(url, timeout=10)
            if "login" in response.text.lower():
                return {"check_name": "Insecure Design", "result": "Vulnerable", "details": f"Session management or login might be insecure on {url}."}
            else:
                return {"check_name": "Insecure Design", "result": "Safe", "details": "No design vulnerabilities detected."}
        except Exception as e:
            logger.error(f"[Insecure Design Check] Error: {e}")
            return {"check_name": "Insecure Design", "result": "Error", "details": f"Error: {e}"}

    def check_security_misconfiguration(self, url, session):
        logger.info(f"\n[Security Misconfiguration Check] Testing {url} for misconfigurations...")
        return self.check_http_headers(url, session)  # Use self to call the method
    
    def check_http_headers(self, url, session):
        logger.info(f"\n[HTTP Headers Check] Testing {url} for missing security headers...")
        try:
            response = session.get(url, timeout=10)
            critical_headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-XSS-Protection', 'Content-Security-Policy']
            
            vulnerabilities = []
            for header in critical_headers:
                if header not in response.headers:
                    vulnerabilities.append(f"Missing {header} header.")
                else:
                    logger.info(f"  [SAFE] {header} header is present.")
                    
            if vulnerabilities:
                return {"check_name": "HTTP Headers", "result": "Vulnerable", "details": "\n".join(vulnerabilities)}
            else:
                return {"check_name": "HTTP Headers", "result": "Safe", "details": "No missing security headers."}
        except TimeoutError:
            logger.error(f"[HTTP Headers Check] Timeout error when testing {url}.")
            return {"check_name": "HTTP Headers", "result": "Error", "details": f"Timeout error when testing {url}."}
        except Exception as e:
            logger.error(f"[HTTP Headers Check] Error: {e}")
            return {"check_name": "HTTP Headers", "result": "Error", "details": f"Error: {e}"}
    
    def check_outdated_components(self, url, session):
        logger.info(f"\n[Vulnerable and Outdated Components Check] Testing {url} for outdated components...")
        response = session.get(url, timeout=10)
        if "X-Powered-By" in response.headers:
            return {"check_name": "Outdated Components", "result": "Vulnerable", "details": f"Outdated components detected by X-Powered-By header (URL: {url})"}
        else:
            return {"check_name": "Outdated Components", "result": "Safe", "details": "No vulnerable components detected."}

    def check_authentication_failures(self, url, session):
        logger.info(f"\n[Authentication Failures Check] Testing {url} for authentication weaknesses...")
        response = session.get(url + "/login", timeout=10)
        if "password" in response.text.lower():
            return {"check_name": "Authentication Failures", "result": "Vulnerable", "details": f"Weak or missing authentication checks on {url}/login"}
        else:
            return {"check_name": "Authentication Failures", "result": "Safe", "details": "Authentication mechanism seems secure."}

    def check_data_integrity(self, url, session):
        logger.info(f"\n[Software and Data Integrity Check] Testing {url} for data integrity failures...")
        return {"check_name": "Data Integrity", "result": "Info", "details": "Data integrity check requires deeper analysis."}

    def check_logging(self, url, session):
        logger.info(f"\n[Security Logging Check] Testing {url} for logging and monitoring failures...")
        response = session.get(url, timeout=10)
        if "error" in response.text:
            return {"check_name": "Logging Failures", "result": "Vulnerable", "details": f"Possible missing logging for errors on {url}."}
        else:
            return {"check_name": "Logging Failures", "result": "Safe", "details": "Logging appears to be configured."}

    def check_ssrf(self, url, session):
        logger.info(f"\n[SSRF Check] Testing {url} for SSRF vulnerabilities...")
        
        # Define a list of potential internal resources or metadata services to test
        test_urls = [
            "http://localhost:8080",  # Localhost test (can be blocked in production)
            "http://127.0.0.1:8080",  # Local IP test
            "http://169.254.169.254/latest/meta-data",  # AWS Metadata service endpoint (targeted by SSRF)
            "http://metadata.google.internal",  # Google Cloud Metadata service (targeted by SSRF)
            "http://localhost",  # General localhost test
            "http://0.0.0.0",  # Testing the all-zero IP, often associated with SSRF
            "http://example.com"  # External test to see if SSRF is generally allowed
        ]
        
        # Loop over each URL and test for SSRF vulnerabilities
        for payload_url in test_urls:
            try:
                # Build the URL with the payload query string
                test_payload = f"{url}/test?url={payload_url}"
                response = session.get(test_payload, timeout=10)
                
                # Check if the response status is 200
                if response.status_code == 200:
                    logger.info(f"SSRF vulnerability detected with payload: {payload_url}")
                    return {
                        "check_name": "SSRF",
                        "result": "Vulnerable",
                        "details": f"SSRF vulnerability detected via payload URL: {payload_url} (Status: {response.status_code})"
                    }
                else:
                    logger.info(f"No SSRF vulnerability found with payload: {payload_url} (Status: {response.status_code})")
            except requests.exceptions.Timeout:
                logger.error(f"[SSRF Check] Timeout when testing {payload_url}")
                return {"check_name": "SSRF", "result": "Error", "details": "Timeout occurred during SSRF check."}
            except requests.RequestException as e:
                logger.error(f"[SSRF Check] Error when testing {payload_url}: {e}")
                return {"check_name": "SSRF", "result": "Error", "details": f"Error: {e}"}
        
        # If no vulnerabilities were found, return Safe
        logger.info("No SSRF vulnerabilities detected.")
        return {
            "check_name": "SSRF",
            "result": "Safe",
            "details": "No SSRF vulnerability detected."
        }
    
    def check_http_headers(self, url, session):
        logger.info(f"\n[HTTP Headers Check] Testing {url} for missing security headers...")
        try:
            response = session.get(url, timeout=10)
            critical_headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-XSS-Protection', 'Content-Security-Policy']
            
            vulnerabilities = []
            for header in critical_headers:
                if header not in response.headers:
                    vulnerabilities.append(f"Missing {header} header.")
                else:
                    logger.info(f"  [SAFE] {header} header is present.")
                    
            if vulnerabilities:
                return {"check_name": "HTTP Headers", "result": "Vulnerable", "details": "\n".join(vulnerabilities)}
            else:
                return {"check_name": "HTTP Headers", "result": "Safe", "details": "No missing security headers."}
        except Exception as e:
            logger.error(f"[HTTP Headers Check] Error: {e}")
            return {"check_name": "HTTP Headers", "result": "Error", "details": f"Error: {e}"}


    def generate_pdf_report(self, vulnerabilities, target, report_path):
        """ Generate PDF report with vulnerabilities """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Vulnerability Assessment Report", ln=True, align="C")
        pdf.set_font("Arial", style='B', size=14)
        pdf.cell(200, 10, txt=f"Target: {target}", ln=True, align="C")
        pdf.ln(5)

        for vulnerability in vulnerabilities:
            pdf.ln(5)
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(200, 10, txt=f"Vulnerability: {vulnerability['check_name']}", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=f"Result: {vulnerability['result']}\nDetails: {vulnerability['details']}\n")

        try:
            pdf.output(report_path)
            self.log_message(f"PDF report generated at: {report_path}")
        except Exception as e:
            self.log_message(f"Error generating PDF: {e}")

# Create the Tkinter window and run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()