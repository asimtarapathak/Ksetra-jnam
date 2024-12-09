import requests
from bs4 import BeautifulSoup
import socket
import ssl
from urllib.parse import urlparse, urljoin
import re
import threading
import logging
import argparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from fpdf import FPDF
from colorama import Fore, Back, Style

# Configure logging
logger = logging.getLogger()
log_format = '%(message)s'  # No date/time

# Function to configure logging based on verbosity
def configure_logging(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format=log_format)

# Retry configuration for network requests
def get_session_with_retries():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# Function to validate URL format
def validate_url(url):
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        try:
            socket.inet_aton(url)
            return True
        except socket.error:
            return False
    return bool(parsed_url.scheme) and bool(parsed_url.netloc)

# Function to generate PDF report with vulnerabilities
def generate_pdf_report(vulnerabilities, target):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Vulnerability Assessment Report", ln=True, align="C")
    
    # Add target/domain to the report
    pdf.set_font("Arial", style='B', size=14)
    pdf.cell(200, 10, txt=f"Target: {target}", ln=True, align="C")
    pdf.ln(5)
    
    # Iterate over vulnerabilities and add them to the PDF
    for vulnerability in vulnerabilities:
        pdf.ln(5)  # Add a small line break
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(200, 10, txt=f"Vulnerability: {vulnerability['check_name']}", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt=f"Result: {vulnerability['result']}\nDetails: {vulnerability['details']}\n")
    
    pdf.output("vulnerability_report.pdf")
    print(Fore.BLACK+Back.BLUE)
    logger.info("Report generated: vulnerability_report.pdf")
    print(Style.RESET_ALL)

# Vulnerability Check Functions (return structured data)

def check_broken_access_control(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Broken Access Control Check] Testing {url} for access control issues...")
    print(Style.RESET_ALL)
    try:
        response = session.get(url + "/admin", timeout=10)
        if response.status_code == 200:
            return {"check_name": "Broken Access Control", "result": "Vulnerable", "details": f"Access control issue detected on {url}/admin"}
        else:
            return {"check_name": "Broken Access Control", "result": "Safe", "details": "Access control seems intact."}
    except Exception as e:
        print(Fore.BLACK+Back.GREEN)
        logger.error(f"[Broken Access Control Check] Error: {e}")
        print(Style.RESET_ALL)
        return {"check_name": "Broken Access Control", "result": "Error", "details": f"Error: {e}"}

def check_cryptographic_failures(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Cryptographic Failures Check] Testing {url} for cryptographic issues...")
    print(Style.RESET_ALL)
    if not url.startswith("https://"):
        return {"check_name": "Cryptographic Failures", "result": "Vulnerable", "details": "Website does not use HTTPS for secure communication."}
    else:
        return {"check_name": "Cryptographic Failures", "result": "Safe", "details": "Website is using HTTPS for secure communication."}

def check_sql_injection(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[SQL Injection Check] Testing {url} for SQL Injection vulnerabilities...")
    print(Style.RESET_ALL)
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
        print(Fore.BLACK+Back.GREEN)
        logger.error(f"[SQL Injection Check] Error: {e}")
        print(Style.RESET_ALL)
        return {"check_name": "SQL Injection", "result": "Error", "details": f"Error: {e}"}

def check_command_injection(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Command Injection Check] Testing {url} for Command Injection...")
    print(Style.RESET_ALL)
    try:
        payload = "; ls"
        vulnerable_url = f"{url}{payload}"
        response = session.get(vulnerable_url, timeout=10)

        if "bin" in response.text or "ls" in response.text:
            return {"check_name": "Command Injection", "result": "Vulnerable", "details": f"Command Injection detected (URL: {vulnerable_url})"}
        else:
            return {"check_name": "Command Injection", "result": "Safe", "details": "No Command Injection vulnerabilities detected."}
    except Exception as e:
        print(Fore.BLACK+Back.GREEN)
        logger.error(f"[Command Injection Check] Error: {e}")
        print(Style.RESET_ALL)
        return {"check_name": "Command Injection", "result": "Error", "details": f"Error: {e}"}

def check_insecure_design(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Insecure Design Check] Testing {url} for insecure design...")
    print(Style.RESET_ALL)
    try:
        response = session.get(url, timeout=10)
        if "login" in response.text.lower():
            return {"check_name": "Insecure Design", "result": "Vulnerable", "details": f"Session management or login might be insecure on {url}."}
        else:
            return {"check_name": "Insecure Design", "result": "Safe", "details": "No design vulnerabilities detected."}
    except Exception as e:
        print(Fore.BLACK+Back.GREEN)
        logger.error(f"[Insecure Design Check] Error: {e}")
        print(Style.RESET_ALL)
        return {"check_name": "Insecure Design", "result": "Error", "details": f"Error: {e}"}

def check_security_misconfiguration(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Security Misconfiguration Check] Testing {url} for misconfigurations...")
    print(Style.RESET_ALL)
    return check_http_headers(url, session)

def check_outdated_components(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Vulnerable and Outdated Components Check] Testing {url} for outdated components...")
    print(Style.RESET_ALL)
    response = session.get(url, timeout=10)
    if "X-Powered-By" in response.headers:
        return {"check_name": "Outdated Components", "result": "Vulnerable", "details": f"Outdated components detected by X-Powered-By header (URL: {url})"}
    else:
        return {"check_name": "Outdated Components", "result": "Safe", "details": "No vulnerable components detected."}

def check_authentication_failures(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Authentication Failures Check] Testing {url} for authentication weaknesses...")
    print(Style.RESET_ALL)
    response = session.get(url + "/login", timeout=10)
    if "password" in response.text.lower():
        return {"check_name": "Authentication Failures", "result": "Vulnerable", "details": f"Weak or missing authentication checks on {url}/login"}
    else:
        return {"check_name": "Authentication Failures", "result": "Safe", "details": "Authentication mechanism seems secure."}

def check_data_integrity(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Software and Data Integrity Check] Testing {url} for data integrity failures...")
    print(Style.RESET_ALL)
    return {"check_name": "Data Integrity", "result": "Info", "details": "Data integrity check requires deeper analysis."}

def check_logging(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[Security Logging Check] Testing {url} for logging and monitoring failures...")
    print(Style.RESET_ALL)
    response = session.get(url, timeout=10)
    if "error" in response.text:
        return {"check_name": "Logging Failures", "result": "Vulnerable", "details": f"Possible missing logging for errors on {url}."}
    else:
        return {"check_name": "Logging Failures", "result": "Safe", "details": "Logging appears to be configured."}


def check_ssrf(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[SSRF Check] Testing {url} for SSRF vulnerabilities...")
    print(Style.RESET_ALL)
    
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
                print(Fore.BLACK+Back.GREEN)
                logger.info(f"SSRF vulnerability detected with payload: {payload_url}")
                print(Style.RESET_ALL)
                return {
                    "check_name": "SSRF",
                    "result": "Vulnerable",
                    "details": f"SSRF vulnerability detected via payload URL: {payload_url} (Status: {response.status_code})"
                }
            else:
                print(Fore.BLACK+Back.GREEN)
                logger.info(f"No SSRF vulnerability found with payload: {payload_url} (Status: {response.status_code})")
                print(Style.RESET_ALL)
        except requests.exceptions.Timeout:
            print(Fore.BLACK+Back.GREEN)
            logger.error(f"[SSRF Check] Timeout when testing {payload_url}")
            print(Style.RESET_ALL)
            return {"check_name": "SSRF", "result": "Error", "details": "Timeout occurred during SSRF check."}
        except requests.RequestException as e:
            print(Fore.BLACK+Back.GREEN)
            logger.error(f"[SSRF Check] Error when testing {payload_url}: {e}")
            print(Style.RESET_ALL)
            return {"check_name": "SSRF", "result": "Error", "details": f"Error: {e}"}
    
    # If no vulnerabilities were found, return Safe
    logger.info("No SSRF vulnerabilities detected.")
    return {
        "check_name": "SSRF",
        "result": "Safe",
        "details": "No SSRF vulnerability detected."
    }

# Missing HTTP Security Headers (check for headers)
def check_http_headers(url, session):
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"\n[HTTP Headers Check] Testing {url} for missing security headers...")
    print(Style.RESET_ALL)
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

# Function to run all vulnerability checks in parallel
def vulnerability_scan(url, verbose, advanced):
    configure_logging(verbose)
    print(Fore.BLACK+Back.GREEN)
    logger.info(f"[+] Running vulnerability scan on: {url}")
    print(Style.RESET_ALL)
    session = get_session_with_retries()

    vulnerabilities = []

    def scan_check(check_func):
        result = check_func(url, session)
        if result:
            vulnerabilities.append(result)

    # List of all vulnerability checks
    check_functions = [
        check_broken_access_control,
        check_cryptographic_failures,
        check_sql_injection,
        check_command_injection,
        check_insecure_design,
        check_security_misconfiguration,
        check_outdated_components,
        check_authentication_failures,
        check_data_integrity,
        check_logging,
        check_ssrf,
        check_http_headers
    ]

    threads = []
    for check_func in check_functions:
        thread = threading.Thread(target=scan_check, args=(check_func,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Optionally generate report
    if advanced.get('report'):
        generate_pdf_report(vulnerabilities, url)

# Validate and run the scan
def run_scan(target, verbose, advanced):
    if not validate_url(target):
        print(Fore.BLACK+Back.YELLOW)
        logger.error(f"Error: Invalid URL format - {target}")
        print(Style.RESET_ALL)
        return

    logger.info(f"Scanning {target}...")
    vulnerability_scan(target, verbose, advanced)

def welcome_screen():
    print(Fore.GREEN)
    print("""
██╗  ██╗███████╗███████╗████████╗██████╗  █████╗            ██╗███╗   ██╗ █████╗ ███╗   ███╗
██║ ██╔╝██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗           ██║████╗  ██║██╔══██╗████╗ ████║
█████╔╝ ███████╗█████╗     ██║   ██████╔╝███████║█████╗     ██║██╔██╗ ██║███████║██╔████╔██║
██╔═██╗ ╚════██║██╔══╝     ██║   ██╔══██╗██╔══██║╚════╝██   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║
██║  ██╗███████║███████╗   ██║   ██║  ██║██║  ██║      ╚█████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝       ╚════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝    """)
    print(Style.RESET_ALL)
    print(Fore.GREEN+Back.WHITE+""" By: Asim Tara Pathak | Kṣetra-jñam (the knower of the field) is a web application vulnerability scanner that uses both 
    GUI and CLI interfaces to detect and report on the OWASP Top 10 vulnerabilities. With multiple scanning algorithms 
    and customizable reporting, it helps developers and security teams identify and address critical security risks.\n\n"""+Style.RESET_ALL)

# Main script entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=welcome_screen())
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logs")
    parser.add_argument("-r", "--report", action="store_true", help="Generate a PDF report")
    parser.add_argument("-a", "--advanced", action="store_true", help="Enable advanced vulnerability checks")
    
    args = parser.parse_args()
    advanced_options = {'report': args.report, 'advanced': args.advanced}
    run_scan(args.url, args.verbose, advanced_options)