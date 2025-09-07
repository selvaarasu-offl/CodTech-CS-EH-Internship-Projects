Web Vulnerability Scanner
Lightweight Python tool to scan a website for reflected XSS and basic SQL injection vulnerabilities.

Features
Crawl target URL and same-domain links up to specified depth
Detect reflected XSS and basic SQLi in forms and query parameters

Requirements
Python 3.6 or higher
requests and beautifulsoup4 libraries (pip install requests beautifulsoup4)

Usage
python web_vuln_scanner.py --url https://example.com --depth 1

Example Output
[+] Scanning https://example.com
  form: POST https://example.com/login.php fields: ['username', 'password']
    --> reflected XSS likely (payload reflected)
=== Findings ===
XSS https://example.com/login.php {'username': '<sCript>alert(1)</sCript>', 'password': '<sCript>alert(1)</sCript>'}
