import argparse, time, re, urllib.parse
import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()  # ignore self-signed cert warnings

XSS_PAYLOAD = "<sCript>alert(1)</sCript>"
SQLI_TESTS = ["' OR '1'='1", "' OR '1'='1' -- ", "\" OR \"1\"=\"1"]
HEADERS = {"User-Agent": "MiniVulnScanner/1.0 (+research)"}

def get_links(html, base):
    soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for a in soup.find_all("a", href=True):
        u = urllib.parse.urljoin(base, a["href"])
        if u.startswith(base):
            urls.add(u.split("#")[0])
    return urls

def find_forms(html, base):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or base
        method = (f.get("method") or "get").lower()
        inputs = []
        for inp in f.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append(name)
        forms.append({
            "action": urllib.parse.urljoin(base, action),
            "method": method,
            "inputs": inputs
        })
    return forms

def test_xss_in_response(resp_text):
    print("    [DEBUG] Checking for XSS payload in response...")
    return XSS_PAYLOAD in resp_text

def test_sqli_reflection(resp_text):
    print("    [DEBUG] Checking for SQL errors in response...")
    errors = ["SQL syntax", "mysql_fetch", "ORA-00933", "syntax error", "unclosed quotation mark"]
    return any(e.lower() in resp_text.lower() for e in errors)

def scan_page(url):
    print(f"[+] Scanning {url}")
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
    except Exception as e:
        print("  [ERROR] request failed:", e)
        return []
    
    out = []
    forms = find_forms(r.text, url)

    for f in forms:
        print("  [FORM]", f["method"].upper(), f["action"], "fields:", f["inputs"])
        for payload in [XSS_PAYLOAD] + SQLI_TESTS:
            data = {k: payload for k in f["inputs"]}
            try:
                if f["method"] == "post":
                    resp = requests.post(f["action"], data=data, headers=HEADERS, timeout=10, verify=False)
                else:
                    resp = requests.get(f["action"], params=data, headers=HEADERS, timeout=10, verify=False)
            except Exception as e:
                print("    [ERROR] form submission failed:", e)
                continue

            print(f"    [DEBUG] Sent payload: {payload}")
            if payload == XSS_PAYLOAD and test_xss_in_response(resp.text):
                out.append(("xss", f["action"], data))
                print("    [!!!] Reflected XSS likely (payload reflected)")
            if payload in SQLI_TESTS and test_sqli_reflection(resp.text):
                out.append(("sqli", f["action"], data))
                print("    [!!!] Possible SQLi (SQL error in response)")

    # Query parameter tests
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    if qs:
        for payload in [XSS_PAYLOAD] + SQLI_TESTS:
            qs2 = {k: payload for k in qs.keys()}
            u = parsed._replace(query=urllib.parse.urlencode(qs2, doseq=True)).geturl()
            try:
                resp = requests.get(u, headers=HEADERS, timeout=10, verify=False)
            except Exception as e:
                print("    [ERROR] query param test failed:", e)
                continue

            print(f"    [DEBUG] Testing URL with payload: {u}")
            if payload == XSS_PAYLOAD and test_xss_in_response(resp.text):
                out.append(("xss", u, qs2))
                print("    [!!!] Reflected XSS via query params")
            if payload in SQLI_TESTS and test_sqli_reflection(resp.text):
                out.append(("sqli", u, qs2))
                print("    [!!!] Possible SQLi via query params")
    return out

def crawl_and_scan(start_url, max_depth=1, throttle=0.5):
    visited = set()
    to_visit = [(start_url, 0)]
    findings = []
    while to_visit:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = requests.get(url, headers=HEADERS, timeout=10, verify=False)
        except Exception as e:
            print("  [ERROR] crawling failed:", e)
            continue
        findings.extend(scan_page(url))
        links = get_links(r.text, urllib.parse.urljoin(url, "/"))
        for L in links:
            if L not in visited:
                to_visit.append((L, depth + 1))
        time.sleep(throttle)
    return findings

def main():
    ap = argparse.ArgumentParser(description="Mini web vuln scanner: reflected XSS & basic SQLi checks")
    ap.add_argument("--url", required=True, help="Target URL (e.g., http://localhost/DVWA)")
    ap.add_argument("--depth", type=int, default=0, help="Link crawl depth (default: 0)")
    ap.add_argument("--throttle", type=float, default=0.3, help="Throttle between requests (default: 0.3s)")
    args = ap.parse_args()

    print("\n** Legal reminder: Only scan targets you own or have permission to test **\n")
    findings = crawl_and_scan(args.url, max_depth=args.depth, throttle=args.throttle)

    print("\n=== Findings ===")
    if not findings:
        print("No issues found (basic checks).")
    else:
        for typ, target, details in findings:
            print(f"{typ.upper()} {target} {details}")

if __name__ == "__main__":
    main()
