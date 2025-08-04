import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult
import re
import json

# Common security headers to check
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

# Basic XSS test payload
XSS_TEST_PAYLOAD = "<script>alert(1)</script>"

# Common open redirect parameter names
REDIRECT_PARAMS = [
    "url", "redirect", "next", "dest", "destination", "redir", "continue", "return"
]

def check_security_headers(headers):
    missing = []
    for header in SECURITY_HEADERS:
        if header not in headers:
            missing.append(header)
    return missing

def check_insecure_cookies(cookies):
    issues = []
    for cookie in cookies:
        flags = []
        # HttpOnly and Secure are boolean attributes on cookie objects
        if not getattr(cookie, "httponly", False):
            flags.append("HttpOnly missing")
        if not getattr(cookie, "secure", False):
            flags.append("Secure missing")
        if flags:
            issues.append(f"{cookie.name}: {', '.join(flags)}")
    return issues


def test_xss(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        return False, "No GET parameters to test for XSS"
    vulnerable_params = []
    for param in query:
        original_values = query[param]
        # Inject payload into each value
        for val in original_values:
            query[param] = [XSS_TEST_PAYLOAD]
            new_query = urlencode(query, doseq=True)
            test_url = urlunparse(ParseResult(
                scheme=parsed.scheme,
                netloc=parsed.netloc,
                path=parsed.path,
                params=parsed.params,
                query=new_query,
                fragment=parsed.fragment
            ))
            try:
                resp = requests.get(test_url, timeout=10)
                if XSS_TEST_PAYLOAD in resp.text:
                    vulnerable_params.append(param)
                    break
            except Exception:
                pass
        query[param] = original_values  # restore original
    if vulnerable_params:
        return True, vulnerable_params
    else:
        return False, []

def test_open_redirect(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    vulnerable_params = []
    for param in REDIRECT_PARAMS:
        if param in query:
            # Inject a known external URL
            query[param] = ["http://evil.com"]
            new_query = urlencode(query, doseq=True)
            test_url = urlunparse(ParseResult(
                scheme=parsed.scheme,
                netloc=parsed.netloc,
                path=parsed.path,
                params=parsed.params,
                query=new_query,
                fragment=parsed.fragment
            ))
            try:
                resp = requests.get(test_url, allow_redirects=False, timeout=10)
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulnerable_params.append(param)
            except Exception:
                pass
    if vulnerable_params:
        return True, vulnerable_params
    else:
        return False, []

def scan_url(url):
    report = {
        "url": url,
        "missing_security_headers": [],
        "insecure_cookies": [],
        "xss_vulnerable_params": [],
        "open_redirect_vulnerable_params": [],
        "recommendations": []
    }

    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        print(f"Error fetching URL: {e}")
        return None

    headers = {k.title(): v for k, v in resp.headers.items()}
    missing_headers = check_security_headers(headers)
    if missing_headers:
        report["missing_security_headers"] = missing_headers
        for h in missing_headers:
            if h == "Content-Security-Policy":
                report["recommendations"].append("Add Content-Security-Policy header to mitigate XSS and data injection attacks.")
            elif h == "X-Content-Type-Options":
                report["recommendations"].append("Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing.")
            elif h == "X-Frame-Options":
                report["recommendations"].append("Add X-Frame-Options header to prevent clickjacking.")
            elif h == "Strict-Transport-Security":
                report["recommendations"].append("Add Strict-Transport-Security header to enforce HTTPS.")
            elif h == "Referrer-Policy":
                report["recommendations"].append("Add Referrer-Policy header to control referrer information.")
            elif h == "Permissions-Policy":
                report["recommendations"].append("Add Permissions-Policy header to control browser features.")

    cookies = resp.cookies
    insecure_cookies = check_insecure_cookies(cookies)
    if insecure_cookies:
        report["insecure_cookies"] = insecure_cookies
        report["recommendations"].append("Set HttpOnly and Secure flags on cookies to improve security.")

    xss_found, xss_params = test_xss(url)
    if xss_found:
        report["xss_vulnerable_params"] = xss_params
        report["recommendations"].append("Sanitize and validate user input to prevent XSS vulnerabilities.")

    open_redirect_found, open_redirect_params = test_open_redirect(url)
    if open_redirect_found:
        report["open_redirect_vulnerable_params"] = open_redirect_params
        report["recommendations"].append("Validate and restrict redirect URLs to prevent open redirect vulnerabilities.")

    return report

def print_report(report):
    if not report:
        print("No report generated.")
        return
    print(f"Scan Report for: {report['url']}\n")
    if report["missing_security_headers"]:
        print("Missing Security Headers:")
        for h in report["missing_security_headers"]:
            print(f" - {h}")
    else:
        print("All common security headers are present.")

    if report["insecure_cookies"]:
        print("\nInsecure Cookies:")
        for c in report["insecure_cookies"]:
            print(f" - {c}")
    else:
        print("\nNo insecure cookies detected.")

    if report["xss_vulnerable_params"]:
        print("\nPotential XSS Vulnerabilities in parameters:")
        for p in report["xss_vulnerable_params"]:
            print(f" - {p}")
    else:
        print("\nNo XSS vulnerabilities detected.")

    if report["open_redirect_vulnerable_params"]:
        print("\nPotential Open Redirect Vulnerabilities in parameters:")
        for p in report["open_redirect_vulnerable_params"]:
            print(f" - {p}")
    else:
        print("\nNo open redirect vulnerabilities detected.")

    if report["recommendations"]:
        print("\nRecommendations:")
        for r in report["recommendations"]:
            print(f" - {r}")
    else:
        print("\nNo recommendations. The target looks secure for the tested items.")

def save_report(report, filename):
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\nReport saved to {filename}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner MVP")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-o", "--output", help="Save report to JSON file")
    args = parser.parse_args()

    report = scan_url(args.url)
    print_report(report)
    if args.output and report:
        save_report(report, args.output)

if __name__ == "__main__":
    main()
