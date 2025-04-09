import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor
import sys
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3, report_json="report.json"):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.report_json = report_json

    def normalize_url(self, url: str):
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0):
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url):
                    self.crawl(next_url, depth + 1)

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str):
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, verify=False)

                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)

                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=False)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })

            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str):
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        }
        try:
            response = self.session.get(url, verify=False)

            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type': 'Sensitive Information Exposure',
                        'url': url,
                        'info_type': info_type,
                        'pattern': pattern
                    })

        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def scan(self):
        print(f"\nStarting security scan of {self.target_url}\n")
        self.crawl(self.target_url)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)

        print(f"\nScan Complete!\nTotal URLs scanned: {len(self.visited_urls)}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")

        self.save_report()

    def report_vulnerability(self, vulnerability):
        self.vulnerabilities.append(vulnerability)
        print(f"[VULNERABILITY FOUND] {vulnerability}")

    def save_report(self):
        report_data = {
            "target_url": self.target_url,
            "total_urls": len(self.visited_urls),
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(self.report_json, "w") as file:
            json.dump(report_data, file, indent=4)
        print(f"Report saved to {self.report_json}")

if __name__ == "__main__":
    target_url = sys.argv[1]
    report_json = sys.argv[2] if len(sys.argv) > 2 else "report.json"
    scanner = WebSecurityScanner(target_url, report_json=report_json)
    scanner.scan()
