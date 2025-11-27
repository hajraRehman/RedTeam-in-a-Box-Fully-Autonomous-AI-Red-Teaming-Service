"""
Advanced Web Vulnerability Scanner with ML-based Detection
Features:
- Intelligent deduplication
- Severity scoring
- Attack vector prioritization  
- Response pattern analysis
- Automated exploit generation
- Confidence scoring
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import time
import re
from typing import Set, Dict, List
from collections import deque
import hashlib
from datetime import datetime


class AdvancedVulnerabilityScanner:
    """
    Advanced vulnerability scanner with intelligent deduplication and severity scoring
    """
    
    # Severity levels
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    # Vulnerability categories with CVSS-like scoring
    VULN_SEVERITY = {
        "SQL Injection": (CRITICAL, 9.8),
        "Command Injection": (CRITICAL, 9.8),
        "Path Traversal": (HIGH, 7.5),
        "XSS (Cross-Site Scripting)": (HIGH, 7.3),
        "Blind SQL Injection": (HIGH, 8.1),
        "XXE (XML External Entity)": (HIGH, 8.6),
        "SSRF (Server-Side Request Forgery)": (HIGH, 8.5),
        "SSTI (Server-Side Template Injection)": (CRITICAL, 9.0),
        "NoSQL Injection": (HIGH, 8.2),
        "LDAP Injection": (HIGH, 7.8),
        "LFI (Local File Inclusion)": (HIGH, 8.3),
        "Open Redirect": (MEDIUM, 6.1),
        "CSRF (Cross-Site Request Forgery)": (MEDIUM, 6.5),
        "IDOR (Insecure Direct Object Reference)": (MEDIUM, 5.3),
        "Weak Credentials": (HIGH, 7.5),
        "Sensitive File Exposure": (MEDIUM, 6.5)
    }
    
    def __init__(self, root_url: str, max_depth: int = 5, payloads_file: str = "payloads.json", 
                 history_file: str = "scan_history.txt"):
        self.root_url = root_url.rstrip('/')
        self.max_depth = max_depth
        self.history_file = history_file
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.vulnerability_signatures: Set[str] = set()  # For deduplication
        self.payloads = self._load_payloads(payloads_file)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner) AdvancedScanner/2.0'
        })
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'forms_tested': 0,
            'parameters_tested': 0,
            'requests_sent': 0,
            'errors_encountered': 0
        }
    
    def _load_payloads(self, filename: str) -> Dict:
        """Load attack payloads from JSON file"""
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"⚠️  Payloads file {filename} not found, using defaults")
            return self._get_default_payloads()
    
    def _get_default_payloads(self) -> Dict:
        """Minimal default payloads"""
        return {
            "SQL": ["' OR '1'='1", "admin' --"],
            "XSS": ["<script>alert('XSS')</script>"],
            "COMMAND_INJECTION": ["; ls", "| whoami"],
            "PATH_TRAVERSAL": ["../../../etc/passwd"]
        }
    
    def _generate_signature(self, vuln_type: str, url: str, method: str, param: str) -> str:
        """Generate unique signature for vulnerability deduplication"""
        # Normalize URL (remove query params for signature)
        parsed = urlparse(url)
        normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Create signature
        sig_string = f"{vuln_type}|{normalized_url}|{method.upper()}|{param}"
        return hashlib.md5(sig_string.encode()).hexdigest()
    
    def _add_vulnerability(self, vuln_type: str, url: str, method: str, param: str, 
                          payload: str, evidence: str, response_snippet: str = "",
                          confidence: float = 1.0):
        """
        Add vulnerability with intelligent deduplication and severity scoring
        
        Args:
            vuln_type: Type of vulnerability
            url: Target URL
            method: HTTP method
            param: Vulnerable parameter
            payload: Attack payload used
            evidence: Evidence of vulnerability
            response_snippet: Relevant response content
            confidence: Confidence score (0.0-1.0)
        """
        # Generate unique signature
        signature = self._generate_signature(vuln_type, url, method, param)
        
        # Skip if duplicate
        if signature in self.vulnerability_signatures:
            return
        
        # Mark as found
        self.vulnerability_signatures.add(signature)
        
        # Get severity and CVSS score
        severity, cvss_score = self.VULN_SEVERITY.get(vuln_type, (self.MEDIUM, 5.0))
        
        # Generate exploit URL/command
        exploit = self._generate_exploit_url(url, method, param, payload)
        
        # Calculate risk score (CVSS * confidence)
        risk_score = cvss_score * confidence
        
        # Create vulnerability record
        vuln = {
            'id': len(self.vulnerabilities) + 1,
            'category': vuln_type,
            'severity': severity,
            'cvss_score': cvss_score,
            'risk_score': round(risk_score, 2),
            'confidence': round(confidence * 100, 1),
            'url': url,
            'method': method.upper(),
            'parameter': param,
            'payload': payload,
            'evidence': evidence,
            'response_snippet': response_snippet[:200] if response_snippet else "",
            'exploit': exploit,
            'timestamp': datetime.now().isoformat(),
            'signature': signature
        }
        
        self.vulnerabilities.append(vuln)
        
        # Console output with severity color coding
        severity_emoji = {
            self.CRITICAL: "🔴",
            self.HIGH: "🟠", 
            self.MEDIUM: "🟡",
            self.LOW: "🟢",
            self.INFO: "ℹ️"
        }
        emoji = severity_emoji.get(severity, "🚨")
        print(f"        {emoji} [{severity}] {vuln_type} in '{param}' (confidence: {vuln['confidence']}%)")
    
    def _generate_exploit_url(self, url: str, method: str, param: str, payload: str) -> str:
        """Generate exploitable URL or curl command"""
        if method.upper() == 'GET':
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # Escape single quotes in payload for curl
            escaped_payload = payload.replace("'", "'\\''")
            return f"curl -X POST '{url}' -d '{param}={escaped_payload}'"
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain"""
        root_domain = urlparse(self.root_url).netloc
        url_domain = urlparse(url).netloc
        return root_domain == url_domain or url_domain == ''
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicates"""
        parsed = urlparse(url)
        return parsed._replace(fragment='').geturl()
    
    def crawl(self):
        """Main BFS crawling with vulnerability scanning"""
        self.scan_stats['start_time'] = datetime.now()
        queue = deque([(self.root_url, 0)])
        
        print(f"\n🕷️  ADVANCED VULNERABILITY SCANNER v2.0")
        print(f"{'=' * 70}")
        print(f"Target: {self.root_url}")
        print(f"Max Depth: {self.max_depth}")
        print(f"{'=' * 70}\n")
        
        while queue:
            current_url, depth = queue.popleft()
            
            if depth > self.max_depth:
                continue
            
            normalized_url = self._normalize_url(current_url)
            
            if normalized_url in self.visited_urls:
                continue
            
            self.visited_urls.add(normalized_url)
            
            print(f"{'  ' * depth}🔍 [Depth {depth}] {current_url[:80]}...")
            
            try:
                response = self.session.get(current_url, timeout=10, allow_redirects=True)
                self.scan_stats['requests_sent'] += 1
                
                if response.status_code != 200:
                    print(f"{'  ' * depth}⚠️  Status {response.status_code}")
                    continue
                
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Scan for vulnerabilities
                self._intelligent_scan(current_url, soup, response)
                
                # Extract and queue new URLs
                if depth < self.max_depth:
                    new_urls = self._extract_urls(current_url, soup)
                    for new_url in new_urls:
                        queue.append((new_url, depth + 1))
                
                time.sleep(0.5)  # Rate limiting
                
            except requests.exceptions.RequestException as e:
                self.scan_stats['errors_encountered'] += 1
                print(f"{'  ' * depth}❌ Error: {str(e)[:50]}")
                continue
        
        self.scan_stats['end_time'] = datetime.now()
        self._print_summary()
        self._save_results()
    
    def _intelligent_scan(self, url: str, soup: BeautifulSoup, response: requests.Response):
        """Intelligent vulnerability scanning with prioritization"""
        # 1. Scan forms (high priority)
        forms = soup.find_all('form')
        if forms:
            print(f"    📝 Found {len(forms)} form(s)")
            for idx, form in enumerate(forms):
                self.scan_stats['forms_tested'] += 1
                print(f"    🔬 Testing form {idx + 1}/{len(forms)}")
                self._test_form_intelligent(url, form)
        
        # 2. Scan URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            print(f"    🔗 Testing URL parameters")
            self._test_url_parameters_intelligent(url)
        
        # 3. Security headers check
        self._check_security_headers(url, response)
        
        # 4. Check for sensitive files
        self._check_sensitive_files(url)
    
    def _test_form_intelligent(self, page_url: str, form: BeautifulSoup):
        """Intelligently test forms with prioritized payloads"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = urljoin(page_url, action)
        
        # Get all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        
        for input_field in inputs:
            input_name = input_field.get('name')
            input_type = input_field.get('type', 'text')
            
            if not input_name:
                continue
            
            # Set smart default values
            if input_type == 'email':
                form_data[input_name] = 'test@example.com'
            elif input_type == 'password':
                form_data[input_name] = 'password123'
            elif input_type in ['text', 'search', 'tel', 'url']:
                form_data[input_name] = 'test'
            elif input_type == 'number':
                form_data[input_name] = '1'
            elif input_type == 'hidden':
                form_data[input_name] = input_field.get('value', '')
            elif input_field.name == 'textarea':
                form_data[input_name] = 'test'
        
        if not form_data:
            return
        
        # Check if login form
        is_login = self._is_login_form(form)
        if is_login:
            print(f"        🔐 Detected login form")
            self._test_login_bypass_intelligent(form_url, method, form_data)
        
        # Test high-priority vulns first
        self._test_sql_injection_intelligent(form_url, method, form_data)
        self._test_command_injection_intelligent(form_url, method, form_data)
        self._test_xss_intelligent(form_url, method, form_data)
        self._test_path_traversal_intelligent(form_url, method, form_data)
    
    def _test_sql_injection_intelligent(self, url: str, method: str, form_data: Dict):
        """Intelligent SQL injection testing with confidence scoring"""
        for field_name in form_data.keys():
            self.scan_stats['parameters_tested'] += 1
            
            # Skip if already found
            sig = self._generate_signature("SQL Injection", url, method, field_name)
            if sig in self.vulnerability_signatures:
                continue
            
            for payload in self.payloads.get('SQL', [])[:3]:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(url, params=test_data, timeout=10)
                    
                    self.scan_stats['requests_sent'] += 1
                    
                    # Pattern matching with confidence scoring
                    sql_patterns = {
                        'sql syntax': 0.95,
                        'mysql_fetch': 0.90,
                        'postgresql': 0.90,
                        'ora-[0-9]+': 0.95,
                        'sqlite': 0.85,
                        'syntax error': 0.70,
                        'sqlstate': 0.85,
                        'database error': 0.70,
                        'warning: mysql': 0.90,
                        'unclosed quotation mark': 0.85,
                        'quoted string not properly terminated': 0.85
                    }
                    
                    response_lower = response.text.lower()
                    for pattern, confidence in sql_patterns.items():
                        if re.search(pattern, response_lower):
                            # Extract snippet around error
                            match = re.search(f'.{{0,50}}{pattern}.{{0,50}}', response_lower)
                            snippet = match.group(0) if match else ""
                            
                            self._add_vulnerability(
                                'SQL Injection',
                                url,
                                method,
                                field_name,
                                payload,
                                f'SQL error detected: {pattern}',
                                snippet,
                                confidence
                            )
                            return  # Stop after finding vulnerability
                    
                except Exception as e:
                    self.scan_stats['errors_encountered'] += 1
    
    def _test_command_injection_intelligent(self, url: str, method: str, form_data: Dict):
        """Intelligent command injection testing"""
        for field_name in form_data.keys():
            self.scan_stats['parameters_tested'] += 1
            
            sig = self._generate_signature("Command Injection", url, method, field_name)
            if sig in self.vulnerability_signatures:
                continue
            
            for payload in self.payloads.get('COMMAND_INJECTION', [])[:2]:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(url, params=test_data, timeout=10)
                    
                    self.scan_stats['requests_sent'] += 1
                    
                    # Command output patterns with confidence
                    cmd_patterns = {
                        r'root:x:[0-9]+:[0-9]+': 0.95,  # /etc/passwd
                        r'uid=[0-9]+': 0.90,  # id command
                        r'drwx': 0.80,  # ls output
                        r'/home/[\w]+': 0.75,
                        r'total\s+[0-9]+': 0.70,  # ls -l
                        r'bin/bash': 0.85
                    }
                    
                    for pattern, confidence in cmd_patterns.items():
                        if re.search(pattern, response.text):
                            match = re.search(f'.{{0,50}}{pattern}.{{0,50}}', response.text)
                            snippet = match.group(0) if match else ""
                            
                            self._add_vulnerability(
                                'Command Injection',
                                url,
                                method,
                                field_name,
                                payload,
                                f'Command output detected: {pattern}',
                                snippet,
                                confidence
                            )
                            return
                    
                except Exception as e:
                    self.scan_stats['errors_encountered'] += 1
    
    def _test_xss_intelligent(self, url: str, method: str, form_data: Dict):
        """Intelligent XSS testing with context analysis"""
        for field_name in form_data.keys():
            self.scan_stats['parameters_tested'] += 1
            
            sig = self._generate_signature("XSS (Cross-Site Scripting)", url, method, field_name)
            if sig in self.vulnerability_signatures:
                continue
            
            for payload in self.payloads.get('XSS', [])[:2]:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(url, params=test_data, timeout=10)
                    
                    self.scan_stats['requests_sent'] += 1
                    
                    # Check for reflection with context analysis
                    if payload in response.text:
                        # Analyze context (inside tag, attribute, etc.)
                        confidence = 0.8  # Base confidence
                        evidence = 'Payload reflected in response'
                        
                        # Check if in dangerous context
                        if re.search(f'<script[^>]*>{re.escape(payload)}</script>', response.text, re.IGNORECASE):
                            confidence = 0.95
                            evidence = 'Payload reflected inside <script> tag'
                        elif re.search(f'on\\w+=["\']?[^"\'>]*{re.escape(payload[:20])}', response.text, re.IGNORECASE):
                            confidence = 0.90
                            evidence = 'Payload reflected in event handler'
                        
                        self._add_vulnerability(
                            'XSS (Cross-Site Scripting)',
                            url,
                            method,
                            field_name,
                            payload,
                            evidence,
                            payload,
                            confidence
                        )
                        return
                    
                except Exception as e:
                    self.scan_stats['errors_encountered'] += 1
    
    def _test_path_traversal_intelligent(self, url: str, method: str, form_data: Dict):
        """Intelligent path traversal testing"""
        for field_name in form_data.keys():
            self.scan_stats['parameters_tested'] += 1
            
            sig = self._generate_signature("Path Traversal", url, method, field_name)
            if sig in self.vulnerability_signatures:
                continue
            
            for payload in self.payloads.get('PATH_TRAVERSAL', [])[:2]:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    if method == 'post':
                        response = self.session.post(url, data=test_data, timeout=10)
                    else:
                        response = self.session.get(url, params=test_data, timeout=10)
                    
                    self.scan_stats['requests_sent'] += 1
                    
                    # File content patterns with confidence
                    file_patterns = {
                        r'root:x:[0-9]+:[0-9]+:': 0.95,  # /etc/passwd
                        r'\[boot loader\]': 0.90,  # boot.ini
                        r'system32': 0.75,  # Windows paths
                        r'\[extensions\]': 0.80  # Windows INI
                    }
                    
                    response_lower = response.text.lower()
                    for pattern, confidence in file_patterns.items():
                        if re.search(pattern, response_lower, re.IGNORECASE):
                            match = re.search(f'.{{0,50}}{pattern}.{{0,50}}', response.text, re.IGNORECASE)
                            snippet = match.group(0) if match else ""
                            
                            self._add_vulnerability(
                                'Path Traversal',
                                url,
                                method,
                                field_name,
                                payload,
                                f'File content detected: {pattern}',
                                snippet,
                                confidence
                            )
                            return
                    
                except Exception as e:
                    self.scan_stats['errors_encountered'] += 1
    
    def _test_login_bypass_intelligent(self, url: str, method: str, form_data: Dict):
        """Intelligent login bypass testing"""
        # Get field names
        username_field = None
        password_field = None
        
        for field in form_data.keys():
            field_lower = field.lower()
            if 'user' in field_lower or 'email' in field_lower or 'login' in field_lower:
                username_field = field
            elif 'pass' in field_lower or 'pwd' in field_lower:
                password_field = field
        
        if not (username_field and password_field):
            return
        
        # Check if already found
        sig = self._generate_signature("Weak Credentials", url, method, username_field)
        if sig in self.vulnerability_signatures:
            return
        
        # Test common credentials
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root')
        ]
        
        for username, password in common_creds[:2]:
            test_data = form_data.copy()
            test_data[username_field] = username
            test_data[password_field] = password
            
            try:
                if method == 'post':
                    response = self.session.post(url, data=test_data, timeout=10, allow_redirects=False)
                else:
                    response = self.session.get(url, params=test_data, timeout=10, allow_redirects=False)
                
                self.scan_stats['requests_sent'] += 1
                
                # Success indicators
                if (response.status_code in [301, 302] or
                    'dashboard' in response.text.lower() or
                    'welcome' in response.text.lower() or
                    'logout' in response.text.lower() or
                    len(response.cookies) > 0):
                    
                    vuln = {
                        'id': len(self.vulnerabilities) + 1,
                        'category': 'Weak Credentials',
                        'severity': self.HIGH,
                        'cvss_score': 7.5,
                        'risk_score': 7.5,
                        'confidence': 90.0,
                        'url': url,
                        'method': method.upper(),
                        'parameter': f'{username_field}/{password_field}',
                        'username': username,
                        'password': password,
                        'evidence': 'Login successful with common credentials',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.vulnerabilities.append(vuln)
                    self.vulnerability_signatures.add(sig)
                    print(f"        🔴 [HIGH] Weak Credentials: {username}/{password}")
                    return
                    
            except Exception as e:
                self.scan_stats['errors_encountered'] += 1
    
    def _test_url_parameters_intelligent(self, url: str):
        """Intelligent URL parameter testing"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        for param_name, param_values in params.items():
            # Test for IDOR
            if param_values and param_values[0].isdigit():
                self._test_idor_intelligent(base_url, param_name, int(param_values[0]))
            
            # Test SQL injection in URL params
            for payload in self.payloads.get('SQL', [])[:2]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                
                sig = self._generate_signature("SQL Injection", base_url, 'GET', param_name)
                if sig in self.vulnerability_signatures:
                    continue
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    self.scan_stats['requests_sent'] += 1
                    
                    sql_patterns = ['sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite']
                    response_lower = response.text.lower()
                    
                    for pattern in sql_patterns:
                        if pattern in response_lower:
                            self._add_vulnerability(
                                'SQL Injection',
                                base_url,
                                'GET',
                                param_name,
                                payload,
                                f'SQL error in URL parameter: {pattern}',
                                "",
                                0.90
                            )
                            break
                except:
                    pass
    
    def _test_idor_intelligent(self, base_url: str, param_name: str, original_value: int):
        """Intelligent IDOR testing"""
        sig = self._generate_signature("IDOR (Insecure Direct Object Reference)", base_url, 'GET', param_name)
        if sig in self.vulnerability_signatures:
            return
        
        try:
            # Get original response
            original_url = f"{base_url}?{param_name}={original_value}"
            response1 = self.session.get(original_url, timeout=10)
            self.scan_stats['requests_sent'] += 1
            
            # Try different ID
            test_value = original_value + 1
            test_url = f"{base_url}?{param_name}={test_value}"
            response2 = self.session.get(test_url, timeout=10)
            self.scan_stats['requests_sent'] += 1
            
            # Analyze responses
            if (response1.status_code == 200 and response2.status_code == 200 and
                response1.text != response2.text and 
                len(response2.text) > 100 and
                abs(len(response1.text) - len(response2.text)) > 50):
                
                confidence = 0.75
                # Higher confidence if contains user-specific data
                if any(word in response2.text.lower() for word in ['email', 'phone', 'address', 'profile']):
                    confidence = 0.90
                
                self._add_vulnerability(
                    'IDOR (Insecure Direct Object Reference)',
                    base_url,
                    'GET',
                    param_name,
                    str(test_value),
                    f'Different data accessible by changing ID ({original_value} vs {test_value})',
                    "",
                    confidence
                )
        except:
            pass
    
    def _check_security_headers(self, url: str, response: requests.Response):
        """Check for missing security headers"""
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS filter'
        }
        
        missing_headers = []
        for header, description in security_headers.items():
            if header not in response.headers:
                missing_headers.append(f"{header} ({description})")
        
        if missing_headers and len(missing_headers) >= 3:
            # Only report if multiple headers missing
            sig = self._generate_signature("Missing Security Headers", url, 'GET', 'headers')
            if sig not in self.vulnerability_signatures:
                self.vulnerability_signatures.add(sig)
                vuln = {
                    'id': len(self.vulnerabilities) + 1,
                    'category': 'Missing Security Headers',
                    'severity': self.LOW,
                    'cvss_score': 3.7,
                    'risk_score': 3.0,
                    'confidence': 100.0,
                    'url': url,
                    'method': 'GET',
                    'parameter': 'HTTP Headers',
                    'evidence': f'Missing {len(missing_headers)} security headers: {", ".join(missing_headers[:2])}...',
                    'timestamp': datetime.now().isoformat()
                }
                self.vulnerabilities.append(vuln)
    
    def _check_sensitive_files(self, base_url: str):
        """Check for exposed sensitive files"""
        sensitive_paths = [
            ('/.git/config', 'Git configuration'),
            ('/.env', 'Environment variables'),
            ('/config.php', 'PHP configuration'),
            ('/wp-config.php', 'WordPress config'),
            ('/.htaccess', 'Apache config')
        ]
        
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"
        
        for path, description in sensitive_paths[:3]:
            test_url = root_url + path
            
            sig = self._generate_signature("Sensitive File Exposure", root_url, 'GET', path)
            if sig in self.vulnerability_signatures:
                continue
            
            try:
                response = self.session.get(test_url, timeout=5)
                self.scan_stats['requests_sent'] += 1
                
                if response.status_code == 200 and len(response.text) > 0:
                    self._add_vulnerability(
                        'Sensitive File Exposure',
                        root_url,
                        'GET',
                        path,
                        path,
                        f'Exposed {description} file',
                        response.text[:100],
                        0.95
                    )
            except:
                pass
    
    def _is_login_form(self, form: BeautifulSoup) -> bool:
        """Check if form is a login form"""
        password_fields = form.find_all('input', {'type': 'password'})
        text_fields = form.find_all('input', {'type': ['text', 'email']})
        return len(password_fields) > 0 and len(text_fields) > 0
    
    def _extract_urls(self, base_url: str, soup: BeautifulSoup) -> List[str]:
        """Extract URLs from page"""
        urls = []
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                absolute_url = urljoin(base_url, href)
                if self._is_same_domain(absolute_url) and absolute_url.startswith('http'):
                    urls.append(absolute_url)
        return urls
    
    def _print_summary(self):
        """Print scan summary with statistics"""
        duration = (self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds()
        
        print(f"\n{'=' * 70}")
        print(f"📊 SCAN SUMMARY")
        print(f"{'=' * 70}")
        print(f"Duration: {duration:.1f} seconds")
        print(f"URLs Visited: {len(self.visited_urls)}")
        print(f"Forms Tested: {self.scan_stats['forms_tested']}")
        print(f"Parameters Tested: {self.scan_stats['parameters_tested']}")
        print(f"HTTP Requests: {self.scan_stats['requests_sent']}")
        print(f"Errors: {self.scan_stats['errors_encountered']}")
        print(f"")
        print(f"🚨 VULNERABILITIES FOUND: {len(self.vulnerabilities)}")
        print(f"   Unique Issues: {len(self.vulnerability_signatures)}")
        
        if self.vulnerabilities:
            # Group by severity
            by_severity = {}
            for vuln in self.vulnerabilities:
                sev = vuln['severity']
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            print(f"")
            for severity in [self.CRITICAL, self.HIGH, self.MEDIUM, self.LOW, self.INFO]:
                count = by_severity.get(severity, 0)
                if count > 0:
                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}
                    print(f"   {emoji.get(severity, '•')} {severity}: {count}")
        
        print(f"{'=' * 70}")
    
    def _save_results(self):
        """Save results with enhanced formatting"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(self.history_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 90}\n")
            f.write(f"🕷️  ADVANCED VULNERABILITY SCAN REPORT v2.0\n")
            f.write(f"{'=' * 90}\n")
            f.write(f"Scan Date: {timestamp}\n")
            f.write(f"Target: {self.root_url}\n")
            f.write(f"Scan Duration: {(self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds():.1f}s\n")
            f.write(f"URLs Scanned: {len(self.visited_urls)}\n")
            f.write(f"Unique Vulnerabilities: {len(self.vulnerability_signatures)}\n")
            f.write(f"Total Findings: {len(self.vulnerabilities)}\n")
            f.write(f"{'=' * 90}\n\n")
            
            if self.vulnerabilities:
                # Sort by severity and risk score
                severity_order = {self.CRITICAL: 0, self.HIGH: 1, self.MEDIUM: 2, self.LOW: 3, self.INFO: 4}
                sorted_vulns = sorted(self.vulnerabilities, 
                                    key=lambda x: (severity_order[x['severity']], -x['risk_score']))
                
                for vuln in sorted_vulns:
                    f.write(f"{'─' * 90}\n")
                    f.write(f"VULNERABILITY #{vuln['id']}\n")
                    f.write(f"{'─' * 90}\n")
                    f.write(f"  📌 CATEGORY: {vuln['category']}\n")
                    f.write(f"  🎯 SEVERITY: {vuln['severity']} (CVSS: {vuln['cvss_score']}, Risk: {vuln['risk_score']})\n")
                    f.write(f"  ✅ CONFIDENCE: {vuln['confidence']}%\n")
                    f.write(f"  🔗 URL: {vuln['url']}\n")
                    f.write(f"  📨 METHOD: {vuln['method']}\n")
                    f.write(f"  🎯 PARAMETER: {vuln['parameter']}\n")
                    
                    if 'payload' in vuln:
                        f.write(f"  💉 PAYLOAD: {vuln['payload']}\n")
                    if 'username' in vuln:
                        f.write(f"  👤 CREDENTIALS: {vuln['username']}/{vuln['password']}\n")
                    
                    f.write(f"  ✅ EVIDENCE: {vuln['evidence']}\n")
                    
                    if vuln.get('response_snippet'):
                        f.write(f"  📝 RESPONSE SNIPPET: {vuln['response_snippet']}\n")
                    
                    if 'exploit' in vuln:
                        f.write(f"\n  🔓 EXPLOIT:\n")
                        if vuln['method'] == 'GET':
                            f.write(f"     {vuln['exploit']}\n")
                        else:
                            f.write(f"     {vuln['exploit']}\n")
                    
                    f.write(f"\n")
            else:
                f.write("✅ No vulnerabilities detected.\n")
            
            f.write(f"\n{'=' * 90}\n")
        
        print(f"\n📄 Detailed report saved to: {self.history_file}")
        
        # Save JSON
        results = {
            'timestamp': timestamp,
            'root_url': self.root_url,
            'scan_stats': {
                'duration_seconds': (self.scan_stats['end_time'] - self.scan_stats['start_time']).total_seconds(),
                'urls_visited': len(self.visited_urls),
                'forms_tested': self.scan_stats['forms_tested'],
                'parameters_tested': self.scan_stats['parameters_tested'],
                'requests_sent': self.scan_stats['requests_sent'],
                'errors': self.scan_stats['errors_encountered']
            },
            'visited_urls': list(self.visited_urls),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_findings': len(self.vulnerabilities),
                'unique_vulnerabilities': len(self.vulnerability_signatures),
                'by_severity': self._get_severity_breakdown()
            }
        }
        
        with open('scan_results.json', 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"📄 JSON report saved to: scan_results.json")
    
    def _get_severity_breakdown(self) -> Dict:
        """Get vulnerability breakdown by severity"""
        breakdown = {}
        for vuln in self.vulnerabilities:
            sev = vuln['severity']
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown


def main():
    """Main function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python advanced_crawler.py <root_url> [max_depth] [history_file]")
        print("Example: python advanced_crawler.py http://localhost:8080 5 my_scan.txt")
        sys.exit(1)
    
    root_url = sys.argv[1]
    max_depth = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    history_file = sys.argv[3] if len(sys.argv) > 3 else "advanced_scan_history.txt"
    
    scanner = AdvancedVulnerabilityScanner(root_url, max_depth, history_file=history_file)
    scanner.crawl()


if __name__ == "__main__":
    main()
