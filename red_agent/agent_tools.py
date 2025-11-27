import socket
import subprocess
import requests
from langchain_core.tools import Tool

# Tool 1: URL to IP converter
def url_to_ip(url: str) -> str:
    """Convert URL to IP address"""
    try:
        # Remove protocol if present
        url = url.replace("https://", "").replace("http://", "").split("/")[0]
        ip = socket.gethostbyname(url)
        return f"IP address for {url}: {ip}"
    except Exception as e:
        return f"Error resolving {url}: {str(e)}"

# Tool 2: Nmap scanner
def run_nmap(ip: str) -> str:
    """Run nmap service version scan on IP address"""
    try:
        # Run nmap with sudo and password
        cmd = f'echo "1234" | sudo -S nmap -sV {ip}'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode == 0:
            return f"Nmap scan results for {ip}:\n{result.stdout}"
        else:
            return f"Nmap error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Nmap scan timed out (>120s)"
    except Exception as e:
        return f"Error running nmap: {str(e)}"

# Tool 3: Nikto scanner
def run_nikto(url: str) -> str:
    """Run Nikto web vulnerability scanner"""
    try:
        cmd = f'nikto -h {url} -Tuning 123bde'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600  # Increased from 300s to 600s (10 minutes)
        )
        
        return f"Nikto scan results for {url}:\n{result.stdout}"
    except subprocess.TimeoutExpired:
        return "Nikto scan timed out (>600s). The scan may need more time or the target is slow to respond."
    except Exception as e:
        return f"Error running Nikto: {str(e)}"

# Tool 4: Wappalyzer (using wappalyzer CLI or similar)
def run_wappalyzer(url: str) -> str:
    """Detect technologies used on website"""
    try:
        # First check if wappalyzer CLI is installed
        check_cmd = 'which wappalyzer'
        check_result = subprocess.run(
            check_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if check_result.returncode != 0:
            # Wappalyzer not installed, use basic HTTP header detection
            try:
                response = requests.get(url, timeout=10, allow_redirects=True)
                headers = response.headers
                
                tech_info = []
                tech_info.append(f"URL: {url}")
                tech_info.append(f"Status Code: {response.status_code}")
                tech_info.append(f"\nServer Headers:")
                
                # Detect server
                if 'Server' in headers:
                    tech_info.append(f"  Server: {headers['Server']}")
                
                # Detect common frameworks/technologies
                if 'X-Powered-By' in headers:
                    tech_info.append(f"  X-Powered-By: {headers['X-Powered-By']}")
                
                if 'X-AspNet-Version' in headers:
                    tech_info.append(f"  ASP.NET Version: {headers['X-AspNet-Version']}")
                
                if 'X-Generator' in headers:
                    tech_info.append(f"  Generator: {headers['X-Generator']}")
                
                # Check for common CMS/Framework indicators in HTML
                content = response.text[:5000]  # First 5KB
                tech_info.append(f"\nDetected Technologies from HTML:")
                
                if 'wp-content' in content or 'wp-includes' in content:
                    tech_info.append("  - WordPress detected")
                if 'Joomla' in content:
                    tech_info.append("  - Joomla detected")
                if 'drupal' in content.lower():
                    tech_info.append("  - Drupal detected")
                if 'react' in content.lower() or '_next' in content:
                    tech_info.append("  - React/Next.js possibly detected")
                if 'angular' in content.lower():
                    tech_info.append("  - Angular possibly detected")
                if 'vue' in content.lower():
                    tech_info.append("  - Vue.js possibly detected")
                
                tech_info.append(f"\nNote: Wappalyzer CLI not installed. Using basic HTTP header analysis.")
                tech_info.append(f"Install with: npm install -g wappalyzer (for more detailed analysis)")
                
                return "\n".join(tech_info)
            except requests.RequestException as req_err:
                return f"Error fetching {url} for tech detection: {str(req_err)}\nNote: Wappalyzer CLI not installed."
        
        # Wappalyzer is installed, use it
        cmd = f'wappalyzer {url}'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            return f"Wappalyzer results for {url}:\n{result.stdout}"
        else:
            return f"Wappalyzer results for {url}:\n{result.stdout}\nNote: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Wappalyzer scan timed out"
    except Exception as e:
        return f"Error running Wappalyzer: {str(e)}"

# Tool 5: DNS Lookup
def dns_lookup(domain: str) -> str:
    """Perform DNS lookup to get DNS records"""
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        
        dns_info = []
        dns_info.append(f"DNS Information for {domain}:\n")
        
        # A record
        try:
            ip = socket.gethostbyname(domain)
            dns_info.append(f"A Record (IPv4): {ip}")
        except:
            dns_info.append("A Record: Not found")
        
        # More detailed DNS using dig/host
        try:
            cmd = f'dig {domain} ANY +noall +answer'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                dns_info.append(f"\nDetailed DNS Records:\n{result.stdout}")
        except:
            pass
        
        return "\n".join(dns_info)
    except Exception as e:
        return f"Error performing DNS lookup: {str(e)}"

# Tool 6: WHOIS Lookup
def whois_lookup(domain: str) -> str:
    """Get WHOIS information for a domain"""
    try:
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        cmd = f'whois {domain}'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            return f"WHOIS information for {domain}:\n{result.stdout[:2000]}"  # Limit output
        else:
            return f"WHOIS lookup failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "WHOIS lookup timed out"
    except Exception as e:
        return f"Error running WHOIS: {str(e)}"

# Tool 7: SSL Certificate Info
def ssl_cert_info(url: str) -> str:
    """Get SSL certificate information"""
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Try using openssl
        cmd = f'echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -text'
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return f"SSL Certificate Info for {domain}:\n{result.stdout[:1500]}"
        else:
            # Fallback to basic check
            try:
                import ssl
                import socket as sock
                context = ssl.create_default_context()
                with sock.create_connection((domain, 443), timeout=10) as s:
                    with context.wrap_socket(s, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        info = [f"SSL Certificate for {domain}:"]
                        info.append(f"Subject: {cert.get('subject', 'N/A')}")
                        info.append(f"Issuer: {cert.get('issuer', 'N/A')}")
                        info.append(f"Version: {cert.get('version', 'N/A')}")
                        info.append(f"Serial Number: {cert.get('serialNumber', 'N/A')}")
                        info.append(f"Not Before: {cert.get('notBefore', 'N/A')}")
                        info.append(f"Not After: {cert.get('notAfter', 'N/A')}")
                        return "\n".join(info)
            except Exception as fallback_err:
                return f"Could not retrieve SSL certificate info: {str(fallback_err)}"
    except subprocess.TimeoutExpired:
        return "SSL certificate check timed out"
    except Exception as e:
        return f"Error getting SSL info: {str(e)}"

# Tool 8: HTTP Headers
def http_headers(url: str) -> str:
    """Get HTTP response headers"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        headers_info = [f"HTTP Headers for {url}:"]
        headers_info.append(f"Status Code: {response.status_code}")
        headers_info.append(f"\nResponse Headers:")
        
        for key, value in response.headers.items():
            headers_info.append(f"  {key}: {value}")
        
        return "\n".join(headers_info)
    except requests.RequestException as e:
        return f"Error fetching HTTP headers: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

# Tool 9: Robots.txt Checker
def check_robots(url: str) -> str:
    """Check robots.txt file"""
    try:
        base_url = url.replace("https://", "").replace("http://", "").split("/")[0]
        robots_url = f"http://{base_url}/robots.txt"
        robots_url_https = f"https://{base_url}/robots.txt"
        
        # Try HTTPS first
        try:
            response = requests.get(robots_url_https, timeout=10)
            if response.status_code == 200:
                return f"robots.txt found at {robots_url_https}:\n\n{response.text[:2000]}"
        except:
            pass
        
        # Try HTTP
        response = requests.get(robots_url, timeout=10)
        if response.status_code == 200:
            return f"robots.txt found at {robots_url}:\n\n{response.text[:2000]}"
        else:
            return f"No robots.txt found (Status: {response.status_code})"
    except requests.RequestException as e:
        return f"Error checking robots.txt: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

# Tool 10: Port Scanner (Quick Common Ports)
def quick_port_scan(ip: str) -> str:
    """Scan common ports quickly"""
    try:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        ip = ip.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Try to resolve to IP if it's a domain
        try:
            import socket as sock
            ip = sock.gethostbyname(ip)
        except:
            pass
        
        results = [f"Quick port scan for {ip}:"]
        results.append(f"Scanning common ports: {common_ports}\n")
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    results.append(f"Port {port}: OPEN")
                sock.close()
            except:
                pass
        
        if not open_ports:
            results.append("No common ports found open")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error during port scan: {str(e)}"


# Create tools list
tools = [
    Tool(
        name="URLtoIP",
        func=url_to_ip,
        description="Converts a URL/domain to its IP address. Input should be a URL or domain name."
    ),
    Tool(
        name="Nmap",
        func=run_nmap,
        description="Runs 'sudo nmap -sV IP' to scan services on an IP address. Input must be an IP address."
    ),
    # Tool(
    #     name="Nikto",
    #     func=run_nikto,
    #     description="Runs Nikto web vulnerability scanner on a URL. Input should be a full URL (e.g., http://example.com). Takes 10+ minutes."
    # ),
    Tool(
        name="Wappalyzer",
        func=run_wappalyzer,
        description="Detects web technologies used on a website. Input should be a URL."
    ),
    Tool(
        name="DNSLookup",
        func=dns_lookup,
        description="Performs DNS lookup to get DNS records for a domain. Input should be a domain name."
    ),
    Tool(
        name="WHOIS",
        func=whois_lookup,
        description="Gets WHOIS registration information for a domain. Input should be a domain name."
    ),
    Tool(
        name="SSLCertInfo",
        func=ssl_cert_info,
        description="Gets SSL/TLS certificate information for a website. Input should be a URL or domain."
    ),
    Tool(
        name="HTTPHeaders",
        func=http_headers,
        description="Gets HTTP response headers from a URL. Input should be a full URL."
    ),
    Tool(
        name="RobotsTxt",
        func=check_robots,
        description="Checks and retrieves the robots.txt file from a website. Input should be a URL or domain."
    ),
    Tool(
        name="QuickPortScan",
        func=quick_port_scan,
        description="Quickly scans common ports (21,22,80,443,etc) on an IP or domain. Input should be an IP address or domain."
    )
]