"""
CVE Checker Module
Extracts services and versions from scan reports and searches for relevant CVEs
Provides focused, actionable CVE information (top CVEs only)
"""

import json
import os
import re
import requests
import time
from datetime import datetime
from typing import Dict, List, Any


# -----------------------------
# Utility Functions
# -----------------------------
def get_severity(score):
    """Maps CVSS base score to severity."""
    if score is None or score == 'N/A':
        return 'Unknown'
    
    # Handle CVSS Score (Float)
    if isinstance(score, (int, float)):
        score = float(score)
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    return 'Unknown'


def extract_services_from_reports(scan_result: str = "", crawler_txt_content: str = "", 
                                   json_data: Dict = None) -> List[Dict[str, Any]]:
    """
    Extract services and versions from all available scan reports.
    Returns list of dicts with 'service', 'version', 'source' keys.
    """
    services = []
    
    # Extract from Red Agent scan result (contains Wappalyzer, Nmap, etc.)
    if scan_result:
        # Look for technology patterns (e.g., "Apache 2.4.41", "PHP 7.4", "MySQL 5.7")
        tech_patterns = [
            r'(Apache|Nginx|IIS|Tomcat|Node\.js|Express)\s*([\d\.]+)?',
            r'(PHP|Python|Ruby|Java|\.NET)\s*([\d\.]+)?',
            r'(MySQL|PostgreSQL|MongoDB|Redis|SQLite)\s*([\d\.]+)?',
            r'(WordPress|Joomla|Drupal|Magento)\s*([\d\.]+)?',
            r'(jQuery|React|Vue|Angular)\s*([\d\.]+)?',
            r'(OpenSSL|OpenSSH)\s*([\d\.]+)?',
        ]
        
        for pattern in tech_patterns:
            matches = re.finditer(pattern, scan_result, re.IGNORECASE)
            for match in matches:
                service = match.group(1)
                version = match.group(2) if match.group(2) else None
                services.append({
                    'service': service,
                    'version': version,
                    'source': 'Red Agent Scan'
                })
    
    # Extract from crawler text results
    if crawler_txt_content:
        # Look for server headers and technology mentions
        server_pattern = r'Server:\s*([A-Za-z0-9\-\.\/\s]+)'
        matches = re.finditer(server_pattern, crawler_txt_content, re.IGNORECASE)
        for match in matches:
            server_info = match.group(1).strip()
            # Parse server info (e.g., "Apache/2.4.41 (Ubuntu)")
            parts = re.match(r'([A-Za-z0-9\-]+)[/\s]*([\d\.]+)?', server_info)
            if parts:
                services.append({
                    'service': parts.group(1),
                    'version': parts.group(2) if parts.group(2) else None,
                    'source': 'Crawler Headers'
                })
    
    # Extract from JSON data
    if json_data:
        # Check for any technology info in scan metadata
        scan_info = json_data.get('scan_info', {})
        target_info = scan_info.get('target', '')
        if target_info:
            # Similar pattern matching as above
            for pattern in tech_patterns:
                matches = re.finditer(pattern, str(json_data), re.IGNORECASE)
                for match in matches:
                    service = match.group(1)
                    version = match.group(2) if match.group(2) else None
                    services.append({
                        'service': service,
                        'version': version,
                        'source': 'Crawler JSON Data'
                    })
    
    # Deduplicate services
    unique_services = []
    seen = set()
    for svc in services:
        key = f"{svc['service'].lower()}_{svc.get('version', 'no_version')}"
        if key not in seen:
            seen.add(key)
            unique_services.append(svc)
    
    return unique_services


def search_cves_nvd(keyword: str, limit: int = 10) -> List[Dict]:
    """
    Searches the NVD API for CVEs matching the keyword.
    Returns limited number of results (sorted by severity).
    """
    time.sleep(0.6)  # Rate limiting
    
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}"
        res = requests.get(url, timeout=15)
        res.raise_for_status()

        data = res.json()
        total_results = data.get("totalResults", 0)
        
        if total_results > 0:
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Sort by severity (CVSS score)
            def get_cvss_score(vuln):
                cve = vuln.get('cve', {})
                metrics = cve.get('metrics', {})
                for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics:
                        return metrics[metric_key][0]['cvssData']['baseScore']
                return 0.0
            
            vulnerabilities.sort(key=get_cvss_score, reverse=True)
            return vulnerabilities[:limit]
        else:
            return []

    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying NVD for {keyword}: {e}")
        return []


def run_cve_check(scan_result: str = "", crawler_txt_content: str = "", 
                  json_data: Dict = None, output_dir: str = ".") -> str:
    """
    Main CVE checking function.
    Extracts services from scan reports and searches for relevant CVEs.
    Returns path to saved CVE report file.
    
    Strategy:
    1. Extract services and versions from all reports
    2. Search for exact version matches (top 2 CVEs per service)
    3. Search for service-only matches (top 3 CVEs per service)
    4. Compile focused CVE report (max 10 CVEs total)
    5. Save to file
    """
    
    print("\n" + "=" * 70)
    print("🔍 CVE Vulnerability Database Check")
    print("=" * 70)
    
    # Extract services
    print("\n[+] Extracting services and versions from scan reports...")
    services = extract_services_from_reports(scan_result, crawler_txt_content, json_data)
    
    if not services:
        print("[!] No services detected for CVE search.")
        report_path = os.path.join(output_dir, "cve_report.txt")
        with open(report_path, "w") as f:
            f.write("CVE Vulnerability Check Report\n")
            f.write("=" * 70 + "\n\n")
            f.write("No services or technologies detected for CVE search.\n")
        return report_path
    
    print(f"[+] Found {len(services)} unique services/technologies:")
    for svc in services:
        version_str = f"v{svc['version']}" if svc.get('version') else "version unknown"
        print(f"    - {svc['service']} ({version_str}) from {svc['source']}")
    
    # Search for CVEs
    print(f"\n[+] Searching NVD CVE database...")
    all_cves = []
    
    for svc in services:
        service_name = svc['service']
        version = svc.get('version')
        
        # Strategy 1: Exact version match (if version available)
        if version:
            keyword = f"{service_name} {version}".replace(" ", "%20")
            print(f"    Searching: {service_name} {version} (exact match)...")
            cves = search_cves_nvd(keyword, limit=2)
            
            for cve_item in cves:
                cve = cve_item.get('cve', {})
                metrics = cve.get('metrics', {})
                base_score = None
                
                for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if metric_key in metrics:
                        base_score = metrics[metric_key][0]['cvssData']['baseScore']
                        break
                
                all_cves.append({
                    'id': cve.get('id', 'N/A'),
                    'service': service_name,
                    'version': version,
                    'search_type': 'Exact Version Match',
                    'score': base_score,
                    'severity': get_severity(base_score),
                    'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                    'published': cve.get('published', 'N/A'),
                    'references': [ref.get('url', '') for ref in cve.get('references', [])[:3]]
                })
        
        # Strategy 2: Service-only match (broader search)
        keyword = service_name.replace(" ", "%20")
        print(f"    Searching: {service_name} (service-only)...")
        cves = search_cves_nvd(keyword, limit=3)
        
        for cve_item in cves:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            
            # Skip if already added
            if any(c['id'] == cve_id for c in all_cves):
                continue
            
            metrics = cve.get('metrics', {})
            base_score = None
            
            for metric_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if metric_key in metrics:
                    base_score = metrics[metric_key][0]['cvssData']['baseScore']
                    break
            
            all_cves.append({
                'id': cve_id,
                'service': service_name,
                'version': version if version else 'N/A',
                'search_type': 'Service Match',
                'score': base_score,
                'severity': get_severity(base_score),
                'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                'published': cve.get('published', 'N/A'),
                'references': [ref.get('url', '') for ref in cve.get('references', [])[:3]]
            })
    
    # Sort all CVEs by severity (Critical > High > Medium > Low)
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
    all_cves.sort(key=lambda x: (severity_order.get(x['severity'], 5), -(x['score'] or 0)))
    
    # Limit to top 10 most critical CVEs
    top_cves = all_cves[:10]
    
    print(f"\n[+] Found {len(all_cves)} total CVEs, reporting top {len(top_cves)} most critical")
    
    # Generate report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = os.path.join(output_dir, "cve_report.txt")
    
    with open(report_path, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("CVE Vulnerability Database Check Report\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Generated: {timestamp}\n")
        f.write(f"Services Analyzed: {len(services)}\n")
        f.write(f"Total CVEs Found: {len(all_cves)}\n")
        f.write(f"Top Critical CVEs Reported: {len(top_cves)}\n\n")
        
        # Summary by severity
        severity_counts = {}
        for cve in top_cves:
            severity = cve['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        f.write("Severity Breakdown:\n")
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                f.write(f"  {severity}: {count}\n")
        f.write("\n")
        
        # Detailed CVE list
        f.write("=" * 70 + "\n")
        f.write("DETAILED CVE FINDINGS (Top 10 Most Critical)\n")
        f.write("=" * 70 + "\n\n")
        
        for idx, cve in enumerate(top_cves, 1):
            f.write(f"\n[{idx}] {cve['id']}\n")
            f.write("-" * 70 + "\n")
            f.write(f"Service: {cve['service']}\n")
            f.write(f"Version: {cve['version']}\n")
            f.write(f"Search Type: {cve['search_type']}\n")
            f.write(f"Severity: {cve['severity']}\n")
            f.write(f"CVSS Score: {cve['score']}\n")
            f.write(f"Published: {cve['published']}\n\n")
            
            f.write("Description:\n")
            desc = cve['description']
            # Wrap description at 70 chars
            words = desc.split()
            line = ""
            for word in words:
                if len(line) + len(word) + 1 <= 70:
                    line += word + " "
                else:
                    f.write(f"  {line.strip()}\n")
                    line = word + " "
            if line:
                f.write(f"  {line.strip()}\n")
            
            f.write("\nReferences:\n")
            for ref in cve['references']:
                f.write(f"  - {ref}\n")
            f.write("\n")
        
        f.write("=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 70 + "\n")
    
    print(f"\n✅ CVE report saved to: {report_path}")
    return report_path


if __name__ == "__main__":
    # For standalone testing
    print("CVE Checker Module")
    print("This module is designed to be imported and used by the main agent.")
    print("\nFor testing, provide scan result strings:")
    
    test_scan = input("\nEnter test scan result (or press Enter to skip): ").strip()
    if test_scan:
        report = run_cve_check(scan_result=test_scan)
        print(f"\nTest report generated: {report}")