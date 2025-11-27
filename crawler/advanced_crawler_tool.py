"""
Advanced Crawler Tool for LangGraph Integration
"""
from advanced_crawler import AdvancedVulnerabilityScanner

def run_advanced_scan(url: str, max_depth: int = 3, history_file: str = "crawler_scan.txt") -> str:
    """
    Run advanced vulnerability scanner
    
    Args:
        url: Target URL
        max_depth: Crawl depth (default: 3 for performance)
        history_file: Output file name
    
    Returns:
        Formatted scan summary
    """
    try:
        print(f"\n🚀 Starting Advanced Vulnerability Scanner...")
        
        scanner = AdvancedVulnerabilityScanner(url, max_depth=max_depth, history_file=history_file)
        scanner.crawl()
        
        # Format results
        result = []
        result.append(f"\n{'=' * 80}")
        result.append(f"🕷️  ADVANCED VULNERABILITY SCAN - EXECUTIVE SUMMARY")
        result.append(f"{'=' * 80}")
        result.append(f"Target: {url}")
        result.append(f"Depth: {max_depth}")
        result.append(f"")
        
        # Statistics
        result.append(f"📊 SCAN STATISTICS:")
        result.append(f"  • URLs Scanned: {len(scanner.visited_urls)}")
        result.append(f"  • Forms Tested: {scanner.scan_stats['forms_tested']}")
        result.append(f"  • Parameters Tested: {scanner.scan_stats['parameters_tested']}")
        result.append(f"  • Total Requests: {scanner.scan_stats['requests_sent']}")
        result.append(f"  • Unique Vulnerabilities: {len(scanner.vulnerability_signatures)}")
        result.append(f"  • Total Findings: {len(scanner.vulnerabilities)}")
        result.append(f"")
        
        if scanner.vulnerabilities:
            # Group by severity
            severity_groups = {
                scanner.CRITICAL: [],
                scanner.HIGH: [],
                scanner.MEDIUM: [],
                scanner.LOW: []
            }
            
            for vuln in scanner.vulnerabilities:
                severity_groups[vuln['severity']].append(vuln)
            
            result.append(f"🚨 VULNERABILITIES BY SEVERITY:")
            result.append(f"")
            
            severity_emoji = {
                scanner.CRITICAL: "🔴",
                scanner.HIGH: "🟠",
                scanner.MEDIUM: "🟡",
                scanner.LOW: "🟢"
            }
            
            for severity in [scanner.CRITICAL, scanner.HIGH, scanner.MEDIUM, scanner.LOW]:
                vulns = severity_groups[severity]
                if vulns:
                    emoji = severity_emoji[severity]
                    result.append(f"{emoji} {severity} SEVERITY ({len(vulns)} issues):")
                    result.append(f"")
                    
                    # Group by category
                    by_category = {}
                    for v in vulns:
                        cat = v['category']
                        if cat not in by_category:
                            by_category[cat] = []
                        by_category[cat].append(v)
                    
                    for category, cat_vulns in by_category.items():
                        result.append(f"  [{category}] - {len(cat_vulns)} instance(s)")
                        
                        # Show first example
                        example = cat_vulns[0]
                        result.append(f"    Example:")
                        result.append(f"      🔗 URL: {example['url'][:60]}...")
                        result.append(f"      🎯 Parameter: {example['parameter']}")
                        result.append(f"      ✅ Confidence: {example['confidence']}%")
                        result.append(f"      💯 Risk Score: {example['risk_score']}/10")
                        
                        if 'payload' in example:
                            result.append(f"      💉 Payload: {example['payload'][:50]}...")
                        if 'username' in example:
                            result.append(f"      👤 Credentials: {example['username']}/{example['password']}")
                        
                        result.append(f"      ✅ Evidence: {example['evidence'][:60]}...")
                        
                        if len(cat_vulns) > 1:
                            result.append(f"    ... and {len(cat_vulns) - 1} more {category} instance(s)")
                        
                        result.append(f"")
                    
        else:
            result.append(f"✅ NO VULNERABILITIES DETECTED")
            result.append(f"   The target appears to be secure against tested attack vectors.")
        
        result.append(f"")
        result.append(f"{'=' * 80}")
        result.append(f"📄 FULL REPORT: {history_file}")
        result.append(f"📄 JSON DATA: scan_results.json")
        result.append(f"{'=' * 80}")
        
        return "\n".join(result)
        
    except Exception as e:
        return f"❌ Scanner Error: {str(e)}"


def advanced_crawler_tool(url: str) -> str:
    """LangChain tool wrapper for advanced crawler"""
    return run_advanced_scan(url, max_depth=3, history_file="agent_scan_results.txt")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
        depth = int(sys.argv[2]) if len(sys.argv) > 2 else 3
        print(run_advanced_scan(url, depth))
    else:
        print("Usage: python advanced_crawler_tool.py <url> [depth]")
        print("Example: python advanced_crawler_tool.py http://localhost:8080 3")
