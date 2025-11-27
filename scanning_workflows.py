"""
Scanning workflow functions for URL and Directory (Docker) scanning
"""
from langchain_core.messages import HumanMessage, AIMessage
from crawler.advanced_crawler_tool import run_advanced_scan
from red_agent.agent import run_red_agent
from code_analyzer.analyzer import analyze_codespace_with_ai
from CVE_checker.checker import run_cve_check
from tools import (
    start_docker_container,
    stop_docker_container,
    wait_for_service_ready,
    read_text_file,
    read_json_file
)
import os
import time
from pathlib import Path


def handle_url_scanning(state, llm, validated_url: str, user_intent: str):
    """Handle URL scanning workflow"""
    validation_result = state.get("validation_result", "")
    
    # Plan what type of scan to perform
    planning_prompt = f"""The user provided: "{user_intent}"
A URL has been validated as accessible: {validated_url}

Based on the user's intent, decide what type of security scan to perform:
- If user mentions specific tools or "quick"/"basic" → BASIC_SCAN (Red Agent only)
- If user mentions "detailed" or specific security aspects → PARTIAL_SCAN (Red Agent + Crawler)
- If no specific intent or wants comprehensive check → FULL_SCAN (Red Agent + Crawler with detailed analysis) (default)

Formulate a clear query for the security scanning agents.

Respond in this format:
SCAN_TYPE: [FULL_SCAN/PARTIAL_SCAN/BASIC_SCAN]
QUERY: [Clear query for red agent]"""

    planning_response = llm.invoke([HumanMessage(content=planning_prompt)])
    planning_result = planning_response.content.strip()
    
    # Parse planning result
    scan_type = "FULL_SCAN"
    query = f"Perform a comprehensive security scan on {validated_url} using all available tools except Nikto"
    
    if "SCAN_TYPE:" in planning_result:
        lines = planning_result.split("\n")
        for line in lines:
            if line.startswith("SCAN_TYPE:"):
                scan_type = line.replace("SCAN_TYPE:", "").strip()
            if line.startswith("QUERY:"):
                query = line.replace("QUERY:", "").strip()
    
    # Step 1: Red Agent Reconnaissance
    plan_message = f"🔍 Initiating {scan_type} on {validated_url}...\n\n**Phase 1: Reconnaissance Scanning (Red Agent)**"
    state["messages"].append(AIMessage(content=plan_message))
    
    print(f"\n🔧 Phase 1: Calling Red Agent with query: {query}")
    scan_result = run_red_agent(query)
    state["scan_result"] = scan_result
    
    # Step 2: Advanced Crawler (if not BASIC_SCAN)
    if scan_type in ["FULL_SCAN", "PARTIAL_SCAN"]:
        crawler_message = "\n**Phase 2: Vulnerability Scanning (Advanced Crawler)**"
        state["messages"].append(AIMessage(content=crawler_message))
        
        print(f"\n🕷️ Phase 2: Running Advanced Vulnerability Crawler on {validated_url}")
        
        # Generate unique filename with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        txt_filename = f"crawler_scan_{timestamp}.txt"
        json_filename = "scan_results.json"
        
        # Run advanced crawler
        crawler_result = run_advanced_scan(
            url=validated_url,
            max_depth=3,
            history_file=txt_filename
        )
        state["crawler_result"] = crawler_result
        state["crawler_txt_file"] = txt_filename
        state["crawler_json_file"] = json_filename
        
        # Step 3: Read and analyze results
        analysis_message = "\n**Phase 3: Analyzing Scan Results**"
        state["messages"].append(AIMessage(content=analysis_message))
        
        print(f"\n📄 Phase 3: Reading scan result files...")
        
        # Read TXT file
        txt_result = read_text_file(txt_filename)
        txt_content = txt_result.get("content", "") if txt_result.get("success") else "Could not read TXT file"
        
        # Read JSON file
        json_result = read_json_file(json_filename)
        json_data = json_result.get("data", {}) if json_result.get("success") else {}
        
        # Step 4: CVE Database Check
        cve_message = "\n**Phase 4: CVE Vulnerability Database Check**"
        state["messages"].append(AIMessage(content=cve_message))
        
        print(f"\n🔍 Phase 4: Running CVE Database Check...")
        
        # Run CVE checker with all available data
        cve_report_path = run_cve_check(
            scan_result=scan_result,
            crawler_txt_content=txt_content,
            json_data=json_data,
            output_dir="."
        )
        state["cve_report_file"] = cve_report_path
        
        # Read CVE report
        cve_report_result = read_text_file(cve_report_path)
        cve_report_content = cve_report_result.get("content", "") if cve_report_result.get("success") else "Could not read CVE report"
        
        # Step 5: Comprehensive analysis
        comprehensive_prompt = f"""You are analyzing comprehensive security scan results for {validated_url}.

**USER REQUEST:**
{user_intent}

**VALIDATION STATUS:**
{validation_result}

**RED AGENT RECONNAISSANCE RESULTS:**
{scan_result}

**ADVANCED CRAWLER VULNERABILITY SCAN:**
{crawler_result}

**DETAILED VULNERABILITY REPORT (TXT):**
{txt_content[:3000]}... [truncated for brevity]

**VULNERABILITY DATA (JSON SUMMARY):**
Total Vulnerabilities: {len(json_data.get('vulnerabilities', []))}
Scan Statistics: {json_data.get('scan_stats', {})}

**CVE DATABASE CHECK REPORT:**
{cve_report_content[:2000]}... [truncated for brevity]

Provide a comprehensive security analysis that includes:

1. **Executive Summary**
   - Overall security posture
   - Critical findings from all scans
   - Risk assessment with actionable severity ratings

2. **Reconnaissance Findings (Red Agent)**
   - Technologies detected with versions
   - Server information and configuration
   - DNS/Network details
   - SSL/TLS status and certificate info
   - Any exposed information (robots.txt, headers, etc.)

3. **Runtime Vulnerability Assessment (Advanced Crawler)**
   - Number and severity of vulnerabilities found
   - Critical vulnerabilities requiring immediate attention
   - High/Medium/Low severity issues breakdown
   - Common vulnerability patterns detected (XSS, SQLi, CSRF, etc.)

4. **Known Vulnerabilities (CVE Database)**
   - Number of CVEs found in NVD database
   - Critical CVEs affecting detected technologies
   - Services with known security issues
   - Version-specific vulnerabilities

5. **Detailed Vulnerability Analysis**
   - Top 5 most critical runtime vulnerabilities with:
     * Vulnerability type
     * Location (URL/parameter)
     * Severity and risk score
     * Exploitation evidence
     * Remediation recommendations
   - Top 5 most critical CVEs with:
     * CVE ID and CVSS score
     * Affected service/version
     * Description and impact
     * Mitigation techniques

6. **Security Issues and Bugs Summary**
   - Authentication/Authorization issues
   - Input validation problems
   - Information disclosure vulnerabilities
   - Configuration weaknesses
   - Missing security headers

7. **Comprehensive Recommendations**
   - **Immediate Actions Required:**
     * Critical patches to apply
     * Emergency configuration changes
     * Services to disable/restrict
   
   - **Short-term Improvements:**
     * Software updates needed (with specific versions)
     * Security header implementations
     * Input validation enhancements
     * Authentication strengthening
   
   - **Long-term Security Enhancements:**
     * Architecture improvements
     * Security monitoring setup
     * Regular vulnerability scanning schedule
     * Security best practices to adopt
   
   - **Mitigation Techniques:**
     * For each critical vulnerability, provide specific mitigation steps
     * Code-level fixes where applicable
     * Configuration changes with examples
     * WAF rules or network security measures

8. **Suggestions for Security Hardening**
   - Update outdated software and libraries
   - Implement security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Enable rate limiting and input sanitization
   - Use HTTPS everywhere with strong TLS configuration
   - Regular security audits and penetration testing
   - Implement proper logging and monitoring
   - Follow OWASP Top 10 guidelines

9. **Report Files Generated**
   - Detailed TXT report: {txt_filename}
   - JSON data export: {json_filename}
   - CVE database report: {cve_report_path}

Format your response with clear sections, emojis for readability, and actionable insights.
Be professional but accessible in your language. Prioritize by risk level and provide specific, implementable recommendations."""

        final_response = llm.invoke([HumanMessage(content=comprehensive_prompt)])
        state["messages"].append(AIMessage(content=final_response.content))
        
    else:
        # BASIC_SCAN - only red agent results
        basic_prompt = f"""The URL {validated_url} has been validated and scanned with reconnaissance tools.

**USER REQUEST:**
{user_intent}

**VALIDATION RESULT:**
{validation_result}

**RECONNAISSANCE SCAN RESULTS:**
{scan_result}

Provide a comprehensive summary that includes:
1. URL accessibility status
2. Key findings from the reconnaissance scan
3. Technologies and services detected
4. Any security observations
5. Recommendations if applicable

Be clear, organized, and highlight important information."""

        final_response = llm.invoke([HumanMessage(content=basic_prompt)])
        state["messages"].append(AIMessage(content=final_response.content))
    
    return state


def handle_directory_scanning(state, llm, localhost_url: str, user_intent: str, validation_result: str):
    """Handle directory (Docker) scanning workflow with container lifecycle management"""
    messages = state["messages"]
    
    # Extract directory from validation result or messages
    directory = None
    for msg in reversed(messages):
        if isinstance(msg, HumanMessage):
            # Try to extract directory path
            content = msg.content
            if os.path.isabs(content) and os.path.isdir(content):
                directory = content
                break
    
    if not directory:
        state["messages"].append(AIMessage(content="❌ Could not determine directory path for Docker management."))
        return state
    
    state["docker_directory"] = directory
    
    try:
        # Step 1: Start Docker containers
        start_message = f"🐳 **Phase 1: Starting Docker Containers**\n\nDirectory: `{directory}`"
        state["messages"].append(AIMessage(content=start_message))
        
        print(f"\n🐳 Phase 1: Starting Docker containers in {directory}")
        
        start_result = start_docker_container(directory)
        
        if not start_result.get("success"):
            error_msg = f"❌ Failed to start Docker containers:\n{start_result.get('message', 'Unknown error')}"
            state["messages"].append(AIMessage(content=error_msg))
            return state
        
        state["docker_started"] = True
        actual_localhost_url = start_result.get("localhost_url", localhost_url)
        state["localhost_url"] = actual_localhost_url
        
        # Step 2: Wait for service to be ready
        wait_message = f"\n⏳ **Phase 2: Waiting for Service to be Ready**\n\nURL: `{actual_localhost_url}`"
        state["messages"].append(AIMessage(content=wait_message))
        
        print(f"\n⏳ Phase 2: Waiting for service at {actual_localhost_url}")
        wait_result = wait_for_service_ready(actual_localhost_url, max_attempts=30, delay=2)
        
        if not wait_result.get("success"):
            error_msg = f"❌ Service did not become ready:\n{wait_result.get('message', 'Timeout')}"
            state["messages"].append(AIMessage(content=error_msg))
            # Stop containers before returning
            cleanup_docker_containers(state)
            return state
        
        ready_message = f"✅ Service is ready at `{actual_localhost_url}`"
        state["messages"].append(AIMessage(content=ready_message))
        
        # Step 3: Red Agent Reconnaissance
        plan_message = f"\n🔍 **Phase 3: Reconnaissance Scanning (Red Agent)**"
        state["messages"].append(AIMessage(content=plan_message))
        
        query = f"Perform a comprehensive security scan on {actual_localhost_url} using all available tools except Nikto"
        print(f"\n🔧 Phase 3: Calling Red Agent with query: {query}")
        scan_result = run_red_agent(query)
        state["scan_result"] = scan_result
        
        # Step 4: Advanced Crawler
        crawler_message = f"\n🕷️ **Phase 4: Vulnerability Scanning (Advanced Crawler)**"
        state["messages"].append(AIMessage(content=crawler_message))
        
        print(f"\n🕷️ Phase 4: Running Advanced Vulnerability Crawler on {actual_localhost_url}")
        
        # Generate unique filename with timestamp
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        txt_filename = f"crawler_scan_docker_{timestamp}.txt"
        json_filename = "scan_results.json"
        
        # Run advanced crawler
        crawler_result = run_advanced_scan(
            url=actual_localhost_url,
            max_depth=3,
            history_file=txt_filename
        )
        state["crawler_result"] = crawler_result
        state["crawler_txt_file"] = txt_filename
        state["crawler_json_file"] = json_filename
        
        # Step 5: Code Analysis (Static Analysis of Directory Source Code)
        code_analysis_message = f"\n🔍 **Phase 5: Static Code Analysis**"
        state["messages"].append(AIMessage(content=code_analysis_message))
        
        print(f"\n🔍 Phase 5: Running Static Code Analysis on {directory}")
        
        try:
            code_analysis_report_path = analyze_codespace_with_ai(directory)
            state["code_analysis_result"] = code_analysis_report_path
            
            # Read the code analysis report
            if os.path.exists(code_analysis_report_path.split(": ")[1].split(" for")[0]):
                report_path = code_analysis_report_path.split(": ")[1].split(" for")[0]
                code_report_result = read_text_file(report_path)
                code_report_content = code_report_result.get("content", "") if code_report_result.get("success") else "Could not read code analysis report"
            else:
                code_report_content = "Code analysis report file not found"
                
            print(f"✅ Code analysis completed: {code_analysis_report_path}")
        except Exception as e:
            code_analysis_report_path = f"Error during code analysis: {str(e)}"
            code_report_content = "Code analysis failed"
            print(f"⚠️ Code analysis error: {str(e)}")
        
        # Step 6: Stop Docker containers
        stop_message = f"\n🛑 **Phase 6: Stopping Docker Containers**"
        state["messages"].append(AIMessage(content=stop_message))
        
        cleanup_result = cleanup_docker_containers(state)
        state["messages"].append(AIMessage(content=cleanup_result))
        
        # Step 7: Read and analyze results
        analysis_message = f"\n📊 **Phase 7: Analyzing All Scan Results**"
        state["messages"].append(AIMessage(content=analysis_message))
        
        print(f"\n📄 Phase 7: Reading scan result files...")
        
        # Read TXT file
        txt_result = read_text_file(txt_filename)
        txt_content = txt_result.get("content", "") if txt_result.get("success") else "Could not read TXT file"
        
        # Read JSON file
        json_result = read_json_file(json_filename)
        json_data = json_result.get("data", {}) if json_result.get("success") else {}
        
        # Step 8: CVE Database Check
        cve_message = f"\n🔍 **Phase 8: CVE Vulnerability Database Check**"
        state["messages"].append(AIMessage(content=cve_message))
        
        print(f"\n🔍 Phase 8: Running CVE Database Check...")
        
        # Run CVE checker with all available data
        cve_report_path = run_cve_check(
            scan_result=scan_result,
            crawler_txt_content=txt_content,
            json_data=json_data,
            output_dir="."
        )
        state["cve_report_file"] = cve_report_path
        
        # Read CVE report
        cve_report_result = read_text_file(cve_report_path)
        cve_report_content = cve_report_result.get("content", "") if cve_report_result.get("success") else "Could not read CVE report"
        
        # Step 9: Comprehensive analysis
        comprehensive_prompt = f"""You are analyzing comprehensive security scan results for a Docker web application.

**USER REQUEST:**
{user_intent}

**DOCKER DIRECTORY:**
{directory}

**VALIDATION STATUS:**
{validation_result}

**LOCALHOST URL:**
{actual_localhost_url}

**RED AGENT RECONNAISSANCE RESULTS:**
{scan_result}

**ADVANCED CRAWLER VULNERABILITY SCAN:**
{crawler_result}

**DETAILED VULNERABILITY REPORT (TXT):**
{txt_content[:3000]}... [truncated for brevity]

**VULNERABILITY DATA (JSON SUMMARY):**
Total Vulnerabilities: {len(json_data.get('vulnerabilities', []))}
Scan Statistics: {json_data.get('scan_stats', {})}

**STATIC CODE ANALYSIS REPORT:**
{code_analysis_report_path}

**CODE ANALYSIS FINDINGS:**
{code_report_content[:3000]}... [truncated for brevity]

**CVE DATABASE CHECK REPORT:**
{cve_report_content[:2000]}... [truncated for brevity]

Provide a comprehensive security analysis that includes:

1. **Executive Summary**
   - Overall security posture of the Docker web application
   - Critical findings from runtime, static analysis, and CVE database
   - Risk assessment with severity ratings

2. **Docker Application Info**
   - Directory: {directory}
   - Tested URL: {actual_localhost_url}
   - Container status: Started, scanned, and stopped successfully

3. **Reconnaissance Findings (Red Agent)**
   - Technologies detected with versions
   - Server information and configuration
   - Security headers analysis
   - Any exposed information

4. **Runtime Vulnerability Assessment (Advanced Crawler)**
   - Number and severity of vulnerabilities found during runtime testing
   - Critical vulnerabilities requiring immediate attention
   - High/Medium/Low severity issues breakdown
   - Common vulnerability patterns detected (XSS, SQLi, CSRF, etc.)

5. **Static Code Analysis Findings**
   - Code-level security issues detected
   - Dangerous coding patterns
   - Hardcoded credentials or secrets
   - Insecure function usage
   - Dependency vulnerabilities

6. **Known Vulnerabilities (CVE Database)**
   - Number of CVEs found in NVD database
   - Critical CVEs affecting detected technologies
   - Services with known security issues
   - Version-specific vulnerabilities

7. **Detailed Vulnerability Analysis**
   - Top 5 most critical runtime vulnerabilities with:
     * Vulnerability type
     * Location (URL/parameter)
     * Severity and risk score
     * Exploitation evidence
     * Remediation recommendations
   - Top 5 most critical code-level vulnerabilities with:
     * Vulnerability type
     * File/line location
     * Security impact
     * Code fix examples
   - Top 5 most critical CVEs with:
     * CVE ID and CVSS score
     * Affected service/version
     * Description and impact
     * Mitigation techniques

8. **Security Issues and Bugs Summary**
   - Authentication/Authorization issues
   - Input validation problems
   - Information disclosure vulnerabilities
   - Configuration weaknesses
   - Missing security headers
   - Code-level security flaws

9. **Comprehensive Recommendations**
   - **Immediate Actions Required:**
     * Critical patches to apply (with CVE references)
     * Emergency code fixes (with file locations)
     * Configuration changes needed
     * Services to disable/restrict
   
   - **Short-term Improvements:**
     * Software updates needed (with specific versions from CVE report)
     * Code refactoring for security issues
     * Security header implementations
     * Input validation enhancements
     * Authentication strengthening
   
   - **Long-term Security Enhancements:**
     * Architecture improvements
     * Security monitoring setup
     * Regular vulnerability scanning schedule
     * Code review processes
     * Dependency management strategy
     * Security best practices to adopt
   
   - **Mitigation Techniques:**
     * For each critical vulnerability, provide specific mitigation steps
     * Code-level fixes with examples
     * Configuration changes with exact commands
     * WAF rules or network security measures
     * Docker security hardening

10. **Suggestions for Security Hardening**
   - Update outdated software and libraries (prioritize based on CVE findings)
   - Apply patches for known CVEs
   - Fix code-level security issues in source files
   - Implement security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Enable rate limiting and input sanitization
   - Use HTTPS everywhere with strong TLS configuration
   - Regular security audits and penetration testing
   - Implement proper logging and monitoring
   - Follow OWASP Top 10 guidelines
   - Docker security best practices (non-root users, minimal images, etc.)

11. **Report Files Generated**
   - Detailed TXT report: {txt_filename}
   - JSON data export: {json_filename}
   - Code analysis report: {code_analysis_report_path}
   - CVE database report: {cve_report_path}

Format your response with clear sections, emojis for readability, and actionable insights.
Be professional but accessible in your language. Prioritize by risk level and provide specific, implementable recommendations with code examples where applicable."""

        final_response = llm.invoke([HumanMessage(content=comprehensive_prompt)])
        state["messages"].append(AIMessage(content=final_response.content))
    
    except Exception as e:
        error_msg = f"❌ Error during directory scanning: {str(e)}"
        print(f"⚠️ {error_msg}")
        import traceback
        traceback.print_exc()
        state["messages"].append(AIMessage(content=error_msg))
        
        # Ensure Docker cleanup even on error
        cleanup_docker_containers(state)
    
    return state


def cleanup_docker_containers(state) -> str:
    """Stop Docker containers gracefully"""
    docker_directory = state.get("docker_directory", "")
    docker_started = state.get("docker_started", False)
    
    if not docker_started or not docker_directory:
        return "ℹ️ No Docker containers to stop."
    
    try:
        print(f"\n🛑 Stopping Docker containers in {docker_directory}")
        
        stop_result = stop_docker_container(docker_directory)
        
        if stop_result.get("success"):
            state["docker_started"] = False
            return f"✅ Docker containers stopped successfully.\n{stop_result.get('message', '')}"
        else:
            return f"⚠️ Warning: Failed to stop Docker containers:\n{stop_result.get('message', 'Unknown error')}"
    
    except Exception as e:
        return f"⚠️ Warning: Error stopping Docker containers: {str(e)}"
