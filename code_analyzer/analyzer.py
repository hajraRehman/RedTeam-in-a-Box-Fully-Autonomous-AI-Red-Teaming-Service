import requests
import json
import os
import re
from langchain_community.document_loaders import TextLoader

with open('config.json', 'r') as f:
    config = json.load(f)

# Configuration
OLLAMA_NGROK = config.get("OLLAMA_NGROK")
MODEL_ID = config.get("MODEL_ID")

class CodespaceSecurityAnalyzer:
    def __init__(self):
        self.ollama_url = f"{OLLAMA_NGROK}/api/generate"
        self.model = MODEL_ID
        self.benchmark_repo = "./validation-benchmarks"
    
    def check_dependencies(self, codespace_path):
        """Check for outdated dependencies and language versions"""
        dependency_info = []
    
        # Check for common dependency files
        dependency_files = {
        'requirements.txt': 'Python',
        'package.json': 'Node.js', 
        'composer.json': 'PHP',
        'pom.xml': 'Java',
        'build.gradle': 'Java',
        'Gemfile': 'Ruby',
        'Cargo.toml': 'Rust'
        }
    
        for dep_file, language in dependency_files.items():
            file_path = os.path.join(codespace_path, dep_file)
            if os.path.exists(file_path):
                dependency_info.append(f" {language} dependencies found: {dep_file}")
    
        # Check Python version in code files
        python_files = [f for f in os.listdir(codespace_path) if f.endswith('.py')]
        if python_files:
            dependency_info.append(" Python code detected - check Python version compatibility")
    
        # Check for Dockerfile
        if any(f.lower().startswith('dockerfile') for f in os.listdir(codespace_path)):
            dependency_info.append(" Docker configuration found - check base image versions")
    
        return dependency_info


    def get_codespace_path(self, user_input):
        """Handle any codebase path provided by user"""
    
        # If it's a full path that exists, use it directly
        if os.path.exists(user_input):
            return user_input
    
        # If it's a relative path
        if os.path.exists(os.path.join(os.getcwd(), user_input)):
           return os.path.join(os.getcwd(), user_input)
    
        # Check if it's a codespace name in benchmark repo (for backward compatibility)
        benchmark_paths = [
             os.path.join(self.benchmark_repo, "benchmarks", user_input),
             os.path.join(self.benchmark_repo, user_input),
        ]
    
        for path in benchmark_paths:
            if os.path.exists(path):
                return path
    
        # Path not found
        print(f" Path not found: {user_input}")
        print("  Please provide a full path to your codebase folder")
        return None   
    def list_available_codespaces(self):
        """Show all available codespaces in the benchmark repo"""
        benchmarks_path = os.path.join(self.benchmark_repo, "benchmarks")
        if os.path.exists(benchmarks_path):
            codespaces = os.listdir(benchmarks_path)
            for cs in codespaces:
                print(f"  - {cs}")
        else:
            print("  No benchmarks found. Make sure validation-benchmarks repo is cloned.")
    
    def analyze_codespace_with_ai(self, codespace_path):
        """Analyze all files in a specific codespace"""
        print(f"Analyzing codespace: {codespace_path}")
        
        # Find all files in the codespace
        all_files = []
        for root, dirs, files in os.walk(codespace_path):
            for file in files:
                # Fixed: Check if file has extension and it's in our list
                if len(file.split(".")) > 1 and file.split(".")[-1].strip().lower() in ["py", "js", "html", "php"]:
                    all_files.append(os.path.join(root, file))
        
        print(f"Found {len(all_files)} code files")
        
        # FIX: Get dependency info once and pass it to generate_text_report
        dependency_info = self.check_dependencies(codespace_path)
        if dependency_info:
            print("Dependency Information:")
            for info in dependency_info:
                print(f"  {info}")
        
        if not all_files:
            return "No code files found in this codespace."
        
        # FIX: Pass dependency_info to generate_text_report
        report = self.generate_text_report(all_files, codespace_path, dependency_info)
        return report
    
    def generate_text_report(self, all_files, codespace_path=None, dependency_info=None):
        """Generate a clean text security report"""
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("AUTO-RED-TEAM SECURITY ANALYSIS REPORT")
        report_lines.append("=" * 70)
        report_lines.append("")
        
        # FIX: Use the provided dependency_info instead of calling check_dependencies again
        if dependency_info:
            report_lines.append("DEPENDENCY CHECK:")
            report_lines.append("-" * 50)
            for info in dependency_info:
                report_lines.append(f"  {info}")
            report_lines.append("  💡 Recommendation: Regularly update dependencies for security patches")
            report_lines.append("")

        
        for file_path in all_files:
            # FIX: Use absolute path if relative path fails
            try:
                relative_path = os.path.relpath(file_path, self.benchmark_repo)
            except:
                relative_path = file_path  # Fallback to full path
            
            report_lines.append(f"[[FILE: {relative_path}]]")
            report_lines.append("-" * 20)
            
            try:
                with open(file_path, 'r', encoding='ascii', errors='ignore') as f:
                    content = f.read()[:1500]
                
                # Perform AI analysis on the content
                ai_analysis = self.analyze_with_ai(relative_path, content)
                report_lines.append(ai_analysis)

                report_lines.append("\n\n")  # Empty line between files
            
            except Exception as e:
                report_lines.append(f" Error analyzing file: {e}")
                report_lines.append("")
        
        # Summary
        report_lines.append("=" * 70)
        report_lines.append("SUMMARY")
        report_lines.append("=" * 70)
        report_lines.append(f"Total Files Analyzed: {len(all_files)}")
        report_lines.append("")
        
        return "\n".join(report_lines)
    
    def quick_scan(self, code_content):
        """Quick regex scan to find suspicious patterns"""
        dangerous_patterns = [
            r'os\.system\(', r'eval\(', r'exec\(', r'subprocess\.',
            r'pickle\.loads\(', r'yaml\.load\(', r'render_template_string\(',
            r'password\s*=\s*["\']', r'api_key\s*=\s*["\']', r'secret_key\s*=\s*["\']',
            r'\.\./', r'requests\.get\(', r'urllib\.request\.urlopen\('
        ]
        
        found_patterns = []
        for pattern in dangerous_patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                found_patterns.append(pattern)
        
        return found_patterns
    
    def analyze_with_ai(self, file_path, code_snippet):
        """Use AI for detailed vulnerability analysis"""
        prompt = f"""
        You are a cybersecurity expert. Analyze this all code for ATLEAST one most critical security vulnerability .
        
        File: {file_path}
        Code: {code_snippet}
        
        Respond in this EXACT format (no JSON, just plain text):
        
        VULNERABILITY: [Type of vulnerability]
        SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]
        LOCATION: [File and line reference]
        DESCRIPTION: [1-2 sentences explaining the issue]
        RISK: [What attackers could do]
        FIX: [Specific code fix suggestion]
        EXAMPLE: [Safe code example]
        
        Be concise and direct. Only report actual security issues. 
        Also in the end write the summary of ALL the vulnerabilities and how they can effect in just 3 to 4 lines.
        """
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.3}
        }
        
        try:
            response = requests.post(self.ollama_url, json=payload, timeout=45)
            if response.status_code == 200:
                return response.json()['response']
            else:
                return f"AI Analysis Error: {response.status_code}"
        except Exception as e:
            return f"AI Connection Error: {e}"
        
def analyze_codespace_with_ai(codespace_path):
    analyzer = CodespaceSecurityAnalyzer()

    # Analyze the provided codebase path directly
    print(f"\nAnalyzing codebase: {codespace_path}...")
    report = analyzer.analyze_codespace_with_ai(codespace_path)
    
    # Generate a safe filename from the path
    safe_name = os.path.basename(codespace_path) or "codebase"
    report_filename = f"/home/redi02/Desktop/Hackathon/RedTeam-in-a-Box-Fully-Autonomous-AI-Red-Teaming-Service/security_report_{safe_name}.txt"
    
    # Save report to file
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report)

    return f"This is the security report saved at: {report_filename} for codespace: {codespace_path}"

def main():
    print("CODESPACE SECURITY ANALYZER")
    print("=" * 50)
    print("This tool can analyze ANY codebase on your system")
    print("Just provide the full path to the folder containing code")
    print("=" * 50)
    
    analyzer = CodespaceSecurityAnalyzer()
    
    while True:
        # Get user input for ANY codebase path
        print("\n Enter the full path to your codebase folder")
        print("   Examples:")
        print("   - /home/user/my_project")
        print("   - C:\\Users\\user\\projects\\my_app") 
        print("   - ./my_local_project")
        print("")
        
        user_input = input("Enter codebase path (or 'exit' to quit): ").strip()
        
        if user_input.lower() == 'exit':
            print(" Goodbye!")
            break
        
        if not user_input:
            continue
        
        # Check if path exists
        if not os.path.exists(user_input):
            print(f" Path does not exist: {user_input}")
            print(" Please check the path and try again")
            continue
        
        if not os.path.isdir(user_input):
            print(f" Not a directory: {user_input}")
            print(" Please provide a folder path, not a file")
            continue
        
        # Analyze the provided codebase path directly
        print(f"\nAnalyzing codebase: {user_input}...")
        report = analyzer.analyze_codespace_with_ai(user_input)
        
        # Generate a safe filename from the path
        safe_name = os.path.basename(user_input) or "codebase"
        report_filename = f"security_report_{safe_name}.txt"
        
        # Save report to file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Show report preview
        print("\n" + "=" * 70)
        print("SECURITY REPORT GENERATED!")
        print("=" * 70)
        print(report[:500] + "..." if len(report) > 500 else report)
        print(f"\nFull report saved to: {report_filename}")
        print("=" * 70 + "\n")

if __name__ == "__main__":
    main()