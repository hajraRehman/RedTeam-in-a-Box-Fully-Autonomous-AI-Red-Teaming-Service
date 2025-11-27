"""
Tools for URL validation and Docker operations
"""
import subprocess
import os
import socket
import json
from pathlib import Path
from typing import Dict, Any
import yaml


def ping_url(url: str) -> Dict[str, Any]:
    """
    Ping a URL to check if it's accessible
    
    Args:
        url: The URL to ping (can include http/https or just domain)
    
    Returns:
        Dict with status and message
    """
    try:
        # Remove protocol if present
        clean_url = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Try to resolve the hostname first
        try:
            socket.gethostbyname(clean_url)
        except socket.gaierror:
            return {
                "success": False,
                "message": f"Cannot resolve hostname: {clean_url}"
            }
        
        # Ping the URL (Linux-specific, 4 packets)
        result = subprocess.run(
            ["ping", "-c", "4", clean_url],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return {
                "success": True,
                "message": f"✓ URL {clean_url} is accessible\n{result.stdout}"
            }
        else:
            return {
                "success": False,
                "message": f"✗ URL {clean_url} is not accessible\n{result.stderr}"
            }
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": f"Ping timeout for {url}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error pinging {url}: {str(e)}"
        }


def check_docker_files(directory: str) -> Dict[str, Any]:
    """
    Check if docker-compose file exists in directory
    
    Args:
        directory: Path to the directory to check
    
    Returns:
        Dict with found files and status
    """
    try:
        dir_path = Path(directory).resolve()
        
        if not dir_path.exists():
            return {
                "success": False,
                "message": f"Directory does not exist: {directory}"
            }
        
        if not dir_path.is_dir():
            return {
                "success": False,
                "message": f"Path is not a directory: {directory}"
            }
        
        # Check for docker-compose file
        compose_file = None
        for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
            if (dir_path / name).exists():
                compose_file = name
                break
        
        result = {
            "success": True,
            "directory": str(dir_path),
            "compose_file": compose_file,
            "message": ""
        }
        
        messages = []
        if compose_file:
            messages.append(f"✓ Found compose file: {compose_file}")
        else:
            messages.append("✗ No docker-compose file found")
            result["success"] = False
        
        result["message"] = "\n".join(messages)
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error checking directory: {str(e)}"
        }


def build_and_run_docker(directory: str) -> Dict[str, Any]:
    """
    Validate docker-compose file and extract localhost URL
    
    Args:
        directory: Path to directory containing docker-compose file
    
    Returns:
        Dict with validation status and localhost URL
    """
    try:
        dir_path = Path(directory).resolve()
        
        if not dir_path.exists():
            return {
                "success": False,
                "message": f"Directory does not exist: {directory}"
            }
        
        # Change to directory
        original_dir = os.getcwd()
        os.chdir(dir_path)
        
        try:
            # Check for compose file
            compose_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
            compose_file = None
            
            for cf in compose_files:
                if (dir_path / cf).exists():
                    compose_file = cf
                    break
            
            if not compose_file:
                return {
                    "success": False,
                    "message": "No docker-compose file found"
                }
            
            # Validate compose file with config
            config_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "config"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if config_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Docker compose config failed:\n{config_result.stderr}"
                }
            
            # Run dry-run to check if it would work
            dry_run_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "--dry-run", "up"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if dry_run_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Docker compose dry-run failed:\n{dry_run_result.stderr}"
                }
            
            # Extract port from compose config
            localhost_url = extract_port_from_compose_config(config_result.stdout)
            
            return {
                "success": True,
                "message": f"✓ Docker compose file is valid and ready to run\n{dry_run_result.stdout}",
                "localhost_url": localhost_url,
                "compose_config": config_result.stdout
            }
                
        finally:
            os.chdir(original_dir)
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Docker operation timed out"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error validating Docker compose: {str(e)}"
        }


def extract_port_from_output(output: str) -> str:
    """
    Extract localhost URL from docker output
    
    Args:
        output: Docker command output
    
    Returns:
        Localhost URL string
    """
    try:
        # Look for port mappings like "0.0.0.0:8080->80/tcp"
        import re
        pattern = r'0\.0\.0\.0:(\d+)'
        matches = re.findall(pattern, output)
        
        if matches:
            port = matches[0]
            return f"http://localhost:{port}"
        
        # Default fallback
        return "http://localhost:8080"
        
    except:
        return "http://localhost:8080"


def extract_port_from_compose_config(config_output: str) -> str:
    """
    Extract localhost URL from docker compose config output
    
    Args:
        config_output: Output from docker compose config
    
    Returns:
        Localhost URL string
    """
    try:
        import yaml
        
        # Parse the YAML config
        config = yaml.safe_load(config_output)
        
        if not config or 'services' not in config:
            return "http://localhost:8080"
        
        # Look through services for port mappings
        for service_name, service_config in config['services'].items():
            if 'ports' in service_config:
                ports = service_config['ports']
                if ports:
                    # Get the first port mapping
                    first_port = ports[0]
                    if isinstance(first_port, str):
                        # Format like "8080:80"
                        if ':' in first_port:
                            host_port = first_port.split(':')[0]
                            return f"http://localhost:{host_port}"
                    elif isinstance(first_port, dict):
                        # Format like {"target": 80, "published": 8080}
                        if 'published' in first_port:
                            return f"http://localhost:{first_port['published']}"
        
        # Default fallback
        return "http://localhost:8080"
        
    except Exception as e:
        # Fallback to regex if YAML parsing fails
        import re
        pattern = r'published:\s*(\d+)'
        matches = re.findall(pattern, config_output)
        if matches:
            return f"http://localhost:{matches[0]}"
        
        return "http://localhost:8080"


def ping_localhost(url: str) -> Dict[str, Any]:
    """
    Ping localhost URL to verify it's running
    
    Args:
        url: Localhost URL to check
    
    Returns:
        Dict with status
    """
    try:
        import requests
        
        response = requests.get(url, timeout=5)
        
        return {
            "success": True,
            "status_code": response.status_code,
            "message": f"✓ Localhost URL {url} is accessible (Status: {response.status_code})"
        }
        
    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "message": f"✗ Cannot connect to {url} - Connection refused"
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "message": f"✗ Timeout connecting to {url}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error checking {url}: {str(e)}"
        }


# Tool wrappers for LangChain
def ping_url_tool(url: str) -> str:
    """Ping a URL to check accessibility"""
    result = ping_url(url)
    return result["message"]


def check_docker_files_tool(directory: str) -> str:
    """Check for Docker files in directory"""
    result = check_docker_files(directory)
    return result["message"]


def build_and_run_docker_tool(directory: str) -> str:
    """Build and run Docker using docker-compose. Input should be an absolute directory path."""
    result = build_and_run_docker(directory)
    
    message = result["message"]
    if result["success"] and "localhost_url" in result:
        message += f"\n\nContainer is running at: {result['localhost_url']}"
    
    return message


def ping_localhost_tool(url: str) -> str:
    """Ping localhost URL to verify it's accessible"""
    result = ping_localhost(url)
    return result["message"]


def read_text_file(file_path: str) -> Dict[str, Any]:
    """
    Read contents of a text file
    
    Args:
        file_path: Path to the text file
    
    Returns:
        Dict with file contents and status
    """
    try:
        path = Path(file_path).resolve()
        
        if not path.exists():
            return {
                "success": False,
                "message": f"File does not exist: {file_path}"
            }
        
        if not path.is_file():
            return {
                "success": False,
                "message": f"Path is not a file: {file_path}"
            }
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {
            "success": True,
            "content": content,
            "message": f"Successfully read {len(content)} characters from {path.name}"
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error reading file: {str(e)}"
        }


def read_json_file(file_path: str) -> Dict[str, Any]:
    """
    Read and parse a JSON file
    
    Args:
        file_path: Path to the JSON file
    
    Returns:
        Dict with parsed JSON data and status
    """
    try:
        path = Path(file_path).resolve()
        
        if not path.exists():
            return {
                "success": False,
                "message": f"File does not exist: {file_path}"
            }
        
        if not path.is_file():
            return {
                "success": False,
                "message": f"Path is not a file: {file_path}"
            }
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return {
            "success": True,
            "data": data,
            "message": f"Successfully parsed JSON from {path.name}"
        }
        
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "message": f"Invalid JSON format: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error reading JSON file: {str(e)}"
        }


# Tool wrappers for file reading
def read_text_file_tool(file_path: str) -> str:
    """Read contents of a text file. Input should be an absolute file path."""
    result = read_text_file(file_path)
    if result["success"]:
        return f"{result['message']}\n\nContent:\n{result['content']}"
    return result["message"]


def read_json_file_tool(file_path: str) -> str:
    """Read and parse a JSON file. Input should be an absolute file path."""
    result = read_json_file(file_path)
    if result["success"]:
        import json
        formatted_json = json.dumps(result['data'], indent=2)
        return f"{result['message']}\n\nJSON Data:\n{formatted_json}"
    return result["message"]


def start_docker_container(directory: str) -> Dict[str, Any]:
    """
    Start Docker container using docker-compose up
    
    Args:
        directory: Path to directory containing docker-compose file
    
    Returns:
        Dict with status, localhost URL, and container info
    """
    try:
        dir_path = Path(directory).resolve()
        
        if not dir_path.exists():
            return {
                "success": False,
                "message": f"Directory does not exist: {directory}"
            }
        
        # Change to directory
        original_dir = os.getcwd()
        os.chdir(dir_path)
        
        try:
            # Find compose file
            compose_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
            compose_file = None
            
            for cf in compose_files:
                if (dir_path / cf).exists():
                    compose_file = cf
                    break
            
            if not compose_file:
                return {
                    "success": False,
                    "message": "No docker-compose file found"
                }
            
            # Get compose config to extract port
            config_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "config"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if config_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Docker compose config failed:\n{config_result.stderr}"
                }
            
            # Extract port from config
            localhost_url = extract_port_from_compose_config(config_result.stdout)
            
            # Start containers in detached mode
            print(f"🐳 Starting Docker containers from {compose_file}...")
            up_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "up", "-d"],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if up_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Docker compose up failed:\n{up_result.stderr}"
                }
            
            # Wait a few seconds for containers to be ready
            import time
            print("⏳ Waiting for containers to be ready...")
            time.sleep(5)
            
            # Verify containers are running
            ps_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "ps"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": True,
                "message": f"✓ Docker containers started successfully\n{up_result.stdout}\n{ps_result.stdout}",
                "localhost_url": localhost_url,
                "directory": str(dir_path),
                "compose_file": compose_file
            }
                
        finally:
            os.chdir(original_dir)
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Docker operation timed out"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error starting Docker containers: {str(e)}"
        }


def stop_docker_container(directory: str) -> Dict[str, Any]:
    """
    Stop Docker containers using docker-compose down
    
    Args:
        directory: Path to directory containing docker-compose file
    
    Returns:
        Dict with status
    """
    try:
        dir_path = Path(directory).resolve()
        
        if not dir_path.exists():
            return {
                "success": False,
                "message": f"Directory does not exist: {directory}"
            }
        
        # Change to directory
        original_dir = os.getcwd()
        os.chdir(dir_path)
        
        try:
            # Find compose file
            compose_files = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
            compose_file = None
            
            for cf in compose_files:
                if (dir_path / cf).exists():
                    compose_file = cf
                    break
            
            if not compose_file:
                return {
                    "success": False,
                    "message": "No docker-compose file found"
                }
            
            # Stop and remove containers
            print(f"🛑 Stopping Docker containers from {compose_file}...")
            down_result = subprocess.run(
                ["docker", "compose", "-f", compose_file, "down"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if down_result.returncode != 0:
                return {
                    "success": False,
                    "message": f"Docker compose down failed:\n{down_result.stderr}"
                }
            
            return {
                "success": True,
                "message": f"✓ Docker containers stopped successfully\n{down_result.stdout}"
            }
                
        finally:
            os.chdir(original_dir)
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "Docker operation timed out"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error stopping Docker containers: {str(e)}"
        }


def wait_for_service_ready(url: str, max_attempts: int = 30, delay: int = 2) -> Dict[str, Any]:
    """
    Wait for a service to be ready by polling the URL
    
    Args:
        url: URL to check
        max_attempts: Maximum number of attempts
        delay: Delay between attempts in seconds
    
    Returns:
        Dict with status
    """
    try:
        import requests
        import time
        
        print(f"⏳ Waiting for service at {url} to be ready...")
        
        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 500:  # Any non-server-error response means it's up
                    print(f"✓ Service is ready (attempt {attempt}/{max_attempts})")
                    return {
                        "success": True,
                        "message": f"✓ Service at {url} is ready (Status: {response.status_code})",
                        "status_code": response.status_code,
                        "attempts": attempt
                    }
            except requests.exceptions.RequestException:
                if attempt < max_attempts:
                    print(f"⏳ Attempt {attempt}/{max_attempts} - waiting {delay}s...")
                    time.sleep(delay)
                else:
                    return {
                        "success": False,
                        "message": f"✗ Service at {url} did not become ready after {max_attempts} attempts ({max_attempts * delay}s)"
                    }
        
        return {
            "success": False,
            "message": f"✗ Service at {url} is not responding"
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Error waiting for service: {str(e)}"
        }


# Tool wrappers for Docker management
def start_docker_container_tool(directory: str) -> str:
    """Start Docker containers using docker-compose. Input should be an absolute directory path."""
    result = start_docker_container(directory)
    
    message = result["message"]
    if result["success"] and "localhost_url" in result:
        message += f"\n\n🌐 Container is accessible at: {result['localhost_url']}"
    
    return message


def stop_docker_container_tool(directory: str) -> str:
    """Stop Docker containers using docker-compose. Input should be an absolute directory path."""
    result = stop_docker_container(directory)
    return result["message"]


def wait_for_service_tool(url: str) -> str:
    """Wait for a service to be ready at a URL. Input should be a localhost URL."""
    result = wait_for_service_ready(url)
    return result["message"]
