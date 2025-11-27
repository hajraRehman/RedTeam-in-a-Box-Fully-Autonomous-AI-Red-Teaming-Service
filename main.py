"""
LangGraph-based URL/Docker Validation Agent
Features:
- Main agent for chat and history
- ReAct sub-agent for tool calling
- URL validation via ping
- Docker build and run from directory
- Conversation history management
"""

import json
import os
from typing import TypedDict, Annotated, Sequence
from pathlib import Path

from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_community.chat_models import ChatOllama
from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_core.tools import Tool

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

# Import our custom tools
from tools import (
    ping_url_tool,
    check_docker_files_tool,
    build_and_run_docker_tool,
    ping_localhost_tool,
    read_text_file_tool,
    read_json_file_tool,
    start_docker_container_tool,
    stop_docker_container_tool,
    wait_for_service_tool
)

# Import scanning workflows
from scanning_workflows import handle_url_scanning, handle_directory_scanning, cleanup_docker_containers

# Import red agent
import sys
sys.path.append(str(Path(__file__).parent / "red_agent"))
from red_agent.agent import run_red_agent

# Import code analyzer
sys.path.append(str(Path(__file__).parent / "code_analyzer"))
from code_analyzer.analyzer import analyze_codespace_with_ai


# Load configuration
def load_config():
    """Load configuration from config.json"""
    config_path = Path(__file__).parent / "config.json"
    with open(config_path, "r") as f:
        return json.load(f)


config = load_config()
OLLAMA_NGROK = config.get("OLLAMA_NGROK")
MODEL_ID = config.get("MODEL_ID")


# Define the state for our graph
class AgentState(TypedDict):
    """State for the LangGraph agent"""
    messages: Annotated[Sequence[BaseMessage], add_messages]
    input_type: str  # "url" or "directory" or "chat"
    validation_result: str
    localhost_url: str
    validated_url: str  # Store the validated URL for red agent scan
    user_intent: str  # Store user's original intent/query
    scan_result: str  # Store red agent scan results
    crawler_result: str  # Store crawler scan results
    crawler_txt_file: str  # Path to crawler txt results
    crawler_json_file: str  # Path to crawler json results
    docker_directory: str  # Store directory path for Docker cleanup
    docker_started: bool  # Track if Docker was started by us
    code_analysis_result: str  # Store code analysis report path
    cve_report_file: str  # Path to CVE report file


# Initialize LLM
def create_llm():
    """Create ChatOllama instance"""
    return ChatOllama(
        model=MODEL_ID,
        base_url=OLLAMA_NGROK,
        temperature=0.7,
    )


# Define tools for ReAct agent
tools = [
    Tool(
        name="PingURL",
        func=ping_url_tool,
        description="Ping a URL to check if it's accessible. Input should be a URL (e.g., 'example.com' or 'https://example.com')"
    ),
    Tool(
        name="CheckDockerFiles",
        func=check_docker_files_tool,
        description="Check if docker-compose file exists in a directory. Input should be an absolute directory path."
    ),
    Tool(
        name="BuildAndRunDocker",
        func=build_and_run_docker_tool,
        description="Validate docker-compose file and extract localhost URL. Input should be an absolute directory path containing a docker-compose file."
    ),
    Tool(
        name="PingLocalhost",
        func=ping_localhost_tool,
        description="Check if a localhost URL is accessible. Input should be a localhost URL (e.g., 'http://localhost:8080')"
    ),
    Tool(
        name="ReadTextFile",
        func=read_text_file_tool,
        description="Read contents of a text file. Input should be an absolute file path to a .txt file."
    ),
    Tool(
        name="ReadJSONFile",
        func=read_json_file_tool,
        description="Read and parse a JSON file. Input should be an absolute file path to a .json file."
    ),
    Tool(
        name="StartDockerContainer",
        func=start_docker_container_tool,
        description="Start Docker containers using docker-compose. Input should be an absolute directory path containing docker-compose file."
    ),
    Tool(
        name="StopDockerContainer",
        func=stop_docker_container_tool,
        description="Stop Docker containers using docker-compose. Input should be an absolute directory path containing docker-compose file."
    ),
    Tool(
        name="WaitForService",
        func=wait_for_service_tool,
        description="Wait for a service to be ready at a URL. Input should be a localhost URL (e.g., 'http://localhost:8080')."
    )
]


# Create ReAct agent for tool calling
def create_react_agent_executor():
    """Create ReAct agent for tool calling"""
    
    template = """You are a helpful assistant that validates URLs and manages Docker containers.

You have access to these tools:
{tools}

IMPORTANT INSTRUCTIONS:
1. When user provides a URL, use PingURL to check if it's accessible
2. When user provides a directory path:
   - First use CheckDockerFiles to verify docker-compose file exists
   - If compose file exists, use BuildAndRunDocker to validate the file and extract localhost URL
   - Do not start containers here - just validate
3. Provide clear, concise responses
4. Always summarize what you found

Use this format:

Question: the input question you must answer
Thought: think about what tools to use
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat as needed)
Thought: I now have enough information
Final Answer: the final answer summarizing the results

Question: {input}
Thought: {agent_scratchpad}"""

    prompt = PromptTemplate(
        template=template,
        input_variables=["input", "agent_scratchpad"],
        partial_variables={
            "tools": "\n".join([f"{tool.name}: {tool.description}" for tool in tools]),
            "tool_names": ", ".join([tool.name for tool in tools])
        }
    )
    
    llm = create_llm()
    agent = create_react_agent(llm, tools, prompt)
    
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=10
    )
    
    return agent_executor


# Node functions for LangGraph
def input_classifier(state: AgentState) -> AgentState:
    """Classify the input type using AI agent (URL, directory, or chat)"""
    messages = state["messages"]
    last_message = messages[-1].content if messages else ""
    
    # Create LLM for classification
    llm = create_llm()
    
    # Classification prompt
    classification_prompt = f"""You are an intelligent input classifier. Analyze the user's message and determine:
1. If it contains a URL (http://, https://, or domain like example.com)
2. If it contains a directory/file path (absolute or relative paths)
3. If it's a general chat message

User message: "{last_message}"

Analyze the message and respond with ONLY ONE of these formats:

If URL is found:
URL: <extracted_url>

If directory path is found:
DIRECTORY: <extracted_path>

If it's general chat (questions, greetings, follow-ups):
CHAT

Important:
- Extract the actual URL or path from the message, even if surrounded by text
- URLs can be domains like "google.com" or full URLs like "https://example.com"
- Paths can be like "/home/user/project" or "./myapp" or "~/documents/app"
- If both URL and directory are present, prioritize based on context
- If user asks to "check", "validate", "test" a URL, extract the URL
- If user asks to "build", "run", "deploy" from directory, extract the path

Respond now:"""

    try:
        response = llm.invoke([HumanMessage(content=classification_prompt)])
        classification = response.content.strip()
        
        # Parse the classification response
        if classification.startswith("URL:"):
            input_type = "url"
            extracted_url = classification.replace("URL:", "").strip()
            # Update the last message to just the URL for the ReAct agent
            state["messages"][-1] = HumanMessage(content=extracted_url)
            
        elif classification.startswith("DIRECTORY:"):
            input_type = "directory"
            extracted_path = classification.replace("DIRECTORY:", "").strip()
            # Expand user paths and make absolute
            expanded_path = os.path.expanduser(extracted_path)
            if not os.path.isabs(expanded_path):
                expanded_path = os.path.abspath(expanded_path)
            # Update the last message to just the directory for the ReAct agent
            state["messages"][-1] = HumanMessage(content=expanded_path)
            
        elif classification.startswith("CHAT"):
            input_type = "chat"
            
        else:
            # Fallback: try to detect from classification text
            if "url" in classification.lower() or "http" in classification.lower():
                input_type = "url"
            elif "directory" in classification.lower() or "path" in classification.lower():
                input_type = "directory"
            else:
                input_type = "chat"
        
        state["input_type"] = input_type
        
    except Exception as e:
        # Fallback to simple keyword detection if AI classification fails
        print(f"⚠️  Classification AI error: {str(e)}, using fallback...")
        if any(keyword in last_message.lower() for keyword in ["http://", "https://", ".com", ".org", ".net"]):
            input_type = "url"
        elif any(keyword in last_message.lower() for keyword in ["directory", "folder", "path", "/"]) or Path(last_message.strip()).exists():
            input_type = "directory"
        else:
            input_type = "chat"
        
        state["input_type"] = input_type
    
    return state


def react_agent_node(state: AgentState) -> AgentState:
    """Execute ReAct agent for tool calling"""
    messages = state["messages"]
    last_message = messages[-1].content if messages else ""
    
    # Store original user intent before classification modifies the message
    if not state.get("user_intent"):
        # Find the original user message before it was modified by classifier
        for msg in reversed(messages[:-1]):
            if isinstance(msg, HumanMessage):
                state["user_intent"] = msg.content
                break
        if not state.get("user_intent"):
            state["user_intent"] = last_message
    
    # Create agent executor
    agent_executor = create_react_agent_executor()
    
    # Run the agent
    try:
        result = agent_executor.invoke({"input": last_message})
        output = result["output"]
        
        # Store validation result
        state["validation_result"] = output
        
        # Extract localhost URL if present
        if "localhost" in output:
            import re
            matches = re.findall(r'http://localhost:\d+', output)
            if matches:
                state["localhost_url"] = matches[0]
        
        # Store validated URL for later use
        if state["input_type"] == "url" and "accessible" in output.lower():
            state["validated_url"] = last_message
        
        # Add AI message to history
        state["messages"].append(AIMessage(content=output))
        
    except Exception as e:
        error_msg = f"Error executing tools: {str(e)}"
        state["messages"].append(AIMessage(content=error_msg))
        state["validation_result"] = error_msg
    
    return state


def chat_agent_node(state: AgentState) -> AgentState:
    """Handle general chat without tools"""
    messages = state["messages"]
    
    # Create a simple chat prompt
    llm = create_llm()
    
    system_message = SystemMessage(content="""You are a helpful assistant for URL validation, Docker management, and security scanning.
    
You help users:
- Validate URLs by pinging them
- Check Docker files in directories
- Validate Docker compose configurations
- Perform security scans on URLs
- Analyze and explain security scan results
- Answer questions about previous operations

Be friendly, concise, and helpful. Reference conversation history when relevant.
If there are security scan results, help interpret them and highlight important findings.""")
    
    # Add system message if not already present
    if not any(isinstance(msg, SystemMessage) for msg in messages):
        messages.insert(0, system_message)
    
    # Get response from LLM
    try:
        response = llm.invoke(messages)
        state["messages"].append(AIMessage(content=response.content))
    except Exception as e:
        error_msg = f"Error in chat: {str(e)}"
        state["messages"].append(AIMessage(content=error_msg))
    
    return state


def main_agent_node(state: AgentState) -> AgentState:
    """Main agent that plans and executes actions including calling red agent and crawler for URL scans"""
    messages = state["messages"]
    input_type = state.get("input_type", "")
    validation_result = state.get("validation_result", "")
    validated_url = state.get("validated_url", "")
    user_intent = state.get("user_intent", "")
    
    llm = create_llm()
    
    system_message = SystemMessage(content="""You are the main orchestrator agent for URL validation, Docker management, and comprehensive security scanning.

Your responsibilities:
1. Understand user intent and context
2. Plan appropriate actions based on validation results
3. For URLs: Call security scanning tools (Red Agent + Advanced Crawler)
4. For Directories (Docker apps): 
   - Start Docker containers
   - Extract localhost URL (e.g., http://localhost:8080)
   - Run crawler on the localhost URL
   - Stop Docker containers after scanning
5. Read and analyze scan result files (TXT and JSON)
6. Provide comprehensive responses combining all scan results
7. Maintain conversation history and context

Available security scanning capabilities:
- RED AGENT: Reconnaissance scanning (Wappalyzer, DNSLookup, HTTPHeaders, QuickPortScan, Nmap, WHOIS, SSLCertInfo, RobotsTxt)
- ADVANCED CRAWLER: Comprehensive vulnerability scanning (XSS, SQL Injection, CSRF, Weak Auth, Info Disclosure, etc.)

Workflow for URL scanning:
1. Validate URL accessibility
2. Run Red Agent for reconnaissance
3. Run Advanced Crawler for vulnerability detection
4. Read both TXT and JSON results
5. Provide comprehensive analysis combining all findings

Workflow for Directory scanning:
1. Validate Docker compose file
2. Start Docker containers
3. Wait for service to be ready at localhost URL
4. Extract localhost URL (e.g., http://localhost:8080)
5. Run Red Agent for reconnaissance on localhost URL
6. Run Advanced Crawler for vulnerability detection on localhost URL
7. Stop Docker containers gracefully
8. Read both TXT and JSON results
9. Provide comprehensive analysis

Be helpful, thorough, and provide actionable security insights.""")
    
    # Add system message if not already present
    if not any(isinstance(msg, SystemMessage) for msg in messages):
        messages.insert(0, system_message)
    
    # Check if we have a validated URL that needs security scanning
    if input_type == "url" and validated_url and "accessible" in validation_result.lower():
        try:
            return handle_url_scanning(state, llm, validated_url, user_intent)
        except Exception as e:
            error_msg = f"Error during security scan: {str(e)}"
            print(f"⚠️ {error_msg}")
            import traceback
            traceback.print_exc()
            state["messages"].append(AIMessage(content=error_msg))
    
    # Check if we have a validated directory that needs Docker + scanning
    elif input_type == "directory" and "valid" in validation_result.lower():
        try:
            # Get localhost URL from state
            localhost_url = state.get("localhost_url", "")
            if localhost_url:
                return handle_directory_scanning(state, llm, localhost_url, user_intent, validation_result)
            else:
                state["messages"].append(AIMessage(content="❌ Could not extract localhost URL from Docker validation."))
        except Exception as e:
            error_msg = f"Error during directory scanning: {str(e)}"
            print(f"⚠️ {error_msg}")
            import traceback
            traceback.print_exc()
            state["messages"].append(AIMessage(content=error_msg))
            # Ensure Docker cleanup
            cleanup_docker_containers(state)
    
    else:
        # For non-URL/directory cases or general chat, just provide a helpful response
        try:
            response = llm.invoke(messages)
            state["messages"].append(AIMessage(content=response.content))
        except Exception as e:
            error_msg = f"Error in main agent: {str(e)}"
            state["messages"].append(AIMessage(content=error_msg))
    
    return state


def router(state: AgentState) -> str:
    """Route to appropriate node based on input type"""
    input_type = state.get("input_type", "chat")
    
    if input_type in ["url", "directory"]:
        return "react_agent"
    else:
        return "chat_agent"


def post_validation_router(state: AgentState) -> str:
    """Route after validation - always go to main agent for planning and execution"""
    return "main_agent"


# Build the graph
def create_graph():
    """Create the LangGraph workflow"""
    
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("classifier", input_classifier)
    workflow.add_node("react_agent", react_agent_node)
    workflow.add_node("chat_agent", chat_agent_node)
    workflow.add_node("main_agent", main_agent_node)
    
    # Add edges
    workflow.set_entry_point("classifier")
    
    # Route from classifier to react_agent or chat_agent
    workflow.add_conditional_edges(
        "classifier",
        router,
        {
            "react_agent": "react_agent",
            "chat_agent": "chat_agent"
        }
    )
    
    # After react_agent, route to main_agent
    workflow.add_conditional_edges(
        "react_agent",
        post_validation_router,
        {
            "main_agent": "main_agent"
        }
    )
    
    # Both main_agent and chat_agent end
    workflow.add_edge("main_agent", END)
    workflow.add_edge("chat_agent", END)
    
    return workflow.compile()


# Main interaction loop
def main():
    """Main function to run the agent"""
    print("=" * 70)
    print("🤖 URL/Docker Validation Agent (LangGraph)")
    print("=" * 70)
    print("\nI can help you with:")
    print("  • Validating URLs and performing security scans")
    print("  • Scanning Docker web applications:")
    print("    - Provide directory path with docker-compose file")
    print("    - I'll start containers, extract localhost URL")
    print("    - Run crawler on localhost URL")
    print("    - Stop containers after scanning")
    print("  • General questions and follow-up discussions")
    print("\nType 'exit' or 'quit' to stop")
    print("=" * 70)
    print()
    
    # Create the graph
    graph = create_graph()
    
    # Initialize state
    state = {
        "messages": [],
        "input_type": "",
        "validation_result": "",
        "localhost_url": "",
        "validated_url": "",
        "user_intent": "",
        "scan_result": "",
        "crawler_result": "",
        "crawler_txt_file": "",
        "crawler_json_file": "",
        "docker_directory": "",
        "docker_started": False,
        "code_analysis_result": "",
        "cve_report_file": ""
    }
    
    while True:
        try:
            user_input = input("\n🧑 You: ").strip()
            
            if user_input.lower() in ["exit", "quit", "bye"]:
                print("\n👋 Goodbye! Have a great day!")
                break
            
            if not user_input:
                continue
            
            # Add user message to state
            state["messages"].append(HumanMessage(content=user_input))
            
            # Run the graph
            result = graph.invoke(state)
            
            # Update state with result
            state = result
            
            # Print the last AI message
            last_ai_message = None
            for msg in reversed(state["messages"]):
                if isinstance(msg, AIMessage):
                    last_ai_message = msg
                    break
            
            if last_ai_message:
                print(f"\n🤖 Agent: {last_ai_message.content}")
            
            # Show validation info if available
            if state.get("localhost_url"):
                print(f"\n✅ Container accessible at: {state['localhost_url']}")
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")
            print("Please try again.")


if __name__ == "__main__":
    main()
