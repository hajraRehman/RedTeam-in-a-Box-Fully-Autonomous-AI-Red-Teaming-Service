
import json
from langchain_classic.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_community.chat_models import ChatOllama
from langchain_classic.memory import ConversationBufferMemory

from red_agent.agent_tools import tools

# Load configuration
with open('config.json', 'r') as f:
    config = json.load(f)

# Initialize ChatOllama with custom URL
llm = ChatOllama(
    model=config["MODEL_ID"],  # or your preferred model
    base_url=config["OLLAMA_NGROK"],  # Custom Ollama URL
    temperature=0.7
)

# Create React prompt template
template = """You are a security scanning assistant with access to reconnaissance and vulnerability scanning tools. 

CRITICAL RULES TO PREVENT INFINITE LOOPS:
1. NEVER call the same tool with the same input more than once until explicitly instructed otherwise
2. After gathering information from 3-5 tools, you MUST provide a Final Answer
3. If a tool fails or times out, document it and move on - DO NOT retry
4. Maximum tool calls per question: 6 tools
5. Once you have sufficient information, STOP and provide Final Answer

IMPORTANT: You are a ReAct (Reasoning + Acting) agent. This means:
1. You MUST think step-by-step before taking any action
2. You MUST use tools to gather information - don't make assumptions
3. You MUST reason about what tool to use and why
4. You can chain multiple tools together to accomplish complex tasks
5. After using tools, you MUST conclude with a Final Answer

Available tools:
{tools}

ALWAYS use this exact format:

Question: the input question you must answer
Thought: I need to analyze what the user is asking and decide which tool(s) to use. Let me break down the task...
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat 2-6 times MAX)
Thought: Based on all observations, I can now provide a comprehensive answer
Final Answer: the final answer to the original input question

REASONING GUIDELINES:
- If a tool fails, times out, or returns an error, acknowledge it and move to the next tool - DO NOT retry the same tool
- If given a URL/domain for nmap, first use URLtoIP to get the IP address
- Think about which tools are most appropriate for the request
- Nikto takes 10+ minutes - only use if specifically requested or for thorough scans
- For quick reconnaissance, use: DNSLookup, HTTPHeaders, QuickPortScan, Wappalyzer
- For detailed scans, add: Nmap, Nikto, SSLCertInfo, WHOIS
- After getting results from tools, analyze them and provide Final Answer
- ALWAYS provide a Final Answer after gathering information - do not keep looping
- You can use multiple tools in sequence to build a complete picture
- Always explain your reasoning in the Thought section

STOPPING CRITERIA:
- If you've used 6 or more tools, you MUST provide Final Answer immediately
- If you've gathered sufficient information to answer the question, provide Final Answer
- If multiple tools fail, provide Final Answer with available information
- Never call the same tool twice with the same input

Previous conversation:
{chat_history}

Question: {input}
Thought: {agent_scratchpad}"""

prompt = PromptTemplate(
    template=template,
    input_variables=["input", "agent_scratchpad", "chat_history"],
    partial_variables={"tools": "\n".join([f"{tool.name}: {tool.description}" for tool in tools]),
                      "tool_names": ", ".join([tool.name for tool in tools])}
)

# Initialize memory
memory = ConversationBufferMemory(
    memory_key="chat_history",
    return_messages=True,
    output_key="output"
)

# Create agent
agent = create_react_agent(llm, tools, prompt)

# Create agent executor with memory
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    memory=memory,
    verbose=True,
    handle_parsing_errors=True,
    max_iterations=25  # Reduced from 10 to 8 to prevent infinite loops
)

def red_agent_invoke(user_input: str) -> str:
    """Invoke the agent with user input and return the output"""
    try:
        response = agent_executor.invoke({"input": user_input})
        return response["output"]
    except Exception as e:
        return f"Error: {str(e)}"
    
def run_red_agent(user_input: str) -> str:
    """Run the red agent and return the response"""
    response = agent_executor.invoke({"input": user_input})
    return response['output']

# Main interaction loop
def main():
    print("Security Scanner Agent initialized!")
    print("Commands: 'scan [URL]', 'exit' to quit\n")
    
    while True:
        user_input = input("You: ").strip()
        
        if user_input.lower() == 'exit':
            print("Goodbye!")
            break
        
        if not user_input:
            continue
        
        try:
            response = agent_executor.invoke({"input": user_input})
            print(f"\nAgent: {response['output']}\n")
        except Exception as e:
            print(f"Error: {str(e)}\n")

if __name__ == "__main__":
    # Example usage
    print("Example: scan example.com with all tools")
    print("Example: what did you find in the last scan?")
    print("Example: convert github.com to IP")
    print("-" * 50)
    # main()
    run_red_agent("first use wappalzyer, finally nmap on this website: https://www.nu.edu.pk/ leave nikto")