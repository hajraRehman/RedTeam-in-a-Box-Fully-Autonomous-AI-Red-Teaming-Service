"""
FastAPI Server for RedTeam-in-a-Box
Connects the web interface with the main agent
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import asyncio
import json
from pathlib import Path
from typing import Optional
import sys
import os

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import the main agent
from main import create_graph, AgentState
from langchain_core.messages import HumanMessage, AIMessage

# Initialize FastAPI app
app = FastAPI(
    title="RedTeam-in-a-Box API",
    description="AI-Powered Red Teaming Service",
    version="1.0.0"
)

# Configure CORS to allow requests from the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (for serving the HTML interface)
app.mount("/static", StaticFiles(directory="templates"), name="static")

# Initialize the agent graph
agent_graph = create_graph()

# Store conversation state per session (in production, use Redis or similar)
sessions = {}


class ChatRequest(BaseModel):
    query: str
    session_id: Optional[str] = "default"


class ChatResponse(BaseModel):
    response: str
    scan_status: Optional[str] = None
    localhost_url: Optional[str] = None


def get_or_create_session(session_id: str) -> AgentState:
    """Get existing session or create new one"""
    if session_id not in sessions:
        sessions[session_id] = {
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
    return sessions[session_id]


async def stream_agent_response(query: str, session_id: str):
    """Stream agent responses for real-time updates"""
    state = get_or_create_session(session_id)
    
    # Add user message
    state["messages"].append(HumanMessage(content=query))
    
    # First, send a warning about scan duration
    initial_message = "🔍 **Processing your request...**\n\n"
    
    # Check if this looks like a scan request
    if any(keyword in query.lower() for keyword in ["scan", "test", "check", "analyze", "url", "http"]):
        initial_message += "⏱️ **Note:** Full security scans can take **up to 10 minutes** to complete.\n"
        initial_message += "This includes reconnaissance, vulnerability detection, and comprehensive analysis.\n\n"
    
    yield f"data: {json.dumps({'type': 'status', 'content': initial_message})}\n\n"
    
    try:
        # Run the agent (this may take time)
        result = agent_graph.invoke(state)
        
        # Update session state
        sessions[session_id] = result
        
        # Get the last AI message
        last_ai_message = None
        for msg in reversed(result["messages"]):
            if isinstance(msg, AIMessage):
                last_ai_message = msg
                break
        
        if last_ai_message:
            response_text = last_ai_message.content
            
            # Add localhost URL if available
            if result.get("localhost_url"):
                response_text += f"\n\n✅ **Container accessible at:** {result['localhost_url']}"
            
            yield f"data: {json.dumps({'type': 'complete', 'content': response_text})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'error', 'content': 'No response generated'})}\n\n"
            
    except Exception as e:
        error_msg = f"❌ **Error:** {str(e)}\n\nPlease try again or rephrase your request."
        yield f"data: {json.dumps({'type': 'error', 'content': error_msg})}\n\n"


@app.post("/chat")
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint
    Processes user queries and returns agent responses
    """
    try:
        # Get or create session state
        state = get_or_create_session(request.session_id)
        
        # Add user message
        state["messages"].append(HumanMessage(content=request.query))
        
        # Prepare response with scan time warning
        scan_warning = ""
        if any(keyword in request.query.lower() for keyword in ["scan", "test", "check", "analyze", "url", "http"]):
            scan_warning = "⏱️ **Note:** Full security scans can take **up to 10 minutes** to complete.\n\n"
        
        # Run the agent
        result = agent_graph.invoke(state)
        
        # Update session state
        sessions[request.session_id] = result
        
        # Extract the last AI message
        last_ai_message = None
        for msg in reversed(result["messages"]):
            if isinstance(msg, AIMessage):
                last_ai_message = msg
                break
        
        if last_ai_message:
            response_text = scan_warning + last_ai_message.content
            
            return ChatResponse(
                response=response_text,
                scan_status="completed",
                localhost_url=result.get("localhost_url")
            )
        else:
            return ChatResponse(
                response="No response generated. Please try again.",
                scan_status="failed"
            )
            
    except Exception as e:
        error_message = f"❌ **Error:** {str(e)}\n\nPlease try again or check your input."
        return ChatResponse(
            response=error_message,
            scan_status="error"
        )


@app.post("/chat/stream")
async def chat_stream(request: ChatRequest):
    """
    Streaming chat endpoint for real-time updates
    """
    return StreamingResponse(
        stream_agent_response(request.query, request.session_id),
        media_type="text/event-stream"
    )


@app.get("/")
async def serve_index():
    """Serve the main HTML interface"""
    return FileResponse("templates/index.html")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "RedTeam-in-a-Box API",
        "version": "1.0.0",
        "active_sessions": len(sessions)
    }


@app.delete("/session/{session_id}")
async def clear_session(session_id: str):
    """Clear a specific session"""
    if session_id in sessions:
        del sessions[session_id]
        return {"message": f"Session {session_id} cleared"}
    return {"message": "Session not found"}


@app.get("/sessions")
async def list_sessions():
    """List all active sessions (for debugging)"""
    return {
        "active_sessions": list(sessions.keys()),
        "total": len(sessions)
    }


if __name__ == "__main__":
    import uvicorn
    
    print("=" * 70)
    print("🚀 Starting RedTeam-in-a-Box API Server")
    print("=" * 70)
    print("\n📍 Server will be available at:")
    print("   • API: http://localhost:8000")
    print("   • Web Interface: http://localhost:8000")
    print("   • API Docs: http://localhost:8000/docs")
    print("\n⏱️  Note: Security scans may take up to 10 minutes")
    print("=" * 70)
    print()
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
