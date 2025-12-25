"""
Gemini API Proxy - OpenAI & Anthropic Compatible API for Google Gemini

A reverse-proxy that exposes Google's Gemini Code Assist API as OpenAI and Anthropic
compatible endpoints. Supports all Gemini Code Assist models with rate limiting and usage tracking.
"""

import os
import json
import uuid
import time
import hashlib
import base64
import secrets
import asyncio
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from urllib.parse import urlencode
from collections import deque
import threading

from fastapi.middleware.cors import CORSMiddleware

# =============================================================================
# Configuration
# =============================================================================

CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
CLIENT_SECRET = "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"
SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
]
REDIRECT_URI = "https://codeassist.google.com/authcode"
TOKEN_FILE = os.environ.get("TOKEN_FILE", "google_token.json")
PORT = int(os.environ.get("PORT", 8081))
HOST = os.environ.get("HOST", "0.0.0.0")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", 0))  # Seconds between requests (0 = disabled)
WAIT_MODE = os.environ.get("WAIT_MODE", "false").lower() == "true"
SHOW_TOKEN = os.environ.get("SHOW_TOKEN", "false").lower() == "true"

VERSION = "0.7.5"

# =============================================================================
# Available Models
# =============================================================================

GEMINI_MODELS = [
    {
        "id": "gpt-gemini-2.5-pro",
        "object": "model",
        "type": "model",
        "created": 1718668800,
        "created_at": "2024-06-17T00:00:00.000Z",
        "owned_by": "openai",
        "display_name": "Gemini 2.5 Pro",
        "root": "gpt-gemini-2.5-pro",
        "parent": None,
        "permission": [{
            "id": "modelperm-gpt-gemini-2.5-pro",
            "object": "model_permission",
            "created": 1718668800,
            "allow_create_engine": False,
            "allow_sampling": True,
            "allow_logprobs": True,
            "allow_search_indices": False,
            "allow_view": True,
            "allow_fine_tuning": False,
            "organization": "*",
            "group": None,
            "is_blocking": False
        }]
    },
    {
        "id": "gpt-gemini-2.5-flash",
        "object": "model",
        "type": "model",
        "created": 1718668800,
        "created_at": "2024-06-17T00:00:00.000Z",
        "owned_by": "openai",
        "display_name": "Gemini 2.5 Flash",
        "root": "gpt-gemini-2.5-flash",
        "parent": None,
        "permission": [{
            "id": "modelperm-gpt-gemini-2.5-flash",
            "object": "model_permission",
            "created": 1718668800,
            "allow_create_engine": False,
            "allow_sampling": True,
            "allow_logprobs": True,
            "allow_search_indices": False,
            "allow_view": True,
            "allow_fine_tuning": False,
            "organization": "*",
            "group": None,
            "is_blocking": False
        }]
    },
    {
        "id": "gpt-gemini-2.5-flash-lite",
        "object": "model",
        "type": "model",
        "created": 1718668800,
        "created_at": "2024-06-17T00:00:00.000Z",
        "owned_by": "openai",
        "display_name": "Gemini 2.5 Flash Lite",
        "root": "gpt-gemini-2.5-flash-lite",
        "parent": None,
        "permission": [{
            "id": "modelperm-gpt-gemini-2.5-flash-lite",
            "object": "model_permission",
            "created": 1718668800,
            "allow_create_engine": False,
            "allow_sampling": True,
            "allow_logprobs": True,
            "allow_search_indices": False,
            "allow_view": True,
            "allow_fine_tuning": False,
            "organization": "*",
            "group": None,
            "is_blocking": False
        }]
    },
    {
        "id": "gpt-gemini-3-pro-preview",
        "object": "model",
        "type": "model",
        "created": 1732492800,
        "created_at": "2025-11-20T00:00:00.000Z",
        "owned_by": "openai",
        "display_name": "Gemini 3 Pro Preview",
        "root": "gpt-gemini-3-pro-preview",
        "parent": None,
        "permission": [{
            "id": "modelperm-gpt-gemini-3-pro-preview",
            "object": "model_permission",
            "created": 1732492800,
            "allow_create_engine": False,
            "allow_sampling": True,
            "allow_logprobs": True,
            "allow_search_indices": False,
            "allow_view": True,
            "allow_fine_tuning": False,
            "organization": "*",
            "group": None,
            "is_blocking": False
        }]
    },
    {
        "id": "gpt-gemini-3-flash-preview",
        "object": "model",
        "type": "model",
        "created": 1734566400,
        "created_at": "2025-12-18T00:00:00.000Z",
        "owned_by": "openai",
        "display_name": "Gemini 3 Flash Preview",
        "root": "gpt-gemini-3-flash-preview",
        "parent": None,
        "permission": [{
            "id": "modelperm-gpt-gemini-3-flash-preview",
            "object": "model_permission",
            "created": 1734566400,
            "allow_create_engine": False,
            "allow_sampling": True,
            "allow_logprobs": True,
            "allow_search_indices": False,
            "allow_view": True,
            "allow_fine_tuning": False,
            "organization": "*",
            "group": None,
            "is_blocking": False
        }]
    },
]

# Model aliases for OpenAI compatibility
MODEL_ALIASES = {
    # OpenAI-style names - mapped to Gemini
    "gpt-4": "gemini-2.5-pro",
    "gpt-4-turbo": "gemini-2.5-pro",
    "gpt-4-turbo-preview": "gemini-2.5-pro",
    "gpt-4o": "gemini-2.5-pro",
    "gpt-4o-mini": "gemini-2.5-flash",
    "gpt-3.5-turbo": "gemini-2.5-flash",
    
    # Authropic names
    "claude-3-opus": "gemini-2.5-pro",
    "claude-3-sonnet": "gemini-2.5-pro",
    "claude-3-haiku": "gemini-2.5-flash",
    "claude-3.5-sonnet": "gemini-2.5-pro",
    
    # Internal aliases
    "assistant-codemodel-pro-001": "gemini-2.5-pro",
    "assistant-codemodel-flash-001": "gemini-2.5-flash",
}

def resolve_model(model_name: str) -> str:
    """Resolve model name to actual Gemini model ID."""
    # Check aliases first (e.g. gpt-4 -> gemini-2.5-pro)
    if model_name in MODEL_ALIASES:
        return MODEL_ALIASES[model_name]
    
    # Handle Trojan Horse IDs (strip gpt- prefix)
    # This converts "gpt-gemini-2.5-pro" -> "gemini-2.5-pro"
    if model_name.startswith("gpt-"):
        return model_name.replace("gpt-", "", 1)
            
    # Fallback
    lower = model_name.lower()
    if "flash" in lower or "lite" in lower or "mini" in lower:
        return "gemini-2.5-flash"
    return "gemini-2.5-pro"

# =============================================================================
# Internal State & Usage Tracking
# =============================================================================

state = {
    "project_id": os.environ.get("PROJECT_ID"),
    "tokens": None,
    "pkce_verifier": None,
    "last_request_time": 0,
    "rate_limit_lock": threading.Lock(),
}

usage_stats = {
    "total_requests": 0,
    "successful_requests": 0,
    "failed_requests": 0,
    "total_input_tokens": 0,
    "total_output_tokens": 0,
    "requests_by_model": {},
    "requests_today": 0,
    "last_reset": datetime.now().date().isoformat(),
    "request_history": deque(maxlen=100),  # Last 100 requests
}

def track_request(model: str, success: bool, input_tokens: int = 0, output_tokens: int = 0):
    """Track usage statistics for a request."""
    usage_stats["total_requests"] += 1
    if success:
        usage_stats["successful_requests"] += 1
    else:
        usage_stats["failed_requests"] += 1
    
    usage_stats["total_input_tokens"] += input_tokens
    usage_stats["total_output_tokens"] += output_tokens
    
    if model not in usage_stats["requests_by_model"]:
        usage_stats["requests_by_model"][model] = 0
    usage_stats["requests_by_model"][model] += 1
    
    # Reset daily counter if needed
    today = datetime.now().date().isoformat()
    if usage_stats["last_reset"] != today:
        usage_stats["requests_today"] = 0
        usage_stats["last_reset"] = today
    usage_stats["requests_today"] += 1
    
    # Add to history
    usage_stats["request_history"].append({
        "timestamp": datetime.now().isoformat(),
        "model": model,
        "success": success,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    })

# =============================================================================
# Token Management
# =============================================================================

def load_tokens():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            state["tokens"] = json.load(f)
            return True
    return False

def save_tokens(tokens):
    state["tokens"] = tokens
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f, indent=2)
    # Secure the file (read/write for owner only)
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass # Might fail on Windows or non-standard FS

def refresh_access_token():
    if not state["tokens"] or "refresh_token" not in state["tokens"]:
        return False
    
    print("Refreshing access token...")
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": state["tokens"]["refresh_token"],
        "grant_type": "refresh_token"
    }
    resp = requests.post("https://oauth2.googleapis.com/token", data=data)
    if resp.status_code == 200:
        new_tokens = resp.json()
        if "refresh_token" not in new_tokens:
            new_tokens["refresh_token"] = state["tokens"]["refresh_token"]
        save_tokens(new_tokens)
        return True
    return False

def get_valid_token():
    if not state["tokens"]:
        if not load_tokens():
            return None
    return state["tokens"].get("access_token")

def discover_project():
    token = get_valid_token()
    if not token:
        return
    
    url = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"metadata": {"ideType": "IDE_UNSPECIFIED", "platform": "PLATFORM_UNSPECIFIED", "pluginType": "GEMINI"}}
    
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=10)
        if resp.status_code == 200:
            state["project_id"] = resp.json().get("cloudaicompanionProject")
            print(f"  [DEBUG] Project Discovered: {state['project_id']}")
        elif resp.status_code == 401:
            print(f"  [DEBUG] Project discovery returned 401. Attempting token refresh...")
            if refresh_access_token():
                # Retry once with new token
                token = get_valid_token()
                headers["Authorization"] = f"Bearer {token}"
                resp_retry = requests.post(url, headers=headers, json=payload, timeout=10)
                if resp_retry.status_code == 200:
                    state["project_id"] = resp_retry.json().get("cloudaicompanionProject")
                    print(f"  [DEBUG] Project Discovered after refresh: {state['project_id']}")
                else:
                    print(f"  [DEBUG] Project discovery failed after retry: {resp_retry.status_code}")
            else:
                print("  [DEBUG] Token refresh failed during project discovery.")
        else:
            print(f"  [DEBUG] Project discovery returned status {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"  [DEBUG] Project discovery failed: {e}")

# =============================================================================
# Rate Limiting
# =============================================================================

async def check_rate_limit():
    """Check and enforce rate limiting. Returns True if request can proceed."""
    if RATE_LIMIT <= 0:
        return True
    
    with state["rate_limit_lock"]:
        now = time.time()
        elapsed = now - state["last_request_time"]
        
        if elapsed < RATE_LIMIT:
            if WAIT_MODE:
                wait_time = RATE_LIMIT - elapsed
                print(f"Rate limit: waiting {wait_time:.1f}s...")
                await asyncio.sleep(wait_time)
            else:
                return False
        
        state["last_request_time"] = time.time()
        return True

# =============================================================================
# Pydantic Models
# =============================================================================

# OpenAI Models
class ChatMessage(BaseModel):
    role: str
    content: Optional[Union[str, List[Dict[str, Any]]]] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None  # Function name for tool role

class ToolFunction(BaseModel):
    name: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

class Tool(BaseModel):
    type: str = "function"
    function: ToolFunction

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 4096
    stream: Optional[bool] = False
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    tools: Optional[List[Tool]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None

class EmbeddingRequest(BaseModel):
    input: Union[str, List[str]]
    model: str = "text-embedding-004"
    encoding_format: Optional[str] = "float"

# Anthropic Models
class AnthropicMessage(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]

class AnthropicRequest(BaseModel):
    model: str
    max_tokens: int
    messages: List[AnthropicMessage]
    system: Optional[str] = None
    temperature: Optional[float] = 1.0
    stream: Optional[bool] = False

class CountTokensRequest(BaseModel):
    model: str
    messages: List[AnthropicMessage]
    system: Optional[str] = None

# =============================================================================
# FastAPI App with Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    print("\n" + "=" * 50)
    print(f"  Gemini API Proxy v{VERSION}")
    print("=" * 50)
    
    if load_tokens():
        discover_project()
        print(f"  Status: Authenticated")
        print(f"  Project: {state['project_id']}")
        if SHOW_TOKEN:
            print(f"  Token: {state['tokens'].get('access_token', 'N/A')[:50]}...")
    else:
        state["pkce_verifier"] = secrets.token_urlsafe(64)
        hashed = hashlib.sha256(state["pkce_verifier"].encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
        
        auth_params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "access_type": "offline",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        print(f"  Status: Not authenticated")
        print(f"  Setup:  http://localhost:{PORT}/setup")
    
    print(f"  Server: http://localhost:{PORT}")
    print(f"  Rate Limit: {RATE_LIMIT}s" if RATE_LIMIT > 0 else "  Rate Limit: Disabled")
    print("=" * 50 + "\n")
    
    yield
    
    # Shutdown
    print("Shutting down...")

app = FastAPI(
    title="Gemini API Proxy",
    description="OpenAI & Anthropic compatible API for Google Gemini",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS Middleware to allow n8n (and other browser-based clients) to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# =============================================================================
# Authentication Endpoints
# =============================================================================

def get_auth_url():
    """Generate the Google OAuth URL."""
    if not state["pkce_verifier"]:
        state["pkce_verifier"] = secrets.token_urlsafe(64)
    
    hashed = hashlib.sha256(state["pkce_verifier"].encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(hashed).decode('ascii').rstrip('=')
    
    auth_params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(auth_params)}"

AUTH_PAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini API Proxy v{{VERSION}} - Setup</title>
    <style>
        :root {
            --bg-primary: #0f0f0f;
            --bg-secondary: #1a1a1a;
            --bg-tertiary: #242424;
            --border: #2e2e2e;
            --text-primary: #fafafa;
            --text-secondary: #a0a0a0;
            --text-muted: #6b6b6b;
            --accent: #3b82f6;
            --success: #10b981;
            --error: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            line-height: 1.5;
        }
        .container {
            max-width: 500px;
            width: 100%;
        }
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }
        h1 {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }
        .subtitle { color: var(--text-secondary); margin-bottom: 2rem; font-size: 0.9375rem; }
        .step {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1.25rem;
        }
        .step-number {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 1.5rem;
            height: 1.5rem;
            background: var(--accent);
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
            margin-right: 0.75rem;
            color: white;
        }
        .step h3 { display: flex; align-items: center; margin-bottom: 0.75rem; font-size: 1rem; font-weight: 500; }
        .step p { color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.875rem; }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: var(--accent);
            color: white;
            text-decoration: none;
            padding: 0.625rem 1.25rem;
            border-radius: 6px;
            font-weight: 500;
            border: none;
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.15s;
            width: 100%;
        }
        .btn:hover { filter: brightness(1.1); }
        .btn-outline {
            background: none;
            border: 1px solid var(--border);
            color: var(--text-secondary);
        }
        .btn-outline:hover { background: var(--bg-tertiary); color: var(--text-primary); }
        input[type="text"] {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 0.875rem;
            margin-bottom: 1rem;
            font-family: ui-monospace, monospace;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: var(--accent);
        }
        input[type="text"]::placeholder { color: var(--text-muted); }
        .success {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--success);
            padding: 0.875rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: var(--error);
            padding: 0.875rem;
            border-radius: 6px;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.375rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 500;
            margin-bottom: 1.5rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .status-badge.authenticated {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--success);
        }
        .status-badge.unauthenticated {
            background: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.3);
            color: #fbbf24;
        }
        .status-badge.error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--error);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Setup Proxy</h1>
            <p class="subtitle">Connect your account to enable the API</p>
            
            {{STATUS_BADGE}}
            {{MESSAGE}}
            
            {{CONTENT}}
            
            <div style="margin-top: 2rem; text-align: center; color: var(--text-muted); font-size: 0.75rem;">
                Gemini API Proxy v{{VERSION}}
            </div>
        </div>
    </div>
</body>
</html>
"""

SETUP_STEPS_HTML = """
<div class="step">
    <h3><span class="step-number">1</span> Sign in</h3>
    <p>Authorize the proxy with your Google account. You'll be redirected to Google's sign-in page.</p>
    <a href="{{AUTH_URL}}" target="_blank" class="btn">Link Google Account →</a>
</div>

<div class="step">
    <h3><span class="step-number">2</span> Setup Code</h3>
    <p>After signing in, paste the authorization code below to complete the setup.</p>
    <form action="/auth" method="get">
        <input type="text" name="code" placeholder="Authorization code..." required>
        <button type="submit" class="btn">Finish Setup</button>
    </form>
</div>
"""

SUCCESS_HTML = """
<div class="step" style="border-color: var(--success); background: rgba(16, 185, 129, 0.05);">
    <h3>✅ Connected Successfully</h3>
    <p>The proxy is now active and linked to your Google account.</p>
    <p style="margin-top: 0.5rem;"><strong>ID:</strong> <code style="font-family: inherit; color: var(--text-primary);">{{PROJECT_ID}}</code></p>
    <br>
    <a href="/" class="btn btn-outline">Open Dashboard →</a>
</div>
"""

@app.get("/setup", response_class=HTMLResponse)
async def setup_page():
    """Show the setup/authentication page."""
    if state["tokens"]:
        # Already authenticated
        content = SUCCESS_HTML.replace("{{PROJECT_ID}}", state["project_id"] or "Auto-discovered")
        status = '<span class="status-badge authenticated">✓ Authenticated</span>'
        message = ""
    else:
        # Need authentication
        auth_url = get_auth_url()
        content = SETUP_STEPS_HTML.replace("{{AUTH_URL}}", auth_url)
        status = '<span class="status-badge unauthenticated">⚠ Not authenticated</span>'
        message = ""
    
    html = AUTH_PAGE_HTML.replace("{{CONTENT}}", content)
    html = html.replace("{{STATUS_BADGE}}", status)
    html = html.replace("{{MESSAGE}}", message)
    html = html.replace("{{VERSION}}", VERSION)
    return html

@app.get("/auth", response_class=HTMLResponse)
async def handle_auth(code: str):
    """Complete OAuth2 authentication with authorization code."""
    print(f"  [DEBUG] Incoming auth request with code: {code[:10]}...")
    
    if not state["pkce_verifier"]:
        print("  [DEBUG] Error: No pkce_verifier in state (likely server restart).")
        content = SETUP_STEPS_HTML.replace("{{AUTH_URL}}", get_auth_url())
        status = '<span class="status-badge error">⚠ Auth Flow Expired</span>'
        message = '<div class="error">❌ No active authentication flow found. The server may have restarted. Please try again.</div>'
        html = AUTH_PAGE_HTML.replace("{{CONTENT}}", content).replace("{{STATUS_BADGE}}", status).replace("{{MESSAGE}}", message).replace("{{VERSION}}", VERSION)
        return HTMLResponse(content=html)
    
    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "code_verifier": state["pkce_verifier"]
    }
    
    print(f"  [DEBUG] Exchanging code for tokens with Redirect URI: {REDIRECT_URI}")
    try:
        resp = requests.post("https://oauth2.googleapis.com/token", data=token_data, timeout=10)
        print(f"  [DEBUG] Token exchange status: {resp.status_code}")
        
        if resp.status_code == 200:
            tokens = resp.json()
            save_tokens(tokens)
            print("  [DEBUG] Tokens saved successfully.")
            discover_project()
            
            content = SUCCESS_HTML.replace("{{PROJECT_ID}}", state["project_id"] or "Auto-discovered")
            status = '<span class="status-badge authenticated">✓ Authenticated</span>'
            message = '<div class="success">🎉 Authentication successful! Your proxy is now ready to use.</div>'
        else:
            print(f"  [DEBUG] Token exchange failed: {resp.text}")
            content = SETUP_STEPS_HTML.replace("{{AUTH_URL}}", get_auth_url())
            status = '<span class="status-badge unauthenticated">⚠ Authentication Failed</span>'
            error_msg = resp.json().get("error_description", resp.text)
            message = f'<div class="error">❌ Failed to exchange code: {error_msg}</div>'
            
    except Exception as e:
        print(f"  [DEBUG] Auth Exception: {e}")
        content = SETUP_STEPS_HTML.replace("{{AUTH_URL}}", get_auth_url())
        status = '<span class="status-badge error">⚠ System Error</span>'
        message = f'<div class="error">❌ An unexpected error occurred: {e}</div>'
        
    html = AUTH_PAGE_HTML.replace("{{CONTENT}}", content)
    html = html.replace("{{STATUS_BADGE}}", status)
    html = html.replace("{{MESSAGE}}", message)
    html = html.replace("{{VERSION}}", VERSION)
    return HTMLResponse(content=html)

# =============================================================================
# OpenAI Compatible Endpoints
# =============================================================================

@app.get("/v1/models")
async def list_models(request: Request):
    """List available models (OpenAI compatible)."""
    # Check for Anthropic client
    if request.headers.get("x-api-key") or request.headers.get("anthropic-version"):
        # Serve Anthropic-friendly models (Claude aliases + clean Gemini IDs)
        anthropic_models = []
        
        # Add Claude aliases
        for alias, target in MODEL_ALIASES.items():
            if alias.startswith("claude-"):
                anthropic_models.append({
                    "id": alias,
                    "object": "model",
                    "type": "model",
                    "created": 1718668800,
                    "owned_by": "anthropic",
                    "display_name": alias.replace("-", " ").title(),
                    "permission": []
                })
        
        # Add clean Gemini IDs (strip gpt- prefix)
        for model in GEMINI_MODELS:
            clean_id = model["id"].replace("gpt-", "", 1)
            new_model = model.copy()
            new_model["id"] = clean_id
            new_model["root"] = clean_id
            new_model["display_name"] = model["display_name"]
            new_model["owned_by"] = "google"
            anthropic_models.append(new_model)
            
        return {
            "object": "list",
            "data": anthropic_models,
            "has_more": False
        }
        
    return {
        "object": "list",
        "data": GEMINI_MODELS,
        "has_more": False
    }

@app.get("/models")
async def list_models_root(request: Request):
    """List available models (Root alias for compatibility)."""
    return await list_models(request)

@app.get("/v1/models/{model_id}")
async def get_model(model_id: str):
    """Get a specific model's details."""
    for model in GEMINI_MODELS:
        if model["id"] == model_id:
            return model
    raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    """Create a chat completion (OpenAI compatible)."""
    token = get_valid_token()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated. Check server logs.")
    
    # Rate limiting
    if not await check_rate_limit():
        raise HTTPException(status_code=429, detail=f"Rate limited. Wait {RATE_LIMIT}s between requests.")
    
    if not state["project_id"]:
        discover_project()
    
    if not state["project_id"]:
        raise HTTPException(status_code=500, detail="Project ID could not be determined. Check authentication.")
    
    # Resolve model
    gemini_model = resolve_model(req.model)
    
    # Translate messages
    contents = []
    for msg in req.messages:
        # Handle tool role (function results)
        if msg.role == "tool":
            contents.append({
                "role": "user",
                "parts": [{
                    "functionResponse": {
                        "name": msg.name or "unknown",
                        "response": {"result": msg.content}
                    }
                }]
            })
            continue
        
        # Handle assistant messages with tool_calls
        if msg.role == "assistant" and msg.tool_calls:
            parts = []
            for tc in msg.tool_calls:
                func = tc.get("function", {})
                args = func.get("arguments", "{}")
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except:
                        args = {}
                parts.append({
                    "functionCall": {
                        "name": func.get("name", ""),
                        "args": args
                    }
                })
            contents.append({"role": "model", "parts": parts})
            continue
        
        # Standard message handling
        role = "user" if msg.role in ["user", "system"] else "model"
        if isinstance(msg.content, str):
            content_text = msg.content or ""
        elif msg.content:
            # Handle structured content (e.g., with images)
            content_text = " ".join(
                part.get("text", "") for part in msg.content if part.get("type") == "text"
            )
        else:
            content_text = ""
        
        if content_text:
            contents.append({
                "role": role,
                "parts": [{"text": content_text}]
            })
    
    # Build Gemini payload
    gemini_payload = {
        "model": gemini_model,
        "project": state["project_id"],
        "user_prompt_id": str(uuid.uuid4()),
        "request": {
            "contents": contents,
            "generationConfig": {
                "temperature": req.temperature,
                "maxOutputTokens": req.max_tokens
            },
            "session_id": str(uuid.uuid4())
        }
    }
    
    # Translate OpenAI tools to Gemini functionDeclarations
    if req.tools:
        function_declarations = []
        for tool in req.tools:
            if tool.type == "function":
                func = tool.function
                function_declarations.append({
                    "name": func.name,
                    "description": func.description or "",
                    "parameters": func.parameters or {"type": "object", "properties": {}}
                })
        if function_declarations:
            gemini_payload["request"]["tools"] = [{
                "functionDeclarations": function_declarations
            }]
    
    endpoint = "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    async def generate_openai():
        import time
        created_time = int(time.time())
        msg_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
        
        response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code == 401:
            if refresh_access_token():
                headers["Authorization"] = f"Bearer {state['tokens']['access_token']}"
                response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code != 200:
            track_request(gemini_model, success=False)
            error_chunk = {
                "id": msg_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": req.model,
                "choices": [{"index": 0, "delta": {"content": f"Error: {response.text}"}, "finish_reason": "stop"}]
            }
            yield f"data: {json.dumps(error_chunk)}\n\n"
            return

        last_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        accumulated_response_text = ""
        
        for line in response.iter_lines():
            if line:
                decoded = line.decode('utf-8')
                if decoded.startswith("data: "):
                    try:
                        data = json.loads(decoded[6:])
                        
                        # Extract usage metadata if present
                        usage = data.get("usageMetadata")
                        if usage:
                            last_usage["prompt_tokens"] = usage.get("promptTokenCount", 0)
                            last_usage["completion_tokens"] = usage.get("candidatesTokenCount", 0)
                            last_usage["total_tokens"] = usage.get("totalTokenCount", 0)

                        text = ""
                        tool_calls = []
                        candidates = data.get("response", {}).get("candidates", [])
                        if candidates:
                            for part in candidates[0].get("content", {}).get("parts", []):
                                # Check for function call
                                if "functionCall" in part:
                                    fc = part["functionCall"]
                                    tool_calls.append({
                                        "id": f"call_{uuid.uuid4().hex[:8]}",
                                        "type": "function",
                                        "function": {
                                            "name": fc.get("name", ""),
                                            "arguments": json.dumps(fc.get("args", {}))
                                        }
                                    })
                                # Check for text
                                if "text" in part:
                                    text += part.get("text", "")
                                    accumulated_response_text += part.get("text", "")
                        
                        # Emit tool_calls chunk if present
                        if tool_calls:
                            chunk = {
                                "id": msg_id,
                                "object": "chat.completion.chunk",
                                "created": created_time,
                                "model": req.model,
                                "choices": [{
                                    "index": 0,
                                    "delta": {
                                        "role": "assistant",
                                        "content": None,
                                        "tool_calls": tool_calls
                                    },
                                    "finish_reason": "tool_calls"
                                }]
                            }
                            yield f"data: {json.dumps(chunk)}\n\n"
                        elif text:
                            chunk = {
                                "id": msg_id,
                                "object": "chat.completion.chunk",
                                "created": created_time,
                                "model": req.model,
                                "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]
                            }
                            yield f"data: {json.dumps(chunk)}\n\n"
                    except Exception as e:
                        print(f"  [DEBUG] Error parsing stream chunk: {e}")
                        continue
        
        # Fallback estimation if no usage metadata was received
        if last_usage["total_tokens"] == 0:
            # Input estimation
            input_char_count = 0
            for item in contents:
                for part in item.get("parts", []):
                    input_char_count += len(part.get("text", ""))
            
            last_usage["prompt_tokens"] = input_char_count // 4
            last_usage["completion_tokens"] = len(accumulated_response_text) // 4
            last_usage["total_tokens"] = last_usage["prompt_tokens"] + last_usage["completion_tokens"]

        # Send final chunk with finish_reason
        final_chunk = {
            "id": msg_id,
            "object": "chat.completion.chunk",
            "created": created_time,
            "model": req.model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]
        }
        yield f"data: {json.dumps(final_chunk)}\n\n"

        # Send usage chunk (OpenAI standard)
        usage_chunk = {
            "id": msg_id,
            "object": "chat.completion.chunk",
            "created": created_time,
            "model": req.model,
            "choices": [],
            "usage": last_usage
        }
        yield f"data: {json.dumps(usage_chunk)}\n\n"
        
        yield "data: [DONE]\n\n"

        track_request(gemini_model, success=True,
                      input_tokens=last_usage["prompt_tokens"],
                      output_tokens=last_usage["completion_tokens"])

    if req.stream:
        return StreamingResponse(generate_openai(), media_type="text/event-stream")
    else:
        # Non-streaming implementation re-using generate_openai or just simple post
        # For simplicity and robustness, using direct requests again here to avoid complex generator parsing
        # or we can collect from generate_openai()
        
        # Helper to collect from stream
        import asyncio
        chunks = []
        collected_tool_calls = []
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        
        async for chunk_str in generate_openai():
            chunk_line = chunk_str.strip()
            if chunk_line.startswith("data: {"):
                try:
                    data = json.loads(chunk_line[6:])
                    if "usage" in data:
                        usage = data["usage"]
                    if "choices" in data and data["choices"]:
                         delta = data["choices"][0].get("delta", {})
                         if "content" in delta and delta["content"]:
                             chunks.append(delta["content"])
                         if "tool_calls" in delta:
                             collected_tool_calls.extend(delta["tool_calls"])
                         # Check finish_reason for tool_calls
                         if data["choices"][0].get("finish_reason") == "tool_calls":
                             pass  # tool_calls already collected above
                except:
                    pass
        
        full_text = "".join(chunks)
        
        # Build response message
        response_message = {"role": "assistant", "content": full_text if full_text else None}
        finish_reason = "stop"
        
        if collected_tool_calls:
            response_message["tool_calls"] = collected_tool_calls
            finish_reason = "tool_calls"
        
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.model,
            "choices": [{
                "message": response_message,
                "index": 0,
                "finish_reason": finish_reason
            }],
            "usage": usage
        }

@app.post("/v1/embeddings")
async def create_embedding(req: EmbeddingRequest):
    """Create embeddings (OpenAI compatible)."""
    token = get_valid_token()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    
    # Note: Gemini Code Assist API may not support embeddings directly
    # This is a placeholder that returns a mock response
    # In production, you'd call the appropriate Gemini embedding endpoint
    
    inputs = req.input if isinstance(req.input, list) else [req.input]
    
    data = []
    for i, text in enumerate(inputs):
        # Generate a deterministic mock embedding based on text hash
        text_hash = hashlib.md5(text.encode()).hexdigest()
        embedding = [float(int(text_hash[j:j+2], 16)) / 255.0 for j in range(0, 32, 2)]
        # Pad to 1536 dimensions (OpenAI ada-002 size)
        embedding = embedding * 96
        data.append({
            "object": "embedding",
            "embedding": embedding,
            "index": i
        })
    
    return {
        "object": "list",
        "data": data,
        "model": req.model,
        "usage": {
            "prompt_tokens": sum(len(t) // 4 for t in inputs),
            "total_tokens": sum(len(t) // 4 for t in inputs)
        }
    }

# =============================================================================
# Anthropic Compatible Endpoints
# =============================================================================

@app.post("/v1/messages")
async def anthropic_messages(req: AnthropicRequest):
    """Create a message (Anthropic compatible)."""
    token = get_valid_token()
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    
    if not await check_rate_limit():
        raise HTTPException(status_code=429, detail="Rate limited.")
    
    if not state["project_id"]:
        discover_project()
    
    gemini_model = resolve_model(req.model)
    
    # Build contents with system prompt
    contents = []
    if req.system:
        contents.append({
            "role": "user",
            "parts": [{"text": f"[System]: {req.system}"}]
        })
    
    for msg in req.messages:
        role = "user" if msg.role == "user" else "model"
        if isinstance(msg.content, str):
            content_text = msg.content
        else:
            content_text = " ".join(
                part.get("text", "") for part in msg.content if part.get("type") == "text"
            )
        contents.append({
            "role": role,
            "parts": [{"text": content_text}]
        })
    
    gemini_payload = {
        "model": gemini_model,
        "project": state["project_id"],
        "user_prompt_id": str(uuid.uuid4()),
        "request": {
            "contents": contents,
            "generationConfig": {
                "temperature": req.temperature,
                "maxOutputTokens": req.max_tokens
            },
            "session_id": str(uuid.uuid4())
        }
    }
    
    endpoint = "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    def generate_anthropic():
        response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code == 401:
            if refresh_access_token():
                headers["Authorization"] = f"Bearer {state['tokens']['access_token']}"
                response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code != 200:
            track_request(gemini_model, success=False)
            error_event = {
                "type": "error",
                "error": {"type": "api_error", "message": response.text}
            }
            yield f"event: error\ndata: {json.dumps(error_event)}\n\n"
            return
        
        # Send message_start event
        msg_id = f"msg_{uuid.uuid4().hex[:24]}"
        start_event = {
            "type": "message_start",
            "message": {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": req.model,
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }
        }
        yield f"event: message_start\ndata: {json.dumps(start_event)}\n\n"
        
        # Send content_block_start
        block_start = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
        yield f"event: content_block_start\ndata: {json.dumps(block_start)}\n\n"
        
        last_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        
        accumulated_response_text = ""
        
        for line in response.iter_lines():
            if line:
                decoded = line.decode('utf-8')
                if decoded.startswith("data: "):
                    try:
                        data = json.loads(decoded[6:])
                        
                        # Extract usage metadata if present
                        usage = data.get("usageMetadata")
                        if usage:
                            last_usage["prompt_tokens"] = usage.get("promptTokenCount", 0)
                            last_usage["completion_tokens"] = usage.get("candidatesTokenCount", 0)
                            last_usage["total_tokens"] = usage.get("totalTokenCount", 0)

                        text = ""
                        candidates = data.get("response", {}).get("candidates", [])
                        if candidates:
                            for part in candidates[0].get("content", {}).get("parts", []):
                                text += part.get("text", "")
                                accumulated_response_text += part.get("text", "")
                        
                        if text:
                            delta_event = {
                                "type": "content_block_delta",
                                "index": 0,
                                "delta": {"type": "text_delta", "text": text}
                            }
                            yield f"event: content_block_delta\ndata: {json.dumps(delta_event)}\n\n"
                    except Exception as e:
                        print(f"  [DEBUG] Error parsing stream chunk: {e}")
                        continue
        
        # Send content_block_stop
        block_stop = {"type": "content_block_stop", "index": 0}
        yield f"event: content_block_stop\ndata: {json.dumps(block_stop)}\n\n"
        
        # Fallback estimation if no usage metadata was received
        if last_usage["total_tokens"] == 0:
            # Input estimation
            input_char_count = 0
            for item in contents:
                for part in item.get("parts", []):
                    input_char_count += len(part.get("text", ""))
            
            last_usage["prompt_tokens"] = input_char_count // 4
            last_usage["completion_tokens"] = len(accumulated_response_text) // 4
            last_usage["total_tokens"] = last_usage["prompt_tokens"] + last_usage["completion_tokens"]
        
        # Send message_delta with stop_reason and usage
        msg_delta = {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": last_usage["completion_tokens"]}
        }
        yield f"event: message_delta\ndata: {json.dumps(msg_delta)}\n\n"
        
        # Send message_stop
        yield f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n"
        
            
    
    if req.stream:
        return StreamingResponse(generate_anthropic(), media_type="text/event-stream")
    else:
        # Non-streaming request
        response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code == 401:
            if refresh_access_token():
                headers["Authorization"] = f"Bearer {state['tokens']['access_token']}"
                response = requests.post(endpoint, headers=headers, json=gemini_payload, stream=True)
        
        if response.status_code != 200:
            track_request(gemini_model, success=False)
            raise HTTPException(status_code=response.status_code, detail=response.text)
        
        full_text = ""
        prompt_tokens = 0
        completion_tokens = 0
        
        for line in response.iter_lines():
            if line:
                decoded = line.decode('utf-8')
                if decoded.startswith("data: "):
                    try:
                        data = json.loads(decoded[6:])
                        
                        usage = data.get("usageMetadata")
                        if usage:
                            prompt_tokens = usage.get("promptTokenCount", 0)
                            completion_tokens = usage.get("candidatesTokenCount", 0)
                            
                        candidates = data.get("response", {}).get("candidates", [])
                        if candidates:
                            for part in candidates[0].get("content", {}).get("parts", []):
                                full_text += part.get("text", "")
                    except:
                        continue
        
        # Fallback estimation if usage missing
        if prompt_tokens == 0 and completion_tokens == 0:
             prompt_tokens = sum(len(str(m.content)) // 4 for m in req.messages)
             completion_tokens = len(full_text) // 4

        track_request(gemini_model, success=True, input_tokens=prompt_tokens, output_tokens=completion_tokens)
        
        return {
            "id": f"msg_{uuid.uuid4().hex[:24]}",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": full_text}],
            "model": req.model,
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens
            }
        }

@app.post("/v1/messages/count_tokens")
async def count_tokens(req: CountTokensRequest):
    """Count tokens for messages (Anthropic compatible)."""
    total = 0
    if req.system:
        total += len(req.system) // 4
    for msg in req.messages:
        if isinstance(msg.content, str):
            total += len(msg.content) // 4
        else:
            for part in msg.content:
                if part.get("type") == "text":
                    total += len(part.get("text", "")) // 4
    
    return {"input_tokens": total}

# =============================================================================
# Usage & Monitoring Endpoints
# =============================================================================

@app.get("/usage")
async def get_usage():
    """Get usage statistics."""
    return {
        "total_requests": usage_stats["total_requests"],
        "successful_requests": usage_stats["successful_requests"],
        "failed_requests": usage_stats["failed_requests"],
        "requests_today": usage_stats["requests_today"],
        "total_input_tokens": usage_stats["total_input_tokens"],
        "total_output_tokens": usage_stats["total_output_tokens"],
        "requests_by_model": usage_stats["requests_by_model"],
        "recent_requests": list(usage_stats["request_history"]),
    }

@app.get("/token")
async def get_token_info():
    """Get current token information (if enabled)."""
    if not SHOW_TOKEN:
        return {"message": "Token display disabled. Set SHOW_TOKEN=true to enable."}
    
    if not state["tokens"]:
        return {"message": "Not authenticated"}
    
    return {
        "access_token": state["tokens"].get("access_token", "")[:50] + "...",
        "token_type": state["tokens"].get("token_type", "Bearer"),
        "expires_in": state["tokens"].get("expires_in", "unknown"),
        "has_refresh_token": "refresh_token" in state["tokens"],
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "authenticated": state["tokens"] is not None,
        "project_id": state["project_id"],
        "rate_limit": RATE_LIMIT,
        "wait_mode": WAIT_MODE,
    }

# =============================================================================
# Dashboard
# =============================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gemini API Proxy</title>
    <style>
        :root {
            --bg-primary: #0f0f0f;
            --bg-secondary: #1a1a1a;
            --bg-tertiary: #242424;
            --border: #2e2e2e;
            --text-primary: #fafafa;
            --text-secondary: #a0a0a0;
            --text-muted: #6b6b6b;
            --accent: #3b82f6;
            --success: #10b981;
            --error: #ef4444;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }
        .container { max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
        h1 { font-size: 1.5rem; font-weight: 600; }
        .status { display: flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; color: var(--text-secondary); }
        .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
        @media (max-width: 768px) { .stats { grid-template-columns: repeat(2, 1fr); } }
        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.25rem;
        }
        .stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
        .stat-value { font-size: 2rem; font-weight: 600; font-variant-numeric: tabular-nums; }
        .stat-value.success { color: var(--success); }
        .stat-value.error { color: var(--error); }
        .section { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; }
        .section-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; font-weight: 500; color: var(--text-secondary); }
        .section-content { padding: 1rem 1.25rem; }
        .models { display: flex; flex-wrap: wrap; gap: 0.5rem; }
        .model-chip {
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            padding: 0.375rem 0.75rem;
            border-radius: 4px;
            font-size: 0.8125rem;
            font-family: ui-monospace, monospace;
            color: var(--text-secondary);
        }
        table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
        th { text-align: left; padding: 0.75rem 0; color: var(--text-muted); font-weight: 500; border-bottom: 1px solid var(--border); }
        td { padding: 0.75rem 0; border-bottom: 1px solid var(--border); color: var(--text-secondary); }
        tr:last-child td { border-bottom: none; }
        .mono { font-family: ui-monospace, monospace; }
        .success-text { color: var(--success); }
        .error-text { color: var(--error); }
        .empty { color: var(--text-muted); font-style: italic; padding: 2rem; text-align: center; }
        .refresh { background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; transition: all 0.15s; }
        .refresh:hover { background: var(--bg-tertiary); color: var(--text-primary); }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">Gemini API Proxy <span style="font-size: 0.5em; opacity: 0.5; vertical-align: middle;">v{{VERSION}}</span></div>
            <div style="display: flex; align-items: center; gap: 1rem;">
                <div class="status"><span class="status-dot"></span><span id="status-text">Connected</span></div>
                <button class="refresh" onclick="fetchData()">Refresh</button>
            </div>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value" id="total">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Successful</div>
                <div class="stat-value success" id="success">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Failed</div>
                <div class="stat-value error" id="failed">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Input Tokens</div>
                <div class="stat-value" id="input-tokens">-</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">Available Models</div>
            <div class="section-content">
                <div class="models" id="models"></div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">Recent Requests</div>
            <div class="section-content" style="padding: 0;">
                <table style="padding: 0 1.25rem;">
                    <thead>
                        <tr>
                            <th style="padding-left: 1.25rem;">Time</th>
                            <th>Model</th>
                            <th>Status</th>
                            <th style="padding-right: 1.25rem; text-align: right;">Tokens</th>
                        </tr>
                    </thead>
                    <tbody id="history"></tbody>
                </table>
                <div class="empty" id="empty-state">No requests yet</div>
            </div>
        </div>
    </div>
    
    <script>
        async function fetchData() {
            try {
                const [usage, models, health] = await Promise.all([
                    fetch('/usage').then(r => r.json()),
                    fetch('/v1/models').then(r => r.json()),
                    fetch('/health').then(r => r.json())
                ]);
                
                document.getElementById('status-text').textContent = health.authenticated ? 'Connected' : 'Not authenticated';
                document.getElementById('total').textContent = usage.total_requests.toLocaleString();
                document.getElementById('success').textContent = usage.successful_requests.toLocaleString();
                document.getElementById('failed').textContent = usage.failed_requests.toLocaleString();
                document.getElementById('input-tokens').textContent = usage.total_input_tokens.toLocaleString();
                
                document.getElementById('models').innerHTML = models.data
                    .map(m => `<span class="model-chip">${m.id}</span>`)
                    .join('');
                
                const requests = usage.recent_requests.slice(-10).reverse();
                const emptyState = document.getElementById('empty-state');
                const historyTable = document.getElementById('history');
                
                if (requests.length === 0) {
                    emptyState.style.display = 'block';
                    historyTable.innerHTML = '';
                } else {
                    emptyState.style.display = 'none';
                    historyTable.innerHTML = requests.map(r => {
                        const time = new Date(r.timestamp);
                        const timeStr = time.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
                        
                        let tokenDisplay = '—';
                        if (r.input_tokens > 0 || r.output_tokens > 0) {
                            tokenDisplay = `<span style="color: #94a3b8">${r.input_tokens}</span> <span style="color: #4ade80">↑</span> <span style="color: #475569">/</span> <span style="color: #94a3b8">${r.output_tokens}</span> <span style="color: #60a5fa">↓</span>`;
                        }
                        
                        return `
                            <tr>
                                <td style="padding-left: 1.25rem;" class="mono">${timeStr}</td>
                                <td class="mono">${r.model}</td>
                                <td class="${r.success ? 'success-text' : 'error-text'}">${r.success ? 'OK' : 'Error'}</td>
                                <td style="padding-right: 1.25rem; text-align: right;" class="mono">${tokenDisplay}</td>
                            </tr>
                        `;
                    }).join('');
                }
            } catch (e) {
                document.getElementById('status-text').textContent = 'Error';
                console.error('Failed to fetch data:', e);
            }
        }
        
        // Only poll when page is visible
        let pollInterval = null;
        
        function startPolling() {
            if (!pollInterval) {
                fetchData();
                pollInterval = setInterval(fetchData, 10000);
            }
        }
        
        function stopPolling() {
            if (pollInterval) {
                clearInterval(pollInterval);
                pollInterval = null;
            }
        }
        
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stopPolling();
            } else {
                startPolling();
            }
        });
        
        // Start polling if page is visible
        if (!document.hidden) {
            startPolling();
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the usage dashboard or redirect to setup if not authenticated."""
    if not state["tokens"]:
        # Not authenticated, redirect to setup
        return HTMLResponse(content="<script>window.location.href='/setup';</script>")
    return DASHBOARD_HTML.replace("{{VERSION}}", VERSION)

# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
