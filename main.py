"""
GitHub OAuth Dashboard - FastAPI Implementation
Secure OAuth 2.0 authentication demo with GitHub
Python equivalent of the Node.js/Express implementation
"""

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import httpx
import secrets
import os
from urllib.parse import urlencode
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

app = FastAPI(title="GitHub OAuth Dashboard")

# Temporary state storage as fallback (in-memory)
# In production, use Redis or database for distributed systems
_state_store: Dict[str, datetime] = {}

# !!!! importante falar
def cleanup_expired_states():
    """Remove expired states from memory store"""
    now = datetime.now()
    expired = [state for state, expiry in _state_store.items() if now >= expiry]
    for state in expired:
        del _state_store[state]
    if expired:
        print(f"Cleaned up {len(expired)} expired states")

# GitHub OAuth configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/callback")
PORT = int(os.getenv("PORT", 8000))

# Verify environment variables are loaded
if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
    print("ERROR: Missing required environment variables")
    print("Make sure .env file exists with GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET")
    exit(1)

# Verify session secret is set (critical for security)
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET or SESSION_SECRET == "your-secret-key-change-this":
    print("ERROR: SESSION_SECRET is required for security")
    print("Generate a secure random string: python -c 'import secrets; print(secrets.token_hex(32))'")
    exit(1)

# Session configuration with security best practices
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,  # Required, no default fallback for security
    session_cookie="session",
    max_age=3600,  # 1 hour session timeout
    same_site="lax",  # CSRF protection
    https_only=False,  # Set to True in production with HTTPS
    # Note: httpOnly is always True in SessionMiddleware (cannot be disabled)
)

# Mount static files (HTML, CSS, JS)
app.mount("/public", StaticFiles(directory="public"), name="public")


# Helper function to generate cryptographically secure random string
# This prevents CSRF attacks by ensuring the callback we receive is from the same user who initiated login
def generate_state() -> str:
    """
    Generate a cryptographically secure random state token.
    Uses secrets module which generates cryptographically strong random data.
    32 bytes = 256 bits of entropy, making it virtually impossible to guess.
    """
    return secrets.token_hex(32)


# Middleware to check authentication
async def require_auth(request: Request) -> str:
    """
    Dependency that ensures the user is authenticated.
    Returns the access token if valid, raises 401 if not authenticated.
    """
    access_token = request.session.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    return access_token


# Routes
@app.get("/")
async def root():
    """Serve the landing page"""
    return HTMLResponse(content=Path("public/index.html").read_text())


@app.get("/login")
async def login(request: Request):
    """
    OAuth login route - redirects to GitHub
    Initiates the OAuth 2.0 authorization flow
    """
    print("Starting OAuth flow...")
    
    # Generate state for CSRF protection
    state = generate_state()
    request.session["state"] = state
    
    # Store state in memory as fallback (expires in 10 minutes)
    _state_store[state] = datetime.now() + timedelta(minutes=10)
    
    # Build GitHub authorization URL with state parameter
    params = {
        "client_id": GITHUB_CLIENT_ID,       # Identifies our application to GitHub
        "redirect_uri": REDIRECT_URI,         # Where GitHub sends the user after auth
        "scope": "read:user",                 # Minimal permissions: read user info only (read-only)
        "state": state                        # CSRF protection token
    }
    
    github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    print(f"Generated state: {state}")
    print(f"Session state stored: {request.session.get('state')}")
    
    # Create response with redirect
    response = RedirectResponse(url=github_auth_url)
    
    # IMPORTANT: Ensure session is set in the cookie before redirect
    # This is crucial because the session needs to persist across the OAuth flow
    return response


@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):
    """
    OAuth callback route - handles GitHub's response
    Completes the OAuth 2.0 authorization flow
    """
    
    # Cleanup expired states
    cleanup_expired_states()
    
    print(f"Callback received - code: {'present' if code else 'missing'}, state: {state}")
    print(f"Session contents: {dict(request.session)}")
    print(f"Session cookie: {request.cookies.get('session', 'NOT FOUND')}")
    
    # Step 1: Verify state to prevent CSRF attacks
    # The state parameter ensures this callback is in response to OUR authorization request
    # Without this check, attackers could trick users into authorizing malicious apps
    session_state = request.session.get("state")
    
    # Check state from session OR from memory store (fallback)
    state_valid = False
    
    if state and session_state and state == session_state:
        print("✓ State validated from session")
        state_valid = True
    elif state and state in _state_store:
        # Check if state hasn't expired
        if datetime.now() < _state_store[state]:
            print("✓ State validated from memory store (session fallback)")
            state_valid = True
        else:
            print("✗ State expired in memory store")
            del _state_store[state]
    
    if not state_valid:
        print("ERROR: State mismatch - possible CSRF attempt")
        print(f"Expected (session): {session_state}")
        print(f"Received: {state}")
        print(f"Memory store has state: {state in _state_store}")
        raise HTTPException(status_code=403, detail="State verification failed - possible CSRF attempt")
    
    # Clear used state immediately after validation
    # Each state is single-use to prevent replay attacks
    if "state" in request.session:
        del request.session["state"]
    if state in _state_store:
        del _state_store[state]
    
    if not code:
        raise HTTPException(status_code=400, detail="No authorization code received")
    
    try:
        print("Exchanging code for access token...")
        
        # Step 2: Exchange authorization code for access token
        # This code is single-use and expires in 10 minutes - we must exchange it immediately
        # The client_secret is included here, which is why this MUST happen server-side
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "https://github.com/login/oauth/access_token",
                json={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,  # Never expose this to the client!
                    "code": code,                            # Single-use authorization code
                    "redirect_uri": REDIRECT_URI             # Must match exactly what's registered
                },
                headers={"Accept": "application/json"}
            )
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            scope = token_data.get("scope")
            
            if not access_token:
                raise HTTPException(status_code=500, detail="No access token received")
            
            # Step 3: Store token securely in server-side session
            # CRITICAL: Token stays on server, never sent to browser JavaScript
            # Client only gets an httpOnly session cookie that can't be accessed by JS
            request.session["access_token"] = access_token
            request.session["token_scope"] = scope
            
            print("Authentication successful")
            print(f"Granted scopes: {scope}")
            
            # Redirect to dashboard
            return RedirectResponse(url="/dashboard", status_code=302)
            
    except httpx.HTTPError as error:
        print(f"ERROR: Token exchange failed: {str(error)}")
        raise HTTPException(status_code=500, detail="Authentication failed. Please try again.")


@app.get("/dashboard")
async def dashboard(request: Request):
    """Dashboard page route - protected resource"""
    if "access_token" not in request.session:
        return RedirectResponse(url="/")
    
    return HTMLResponse(content=Path("public/dashboard.html").read_text())

# --------- vvvv Coisas da api do git vvvv ---------

@app.get("/api/user")
async def get_user(request: Request, access_token: str = Depends(require_auth)):
    """
    Get user profile endpoint
    Fetches authenticated user's GitHub profile
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user",
                headers={
                    # Bearer token authentication - "Bearer" indicates the type of token
                    # The token proves we're authorized to access this user's data
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code)
            
            user_data = response.json()
            
            # Send only necessary data to client
            return {
                "login": user_data.get("login"),
                "name": user_data.get("name"),
                "avatar_url": user_data.get("avatar_url"),
                "public_repos": user_data.get("public_repos"),
                "followers": user_data.get("followers"),
                "bio": user_data.get("bio"),
                "company": user_data.get("company"),
                "location": user_data.get("location")
            }
            
    except httpx.HTTPError as error:
        print(f"API call failed: {error}")
        
        # Check if token is expired or revoked
        # 401 means unauthorized - the token is no longer valid
        # User needs to re-authenticate with GitHub
        if hasattr(error, 'response') and error.response.status_code == 401:
            if "access_token" in request.session:
                del request.session["access_token"]
            raise HTTPException(status_code=401, detail="Token expired or revoked")
        
        raise HTTPException(status_code=500, detail="Failed to fetch user data")


@app.get("/api/repos")
async def get_repos(request: Request, access_token: str = Depends(require_auth)):
    """
    Get user repositories endpoint with rate limit awareness
    Fetches user's repositories from GitHub
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://api.github.com/user/repos",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                params={
                    "sort": "updated",
                    "per_page": 20  # Limit results
                }
            )
            
            # Check rate limits
            remaining = response.headers.get("x-ratelimit-remaining")
            if remaining and int(remaining) < 100:
                print(f"WARNING: API rate limit low: {remaining} requests remaining")
            
            repos_data = response.json()
            
            # Process and send relevant data
            repo_stats = [
                {
                    "name": repo.get("name"),
                    "description": repo.get("description"),
                    "stars": repo.get("stargazers_count"),
                    "language": repo.get("language"),
                    "updated": repo.get("updated_at"),
                    "url": repo.get("html_url"),
                    "private": repo.get("private")
                }
                for repo in repos_data
            ]
            
            return repo_stats
            
    except httpx.HTTPError as error:
        print(f"Repository fetch failed: {error}")
        raise HTTPException(status_code=500, detail="Failed to fetch repositories")


@app.get("/api/dashboard")
async def get_dashboard_data(request: Request, access_token: str = Depends(require_auth)):
    """
    Dashboard API route - returns user's GitHub data as JSON
    Combines user profile and repositories data
    """
    try:
        async with httpx.AsyncClient() as client:
            # Fetch user data from GitHub
            user_response = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            # Fetch user's repositories
            repos_response = await client.get(
                "https://api.github.com/user/repos",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                params={
                    "sort": "updated",
                    "per_page": 10
                }
            )
            
            # Check rate limits
            remaining = repos_response.headers.get("x-ratelimit-remaining")
            if remaining and int(remaining) < 100:
                print(f"WARNING: API rate limit low: {remaining} requests remaining")
            
            return {
                "user": user_response.json(),
                "repositories": repos_response.json()
            }
            
    except httpx.HTTPError as error:
        print(f"ERROR: Error fetching GitHub data: {error}")
        
        # Check if token is expired or revoked
        if hasattr(error, 'response') and error.response.status_code == 401:
            if "access_token" in request.session:
                del request.session["access_token"]
            raise HTTPException(status_code=401, detail="Token expired or revoked")
        
        raise HTTPException(status_code=500, detail="Error fetching data")


@app.get("/api/stats")
async def get_stats(request: Request, access_token: str = Depends(require_auth)):
    """
    API endpoint to get commit statistics
    Fetches recent activity events from GitHub
    """
    try:
        async with httpx.AsyncClient() as client:
            # Fetch user info
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            username = user_response.json().get("login")
            
            # Fetch recent events (includes commits)
            events_response = await client.get(
                f"https://api.github.com/users/{username}/events",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"per_page": 100}
            )
            
            events = events_response.json()
            
            # Calculate statistics
            stats = {
                "totalEvents": len(events),
                "pushEvents": len([e for e in events if e.get("type") == "PushEvent"]),
                "pullRequests": len([e for e in events if e.get("type") == "PullRequestEvent"]),
                "issues": len([e for e in events if e.get("type") == "IssuesEvent"]),
                "recentActivity": events[:10]
            }
            
            return stats
            
    except httpx.HTTPError as error:
        print(f"Error fetching stats: {error}")
        raise HTTPException(status_code=500, detail="Error fetching statistics")


@app.get("/api/validate")
async def validate_token(request: Request, access_token: str = Depends(require_auth)):
    """
    Token validation endpoint - checks if current token is still valid
    Makes a simple API call to verify token validity
    """
    try:
        async with httpx.AsyncClient() as client:
            await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
        
        token_scope = request.session.get("token_scope", "")
        return {"valid": True, "scope": token_scope}
        
    except httpx.HTTPError as error:
        # Token is invalid or expired
        if hasattr(error, 'response') and error.response.status_code == 401:
            if "access_token" in request.session:
                del request.session["access_token"]
            if "token_scope" in request.session:
                del request.session["token_scope"]
        
        return {"valid": False}


@app.get("/logout")
async def logout(request: Request):
    """
    Logout route - properly destroy session
    Clears all session data and redirects to home page
    """
    # Clear all session data
    request.session.clear()
    print("User logged out successfully")
    
    return RedirectResponse(url="/", status_code=302)


# Startup event
@app.on_event("startup")
async def startup_event():
    """Print startup information"""
    print("=" * 60)
    print("OAuth Dashboard server started successfully!")
    print(f"Server running on http://localhost:{PORT}")
    print("Make sure your GitHub OAuth app callback URL matches exactly!")
    print("Environment variables loaded:", {
        "hasClientId": bool(GITHUB_CLIENT_ID),
        "hasClientSecret": bool(GITHUB_CLIENT_SECRET),
        "hasSessionSecret": bool(SESSION_SECRET)
    })
    print("=" * 60)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=True,
        log_level="info"
    )
