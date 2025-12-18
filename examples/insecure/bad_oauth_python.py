"""
WARNING: INSECURE OAuth IMPLEMENTATION (PYTHON VERSION)

This file contains examples of common OAuth security mistakes in Python/FastAPI.
DO NOT USE THIS CODE IN PRODUCTION!
This is for educational purposes only to show what NOT to do.

Compare with the secure implementation in main.py
"""

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx

app = FastAPI()

# BAD EXAMPLE 1: Hardcoded credentials
# ❌ NEVER hardcode sensitive credentials in your code!
GITHUB_CLIENT_ID = "Iv1.8a61f9b3a7aba766"  # Never hardcode!
GITHUB_CLIENT_SECRET = "1234567890abcdef1234567890abcdef12345678"  # NEVER do this!
GITHUB_TOKEN = "ghp_RealTokenHere456..."  # Absolutely wrong!

# BAD EXAMPLE 2: Insecure session configuration
# ❌ Weak secret, wrong cookie settings
app.add_middleware(
    SessionMiddleware,
    secret_key="keyboard cat",  # ❌ Weak, predictable secret
    session_cookie="session",
    max_age=None,  # ❌ No expiration
    same_site=None,  # ❌ No CSRF protection
    https_only=False  # ❌ Sends cookie over HTTP
)


# BAD EXAMPLE 3: No state parameter (CSRF vulnerability)
@app.get("/login")
async def login():
    """
    ❌ Missing state parameter - vulnerable to CSRF attacks!
    ❌ Requesting excessive scopes
    """
    # No state generation - CSRF vulnerability!
    github_auth_url = (
        "https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        "&redirect_uri=http://localhost:8000/callback"
        "&scope=repo,user,delete_repo,admin:org"  # ❌ Excessive permissions!
    )
    return RedirectResponse(url=github_auth_url)


# BAD EXAMPLE 4: No state validation in callback
@app.get("/callback")
async def callback(request: Request, code: str = None):
    """
    ❌ No state validation - accepting any callback!
    ❌ Exposing token to client
    ❌ Poor error handling
    """
    # No state validation - CSRF vulnerability!
    
    if not code:
        return {"error": "No code received"}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://github.com/login/oauth/access_token",
                json={
                    "client_id": GITHUB_CLIENT_ID,
                    "client_secret": GITHUB_CLIENT_SECRET,
                    "code": code
                },
                headers={"Accept": "application/json"}
            )
            
            data = response.json()
            access_token = data.get("access_token")
            
            # BAD EXAMPLE 5: Sending token to client
            # ❌ NEVER expose token to client-side JavaScript!
            return JSONResponse({
                "token": access_token,  # ❌ Exposing token!
                "message": "Here's your token!",
                "secret": GITHUB_CLIENT_SECRET  # ❌ Exposing secret!!!
            })
            
    except Exception as error:
        # BAD EXAMPLE 6: Exposing sensitive error details
        # ❌ Never expose internal errors to clients
        return JSONResponse({
            "error": str(error),
            "type": type(error).__name__,
            "traceback": str(error.__traceback__)  # ❌ Exposing stack trace!
        }, status_code=500)


# BAD EXAMPLE 7: Storing token in client (encouraging localStorage)
@app.get("/bad-dashboard")
async def bad_dashboard(token: str = ""):
    """
    ❌ This encourages storing tokens in localStorage
    ❌ Token passed in URL parameters
    """
    return HTMLResponse(f"""
    <html>
    <body>
        <script>
            // ❌ NEVER store tokens in localStorage!
            // They are accessible by any JavaScript on the page
            localStorage.setItem('github_token', '{token}');
            
            // ❌ Sending token in URL parameters - gets logged everywhere!
            const token = localStorage.getItem('github_token');
            fetch('/api/user?token=' + token)
                .then(res => res.json())
                .then(data => console.log(data));
        </script>
    </body>
    </html>
    """)


# BAD EXAMPLE 8: Token in URL parameters
@app.get("/api/user")
async def get_user(token: str = None):
    """
    ❌ Accepting tokens in URL query parameters
    URLs get logged in server logs, proxy logs, browser history!
    """
    if not token:
        return {"error": "No token provided"}
    
    # ❌ Using token from URL - this gets logged everywhere!
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()


# BAD EXAMPLE 9: No authentication check
@app.get("/api/sensitive-data")
async def sensitive_data():
    """
    ❌ No authentication required for sensitive endpoint
    """
    return {
        "secret_key": "my-super-secret-key",
        "database_password": "password123",
        "api_keys": ["key1", "key2", "key3"]
    }


# BAD EXAMPLE 10: Logging sensitive data
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    ❌ Logging all request data including sensitive information
    """
    # ❌ This logs Authorization headers and session data!
    print(f"Request headers: {dict(request.headers)}")
    print(f"Request cookies: {dict(request.cookies)}")
    
    response = await call_next(request)
    return response


# BAD EXAMPLE 11: SQL Injection vulnerability (if using database)
@app.get("/user/{username}")
async def get_user_by_name(username: str):
    """
    ❌ Example of SQL injection vulnerability
    (Not OAuth-specific, but commonly found alongside)
    """
    # ❌ Never construct SQL queries with string concatenation!
    # This is just an example - don't actually run this!
    query = f"SELECT * FROM users WHERE username = '{username}'"
    # If username is "admin' OR '1'='1", this returns all users!
    return {"query": query, "warning": "SQL Injection vulnerable!"}


# BAD EXAMPLE 12: No CORS configuration or overly permissive
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ❌ Allows any origin!
    allow_credentials=True,  # ❌ With allow_origins=["*"] is dangerous!
    allow_methods=["*"],
    allow_headers=["*"],
)


# BAD EXAMPLE 13: Weak session cookie name
# Using default or predictable cookie names makes attacks easier


# BAD EXAMPLE 14: No rate limiting
# Allows unlimited requests - vulnerable to brute force and DoS


# BAD EXAMPLE 15: Mixed HTTP/HTTPS
@app.get("/insecure-redirect")
async def insecure_redirect():
    """
    ❌ Redirecting to HTTP in production
    """
    return RedirectResponse(url="http://example.com/callback")  # ❌ HTTP!


"""
SECURITY CHECKLIST - What this code gets WRONG:

[ ] ❌ Hardcoded credentials
[ ] ❌ Weak session secret
[ ] ❌ No CSRF protection (state parameter)
[ ] ❌ Token exposed to client
[ ] ❌ Tokens in URL parameters
[ ] ❌ Tokens in localStorage
[ ] ❌ Excessive OAuth scopes
[ ] ❌ Poor error handling (exposes internals)
[ ] ❌ No rate limiting
[ ] ❌ Overly permissive CORS
[ ] ❌ Logging sensitive data
[ ] ❌ No HTTPS enforcement
[ ] ❌ No session expiration
[ ] ❌ No authentication on sensitive endpoints
[ ] ❌ Predictable session cookies

NEVER USE THESE PATTERNS IN PRODUCTION CODE!
See main.py for the correct, secure implementation.
"""


if __name__ == "__main__":
    import uvicorn
    print("=" * 70)
    print("WARNING: Running INSECURE OAuth implementation!")
    print("This is for EDUCATIONAL PURPOSES ONLY!")
    print("DO NOT USE IN PRODUCTION!")
    print("=" * 70)
    uvicorn.run(app, host="0.0.0.0", port=8001)
