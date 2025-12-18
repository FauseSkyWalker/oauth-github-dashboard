# 🎓 Explicação Detalhada: OAuth 2.0 com Python/FastAPI

## 📋 Índice
1. [Visão Geral do Fluxo OAuth](#visão-geral)
2. [Explicação Linha por Linha](#código-detalhado)
3. [Como Adaptar para Outros Serviços](#outros-serviços)
4. [Exemplos: Google, Twitter, Facebook](#exemplos-práticos)

---

## 🔄 Visão Geral do Fluxo OAuth 2.0

### Fluxo Completo (Authorization Code Flow)

```
1. Usuário → Sua App
   "Quero fazer login com GitHub"

2. Sua App → GitHub
   "Este usuário quer autorizar minha app (+ state token)"

3. GitHub → Usuário
   "Você autoriza esta app a acessar seus dados?"

4. Usuário → GitHub
   "Sim, autorizo"

5. GitHub → Sua App
   "Aqui está o código de autorização (+ state token de volta)"

6. Sua App → GitHub (servidor para servidor)
   "Troco este código pelo access token (+ client secret)"

7. GitHub → Sua App
   "Aqui está o access token"

8. Sua App → GitHub API (com token)
   "Quero os dados do usuário"

9. GitHub API → Sua App
   "Aqui estão os dados"
```

---

## 💻 Código Detalhado - Parte por Parte

### 1️⃣ Imports e Configuração Inicial

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
import secrets
import os
from urllib.parse import urlencode
from dotenv import load_dotenv
```

**O que cada import faz:**
- `FastAPI`: Framework web moderno e rápido
- `Request`: Objeto que representa a requisição HTTP
- `HTTPException`: Para retornar erros HTTP
- `Depends`: Sistema de Dependency Injection do FastAPI
- `RedirectResponse`: Para redirecionar o usuário
- `SessionMiddleware`: Gerencia cookies de sessão seguros
- `httpx`: Cliente HTTP assíncrono (substituto do `requests`)
- `secrets`: Gera strings aleatórias criptograficamente seguras
- `urlencode`: Codifica parâmetros para URLs
- `load_dotenv`: Carrega variáveis do arquivo `.env`

### 2️⃣ Armazenamento Temporário de State

```python
_state_store: Dict[str, datetime] = {}

def cleanup_expired_states():
    now = datetime.now()
    expired = [state for state, expiry in _state_store.items() if now >= expiry]
    for state in expired:
        del _state_store[state]
```

**Por que isso existe?**
- **State Token**: Previne ataques CSRF (Cross-Site Request Forgery)
- **Armazenamento Temporário**: Backup caso a sessão do cookie falhe
- **Expiração**: States são válidos por 10 minutos apenas
- **Limpeza**: Remove states antigos para economizar memória

**Em produção:** Use Redis ou banco de dados!

### 3️⃣ Configuração de Sessão Segura

```python
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,      # Assina o cookie - previne adulteração
    session_cookie="session",       # Nome do cookie
    max_age=3600,                   # Expira em 1 hora
    same_site="lax",                # Proteção CSRF
    https_only=False,               # True em produção (só HTTPS)
)
```

**Segurança em Camadas:**
1. **secret_key**: Cookie assinado - impossível falsificar
2. **httpOnly**: Automático no SessionMiddleware - JavaScript não acessa
3. **same_site="lax"**: Cookie só enviado em requisições "seguras"
4. **max_age**: Sessão expira automaticamente
5. **https_only**: Em produção, só funciona com HTTPS

### 4️⃣ Geração de State Token (Anti-CSRF)

```python
def generate_state() -> str:
    """
    Gera um token de 256 bits (32 bytes) criptograficamente seguro.
    Impossível de adivinhar, previne ataques CSRF.
    """
    return secrets.token_hex(32)
```

**Por que 32 bytes?**
- 32 bytes = 256 bits = 2^256 possibilidades
- Astronomicamente impossível de adivinhar
- `secrets` usa `/dev/urandom` (Linux) ou `CryptGenRandom` (Windows)

### 5️⃣ Rota de Login (Início do Fluxo OAuth)

```python
@app.get("/login")
async def login(request: Request):
    # 1. Gerar state único para este usuário
    state = generate_state()
    
    # 2. Salvar state na sessão (cookie httpOnly)
    request.session["state"] = state
    
    # 3. Salvar também em memória (fallback)
    _state_store[state] = datetime.now() + timedelta(minutes=10)
    
    # 4. Construir URL de autorização do GitHub
    params = {
        "client_id": GITHUB_CLIENT_ID,     # Identifica sua app
        "redirect_uri": REDIRECT_URI,       # Para onde voltar
        "scope": "read:user",               # O que você quer acessar
        "state": state                      # Token anti-CSRF
    }
    
    github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    # 5. Redirecionar usuário para GitHub
    return RedirectResponse(url=github_auth_url)
```

**Fluxo passo a passo:**
1. Usuário clica "Login com GitHub"
2. Código gera `state` único: `"a3f8b2c..."`
3. Salva `state` na sessão do navegador (cookie)
4. Salva `state` em memória (backup)
5. Redireciona usuário para GitHub com parâmetros:
   ```
   https://github.com/login/oauth/authorize?
     client_id=Iv1.abc123&
     redirect_uri=http://localhost:8000/callback&
     scope=read:user&
     state=a3f8b2c...
   ```

### 6️⃣ Rota de Callback (GitHub Retorna)

```python
@app.get("/callback")
async def callback(request: Request, code: str = None, state: str = None):
    # PASSO 1: Validar State (Anti-CSRF)
    cleanup_expired_states()
    
    session_state = request.session.get("state")
    state_valid = False
    
    # Tenta validar pelo cookie da sessão
    if state and session_state and state == session_state:
        print("✓ State validado pela sessão")
        state_valid = True
    
    # Fallback: tenta validar pela memória
    elif state and state in _state_store:
        if datetime.now() < _state_store[state]:
            print("✓ State validado pela memória (fallback)")
            state_valid = True
        else:
            print("✗ State expirado")
            del _state_store[state]
    
    if not state_valid:
        raise HTTPException(403, "CSRF attack detected!")
    
    # Limpar state (uso único)
    if "state" in request.session:
        del request.session["state"]
    if state in _state_store:
        del _state_store[state]
    
    # PASSO 2: Trocar código pelo access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,  # NUNCA expor ao cliente!
                "code": code,                           # Código temporário
                "redirect_uri": REDIRECT_URI
            },
            headers={"Accept": "application/json"}
        )
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
    
    # PASSO 3: Salvar token na sessão (servidor)
    request.session["access_token"] = access_token
    
    # PASSO 4: Redirecionar para dashboard
    return RedirectResponse(url="/dashboard")
```

**Por que essa validação é importante?**

**Sem validação de state:**
```
Atacante → Vítima: "Clique aqui" [link malicioso]
Vítima → GitHub: Autoriza app do atacante
GitHub → App do atacante: Código de autorização
Atacante → Obtém acesso à conta da vítima
```

**Com validação de state:**
```
Atacante → Vítima: "Clique aqui" [link malicioso]
Vítima → GitHub: Autoriza app
GitHub → Nossa app: Código + state diferente
Nossa app: "State inválido! CSRF detectado!" ❌
Ataque bloqueado! ✓
```

### 7️⃣ Middleware de Autenticação

```python
async def require_auth(request: Request) -> str:
    """
    Dependency que verifica se o usuário está autenticado.
    FastAPI injeta automaticamente em rotas que precisam.
    """
    access_token = request.session.get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="Login required")
    return access_token
```

**Como usar:**
```python
@app.get("/api/user")
async def get_user(access_token: str = Depends(require_auth)):
    # Se chegar aqui, usuário está autenticado!
    # access_token já está disponível
```

### 8️⃣ Fazer Requisições à API

```python
@app.get("/api/user")
async def get_user(request: Request, access_token: str = Depends(require_auth)):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",  # Token no header
                "Accept": "application/vnd.github.v3+json"
            }
        )
        
        return response.json()
```

**Por que `async with`?**
- Gerencia conexões HTTP automaticamente
- Fecha conexões ao terminar
- Reutiliza conexões (HTTP keep-alive)

---

## 🌍 Como Adaptar para Outros Serviços

### 🔑 O que Muda Entre Serviços

| Item | GitHub | Google | Twitter | Facebook |
|------|--------|--------|---------|----------|
| **Authorization URL** | `github.com/login/oauth/authorize` | `accounts.google.com/o/oauth2/v2/auth` | `twitter.com/i/oauth2/authorize` | `facebook.com/v12.0/dialog/oauth` |
| **Token URL** | `github.com/login/oauth/access_token` | `oauth2.googleapis.com/token` | `api.twitter.com/2/oauth2/token` | `graph.facebook.com/v12.0/oauth/access_token` |
| **API URL** | `api.github.com/user` | `www.googleapis.com/oauth2/v2/userinfo` | `api.twitter.com/2/users/me` | `graph.facebook.com/me` |
| **Scopes** | `read:user` | `openid email profile` | `tweet.read users.read` | `email public_profile` |

### 📝 Template Genérico

```python
class OAuthProvider:
    def __init__(self, name: str, client_id: str, client_secret: str):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
    
    @property
    def authorize_url(self) -> str:
        """URL para autorização"""
        raise NotImplementedError
    
    @property
    def token_url(self) -> str:
        """URL para trocar código por token"""
        raise NotImplementedError
    
    @property
    def api_user_url(self) -> str:
        """URL da API para obter dados do usuário"""
        raise NotImplementedError
    
    @property
    def scopes(self) -> str:
        """Escopos/permissões necessários"""
        raise NotImplementedError
```

---

## 🎯 Exemplos Práticos

### 1. Google OAuth 2.0

```python
# Configuração
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = "http://localhost:8000/callback/google"

@app.get("/login/google")
async def login_google(request: Request):
    state = generate_state()
    request.session["google_state"] = state
    _state_store[f"google_{state}"] = datetime.now() + timedelta(minutes=10)
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",  # OpenID Connect
        "state": state,
        "access_type": "offline",  # Para obter refresh token
    }
    
    google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)

@app.get("/callback/google")
async def callback_google(request: Request, code: str = None, state: str = None):
    # Validar state
    session_state = request.session.get("google_state")
    if state != session_state:
        raise HTTPException(403, "Invalid state")
    
    del request.session["google_state"]
    
    # Trocar código por token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={  # Google usa data, não json!
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": GOOGLE_REDIRECT_URI
            }
        )
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
        
    # Obter dados do usuário
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        user_data = user_response.json()
        # user_data = {"email": "...", "name": "...", "picture": "..."}
    
    request.session["access_token"] = access_token
    request.session["provider"] = "google"
    
    return RedirectResponse(url="/dashboard")
```

### 2. Twitter OAuth 2.0

```python
# Configuração
TWITTER_CLIENT_ID = os.getenv("TWITTER_CLIENT_ID")
TWITTER_CLIENT_SECRET = os.getenv("TWITTER_CLIENT_SECRET")
TWITTER_REDIRECT_URI = "http://localhost:8000/callback/twitter"

@app.get("/login/twitter")
async def login_twitter(request: Request):
    state = generate_state()
    request.session["twitter_state"] = state
    
    # Twitter também usa PKCE (code_challenge)
    code_verifier = secrets.token_urlsafe(32)
    request.session["twitter_code_verifier"] = code_verifier
    
    # Gerar code_challenge (SHA256 do verifier)
    import hashlib
    import base64
    challenge = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
    
    params = {
        "client_id": TWITTER_CLIENT_ID,
        "redirect_uri": TWITTER_REDIRECT_URI,
        "response_type": "code",
        "scope": "tweet.read users.read offline.access",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    twitter_auth_url = f"https://twitter.com/i/oauth2/authorize?{urlencode(params)}"
    return RedirectResponse(url=twitter_auth_url)

@app.get("/callback/twitter")
async def callback_twitter(request: Request, code: str = None, state: str = None):
    # Validar state
    session_state = request.session.get("twitter_state")
    if state != session_state:
        raise HTTPException(403, "Invalid state")
    
    code_verifier = request.session.get("twitter_code_verifier")
    del request.session["twitter_state"]
    del request.session["twitter_code_verifier"]
    
    # Trocar código por token
    async with httpx.AsyncClient() as client:
        # Twitter usa Basic Auth para client credentials
        import base64
        credentials = base64.b64encode(
            f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}".encode()
        ).decode()
        
        token_response = await client.post(
            "https://api.twitter.com/2/oauth2/token",
            data={
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": TWITTER_REDIRECT_URI,
                "code_verifier": code_verifier
            },
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
    
    # Obter dados do usuário
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://api.twitter.com/2/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        user_data = user_response.json()
    
    request.session["access_token"] = access_token
    request.session["provider"] = "twitter"
    
    return RedirectResponse(url="/dashboard")
```

### 3. Facebook OAuth 2.0

```python
FACEBOOK_CLIENT_ID = os.getenv("FACEBOOK_CLIENT_ID")
FACEBOOK_CLIENT_SECRET = os.getenv("FACEBOOK_CLIENT_SECRET")
FACEBOOK_REDIRECT_URI = "http://localhost:8000/callback/facebook"

@app.get("/login/facebook")
async def login_facebook(request: Request):
    state = generate_state()
    request.session["facebook_state"] = state
    
    params = {
        "client_id": FACEBOOK_CLIENT_ID,
        "redirect_uri": FACEBOOK_REDIRECT_URI,
        "state": state,
        "scope": "email,public_profile"  # Separado por vírgula
    }
    
    facebook_auth_url = f"https://www.facebook.com/v12.0/dialog/oauth?{urlencode(params)}"
    return RedirectResponse(url=facebook_auth_url)

@app.get("/callback/facebook")
async def callback_facebook(request: Request, code: str = None, state: str = None):
    session_state = request.session.get("facebook_state")
    if state != session_state:
        raise HTTPException(403, "Invalid state")
    
    del request.session["facebook_state"]
    
    # Trocar código por token
    async with httpx.AsyncClient() as client:
        token_response = await client.get(
            "https://graph.facebook.com/v12.0/oauth/access_token",
            params={  # Facebook usa query params no GET
                "client_id": FACEBOOK_CLIENT_ID,
                "client_secret": FACEBOOK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": FACEBOOK_REDIRECT_URI
            }
        )
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
    
    # Obter dados do usuário
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            "https://graph.facebook.com/me",
            params={
                "fields": "id,name,email,picture",
                "access_token": access_token
            }
        )
        
        user_data = user_response.json()
    
    request.session["access_token"] = access_token
    request.session["provider"] = "facebook"
    
    return RedirectResponse(url="/dashboard")
```

---

## 🛠️ Sistema Multi-Provider Completo

```python
from enum import Enum
from typing import Dict, Any

class Provider(str, Enum):
    GITHUB = "github"
    GOOGLE = "google"
    TWITTER = "twitter"
    FACEBOOK = "facebook"

class OAuthConfig:
    PROVIDERS = {
        Provider.GITHUB: {
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "user_url": "https://api.github.com/user",
            "scopes": "read:user",
            "token_method": "POST",
            "token_format": "json"
        },
        Provider.GOOGLE: {
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "user_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "scopes": "openid email profile",
            "token_method": "POST",
            "token_format": "data",
            "extra_params": {"response_type": "code", "access_type": "offline"}
        },
        Provider.TWITTER: {
            "authorize_url": "https://twitter.com/i/oauth2/authorize",
            "token_url": "https://api.twitter.com/2/oauth2/token",
            "user_url": "https://api.twitter.com/2/users/me",
            "scopes": "tweet.read users.read offline.access",
            "token_method": "POST",
            "token_format": "data",
            "requires_pkce": True
        },
        Provider.FACEBOOK: {
            "authorize_url": "https://www.facebook.com/v12.0/dialog/oauth",
            "token_url": "https://graph.facebook.com/v12.0/oauth/access_token",
            "user_url": "https://graph.facebook.com/me",
            "scopes": "email,public_profile",
            "token_method": "GET",
            "token_format": "params"
        }
    }

@app.get("/login/{provider}")
async def login_oauth(provider: Provider, request: Request):
    """Login genérico para qualquer provider"""
    config = OAuthConfig.PROVIDERS[provider]
    
    state = generate_state()
    request.session[f"{provider}_state"] = state
    
    params = {
        "client_id": os.getenv(f"{provider.upper()}_CLIENT_ID"),
        "redirect_uri": f"http://localhost:8000/callback/{provider}",
        "scope": config["scopes"],
        "state": state,
    }
    
    # Adicionar parâmetros extras se necessário
    if "extra_params" in config:
        params.update(config["extra_params"])
    
    # PKCE para Twitter
    if config.get("requires_pkce"):
        code_verifier = secrets.token_urlsafe(32)
        request.session[f"{provider}_code_verifier"] = code_verifier
        
        import hashlib, base64
        challenge = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(challenge).decode().rstrip('=')
        
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    
    auth_url = f"{config['authorize_url']}?{urlencode(params)}"
    return RedirectResponse(url=auth_url)

@app.get("/callback/{provider}")
async def callback_oauth(provider: Provider, request: Request, code: str, state: str):
    """Callback genérico para qualquer provider"""
    # Validar state
    session_state = request.session.get(f"{provider}_state")
    if state != session_state:
        raise HTTPException(403, "Invalid state")
    
    del request.session[f"{provider}_state"]
    
    config = OAuthConfig.PROVIDERS[provider]
    
    # Preparar requisição de token
    token_data = {
        "client_id": os.getenv(f"{provider.upper()}_CLIENT_ID"),
        "client_secret": os.getenv(f"{provider.upper()}_CLIENT_SECRET"),
        "code": code,
        "redirect_uri": f"http://localhost:8000/callback/{provider}",
    }
    
    if config.get("requires_pkce"):
        token_data["code_verifier"] = request.session[f"{provider}_code_verifier"]
        del request.session[f"{provider}_code_verifier"]
    
    if config["token_format"] != "params":
        token_data["grant_type"] = "authorization_code"
    
    # Fazer requisição de token
    async with httpx.AsyncClient() as client:
        if config["token_method"] == "POST":
            if config["token_format"] == "json":
                token_response = await client.post(
                    config["token_url"],
                    json=token_data,
                    headers={"Accept": "application/json"}
                )
            else:  # data
                token_response = await client.post(
                    config["token_url"],
                    data=token_data
                )
        else:  # GET
            token_response = await client.get(
                config["token_url"],
                params=token_data
            )
        
        token_result = token_response.json()
        access_token = token_result["access_token"]
    
    # Salvar na sessão
    request.session["access_token"] = access_token
    request.session["provider"] = provider
    
    return RedirectResponse(url="/dashboard")
```

---

## 📚 Recursos para Cada Provider

### GitHub
- 📖 Docs: https://docs.github.com/en/developers/apps/building-oauth-apps
- 🔑 Criar app: https://github.com/settings/developers
- 🎯 Scopes: https://docs.github.com/en/developers/apps/scopes-for-oauth-apps

### Google
- 📖 Docs: https://developers.google.com/identity/protocols/oauth2
- 🔑 Criar app: https://console.cloud.google.com/apis/credentials
- 🎯 Scopes: https://developers.google.com/identity/protocols/oauth2/scopes

### Twitter
- 📖 Docs: https://developer.twitter.com/en/docs/authentication/oauth-2-0
- 🔑 Criar app: https://developer.twitter.com/en/portal/dashboard
- 🎯 Scopes: https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code

### Facebook
- 📖 Docs: https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow
- 🔑 Criar app: https://developers.facebook.com/apps
- 🎯 Permissions: https://developers.facebook.com/docs/permissions/reference

---

## 🎯 Checklist de Segurança

- [ ] ✅ State token para prevenir CSRF
- [ ] ✅ HTTPS em produção (https_only=True)
- [ ] ✅ Session secret forte e único
- [ ] ✅ Tokens nunca expostos ao cliente (JavaScript)
- [ ] ✅ Cookies httpOnly (automático no SessionMiddleware)
- [ ] ✅ Timeout de sessão configurado
- [ ] ✅ Escopos mínimos necessários
- [ ] ✅ Client secret nunca commitado no Git
- [ ] ✅ Validação de redirect_uri
- [ ] ✅ PKCE para providers que suportam

---

**Criado em:** 16 de dezembro de 2025  
**Autor:** Documentação do OAuth Dashboard Python/FastAPI
