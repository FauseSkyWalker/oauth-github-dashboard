# GitHub OAuth Dashboard

A secure GitHub OAuth 2.0 authentication demo that displays user profile and repository data. This implementation follows security best practices including CSRF protection, secure session management, and proper token handling.

## Quick Start

### Prerequisites
- Node.js (v14 or higher)
- A GitHub account

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd oauth-github-dashboard

# Install dependencies
npm install
```

## Setup

### 1. Create GitHub OAuth App

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **"New OAuth App"**
3. Fill in the details:
   - **Application name:** `My GitHub Dashboard` (or your choice)
   - **Homepage URL:** `http://localhost:3000`
   - **Authorization callback URL:** `http://localhost:3000/callback`
4. Click **"Register application"**
5. Copy the **Client ID** and **Client Secret**

### 2. Configure Environment Variables

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` and add your credentials:

```env
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
SESSION_SECRET=your_random_session_secret_here
REDIRECT_URI=http://localhost:3000/callback
PORT=3000
NODE_ENV=development
```

**Generate a secure session secret:**
```bash
openssl rand -base64 32
```

### 3. Run the Application

```bash
# Production mode
npm start

# Development mode (with auto-reload)
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000)

## Features

### Security Highlights
- **CSRF Protection** - State parameter validation prevents cross-site request forgery
- **Secure Sessions** - httpOnly cookies prevent XSS token theft
- **Server-side Token Storage** - Access tokens never exposed to client JavaScript
- **Single-use State Tokens** - Prevents replay attacks
- **Session Timeout** - Automatic logout after 1 hour of inactivity
- **Minimal Scopes** - Requests only `read:user` permission

### Functionality
- GitHub OAuth 2.0 login flow
- User profile display (avatar, bio, stats)
- Repository listing with stars and languages
- Recent activity tracking
- Secure logout with session destruction

## Project Structure

```
oauth-github-dashboard/
├── server.js              # Main Express server with OAuth implementation
├── public/
│   ├── index.html         # Landing page
│   └── dashboard.html     # Protected dashboard (post-login)
├── examples/
│   └── insecure/          # Examples of insecure implementations (educational)
├── .env.example           # Environment variable template
└── package.json
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/login` | GET | Initiates OAuth flow |
| `/callback` | GET | OAuth callback handler |
| `/dashboard` | GET | Protected dashboard page |
| `/api/user` | GET | Fetch GitHub user profile |
| `/api/repos` | GET | Fetch user repositories |
| `/api/stats` | GET | Fetch activity statistics |
| `/api/validate` | GET | Validate current session |
| `/logout` | GET | Destroy session and logout |


## Troubleshooting

### Common Issues

**"Missing required environment variables"**
- Ensure `.env` file exists with all required variables
- Check that `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` are set

**"State verification failed"**
- Clear browser cookies and try again
- Ensure callback URL in GitHub OAuth app matches exactly

**"Authentication failed"**
- Verify GitHub OAuth app credentials are correct
- Check that redirect URI matches GitHub app configuration

## Development

```bash
# Run with debug logging
npm run debug

# Run with auto-reload and debugging
npm run debug:dev
```

## License

MIT

## Learn More

- [OAuth 2.0 Specification](https://oauth.net/2/)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps)
- [Express Session Security](https://github.com/expressjs/session#cookie-options)
