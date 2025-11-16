const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// GitHub OAuth configuration
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || 'http://localhost:3000/callback';

// Verify environment variables are loaded
if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
  console.error('WARNING: Missing required environment variables');
  console.error('Make sure .env file exists with GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET');
  process.exit(1);
}

// Verify session secret is set (critical for security)
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'your-secret-key-change-this') {
  console.error('WARNING: SESSION_SECRET is required for security');
  console.error('Generate a secure random string: openssl rand -base64 32');
  process.exit(1);
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET, // Required, no default fallback for security
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // "HTTPS only" in production
    httpOnly: true,                                 // Prevents XSS attacks
    sameSite: 'lax',                               // CSRF protection
    maxAge: 60 * 60 * 1000                         // 1 hour session timeout
  }
}));

// Helper function to generate cryptographically secure random string
// This prevents CSRF attacks by ensuring the callback we receive is from the same user who initiated login
function generateState() {
  // crypto.randomBytes generates cryptographically strong random data
  // 32 bytes = 256 bits of entropy, making it virtually impossible to guess
  return crypto.randomBytes(32).toString('hex');
}

// Middleware to check authentication
function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// OAuth login route - redirects to GitHub
app.get('/login', (req, res) => {
  console.log('Starting OAuth flow...');

  // Generate state for CSRF protection
  const state = generateState();
  req.session.state = state;

  // Build GitHub authorization URL with state parameter
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,       // Identifies our application to GitHub
    redirect_uri: REDIRECT_URI,         // Where GitHub sends the user after auth
    scope: 'read:user',                // Minimal permissions: read user info only (read-only)
    state: state                       // CSRF protection token
  });

  const githubAuthURL = `https://github.com/login/oauth/authorize?${params}`;
  console.log('Generated state:', state);

  res.redirect(githubAuthURL);
});

// OAuth callback route - handles GitHub's response
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Step 1: Verify state to prevent CSRF attacks
  // The state parameter ensures this callback is in response to OUR authorization request
  // Without this check, attackers could trick users into authorizing malicious apps
  if (!state || state !== req.session.state) {
    console.error('ERROR: State mismatch - possible CSRF attempt');
    console.error('Expected:', req.session.state);
    console.error('Received:', state);
    return res.status(403).send('State verification failed - possible CSRF attempt');
  }

  // Clear used state immediately after validation
  // Each state is single-use to prevent replay attacks
  delete req.session.state;

  // Save session to ensure state deletion is persisted
  // This prevents race conditions where the session might not save
  req.session.save((err) => {
    if (err) {
      console.error('Session save error:', err);
    }
  });

  if (!code) {
    return res.status(400).send('No authorization code received');
  }

  try {
    console.log('Exchanging code for access token...');

    // Step 2: Exchange authorization code for access token
    // This code is single-use and expires in 10 minutes - we must exchange it immediately
    // The client_secret is included here, which is why this MUST happen server-side
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,  // Never expose this to the client!
      code: code,                            // Single-use authorization code
      redirect_uri: REDIRECT_URI              // Must match exactly what's registered
    }, {
      headers: {
        Accept: 'application/json'
      }
    });

    const { access_token, scope, token_type } = tokenResponse.data;

    if (!access_token) {
      throw new Error('No access token received');
    }

    // Step 3: Store token securely in server-side session
    // CRITICAL: Token stays on server, never sent to browser JavaScript
    // Client only gets an httpOnly session cookie that can't be accessed by JS
    req.session.accessToken = access_token;
    req.session.tokenScope = scope;

    console.log('Authentication successful');
    console.log(`Granted scopes: ${scope}`);

    // Redirect to dashboard
    res.redirect('/dashboard');
  } catch (error) {
    console.error('ERROR: Token exchange failed:', error.message);
    res.status(500).send('Authentication failed. Please try again.');
  }
});

// Dashboard page route
app.get('/dashboard', (req, res) => {
  if (!req.session.accessToken) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Get user profile endpoint
app.get('/api/user', requireAuth, async (req, res) => {
  try {
    const response = await axios.get('https://api.github.com/user', {
      headers: {
        // Bearer token authentication - "Bearer" indicates the type of token
        // The token proves we're authorized to access this user's data
        'Authorization': `Bearer ${req.session.accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    // Send only necessary data to client
    const { login, name, avatar_url, public_repos, followers, bio, company, location } = response.data;
    res.json({ login, name, avatar_url, public_repos, followers, bio, company, location });

  } catch (error) {
    console.error('API call failed:', error.response?.status);

    // Check if token is expired or revoked
    // 401 means unauthorized - the token is no longer valid
    // User needs to re-authenticate with GitHub
    if (error.response?.status === 401) {
      delete req.session.accessToken;
      return res.status(401).json({ error: 'Token expired or revoked' });
    }

    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Get user repositories endpoint with rate limit awareness
app.get('/api/repos', requireAuth, async (req, res) => {
  try {
    const response = await axios.get('https://api.github.com/user/repos', {
      headers: {
        'Authorization': `Bearer ${req.session.accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      },
      params: {
        sort: 'updated',
        per_page: 20  // Limit results
      }
    });

    // Check rate limits
    const remaining = response.headers['x-ratelimit-remaining'];
    if (remaining < 100) {
      console.warn(`WARNING: API rate limit low: ${remaining} requests remaining`);
    }

    // Process and send relevant data
    const repoStats = response.data.map(repo => ({
      name: repo.name,
      description: repo.description,
      stars: repo.stargazers_count,
      language: repo.language,
      updated: repo.updated_at,
      url: repo.html_url,
      private: repo.private
    }));

    res.json(repoStats);

  } catch (error) {
    console.error('Repository fetch failed:', error.message);
    res.status(500).json({ error: 'Failed to fetch repositories' });
  }
});

// Dashboard API route - returns user's GitHub data as JSON
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    // Fetch user data from GitHub
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    // Fetch user's repositories
    const reposResponse = await axios.get('https://api.github.com/user/repos', {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      },
      params: {
        sort: 'updated',
        per_page: 10
      }
    });

    // Check rate limits
    const remaining = reposResponse.headers['x-ratelimit-remaining'];
    if (remaining < 100) {
      console.warn(`WARNING: API rate limit low: ${remaining} requests remaining`);
    }

    res.json({
      user: userResponse.data,
      repositories: reposResponse.data
    });
  } catch (error) {
    console.error('ERROR: Error fetching GitHub data:', error.response?.status);

    // Check if token is expired or revoked
    if (error.response?.status === 401) {
      delete req.session.accessToken;
      return res.status(401).json({ error: 'Token expired or revoked' });
    }

    res.status(500).json({ error: 'Error fetching data' });
  }
});

// API endpoint to get commit statistics
app.get('/api/stats', requireAuth, async (req, res) => {

  try {
    // Fetch user info
    const userResponse = await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`
      }
    });

    const username = userResponse.data.login;

    // Fetch recent events (includes commits)
    const eventsResponse = await axios.get(`https://api.github.com/users/${username}/events`, {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`
      },
      params: {
        per_page: 100
      }
    });

    // Calculate statistics
    const stats = {
      totalEvents: eventsResponse.data.length,
      pushEvents: eventsResponse.data.filter(e => e.type === 'PushEvent').length,
      pullRequests: eventsResponse.data.filter(e => e.type === 'PullRequestEvent').length,
      issues: eventsResponse.data.filter(e => e.type === 'IssuesEvent').length,
      recentActivity: eventsResponse.data.slice(0, 10)
    };

    res.json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Error fetching statistics' });
  }
});

// Token validation endpoint - checks if current token is still valid
app.get('/api/validate', requireAuth, async (req, res) => {
  try {
    // Check if token is still valid by making a simple API call
    await axios.get('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${req.session.accessToken}`,
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    res.json({ valid: true, scope: req.session.tokenScope });
  } catch (error) {
    // Token is invalid or expired
    if (error.response?.status === 401) {
      delete req.session.accessToken;
      delete req.session.tokenScope;
    }
    res.json({ valid: false });
  }
});

// Logout route - properly destroy session
app.get('/logout', (req, res) => {
  // Completely destroy the session on the server
  req.session.destroy((err) => {
    if (err) {
      console.error('ERROR: Logout error:', err);
      return res.status(500).send('Error logging out');
    }
    // Clear the session cookie from the client's browser
    // This ensures complete logout - no tokens remain anywhere
    res.clearCookie('connect.sid');
    console.log('User logged out successfully');
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, () => {
  console.log('OAuth Dashboard server started successfully!');
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Make sure your GitHub OAuth app callback URL matches exactly!');
  console.log('Environment variables loaded:', {
    hasClientId: !!GITHUB_CLIENT_ID,
    hasClientSecret: !!GITHUB_CLIENT_SECRET,
    hasSessionSecret: !!process.env.SESSION_SECRET
  });
});