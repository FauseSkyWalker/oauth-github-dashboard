/**
 * WARNING: INSECURE OAuth IMPLEMENTATION
 *
 * This file contains examples of common OAuth security mistakes.
 * DO NOT USE THIS CODE IN PRODUCTION!
 * This is for educational purposes only to show what NOT to do.
 */

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// BAD EXAMPLE 1: Hardcoded credentials
const GITHUB_CLIENT_ID = "Iv1.8a61f9b3a7aba766";  // Never hardcode!
const GITHUB_CLIENT_SECRET = "1234567890abcdef1234567890abcdef12345678";  // NEVER do this!
const GITHUB_TOKEN = "ghp_RealTokenHere456...";  // Absolutely wrong!

// BAD EXAMPLE 2: Insecure session configuration
app.use(session({
  secret: 'keyboard cat',  // Weak, predictable secret
  resave: true,  // Should be false
  saveUninitialized: true,  // Should be false
  cookie: {
    httpOnly: false,  // ❌ Allows client-side JavaScript to access cookie
    secure: false,    // ❌ Sends cookie over HTTP
    sameSite: false   // ❌ No CSRF protection
  }
}));

// BAD EXAMPLE 3: No state parameter (CSRF vulnerability)
app.get('/login', (req, res) => {
  // Missing state parameter - vulnerable to CSRF attacks!
  const githubAuthURL = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=http://localhost:3000/callback&scope=repo,user,delete_repo,admin:org`;
  res.redirect(githubAuthURL);
});

// BAD EXAMPLE 4: No state validation in callback
app.get('/callback', async (req, res) => {
  const { code } = req.query;
  // No state validation - accepting any callback!
  try {
    const tokenResponse = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code: code
    }, {
      headers: {
        Accept: 'application/json'
      }
    });

    const accessToken = tokenResponse.data.access_token;

    // BAD EXAMPLE 5: Sending token to client
    res.json({
      token: accessToken,  // NEVER expose token to client!
      message: "Here's your token!"
    });

  } catch (error) {
    // BAD EXAMPLE 6: Exposing sensitive error details
    res.status(500).json({
      error: error.message,
      stack: error.stack,  // Exposing stack trace!
      config: error.config  // Might contain secrets!
    });
  }
});

// BAD EXAMPLE 7: Storing token in localStorage (client-side)
app.get('/bad-dashboard', (req, res) => {
  res.send(`
    <html>
    <body>
      <script>
        // ❌ NEVER store tokens in localStorage!
        localStorage.setItem('github_token', '${req.query.token}');

        // ❌ Sending token in URL parameters
        fetch('/api/user?token=' + localStorage.getItem('github_token'))
          .then(res => res.json())
          .then(data => console.log(data));
      </script>
    </body>
    </html>
  `);
});

// BAD EXAMPLE 8: Token in URL parameters
app.get('/api/user', async (req, res) => {
  const token = req.query.token;  // Tokens in URLs get logged!

  const response = await axios.get('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  res.json(response.data);
});


// BAD EXAMPLE 9: Requesting excessive permissions
const EXCESSIVE_SCOPES = 'user repo delete_repo admin:org write:packages delete:packages admin:enterprise';

// BAD EXAMPLE 10: No logout functionality
// Missing proper session destruction and token revocation

// BAD EXAMPLE 11: Logging sensitive data
app.use((req, res, next) => {
  console.log('Request headers:', req.headers);  // Might log Authorization header!
  console.log('Session data:', req.session);  // Might log tokens!
  next();
});

// BAD EXAMPLE 12: No HTTPS in production
app.listen(3001, () => {
  console.log('Insecure server running on HTTP!');
});

/*
 * NEVER USE THESE PATTERNS IN PRODUCTION CODE!
 */

module.exports = app;  // For testing purposes