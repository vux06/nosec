const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const app = express();
const PORT = 3000;
const SECRET = 'supersecret';

let users = [];

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Register route
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send('Missing fields');
  users.push({ username, password, role: 'user' });
  res.redirect('/login.html');
});

// Login route
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.send('Invalid credentials');

  // Generate JWT with role
  const token = jwt.sign({ username: user.username, role: user.role }, SECRET);
  res.cookie('auth', token);
  res.redirect('/welcome.html');
});

// Auth middleware (intentionally vulnerable)
function checkAuth(req, res, next) {
  const token = req.cookies.auth;
  if (!token) return res.redirect('/login.html');

  try {
    // VULNERABLE: just decoding, not verifying!
    const decoded = jwt.decode(token);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect('/login.html');
  }
}

// Routes
app.get('/welcome.html', checkAuth, (req, res) => {
  if (req.user.role !== 'user') return res.send('Access denied');
  res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
  res.redirect('/blog.html');
});

app.get('/admin.html', checkAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/blog.html', checkAuth, (req, res) => {
  if (req.user.role !== 'user') return res.send('Access denied');

  const comment = req.query.comment || '';

  const blogHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>NoSec Blog</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h1>How to Build a Secure Website (but don't trust this blog)</h1>
        <p style="color: #ccc; font-size: 14px;">Posted on: <em>July 11, 2025</em></p>
        <p>
          Building a secure website involves multiple layers of defense. At a minimum, you should:
          <ul>
            <li>Validate and sanitize all user inputs</li>
            <li>Use secure headers (e.g., CSP, HSTS)</li>
            <li>Implement proper authentication and authorization</li>
            <li>Protect against common vulnerabilities like XSS, CSRF, SQLi, and IDOR</li>
            <li>Use HTTPS everywhere</li>
          </ul>
        </p>
        <p>
          But ironically, this blog doesn't do any of that. In fact, it welcomes you to try exploiting it. 😉
        </p>

        <div style="margin-top: 2rem; padding: 1rem; background-color: #222; border-radius: 8px;">
          <strong>👀 Try visiting the <a href="/admin.html" style="color: #ff0055;">Admin Page</a></strong>.<br/>
          Can you access it without being an admin?
        </div>

        <hr />
        <h2>Leave a comment</h2>
        <form method="GET" action="/blog.html">
          <input type="text" name="comment" placeholder="Say something..." />
          <button type="submit">Post</button>
        </form>

        <hr />
        <h3>Recent Comment:</h3>
        <div style="padding: 1rem; background-color: #222; color: #fff; border-radius: 6px;">
          ${comment}
        </div>
      </div>
    </body>
    </html>
  `;

  res.send(blogHtml);
});

// Route with basic 403 logic + known bypass vectors
app.get(['/admin/settings', '/admin/settings/', '/admin/settings%2f', '/..;/admin/settings'], (req, res) => {
  // Simulated protection: only allow if bypass header is present
  const bypassHeader = req.headers['x-original-url'] || req.headers['x-rewrite-url'];

  if (bypassHeader === '/admin/settings') {
    return res.sendFile(path.join(__dirname, 'views', 'admin-settings.html'));
  }

  // Block normally
  res.status(403).send(`
    <h2>🚫 403 Forbidden</h2>
    <p>Access to this resource is denied.</p>
  `);
});


app.get('/dashboard.html', checkAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.send('Access denied');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

app.get('/os-command', checkAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');

  const host = req.query.host;

  if (host) {
    exec(`ping -c 2 ${host}`, (err, stdout, stderr) => {
      const output = stdout || stderr || 'Error executing command';
      renderForm(res, output);
    });
  } else {
    renderForm(res, null);
  }

  function renderForm(res, output) {
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>OS Command Injection - NoSec</title>
        <link rel="stylesheet" href="/style.css">
        <style>
          pre {
            background-color: #1e1e1e;
            color: #f1f1f1;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            max-width: 100%;
            box-sizing: border-box;
            white-space: pre-wrap;
            word-break: break-all;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>🧨 OS Command Injection Lab</h2>
          <p>Enter a host to ping:</p>
          <form method="GET" action="/os-command">
            <input name="host" placeholder="e.g. google.com" required />
            <button type="submit">Ping</button>
          </form>

          ${output !== null ? `
            <hr>
            <h3>Command Output:</h3>
            <pre>${output}</pre>
          ` : ''}
        </div>
      </body>
      </html>
    `;

    res.send(html);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 NoSec running at http://localhost:${PORT}`);
});

