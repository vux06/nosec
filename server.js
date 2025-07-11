const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const app = express();
const PORT = 3000;
const SECRET = 'supersecret';
const axios = require('axios');
const multer = require('multer');
const fs = require('fs');

let users = [];
const fakeUsers = {
  'vux': {
    username: 'vux',
    role: 'user',
    email: 'vux@nosec.local',
    bio: 'Just a regular NoSec user.'
  },
  'admin': {
    username: 'admin',
    role: 'admin',
    email: 'admin@nosec.local',
    bio: 'Super secret administrator profile 👀'
  },
  'bob': {
    username: 'bob',
    role: 'user',
    email: 'bob@nosec.local',
    bio: 'Frontend guy with a love for React and 🍕.'
  },
  'alice': {
    username: 'alice',
    role: 'user',
    email: 'alice@nosec.local',
    bio: 'Backend engineer — Python and caffeine enthusiast.'
  },
  'eve': {
    username: 'eve',
    role: 'user',
    email: 'eve@nosec.local',
    bio: '“Just testing security.” 👀'
  },
  'internal': {
    username: 'internal',
    role: 'internal-only',
    email: 'internal@nosec.local',
    bio: 'System service account. Not meant for public eyes.'
  }
};


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

function escapeHTML(str) {
  return str
    .toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

app.get('/ssrf', checkAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');

  const target = req.query.target;
  let output = null;

  if (target) {
    try {
      const response = await axios.get(target, { timeout: 3000 });
      output = response.data.toString();

      // Limit output length to avoid UI breaking
      if (output.length > 10000) {
        output = output.substring(0, 10000) + '\n\n...truncated...';
      }
    } catch (err) {
      output = `Error fetching URL: ${err.message}`;
    }
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>🌐 SSRF Lab - NoSec</title>
      <link rel="stylesheet" href="/style.css">
      <style>
        pre {
          background-color: #1e1e1e;
          color: #00ff91;
          padding: 1rem;
          border-radius: 6px;
          overflow: auto;
          max-height: 400px;
          max-width: 100%;
          box-sizing: border-box;
          white-space: pre-wrap;
          word-break: break-word;
          font-family: monospace;
          font-size: 0.9rem;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h2>🌐 SSRF Lab</h2>
        <p>Enter a URL to fetch:</p>
        <form method="GET" action="/ssrf">
          <input name="target" placeholder="e.g. http://example.com" required />
          <button type="submit">Fetch</button>
        </form>

        ${output !== null ? `
          <hr>
          <h3>Fetched Content:</h3>
          <pre>${escapeHTML(output)}</pre>
        ` : ''}
      </div>
    </body>
    </html>
  `;

  res.send(html);
});
// 🧱 Profile page generator
function buildProfileHTML(profile) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>🔎 IDOR Lab - NoSec</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h2>🔎 IDOR Lab</h2>
        <p><strong>Username:</strong> ${profile.username}</p>
        <p><strong>Email:</strong> ${profile.email}</p>
        <p><strong>Role:</strong> ${profile.role}</p>
        <p><strong>Bio:</strong> ${profile.bio}</p>

        <hr>
        <p>This is a public user profile.</p>
        <a href="/dashboard">⬅️ Back to Dashboard</a>
      </div>
    </body>
    </html>
  `;
}

// 🚪 /profile route with IDOR logic
app.get('/profile', checkAuth, (req, res) => {
  const userParam = req.query.user;

  // Attacker tries to access someone else's profile
  if (userParam) {
    const profile = fakeUsers[userParam];
    if (!profile) {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>User Not Found</title><link rel="stylesheet" href="/style.css"></head>
        <body>
          <div class="container">
            <h2>❌ User Not Found</h2>
            <p>This profile doesn't exist.</p>
            <a href="/profile">⬅️ Back to profile list</a>
          </div>
        </body>
        </html>
      `);
    }

    return res.send(buildProfileHTML(profile));
  }

  // No param — show a random non-admin user
  const usernames = Object.keys(fakeUsers).filter(u => u !== 'admin');
  const randomUser = fakeUsers[usernames[Math.floor(Math.random() * usernames.length)]];

  res.send(buildProfileHTML(randomUser));
});


// Ensure uploads folder exists
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

// 🧨 Storage config (no filtering)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// 🧱 Upload form (GET)
app.get('/upload', checkAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>📤 File Upload Lab - NoSec</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h2>📤 File Upload Lab</h2>
        <p>Upload any file. Try bypassing filters 😉</p>
        <form method="POST" action="/upload" enctype="multipart/form-data">
          <input type="file" name="file" required />
          <button type="submit">Upload</button>
        </form>
        <p>Uploaded files appear at <code>/uploads/&lt;filename&gt;</code></p>
        <a href="/dashboard">⬅️ Back to Dashboard</a>
      </div>
    </body>
    </html>
  `);
});

// 📥 Handle uploads (POST) - VULNERABLE
app.post('/upload', checkAuth, upload.single('file'), (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');

  if (!req.file) return res.send('No file uploaded.');
  res.send(`
    <h3>✅ File uploaded!</h3>
    <p><a href="/uploads/${req.file.originalname}" target="_blank">View File</a></p>
    <a href="/upload">⬅️ Upload Another</a>
  `);
});

// 🌐 Serve uploaded files
app.use('/uploads', express.static('uploads'));


app.listen(PORT, () => {
  console.log(`🚀 NoSec running at http://localhost:${PORT}`);
});

