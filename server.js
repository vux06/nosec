const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

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
});

app.get('/admin.html', checkAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.send('Admins only');
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});


app.listen(PORT, () => {
  console.log(`🚀 NoSec running at http://localhost:${PORT}`);
});
