const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Set up SQLite database
const db = new sqlite3.Database('./users.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  password TEXT NOT NULL
)`);
db.run(`CREATE TABLE IF NOT EXISTS uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  stored_filename TEXT,
  original_filename TEXT,
  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (username) REFERENCES users (username)
)`);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

app.use(express.static(__dirname));

// Registration route with password hashing
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
    if (row) {
      return res.send('User already exists.');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
      if (err) return res.send('Error registering user.');
      res.send('Registration successful. <a href="/login.html">Login</a>');
    });
  });
});

// Login route with password verification
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT password FROM users WHERE username = ?', [username], async (err, row) => {
    if (!row) {
      return res.send('Invalid credentials. <a href="/login.html">Try again</a>');
    }
    const match = await bcrypt.compare(password, row.password);
    if (match) {
      req.session.user = username;
      return res.redirect('/urologyst3.html');
    }
    res.send('Invalid credentials. <a href="/login.html">Try again</a>');
  });
});

// Protect your page
app.use('/urologyst3.html', (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.redirect('/login.html');
});

// Set up storage for uploaded files
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Save files in /uploads/<username>/
    if (!req.session.user) return cb(new Error('Not logged in'));
    const userDir = path.join(__dirname, 'uploads', req.session.user);
    fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// Serve uploads statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Handle file upload
app.post('/upload', upload.single('fileUpload'), (req, res) => {
  if (!req.file || !req.session.user) {
    return res.status(400).send('No file uploaded or not logged in.');
  }
  db.run(
    'INSERT INTO uploads (username, stored_filename, original_filename) VALUES (?, ?, ?)',
    [req.session.user, req.file.filename, req.file.originalname],
    (err) => {
      if (err) return res.status(500).send('Database error.');
      res.redirect('/urologyst3.html');
    }
  );
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login.html');
  });
});

// Get the latest upload for the logged-in user
app.get('/latest-upload', (req, res) => {
  if (!req.session.user) return res.status(401).send('Not logged in');
  db.get(
    'SELECT stored_filename, original_filename FROM uploads WHERE username = ? ORDER BY uploaded_at DESC LIMIT 1',
    [req.session.user],
    (err, row) => {
      if (err || !row) return res.json(null);
      res.json(row);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

