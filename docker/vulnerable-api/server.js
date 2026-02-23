const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// VULNERABILITY 1: Hardcoded credentials
const DB_CONFIG = {
  host: process.env.DB_HOST || 'mysql',
  user: 'admin',
  password: 'admin123',
  database: 'testdb'
};

const db = mysql.createConnection(DB_CONFIG);

// VULNERABILITY 2: SQL Injection
app.get('/api/user/:id', (req, res) => {
  const userId = req.params.id;
  // Vulnerable to SQL injection - no sanitization
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// VULNERABILITY 3: Weak JWT secret
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // No password validation - accepts anything
  if (username) {
    const token = jwt.sign({ username }, 'insecure_secret', { expiresIn: '24h' });
    res.json({ token, message: 'Login successful' });
  } else {
    res.status(400).json({ error: 'Username required' });
  }
});

// VULNERABILITY 4: No rate limiting
app.post('/api/transfer', (req, res) => {
  const { from, to, amount } = req.body;
  // No authentication check, no rate limiting
  res.json({ success: true, message: `Transferred ${amount} from ${from} to ${to}` });
});

// VULNERABILITY 5: Information disclosure
app.get('/api/debug', (req, res) => {
  res.json({
    env: process.env,
    db_config: DB_CONFIG,
    paths: __dirname
  });
});

// VULNERABILITY 6: Path traversal
app.get('/api/file', (req, res) => {
  const filename = req.query.name;
  const fs = require('fs');
  
  // No path sanitization
  try {
    const content = fs.readFileSync(`/app/files/${filename}`, 'utf8');
    res.send(content);
  } catch (err) {
    res.status(404).json({ error: 'File not found' });
  }
});

// VULNERABILITY 7: Missing security headers
app.get('/api/status', (req, res) => {
  res.json({
    status: 'running',
    version: '1.0.0',
    vulnerabilities: 'intentional'
  });
});

// VULNERABILITY 8: Unvalidated redirects
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url); // Open redirect vulnerability
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable API running on port ${PORT}`);
  console.log('WARNING: This application contains intentional vulnerabilities for testing!');
});

module.exports = app;
