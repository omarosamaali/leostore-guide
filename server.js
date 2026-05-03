const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const CONTENT_FILE = path.join(__dirname, 'data', 'content.json');
const AUTH_FILE = path.join(__dirname, 'data', 'auth.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize auth file if missing
function initAuth() {
  if (!fs.existsSync(AUTH_FILE)) {
    const defaultAuth = {
      username: 'admin',
      password: hashPassword('leostore2025'),
      secret: crypto.randomBytes(32).toString('hex')
    };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(defaultAuth, null, 2), 'utf8');
  }
}

function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw + 'leostore_salt').digest('hex');
}

function getAuth() {
  return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
}

function generateToken(auth) {
  const payload = Buffer.from(JSON.stringify({ user: auth.username, ts: Date.now() })).toString('base64');
  const sig = crypto.createHmac('sha256', auth.secret).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifyToken(token, auth) {
  try {
    const [payload, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', auth.secret).update(payload).digest('hex');
    if (sig !== expected) return false;
    const data = JSON.parse(Buffer.from(payload, 'base64').toString());
    // Token valid for 7 days
    return (Date.now() - data.ts) < 7 * 24 * 60 * 60 * 1000;
  } catch { return false; }
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token = header.replace('Bearer ', '');
  if (!token || !verifyToken(token, getAuth())) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ===== Public Routes =====

app.get('/api/content', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(CONTENT_FILE, 'utf8'));
    res.json(data);
  } catch {
    res.status(500).json({ error: 'Failed to read content' });
  }
});

// ===== Admin Routes =====

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  const auth = getAuth();
  if (username === auth.username && hashPassword(password) === auth.password) {
    const token = generateToken(auth);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/api/admin/verify', authMiddleware, (req, res) => {
  res.json({ ok: true });
});

app.post('/api/admin/content', authMiddleware, (req, res) => {
  try {
    const data = req.body;
    if (!data.site || !data.devices) return res.status(400).json({ error: 'Invalid data' });
    fs.writeFileSync(CONTENT_FILE, JSON.stringify(data, null, 2), 'utf8');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Failed to save' });
  }
});

app.post('/api/admin/change-password', authMiddleware, (req, res) => {
  const { newUsername, newPassword, currentPassword } = req.body;
  const auth = getAuth();
  if (hashPassword(currentPassword) !== auth.password) {
    return res.status(401).json({ error: 'Wrong current password' });
  }
  const newAuth = {
    username: newUsername,
    password: hashPassword(newPassword),
    secret: auth.secret
  };
  fs.writeFileSync(AUTH_FILE, JSON.stringify(newAuth, null, 2), 'utf8');
  res.json({ ok: true });
});

// Admin panel route
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

app.get('/admin/', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initAuth();
app.listen(PORT, () => {
  console.log(`\n✅ السيرفر يعمل على: http://localhost:${PORT}`);
  console.log(`📱 صفحة التفعيل: http://localhost:${PORT}`);
  console.log(`⚙️  لوحة التحكم: http://localhost:${PORT}/admin`);
  console.log(`\n🔐 بيانات الدخول الافتراضية:`);
  console.log(`   المستخدم: admin`);
  console.log(`   كلمة المرور: leostore2025\n`);
});
