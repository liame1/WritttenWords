const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database setup (Render Postgres via DATABASE_URL) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

async function ensureTables() {
  // Users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Sessions
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Posts (now tied to users)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Make sure posts has a user_id column even if the table existed from an earlier version
  await pool.query(`
    ALTER TABLE posts
    ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
  `);

  // Per-user profile data
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      display_name TEXT,
      banner_headline TEXT
    );
  `);

  // Optional banner image storage
  await pool.query(`
    ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS banner_image BYTEA,
    ADD COLUMN IF NOT EXISTS banner_image_type TEXT;
  `);
}

ensureTables().catch((err) => {
  console.error('Error ensuring tables:', err);
});

// --- Middleware ---
app.use(express.json());
app.use(cookieParser());

// Attach req.user based on session cookie
app.use(async (req, res, next) => {
  const sessionId = req.cookies && req.cookies.session_id;
  if (!sessionId) {
    req.user = null;
    return next();
  }

  try {
    const result = await pool.query(
      `
      SELECT u.id, u.username
      FROM sessions s
      JOIN users u ON u.id = s.user_id
      WHERE s.id = $1
      `,
      [sessionId]
    );

    if (!result.rows[0]) {
      req.user = null;
      return next();
    }

    req.user = result.rows[0];

    // Touch last_seen asynchronously (no await)
    pool.query(
      'UPDATE sessions SET last_seen = NOW() WHERE id = $1;',
      [sessionId]
    ).catch(() => {});

    next();
  } catch (err) {
    console.error('Session lookup error:', err);
    req.user = null;
    next();
  }
});

// Serve the static front-end from the "writtten" directory
const staticRoot = path.join(__dirname, 'writtten');
app.use(express.static(staticRoot));

// Root route -> feed page
app.get('/', (req, res) => {
  res.sendFile(path.join(staticRoot, 'index.html'));
});

// Explicit routes to other static pages (optional but clear)
app.get('/feed', (req, res) => {
  res.sendFile(path.join(staticRoot, 'index.html'));
});

app.get('/explore', (req, res) => {
  res.sendFile(path.join(staticRoot, 'explore.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(staticRoot, 'profile.html'));
});

app.get('/settings', (req, res) => {
  res.sendFile(path.join(staticRoot, 'settings.html'));
});

// --- Auth helpers ---
function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

async function createSession(userId) {
  const id = crypto.randomBytes(24).toString('hex');
  await pool.query(
    'INSERT INTO sessions (id, user_id) VALUES ($1, $2);',
    [id, userId]
  );
  return id;
}

// --- API: Auth ---
app.get('/api/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json({ id: req.user.id, username: req.user.username });
});

app.post('/api/auth/signup', async (req, res) => {
  const { username, password } = req.body || {};
  const name = (username || '').trim();
  const pwd = password || '';

  if (!name || !pwd) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (name.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters' });
  }
  if (pwd.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hash = await bcrypt.hash(pwd, 10);
    const userResult = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username;',
      [name, hash]
    );
    const user = userResult.rows[0];

    // Create empty profile row
    await pool.query(
      'INSERT INTO user_profiles (user_id, display_name, banner_headline) VALUES ($1, $2, $3);',
      [user.id, 'Display name', 'Banner headline']
    );

    const sessionId = await createSession(user.id);
    res
      .cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: !!process.env.DATABASE_URL // assume production on Render
      })
      .status(201)
      .json({ id: user.id, username: user.username });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.error('POST /api/auth/signup error:', err);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const name = (username || '').trim();
  const pwd = password || '';

  if (!name || !pwd) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, password_hash FROM users WHERE username = $1;',
      [name]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(pwd, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const sessionId = await createSession(user.id);
    res
      .cookie('session_id', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        secure: !!process.env.DATABASE_URL
      })
      .json({ id: user.id, username: user.username });
  } catch (err) {
    console.error('POST /api/auth/login error:', err);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const sessionId = req.cookies && req.cookies.session_id;
  if (sessionId) {
    try {
      await pool.query('DELETE FROM sessions WHERE id = $1;', [sessionId]);
    } catch (err) {
      console.error('POST /api/auth/logout error:', err);
    }
  }
  res.clearCookie('session_id');
  res.json({ ok: true });
});

// --- API: Profile ---
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT display_name FROM user_profiles WHERE user_id = $1;',
      [req.user.id]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error('GET /api/profile error:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  const { displayName } = req.body || {};

  try {
    const result = await pool.query(
      `
      INSERT INTO user_profiles (user_id, display_name)
      VALUES ($1, $2)
      ON CONFLICT (user_id)
      DO UPDATE SET
        display_name = EXCLUDED.display_name
      RETURNING display_name;
      `,
      [req.user.id, displayName || null]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('PUT /api/profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// --- API: Profile banner image ---
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

app.post('/api/profile/banner', requireAuth, upload.single('banner'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
  if (!allowedTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ error: 'Only JPEG, PNG, or WEBP images are allowed' });
  }

  try {
    await pool.query(
      `
      INSERT INTO user_profiles (user_id, banner_image, banner_image_type)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET
        banner_image = EXCLUDED.banner_image,
        banner_image_type = EXCLUDED.banner_image_type;
      `,
      [req.user.id, req.file.buffer, req.file.mimetype]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/profile/banner error:', err);
    res.status(500).json({ error: 'Failed to save banner image' });
  }
});

// --- API: Posts (create) ---
app.post('/api/posts', requireAuth, async (req, res) => {
  const { body } = req.body || {};
  if (!body || typeof body !== 'string' || !body.trim()) {
    return res.status(400).json({ error: 'Post body is required' });
  }

  try {
    const inserted = await pool.query(
      'INSERT INTO posts (user_id, body) VALUES ($1, $2) RETURNING id, body, created_at, user_id;',
      [req.user.id, body.trim()]
    );
    const post = inserted.rows[0];

    const withAuthor = await pool.query(
      `
      SELECT p.id,
             p.body,
             p.created_at,
             u.username,
             up.display_name
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE p.id = $1;
      `,
      [post.id]
    );

    res.status(201).json(withAuthor.rows[0]);
  } catch (err) {
    console.error('POST /api/posts error:', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.get('/api/profile/banner', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT banner_image, banner_image_type FROM user_profiles WHERE user_id = $1;',
      [req.user.id]
    );
    const row = result.rows[0];
    if (!row || !row.banner_image) {
      return res.status(404).end();
    }
    res.setHeader('Content-Type', row.banner_image_type || 'image/jpeg');
    res.send(row.banner_image);
  } catch (err) {
    console.error('GET /api/profile/banner error:', err);
    res.status(500).end();
  }
});

// --- API: Posts with author info ---
app.get('/api/posts', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT p.id,
             p.body,
             p.created_at,
             u.username,
             up.display_name
      FROM posts p
      JOIN users u ON u.id = p.user_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      ORDER BY p.created_at DESC;
      `
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/posts error:', err);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

// Posts for current user's profile
app.get('/api/profile/posts', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id,
             body,
             created_at
      FROM posts
      WHERE user_id = $1
      ORDER BY created_at DESC;
      `,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/profile/posts error:', err);
    res.status(500).json({ error: 'Failed to load profile posts' });
  }
});

app.listen(PORT, () => {
  console.log(`Written server listening on port ${PORT}`);
});

