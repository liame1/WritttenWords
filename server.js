const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

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

  // Optional storage columns that are no longer used for banners
  await pool.query(`
    ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS banner_image BYTEA,
    ADD COLUMN IF NOT EXISTS banner_image_type TEXT,
    ADD COLUMN IF NOT EXISTS profile_color TEXT;
  `);

  // Subscriptions (follow relationships)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      followee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT subscriptions_pk PRIMARY KEY (follower_id, followee_id),
      CONSTRAINT subscriptions_no_self CHECK (follower_id <> followee_id)
    );
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

async function findUserByUsername(username) {
  const name = (username || '').trim();
  if (!name) return null;
  const result = await pool.query(
    'SELECT id, username FROM users WHERE username = $1;',
    [name]
  );
  return result.rows[0] || null;
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
      'INSERT INTO user_profiles (user_id, display_name) VALUES ($1, $2);',
      [user.id, 'Display name']
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
      'SELECT display_name, profile_color FROM user_profiles WHERE user_id = $1;',
      [req.user.id]
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error('GET /api/profile error:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

// Public-style profile lookup by username (requires viewer auth, but arbitrary user)
app.get('/api/users/:username/profile', requireAuth, async (req, res) => {
  try {
    const user = await findUserByUsername(req.params.username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = await pool.query(
      'SELECT display_name, profile_color FROM user_profiles WHERE user_id = $1;',
      [user.id]
    );

    const row = result.rows[0] || {};
    res.json({
      username: user.username,
      display_name: row.display_name || null,
      profile_color: row.profile_color || null
    });
  } catch (err) {
    console.error('GET /api/users/:username/profile error:', err);
    res.status(500).json({ error: 'Failed to load user profile' });
  }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  const { displayName, profileColor } = req.body || {};

  try {
    const result = await pool.query(
      `
      INSERT INTO user_profiles (user_id, display_name, profile_color)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET
        display_name = EXCLUDED.display_name,
        profile_color = EXCLUDED.profile_color
      RETURNING display_name, profile_color;
      `,
      [req.user.id, displayName || null, profileColor || null]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('PUT /api/profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
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

// --- API: Subscriptions (follow) ---
app.get('/api/subscriptions', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT u.username,
             up.display_name
      FROM subscriptions s
      JOIN users u ON u.id = s.followee_id
      LEFT JOIN user_profiles up ON up.user_id = u.id
      WHERE s.follower_id = $1
      ORDER BY u.username ASC;
      `,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/subscriptions error:', err);
    res.status(500).json({ error: 'Failed to load subscriptions' });
  }
});

app.get('/api/subscription/status', requireAuth, async (req, res) => {
  const username = req.query.username || '';
  try {
    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = await pool.query(
      'SELECT 1 FROM subscriptions WHERE follower_id = $1 AND followee_id = $2;',
      [req.user.id, user.id]
    );
    res.json({ followed: !!result.rows[0] });
  } catch (err) {
    console.error('GET /api/subscription/status error:', err);
    res.status(500).json({ error: 'Failed to check subscription status' });
  }
});

app.post('/api/subscribe', requireAuth, async (req, res) => {
  const { username } = req.body || {};
  try {
    const target = await findUserByUsername(username);
    if (!target) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (target.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot subscribe to yourself' });
    }

    await pool.query(
      `
      INSERT INTO subscriptions (follower_id, followee_id)
      VALUES ($1, $2)
      ON CONFLICT (follower_id, followee_id) DO NOTHING;
      `,
      [req.user.id, target.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/subscribe error:', err);
    res.status(500).json({ error: 'Failed to subscribe' });
  }
});

app.delete('/api/subscribe', requireAuth, async (req, res) => {
  const { username } = req.body || {};
  try {
    const target = await findUserByUsername(username);
    if (!target) {
      return res.status(404).json({ error: 'User not found' });
    }

    await pool.query(
      'DELETE FROM subscriptions WHERE follower_id = $1 AND followee_id = $2;',
      [req.user.id, target.id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/subscribe error:', err);
    res.status(500).json({ error: 'Failed to unsubscribe' });
  }
});

// banner image routes removed; profile color is now used instead

// --- API: Posts with author info ---
app.get('/api/posts', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT p.id,
             p.body,
             p.created_at,
             u.username,
             up.display_name,
             up.profile_color
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
      SELECT p.id,
             p.body,
             p.created_at,
             up.profile_color
      FROM posts p
      LEFT JOIN user_profiles up ON up.user_id = p.user_id
      WHERE p.user_id = $1
      ORDER BY p.created_at DESC;
      `,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/profile/posts error:', err);
    res.status(500).json({ error: 'Failed to load profile posts' });
  }
});

// Posts for an arbitrary user by username
app.get('/api/users/:username/posts', requireAuth, async (req, res) => {
  try {
    const user = await findUserByUsername(req.params.username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = await pool.query(
      `
      SELECT p.id,
             p.body,
             p.created_at,
             up.profile_color
      FROM posts p
      LEFT JOIN user_profiles up ON up.user_id = p.user_id
      WHERE p.user_id = $1
      ORDER BY p.created_at DESC;
      `,
      [user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/users/:username/posts error:', err);
    res.status(500).json({ error: 'Failed to load user posts' });
  }
});

app.listen(PORT, () => {
  console.log(`Written server listening on port ${PORT}`);
});

