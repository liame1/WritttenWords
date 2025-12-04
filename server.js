const path = require('path');
const express = require('express');
const { Pool } = require('pg');

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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS profile (
      id INTEGER PRIMARY KEY DEFAULT 1,
      display_name TEXT,
      banner_headline TEXT
    );
  `);

  // Ensure a single profile row exists
  await pool.query(`
    INSERT INTO profile (id, display_name, banner_headline)
    VALUES (1, 'Display name', 'Banner headline')
    ON CONFLICT (id) DO NOTHING;
  `);
}

ensureTables().catch((err) => {
  console.error('Error ensuring tables:', err);
});

// --- Middleware ---
app.use(express.json());

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

// --- API: Posts ---
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, body, created_at FROM posts ORDER BY created_at DESC;'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('GET /api/posts error:', err);
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

app.post('/api/posts', async (req, res) => {
  const { body } = req.body || {};
  if (!body || typeof body !== 'string' || !body.trim()) {
    return res.status(400).json({ error: 'Post body is required' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO posts (body) VALUES ($1) RETURNING id, body, created_at;',
      [body.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('POST /api/posts error:', err);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// --- API: Profile ---
app.get('/api/profile', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT display_name, banner_headline FROM profile WHERE id = 1;'
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    console.error('GET /api/profile error:', err);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

app.put('/api/profile', async (req, res) => {
  const { displayName, bannerHeadline } = req.body || {};

  try {
    const result = await pool.query(
      `
      UPDATE profile
      SET display_name = $1, banner_headline = $2
      WHERE id = 1
      RETURNING display_name, banner_headline;
      `,
      [displayName || null, bannerHeadline || null]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error('PUT /api/profile error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.listen(PORT, () => {
  console.log(`Written server listening on port ${PORT}`);
});

