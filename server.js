const path = require('path');
const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

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

app.listen(PORT, () => {
  // Simple log for Render logs / local dev
  console.log(`Written server listening on port ${PORT}`);
});


