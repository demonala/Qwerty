const express = require('express');
const app = express();

app.use(express.json());

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'API is running' });
});

// Test login (hardcoded dulu)
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'owner' && password === 'Qwerty@2024') {
    res.json({ 
      success: true, 
      token: 'test-token-123',
      user: { id: 1, username: 'owner', role: 'owner' }
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Simple stats
app.get('/api/stats', (req, res) => {
  res.json({ totalKeys: 100, activeKeys: 50, totalUsers: 20, onlineUsers: 5 });
});

module.exports = app;
