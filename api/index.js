const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'xK9mP2nQ5rT8vW3yZ6aB1cD4eF7gH0jL';

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
};

const requireOwner = (req, res, next) => {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner only' });
  next();
};

// Helper
const generateKeyValue = (prefix = '') => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let key = prefix ? prefix.toUpperCase() + '-' : '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0 && i !== 16) key += '-';
    key += chars[Math.floor(Math.random() * chars.length)];
  }
  return key;
};

const getExpiry = (duration) => {
  const date = new Date();
  if (duration === 'lifetime') {
    date.setFullYear(date.getFullYear() + 100);
    return date.toISOString();
  }
  const days = parseInt(duration) || 30;
  date.setDate(date.getDate() + days);
  return date.toISOString();
};

// ============ ROUTES ============

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  const { data: admin, error } = await supabase
    .from('admins')
    .select('*')
    .eq('username', username)
    .single();
  
  if (error || !admin) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const valid = await bcrypt.compare(password, admin.password_hash);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { id: admin.id, username: admin.username, role: admin.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  
  res.json({ 
    success: true, 
    token, 
    user: { id: admin.id, username: admin.username, role: admin.role } 
  });
});

// Get all keys
app.get('/api/keys', auth, async (req, res) => {
  let query = supabase.from('keys').select('*, admins!created_by(username)');
  if (req.user.role !== 'owner') {
    query = query.eq('created_by', req.user.id);
  }
  const { data, error } = await query.order('created_at', { ascending: false }).limit(500);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Generate key
app.post('/api/keys/generate', auth, async (req, res) => {
  const { prefix, duration, deviceLimit, keyType, note } = req.body;
  const keyValue = generateKeyValue(prefix);
  const expiresAt = getExpiry(duration || '30');
  
  const { data, error } = await supabase.from('keys').insert({
    key_value: keyValue,
    expires_at: expiresAt,
    device_limit: deviceLimit || 1,
    key_type: keyType || 'standard',
    note: note || null,
    created_by: req.user.id,
    status: 'active'
  }).select().single();
  
  if (error) return res.status(500).json({ error: error.message });
  
  await supabase.from('audit_logs').insert({
    admin_id: req.user.id,
    action: 'generate_key',
    target: keyValue
  });
  
  res.json({ success: true, key: data });
});

// Update key status
app.put('/api/keys/:id/status', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { error } = await supabase.from('keys').update({ status }).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  await supabase.from('audit_logs').insert({ 
    admin_id: req.user.id, 
    action: 'update_key_status', 
    target: id,
    details: { status }
  });
  res.json({ success: true });
});

// Delete key
app.delete('/api/keys/:id', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('keys').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  await supabase.from('audit_logs').insert({ 
    admin_id: req.user.id, 
    action: 'delete_key', 
    target: id 
  });
  res.json({ success: true });
});

// Get all users
app.get('/api/users', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('*, keys(key_value)')
    .order('last_seen', { ascending: false })
    .limit(200);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Ban user
app.post('/api/users/:id/ban', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { error } = await supabase.from('users').update({ is_banned: true }).eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  await supabase.from('audit_logs').insert({ admin_id: req.user.id, action: 'ban_user', target: id });
  res.json({ success: true });
});

// Get admins (owner only)
app.get('/api/admins', auth, requireOwner, async (req, res) => {
  const { data, error } = await supabase
    .from('admins')
    .select('id, username, role, is_active, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  
  // Get key counts for each admin
  const adminsWithCounts = await Promise.all((data || []).map(async (admin) => {
    const { count } = await supabase
      .from('keys')
      .select('*', { count: 'exact', head: true })
      .eq('created_by', admin.id);
    return { ...admin, keys_generated: count || 0 };
  }));
  
  res.json(adminsWithCounts);
});

// Create admin (owner only)
app.post('/api/admins', auth, requireOwner, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  const passwordHash = await bcrypt.hash(password, 10);
  const { data, error } = await supabase
    .from('admins')
    .insert({ username, password_hash: passwordHash, role: role || 'admin' })
    .select()
    .single();
  
  if (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    return res.status(500).json({ error: error.message });
  }
  
  await supabase.from('audit_logs').insert({
    admin_id: req.user.id,
    action: 'create_admin',
    target: data.id,
    details: { username, role }
  });
  
  res.json({ success: true, admin: data });
});

// Delete admin (owner only)
app.delete('/api/admins/:id', auth, requireOwner, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }
  
  const { error } = await supabase.from('admins').delete().eq('id', id);
  if (error) return res.status(500).json({ error: error.message });
  
  await supabase.from('audit_logs').insert({
    admin_id: req.user.id,
    action: 'delete_admin',
    target: id
  });
  
  res.json({ success: true });
});

// Get stats
app.get('/api/stats', auth, async (req, res) => {
  const [totalKeys, activeKeys, totalUsers] = await Promise.all([
    supabase.from('keys').select('*', { count: 'exact', head: true }),
    supabase.from('keys').select('*', { count: 'exact', head: true })
      .eq('status', 'active')
      .gt('expires_at', new Date().toISOString()),
    supabase.from('users').select('*', { count: 'exact', head: true })
  ]);
  
  res.json({
    totalKeys: totalKeys.count || 0,
    activeKeys: activeKeys.count || 0,
    totalUsers: totalUsers.count || 0,
    onlineUsers: 0
  });
});

// Get audit logs
app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('audit_logs')
    .select('*, admins!admin_id(username)')
    .order('created_at', { ascending: false })
    .limit(200);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data || []);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Export for Vercel
module.exports = app;
