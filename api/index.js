const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'xK9mP2nQ5rT8vW3yZ6aB1cD4eF7gH0jL';

// ============ MIDDLEWARE ============
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
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

// ============ HELPERS ============
const generateKeyValue = (prefix = '') => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  let key = prefix ? prefix.toUpperCase() + '-' : '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0 && i !== 16) key += '-';
    key += chars[Math.floor(Math.random() * chars.length)];
  }
  return key;
};

const calculateExpiry = (duration) => {
  const date = new Date();
  if (duration === 'lifetime') {
    date.setFullYear(date.getFullYear() + 100);
    return date.toISOString();
  }
  const days = parseInt(duration) || 30;
  date.setDate(date.getDate() + days);
  return date.toISOString();
};

// ============ AUTH ============
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const { data: admin, error } = await supabase
      .from('admins')
      .select('*')
      .eq('username', username)
      .single();
    
    if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
    
    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    
    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    res.json({ success: true, token, user: { id: admin.id, username: admin.username, role: admin.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ KEYS ============
app.get('/api/keys', auth, async (req, res) => {
  try {
    let query = supabase.from('keys').select('*, admins!created_by(username)');
    if (req.user.role !== 'owner') query = query.eq('created_by', req.user.id);
    const { data, error } = await query.order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/keys/generate', auth, async (req, res) => {
  const { prefix, duration, deviceLimit, keyType } = req.body;
  try {
    const keyValue = generateKeyValue(prefix);
    const expiresAt = calculateExpiry(duration || '30');
    const { data, error } = await supabase.from('keys').insert({
      key_value: keyValue,
      expires_at: expiresAt,
      device_limit: deviceLimit || 1,
      key_type: keyType || 'standard',
      created_by: req.user.id,
      status: 'active'
    }).select().single();
    if (error) throw error;
    res.json({ success: true, key: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/keys/:id/status', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    await supabase.from('keys').update({ status }).eq('id', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/keys/:id', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await supabase.from('keys').delete().eq('id', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ REDEEM (GET & POST) ============
app.post('/api/keys/redeem', async (req, res) => {
  const { key, hwid, username } = req.body;
  if (!key) return res.status(400).json({ error: 'Key required' });
  
  try {
    const { data: keyData, error } = await supabase.from('keys').select('*').eq('key_value', key).single();
    if (error || !keyData) return res.status(404).json({ error: 'Key not found' });
    if (keyData.status !== 'active') return res.status(403).json({ error: 'Key ' + keyData.status });
    if (new Date(keyData.expires_at) < new Date()) return res.status(403).json({ error: 'Key expired' });
    
    const { count: usedCount } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('key_id', keyData.id);
    if (usedCount >= keyData.device_limit) return res.status(403).json({ error: 'Device limit reached' });
    
    if (hwid) {
      const { data: existing } = await supabase.from('users').select('*').eq('hwid', hwid).single();
      if (!existing) {
        await supabase.from('users').insert({ username: username || 'user', key_id: keyData.id, hwid: hwid });
      }
    }
    
    res.json({ success: true, expires_at: keyData.expires_at, key_type: keyData.key_type });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/keys/redeem', async (req, res) => {
  const key = req.query.key || req.query.redeem;
  const hwid = req.query.uid || req.query.hwid;
  if (!key) return res.status(400).send('ERROR: Key required');
  
  try {
    const { data: keyData, error } = await supabase.from('keys').select('*').eq('key_value', key).single();
    if (error || !keyData) return res.status(404).send('INVALID KEY');
    if (keyData.status !== 'active') return res.status(403).send('KEY BLOCKED');
    if (new Date(keyData.expires_at) < new Date()) return res.status(403).send('KEY EXPIRED');
    
    const { count: usedCount } = await supabase.from('users').select('*', { count: 'exact', head: true }).eq('key_id', keyData.id);
    if (usedCount >= keyData.device_limit) return res.status(403).send('DEVICE MAX SLOT');
    
    if (hwid) {
      const { data: existing } = await supabase.from('users').select('*').eq('hwid', hwid).single();
      if (!existing) {
        await supabase.from('users').insert({ username: 'user', key_id: keyData.id, hwid: hwid });
      }
    }
    
    const daysLeft = Math.ceil((new Date(keyData.expires_at) - new Date()) / (86400000));
    res.send('LOGIN SUCCESS | Expires: ' + daysLeft + ' days');
  } catch (err) {
    res.status(500).send('SERVER ERROR');
  }
});

// ============ USERS ============
app.get('/api/users', auth, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*, keys(key_value)').order('last_seen', { ascending: false }).limit(200);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMINS ============
app.get('/api/admins', auth, requireOwner, async (req, res) => {
  try {
    const { data, error } = await supabase.from('admins').select('id, username, role, created_at');
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admins', auth, requireOwner, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase.from('admins').insert({ username, password_hash: hash, role: role || 'admin' }).select().single();
    if (error) throw error;
    res.json({ success: true, admin: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admins/:id', auth, requireOwner, async (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) return res.status(400).json({ error: 'Cannot delete self' });
  try {
    await supabase.from('admins').delete().eq('id', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ STATS ============
app.get('/api/stats', auth, async (req, res) => {
  try {
    const { count: totalKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true });
    const { count: activeKeys } = await supabase.from('keys').select('*', { count: 'exact', head: true }).eq('status', 'active').gt('expires_at', new Date().toISOString());
    const { count: totalUsers } = await supabase.from('users').select('*', { count: 'exact', head: true });
    res.json({ totalKeys: totalKeys || 0, activeKeys: activeKeys || 0, totalUsers: totalUsers || 0, onlineUsers: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ LIBRARY ============
app.get('/api/libraries', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('libraries').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/upload/lib', auth, requireAdmin, async (req, res) => {
  const { libName, version, data } = req.body;
  if (!libName || !version || !data) return res.status(400).json({ error: 'Required' });
  try {
    await supabase.from('libraries').insert({ name: libName, version: version, data: data, created_by: req.user.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/libraries/:id', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    await supabase.from('libraries').delete().eq('id', id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/download/lib', async (req, res) => {
  const { key, hwid, libName } = req.query;
  if (!key) return res.status(400).send('Key required');
  
  try {
    const { data: keyData } = await supabase.from('keys').select('*').eq('key_value', key).single();
    if (!keyData || keyData.status !== 'active' || new Date(keyData.expires_at) < new Date()) {
      return res.status(403).send('INVALID KEY');
    }
    
    const { data: libData } = await supabase.from('libraries').select('*').eq('name', libName).order('version', { ascending: false }).limit(1).single();
    if (!libData) return res.status(404).send('Library not found');
    
    await supabase.from('libraries').update({ downloads: (libData.downloads || 0) + 1 }).eq('id', libData.id);
    
    const buffer = Buffer.from(libData.data, 'base64');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(buffer);
  } catch (err) {
    res.status(500).send('SERVER ERROR');
  }
});

// ============ AUDIT ============
app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('audit_logs').select('*, admins!admin_id(username)').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ HEALTH ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

module.exports = app;
