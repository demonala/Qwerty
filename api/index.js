const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'xK9mP2nQ5rT8vW3yZ6aB1cD4eF7gH0jL';

// ============ MIDDLEWARE ============
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const requireOwner = (req, res, next) => {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required' });
  }
  next();
};

// ============ HELPER FUNCTIONS ============
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

// ============ AUTH ROUTES ============
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
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
    
    // Log audit
    await supabase.from('audit_logs').insert({
      admin_id: admin.id,
      action: 'login',
      ip_address: req.headers['x-forwarded-for'] || req.socket.remoteAddress
    });
    
    res.json({
      success: true,
      token,
      user: { id: admin.id, username: admin.username, role: admin.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============ KEY ROUTES ============
app.get('/api/keys', auth, async (req, res) => {
  try {
    let query = supabase
      .from('keys')
      .select('*, admins!created_by(username)');
    
    if (req.user.role !== 'owner') {
      query = query.eq('created_by', req.user.id);
    }
    
    const { data, error } = await query.order('created_at', { ascending: false }).limit(500);
    
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/keys/generate', auth, async (req, res) => {
  const { prefix, duration, deviceLimit, keyType, note } = req.body;
  
  try {
    const keyValue = generateKeyValue(prefix);
    const expiresAt = calculateExpiry(duration || '30');
    
    const { data, error } = await supabase
      .from('keys')
      .insert({
        key_value: keyValue,
        expires_at: expiresAt,
        device_limit: deviceLimit || 1,
        key_type: keyType || 'standard',
        note: note || null,
        created_by: req.user.id,
        status: 'active'
      })
      .select()
      .single();
    
    if (error) throw error;
    
    // Audit log
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'generate_key',
      target: keyValue
    });
    
    res.json({ success: true, key: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/keys/:id/status', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  
  try {
    const { error } = await supabase
      .from('keys')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', id);
    
    if (error) throw error;
    
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'update_key_status',
      target: id,
      details: { status }
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/keys/:id', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const { error } = await supabase.from('keys').delete().eq('id', id);
    if (error) throw error;
    
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'delete_key',
      target: id
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ USER ROUTES ============
app.get('/api/users', auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*, keys(key_value)')
      .order('last_seen', { ascending: false })
      .limit(200);
    
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/users/:id/ban', auth, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    const { error } = await supabase
      .from('users')
      .update({ is_banned: true })
      .eq('id', id);
    
    if (error) throw error;
    
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'ban_user',
      target: id
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN ROUTES (OWNER ONLY) ============
app.get('/api/admins', auth, requireOwner, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('admins')
      .select('id, username, role, is_active, created_at')
      .order('created_at', { ascending: false });
    
    if (error) throw error;
    
    // Get key counts for each admin
    const adminsWithCounts = await Promise.all((data || []).map(async (admin) => {
      const { count } = await supabase
        .from('keys')
        .select('*', { count: 'exact', head: true })
        .eq('created_by', admin.id);
      return { ...admin, keys_generated: count || 0 };
    }));
    
    res.json(adminsWithCounts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admins', auth, requireOwner, async (req, res) => {
  const { username, password, role } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    
    const { data, error } = await supabase
      .from('admins')
      .insert({
        username,
        password_hash: passwordHash,
        role: role || 'admin'
      })
      .select()
      .single();
    
    if (error) {
      if (error.code === '23505') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      throw error;
    }
    
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'create_admin',
      target: data.id,
      details: { username, role }
    });
    
    res.json({ success: true, admin: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admins/:id', auth, requireOwner, async (req, res) => {
  const { id } = req.params;
  
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }
  
  try {
    const { error } = await supabase.from('admins').delete().eq('id', id);
    if (error) throw error;
    
    await supabase.from('audit_logs').insert({
      admin_id: req.user.id,
      action: 'delete_admin',
      target: id
    });
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ STATS ROUTE (REAL DATA) ============
app.get('/api/stats', auth, async (req, res) => {
  try {
    const { count: totalKeys } = await supabase
      .from('keys')
      .select('*', { count: 'exact', head: true });
    
    const { count: activeKeys } = await supabase
      .from('keys')
      .select('*', { count: 'exact', head: true })
      .eq('status', 'active')
      .gt('expires_at', new Date().toISOString());
    
    const { count: totalUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });
    
    const { count: onlineUsers } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .gt('last_seen', new Date(Date.now() - 5 * 60 * 1000).toISOString());
    
    res.json({
      totalKeys: totalKeys || 0,
      activeKeys: activeKeys || 0,
      totalUsers: totalUsers || 0,
      onlineUsers: onlineUsers || 0
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ AUDIT LOGS ============
app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*, admins!admin_id(username)')
      .order('created_at', { ascending: false })
      .limit(200);
    
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    supabase: !!process.env.SUPABASE_URL
  });
});
// ============ REDEEM KEY FOR MOD MENU ============
app.post('/api/keys/redeem', async (req, res) => {
  const { key, hwid, username } = req.body;
  
  if (!key) {
    return res.status(400).json({ error: 'Key required' });
  }
  
  try {
    // Cek key di database
    const { data: keyData, error: keyError } = await supabase
      .from('keys')
      .select('*')
      .eq('key_value', key)
      .single();
    
    if (keyError || !keyData) {
      return res.status(404).json({ error: 'Key not found' });
    }
    
    // Cek status key
    if (keyData.status !== 'active') {
      return res.status(403).json({ error: 'Key is ' + keyData.status });
    }
    
    // Cek expired
    if (new Date(keyData.expires_at) < new Date()) {
      await supabase.from('keys').update({ status: 'expired' }).eq('id', keyData.id);
      return res.status(403).json({ error: 'Key expired' });
    }
    
    // Cek device limit
    const { count: usedCount } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true })
      .eq('key_id', keyData.id);
    
    if (usedCount >= keyData.device_limit) {
      return res.status(403).json({ error: 'Device limit reached (max: ' .. keyData.device_limit .. ')' });
    }
    
    // Cek HWID sudah dipake?
    if (hwid) {
      const { data: existingUser } = await supabase
        .from('users')
        .select('*')
        .eq('hwid', hwid)
        .single();
      
      if (existingUser && existingUser.is_banned) {
        return res.status(403).json({ error: 'HWID banned' });
      }
      
      if (existingUser && existingUser.key_id !== keyData.id) {
        // Update user dengan key baru
        await supabase
          .from('users')
          .update({ 
            key_id: keyData.id, 
            last_seen: new Date().toISOString(),
            username: username or existingUser.username
          })
          .eq('hwid', hwid);
      } else if (!existingUser) {
        // Create new user
        await supabase.from('users').insert({
          username: username or 'user_' .. math.random(10000, 99999),
          key_id: keyData.id,
          hwid: hwid,
          ip_address: req.headers['x-forwarded-for'] or req.socket.remoteAddress,
          last_seen: new Date().toISOString(),
          first_seen: new Date().toISOString()
        });
      }
    }
    
    // Audit log
    await supabase.from('audit_logs').insert({
      action: 'redeem_key',
      target: key,
      details: { hwid: hwid, username: username }
    });
    
    res.json({
      success: true,
      expires_at: keyData.expires_at,
      key_type: keyData.key_type,
      message: 'Key redeemed successfully'
    });
    
  } catch (err) {
    console.error('Redeem error:', err);
    res.status(500).json({ error: 'Server error: ' .. err.message });
  }
});

// Check key status (buat mod menu cek berkala)
app.post('/api/keys/check', async (req, res) => {
  const { key, hwid } = req.body;
  
  try {
    const { data: keyData } = await supabase
      .from('keys')
      .select('*')
      .eq('key_value', key)
      .single();
    
    if (!keyData or keyData.status !== 'active' or new Date(keyData.expires_at) < new Date()) {
      return res.json({ valid: false, message: 'Key invalid or expired' });
    }
    
    // Update last seen
    if (hwid) {
      await supabase
        .from('users')
        .update({ last_seen: new Date().toISOString() })
        .eq('hwid', hwid);
    }
    
    res.json({
      valid: true,
      expires_at: keyData.expires_at,
      days_left: math.ceil((new Date(keyData.expires_at) - new Date()) / (1000 * 60 * 60 * 24))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = app;
