require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs'); // pure JS — works on Vercel serverless
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();
const PORT = process.env.PORT || 3001;

// ── MongoDB User Schema ────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:         { type: String, required: true, unique: true },
  password_hash:    { type: String, required: true },
  role:             { type: String, default: 'customer' },
  is_active:        { type: Boolean, default: true },
  expires_at:       { type: Date, default: null },
  duration_minutes: { type: Number, default: 30 },
  created_at:       { type: Date, default: Date.now },
  last_login:       { type: Date, default: null },
  // Tracks the currently-active session id for single-session enforcement.
  // When a user logs in from a new device, this is overwritten, and any
  // request from an old session id is treated as unauthenticated.
  active_session_id:{ type: String, default: null },
});
const User = mongoose.model('User', userSchema);

// ── Cached connection (Vercel serverless safe) ─────────────────────────────
// Reuse the connection across warm invocations; establish it on cold starts.
const mongoUri = process.env.MONGO_URI;

let _connPromise = null;

async function connectDB() {
  if (!mongoUri) throw new Error('MONGO_URI not set');
  if (mongoose.connection.readyState === 1) return; // already connected
  if (!_connPromise) {
    _connPromise = mongoose.connect(mongoUri, { maxPoolSize: 5, minPoolSize: 0, serverSelectionTimeoutMS: 10000 }).then(() => {
      console.log('✅ MongoDB connected successfully');
    });
  }
  await _connPromise;
}

// ── Session setup ──────────────────────────────────────────────────────────
if (mongoUri) {
  const sessionConfig = {
    store: MongoStore.create({
      mongoUrl: mongoUri,
      collectionName: 'sessions',
      // Re-use a small dedicated pool just for sessions; without this it would
      // open another default pool of 100 connections.
      mongoOptions: { maxPoolSize: 3, minPoolSize: 0 },
    }),
    secret: process.env.SESSION_SECRET || 'cash-clone-secret-2024',
    resave: false,
    saveUninitialized: false,
    name: 'connect.sid',
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/'
    }
  };

  console.log('🍪 Session cookie config:', {
    secure: sessionConfig.cookie.secure,
    sameSite: sessionConfig.cookie.sameSite,
    httpOnly: sessionConfig.cookie.httpOnly,
    name: sessionConfig.name
  });

  app.use(session(sessionConfig));
} else {
  console.log('⚠️  No MONGO_URI found - running in local dev mode without database');
  app.use(session({
    secret: 'cash-clone-dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true
    }
  }));
}

// ── DB connection middleware (runs before every request on Vercel) ─────────
app.use(async (req, res, next) => {
  if (!mongoUri) return next(); // dev mode without DB
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error('❌ DB connection failed:', err.message);
    res.status(503).json({ error: 'Database unavailable' });
  }
});

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow same-origin requests (for Vercel)
    if (!origin) return callback(null, true);
    
    // Allow configured frontend URL
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) {
      return callback(null, true);
    }
    
    // Allow localhost for development
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
    
    // Allow Vercel deployments
    if (origin.includes('.vercel.app')) {
      return callback(null, true);
    }
    
    // Allow Render deployments
    if (origin.includes('.onrender.com')) {
      return callback(null, true);
    }
    
    // Allow all in development
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    callback(null, true); // Allow by default for serverless
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth middleware
async function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!mongoUri) {
    return next();
  }

  try {
    const user = await User.findById(req.session.userId).select('role expires_at active_session_id');

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Single-session enforcement: if this session id is no longer the
    // user's active session, the user has been logged in elsewhere.
    // Admins are exempt so they can manage multiple tabs.
    if (user.role !== 'admin' && user.active_session_id && user.active_session_id !== req.sessionID) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Session replaced by new login', kicked: true });
    }

    if (hasUserExpired(user)) {
      await deactivateExpiredUser(user._id);
      return destroyExpiredSession(req, res);
    }

    return next();
  } catch (error) {
    console.error('requireAuth error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}

function hasUserExpired(user) {
  if (!user || user.role === 'admin' || !user.expires_at) {
    return false;
  }
  const expiresAt = new Date(user.expires_at);
  if (Number.isNaN(expiresAt.getTime())) {
    return false;
  }
  return expiresAt.getTime() <= Date.now();
}

async function deactivateExpiredUser(userId) {
  if (!mongoUri || !userId) return;
  try {
    await User.findByIdAndUpdate(userId, { is_active: false });
  } catch (error) {
    console.error('Failed to deactivate expired user:', error);
  }
}

function destroyExpiredSession(req, res, payload = {}) {
  return new Promise((resolve) => {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
      res.clearCookie('connect.sid');
      res.status(440).json({ authenticated: false, reason: 'expired', ...payload });
      resolve();
    });
  });
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (mongoUri) {
    const user = await User.findById(req.session.userId).select('role');
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
  }
  next();
}

// Routes

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, deviceId } = req.body;
    console.log('🔐 Login attempt:', { username, hasPassword: !!password, deviceId, mongoUri });

    if (!mongoUri) {
      console.error('❌ Database not configured');
      return res.status(503).json({ error: 'Database not configured' });
    }

    const user = await User.findOne({ username });
    console.log('👤 User query result:', { found: !!user, username: user?.username, role: user?.role });

    if (!user) {
      console.log('❌ User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    console.log('🔑 Password validation:', { valid: validPassword });

    if (!validPassword) {
      console.log('❌ Invalid password for:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (hasUserExpired(user)) {
      console.log('⛔ Account expired for:', username);
      await deactivateExpiredUser(user._id);
      return res.status(403).json({ error: 'Your access time has expired. Contact support to renew.' });
    }

    console.log('✅ Login successful for:', username, 'role:', user.role);

    // Regenerate the session id so the new login always gets a fresh id,
    // making the kick-out filter precise.
    await new Promise((resolve) => req.session.regenerate(() => resolve()));

    // Kick out old device sessions for this user (except admin).
    // We match both stored-as-object and stored-as-string session formats.
    if (user.role !== 'admin') {
      try {
        const result = await mongoose.connection.db.collection('sessions').deleteMany({
          $and: [
            { _id: { $ne: req.sessionID } },
            {
              $or: [
                { 'session.userId': user._id.toString() },
                { session: { $regex: `"userId":"${user._id.toString()}"` } },
              ],
            },
          ],
        });
        console.log('🔄 Kicked out old device sessions for user:', user._id.toString(), 'deleted:', result.deletedCount);
      } catch (err) {
        console.error('⚠️  Error removing old sessions:', err);
      }
    }

    // Update last login / set expiry on first login, and record this session
    // id as the user's single active session.
    const userUpdates = { last_login: new Date() };
    if (user.role !== 'admin') {
      userUpdates.active_session_id = req.sessionID;
      if (!user.expires_at) {
        const expiresAt = new Date(Date.now() + (user.duration_minutes || 30) * 60 * 1000);
        userUpdates.expires_at = expiresAt;
        userUpdates.is_active = true;
        user.expires_at = expiresAt;
      }
    }
    await User.findByIdAndUpdate(user._id, userUpdates);

    req.session.userId = user._id.toString();
    req.session.username = user.username;
    req.session.role = user.role;
    req.session.deviceId = deviceId;

    console.log('📝 Session created:', { userId: user._id, username: user.username, role: user.role, deviceId, sessionID: req.sessionID });

    // Save session explicitly before responding
    req.session.save((err) => {
      if (err) {
        console.error('❌ Session save error:', err);
        return res.status(500).json({ error: 'Session save failed', message: err.message });
      }

      console.log('✅ Session saved successfully');
      console.log('🍪 Response headers will include Set-Cookie');

      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user._id,
          username: user.username,
          role: user.role,
          expiresAt: user.expires_at
        }
      });
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Internal server error', message: error.message });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Check auth status
app.get('/api/auth/status', async (req, res) => {
  // Disable caching so Safari/proxies never replay a stale authenticated state
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  console.log('🔍 Auth status check:', {
    hasSession: !!req.session,
    sessionId: req.sessionID,
    userId: req.session?.userId,
    cookies: req.headers.cookie?.substring(0, 50)
  });

  if (!req.session.userId) {
    console.log('❌ No userId in session');
    return res.json({ authenticated: false });
  }

  if (!mongoUri) {
    console.log('❌ Database not ready');
    return res.json({ authenticated: false });
  }

  const user = await User.findById(req.session.userId).select('username role expires_at is_active active_session_id');

  if (!user) {
    console.log('❌ User not found in database');
    return res.json({ authenticated: false });
  }

  // Single-session enforcement: if this session is no longer the user's
  // active session, force-logout this client. Admins are exempt.
  if (user.role !== 'admin' && user.active_session_id && user.active_session_id !== req.sessionID) {
    console.log('🚪 Session kicked out (replaced by newer login):', user.username);
    return req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.json({ authenticated: false, kicked: true });
    });
  }

  if (hasUserExpired(user)) {
    console.log('⛔ Session expired for user:', user.username);
    await deactivateExpiredUser(user._id);
    return destroyExpiredSession(req, res);
  }

  console.log('✅ Auth status success:', { username: user.username, role: user.role });

  res.json({
    authenticated: true,
    user: {
      id: user._id,
      username: user.username,
      role: user.role,
      expiresAt: user.expires_at,
      isActive: user.is_active
    }
  });
});

// Get all users (admin only)
app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    const users = await User.find().sort({ created_at: -1 })
      .select('username role is_active expires_at duration_minutes created_at last_login');

    res.json({
      success: true,
      users: users.map(u => ({
        id: u._id,
        username: u.username,
        role: u.role,
        isActive: u.is_active,
        expiresAt: u.expires_at,
        durationMinutes: u.duration_minutes,
        createdAt: u.created_at,
        lastLogin: u.last_login
      }))
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create user (admin only)
app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const { username, password, duration } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const durationMinutes = duration || 30;

    const newUser = await User.create({
      username,
      password_hash: passwordHash,
      role: 'customer',
      duration_minutes: durationMinutes,
    });

    console.log(`✅ Created user: ${username} with ${durationMinutes} minutes duration`);

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: newUser._id,
        username: newUser.username,
        durationMinutes: newUser.duration_minutes
      }
    });
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Extend user time (admin only)
app.patch('/api/users/:id/extend', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { days } = req.body;

    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    const user = await User.findOne({ _id: userId, role: { $ne: 'admin' } })
      .select('expires_at duration_minutes');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.expires_at) {
      // User hasn't logged in yet – extend the stored duration
      const additionalMinutes = days * 24 * 60;
      const newDuration = (user.duration_minutes || 30) + additionalMinutes;
      await User.findByIdAndUpdate(userId, { duration_minutes: newDuration });
      return res.json({ success: true, message: `Extended duration by ${days} day(s)` });
    }

    // Extend existing expiration
    const currentExpiry = new Date(user.expires_at);
    const newExpiry = new Date(currentExpiry.getTime() + days * 24 * 60 * 60 * 1000);
    await User.findByIdAndUpdate(userId, { expires_at: newExpiry, is_active: true });

    res.json({ success: true, message: `Extended expiration by ${days} day(s)`, newExpiry });
  } catch (error) {
    console.error('Extend user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user password (admin only)
app.patch('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    await User.findByIdAndUpdate(userId, { password_hash: passwordHash });

    res.json({ success: true, message: 'Password updated' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete expired users (admin only) — must be before /:id
app.delete('/api/users/expired', requireAdmin, async (req, res) => {
  try {
    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    const result = await User.deleteMany({
      role:       { $ne: 'admin' },
      expires_at: { $ne: null, $lt: new Date() },
    });

    res.json({
      success: true,
      message: `Deleted ${result.deletedCount} expired user(s)`,
      deletedCount: result.deletedCount
    });
  } catch (error) {
    console.error('Delete expired users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    if (userId === req.session.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    if (!mongoUri) {
      return res.status(503).json({ error: 'Database not configured' });
    }

    await User.findOneAndDelete({ _id: userId, role: { $ne: 'admin' } });
    res.json({ success: true, message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============ TikTok Profile Lookup ============

// In-memory cache: username -> { data, ts }
const profileCache = new Map();
const PROFILE_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Clean expired cache entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of profileCache) {
    if (now - v.ts > PROFILE_CACHE_TTL) profileCache.delete(k);
  }
}, 5 * 60 * 1000);

const normalizeCount = (value) => {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : 0;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim().toUpperCase();
    const match = trimmed.match(/^([0-9]*\.?[0-9]+)\s*([KMB])?$/);

    if (match) {
      const base = Number(match[1]);
      if (!Number.isFinite(base)) return 0;

      const multipliers = { K: 1_000, M: 1_000_000, B: 1_000_000_000 };
      const multiplier = match[2] ? multipliers[match[2]] : 1;
      return Math.round(base * multiplier);
    }

    const numeric = Number(trimmed.replace(/[^0-9]/g, ''));
    return Number.isFinite(numeric) ? numeric : 0;
  }

  return 0;
};

const formatCount = (count) => {
  if (count >= 1_000_000_000) return (count / 1_000_000_000).toFixed(1) + 'B';
  if (count >= 1_000_000) return (count / 1_000_000).toFixed(1) + 'M';
  if (count >= 1_000) return (count / 1_000).toFixed(1) + 'K';
  return count.toString();
};

const TIKTOK_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

async function scrapeEmbedProfile(username) {
  try {
    const response = await fetch(`https://www.tiktok.com/embed/@${username}`, {
      headers: {
        'User-Agent': TIKTOK_UA,
        Accept: 'text/html',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return null;
    const html = await response.text();

    const match = html.match(/<script[^>]*id="__FRONTITY_CONNECT_STATE__"[^>]*>([\s\S]*?)<\/script>/i);
    if (!match || !match[1]) return null;

    const state = JSON.parse(match[1]);
    const sourceData = state?.source?.data || {};
    const sourceKey = Object.keys(sourceData).find((key) => key.toLowerCase().includes(username.toLowerCase()));
    const userInfo = sourceData[sourceKey]?.userInfo || {};

    let avatarRaw = userInfo.avatarThumbUrl || userInfo.avatarThumb || userInfo.avatarMedium || userInfo.avatarLarger || '';
    if (typeof avatarRaw === 'string') {
      avatarRaw = avatarRaw.replace(/\\u0026/g, '&');
    }

    const followerCount = Number(userInfo.followerCount) || 0;
    const followingCount = Number(userInfo.followingCount) || 0;
    const likesCount = Number(userInfo.heartCount) || 0;

    if (!avatarRaw && !userInfo.nickname) return null;

    return {
      username: userInfo.uniqueId || username,
      avatar: avatarRaw ? `/api/tiktok/avatar?url=${encodeURIComponent(avatarRaw)}` : '',
      nickname: userInfo.nickname || userInfo.uniqueId || username,
      followers: formatCount(followerCount),
      followerCount,
      following: formatCount(followingCount),
      followingCount,
      likes: formatCount(likesCount),
      likesCount,
    };
  } catch {
    return null;
  }
}

async function scrapeTikTokProfile(username) {
  const webId = Math.floor(Math.random() * 9_999_999_999_999).toString();
  const urls = [
    `https://www.tiktok.com/@${encodeURIComponent(username)}`,
    `https://www.tiktok.com/@${encodeURIComponent(username)}?lang=en`,
  ];

  let userDetail = null;
  let userStats = null;

  for (const url of urls) {
    try {
      const response = await fetch(url, {
        headers: {
          'User-Agent': TIKTOK_UA,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          Referer: 'https://www.google.com/',
          Cookie: 'tt_webid=' + webId,
        },
        signal: AbortSignal.timeout(9000),
      });

      const html = await response.text();
      if (html.includes('Please wait') || html.includes('wafchallengeid') || html.includes('SlardarWAF')) {
        continue;
      }

      const universalMatch = html.match(/<script[^>]*id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>([\s\S]*?)<\/script>/i);
      if (universalMatch && universalMatch[1]) {
        try {
          const data = JSON.parse(universalMatch[1]);
          const info = data?.__DEFAULT_SCOPE__?.['webapp.user-detail']?.userInfo;
          userDetail = info?.user || null;
          userStats = info?.stats || null;
          if (userDetail || userStats) break;
        } catch {
          // Continue to SIGI parser.
        }
      }

      const sigiMatch = html.match(/<script[^>]*id="SIGI_STATE"[^>]*>([\s\S]*?)<\/script>/i);
      if (sigiMatch && sigiMatch[1]) {
        try {
          const sigi = JSON.parse(sigiMatch[1]);
          userDetail = Object.values(sigi?.UserModule?.users || {})[0] || null;
          userStats = Object.values(sigi?.UserModule?.stats || {})[0] || null;
          if (userDetail || userStats) break;
        } catch {
          // Try next URL variant.
        }
      }
    } catch {
      // Try next URL variant.
    }
  }

  if (!userDetail && !userStats) return null;

  const followerCount = normalizeCount(userStats?.followerCount ?? userDetail?.followerCount ?? 0);
  const followingCount = normalizeCount(userStats?.followingCount ?? userDetail?.followingCount ?? 0);
  const likesCount = normalizeCount(userStats?.heartCount ?? userDetail?.heartCount ?? 0);

  const avatarRaw = userDetail?.avatarLarger || userDetail?.avatarMedium || userDetail?.avatarThumb || '';
  const avatar = avatarRaw
    ? `/api/tiktok/avatar?url=${encodeURIComponent(avatarRaw)}`
    : '';

  return {
    username: userDetail?.uniqueId || username,
    avatar,
    nickname: userDetail?.nickname || username,
    followers: formatCount(followerCount),
    followerCount,
    following: formatCount(followingCount),
    followingCount,
    likes: formatCount(likesCount),
    likesCount,
  };
}

async function buildTikTokProfile(username) {
  const [embed, scraped] = await Promise.all([
    scrapeEmbedProfile(username),
    scrapeTikTokProfile(username).catch(() => null),
  ]);

  const primary = (embed && embed.avatar) ? embed : (scraped && scraped.avatar) ? scraped : null;
  const secondary = primary === embed ? scraped : embed;

  if (primary) {
    if (secondary) {
      if (!primary.avatar && secondary.avatar) {
        primary.avatar = secondary.avatar;
      }
      if (secondary.nickname && secondary.nickname !== secondary.username) {
        primary.nickname = secondary.nickname;
      }
      if (!primary.followerCount && secondary.followerCount) {
        primary.followerCount = secondary.followerCount;
        primary.followers = secondary.followers;
      }
    }
    return primary;
  }

  const clean = String(username).trim().replace(/^@+/, '') || 'user';
  return {
    username: embed?.username || scraped?.username || clean,
    avatar: '',
    nickname: embed?.nickname || scraped?.nickname || clean,
    followers: embed?.followers || scraped?.followers || '0',
    followerCount: embed?.followerCount || scraped?.followerCount || 0,
    following: embed?.following || scraped?.following || '0',
    followingCount: embed?.followingCount || scraped?.followingCount || 0,
    likes: embed?.likes || scraped?.likes || '0',
    likesCount: embed?.likesCount || scraped?.likesCount || 0,
  };
}

app.get('/api/tiktok/profile/:username', async (req, res) => {
  // Disable Safari heuristic caching of JSON responses.
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  const rawUsername = req.params.username || '';
  const cleanUsername = rawUsername.replace(/^@+/, '').trim();

  if (!cleanUsername || cleanUsername.length < 3) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  // Return cached result if available
  const cached = profileCache.get(cleanUsername.toLowerCase());
  if (cached && Date.now() - cached.ts < PROFILE_CACHE_TTL) {
    return res.json({ success: true, data: cached.data });
  }

  try {
    const profile = await buildTikTokProfile(cleanUsername);
    profileCache.set(cleanUsername.toLowerCase(), { data: profile, ts: Date.now() });
    return res.json({ success: true, data: profile });
  } catch (err) {
    console.error('TikTok profile fetch error:', err.message);
    return res.json({
      success: true,
      fallback: true,
      data: {
        username: cleanUsername,
        avatar: '',
        nickname: cleanUsername,
        followers: '0',
        followerCount: 0,
        following: '0',
        followingCount: 0,
        likes: '0',
        likesCount: 0,
      },
    });
  }
});

// Avatar proxy to bypass client DNS blocks on TikTok CDN
app.get('/api/tiktok/avatar', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    const upstream = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Referer: 'https://www.tiktok.com/',
      },
    });

    if (!upstream.ok) return res.status(502).json({ error: 'Failed to fetch avatar' });

    const contentType = upstream.headers.get('content-type') || 'image/jpeg';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    const arrayBuffer = await upstream.arrayBuffer();
    res.end(Buffer.from(arrayBuffer));
  } catch (err) {
    res.status(502).json({ error: 'Avatar proxy error', message: err?.message || 'unknown' });
  }
});

// ============ Cash App Profile Lookup ============

const CASHAPP_UAS = [
  // Modern desktop Chrome — most reliable from datacenter IPs.
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  // iOS Safari
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  // Android Chrome
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
];

// Cache for Cash App profiles
const cashappProfileCache = new Map();
const CASHAPP_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
// Short negative cache: prevent slamming cash.app when a cashtag genuinely
// doesn't exist (or while user is mid-typing). Cleared on the next miss after TTL.
const cashappNegativeCache = new Map();
const CASHAPP_NEG_CACHE_TTL = 30 * 1000; // 30 seconds
// In-flight deduplication: concurrent requests for the same cashtag share
// the same upstream scrape promise. Cleared once it settles.
const cashappInflight = new Map();

// Clean expired Cash App cache entries
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cashappProfileCache) {
    if (now - v.ts > CASHAPP_CACHE_TTL) cashappProfileCache.delete(k);
  }
  for (const [k, v] of cashappNegativeCache) {
    if (now - v.ts > CASHAPP_NEG_CACHE_TTL) cashappNegativeCache.delete(k);
  }
}, 5 * 60 * 1000);

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function fetchCashAppHTML(cashtag, debugInfo) {
  // Try multiple UAs in case Cash App returns a stripped page (e.g. just the
  // React shell with no `var profile = {...}` block) for one UA. Datacenter
  // IPs sometimes get challenge pages on the mobile UA; desktop Chrome is
  // usually the most reliable.
  // Retry the whole UA cycle up to 3 times with backoff to handle transient
  // throttling / 5xx from cash.app — this is what makes the lookup
  // bullet-proof from any customer device or VPN.
  const MAX_ROUNDS = 3;
  let lastErr = null;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    for (const ua of CASHAPP_UAS) {
      try {
        const response = await fetch(`https://cash.app/$${encodeURIComponent(cashtag)}`, {
          headers: {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
          },
          redirect: 'follow',
        });
        if (!response.ok) {
          lastErr = `status_${response.status}`;
          if (debugInfo) debugInfo.attempts.push({ round, ua: ua.slice(0, 30), status: response.status });
          console.warn(`[cashapp] $${cashtag} fetch !ok (${response.status}) round=${round} ua=${ua.slice(0, 30)}`);
          // Real 404 from cash.app means the cashtag doesn't exist — give up.
          if (response.status === 404) {
            if (debugInfo) debugInfo.lastErr = 'status_404';
            return null;
          }
          continue;
        }
        const html = await response.text();
        // Quick signal: page is "usable" if it has either the JSON block,
        // the React testid markup, or at least the formatted cashtag string.
        const hasJson = /var\s+profile\s*=\s*\{/.test(html);
        const hasTestid = /cashtags-profile-(title|subtitle)/.test(html);
        const hasFormatted = /formatted_cashtag/.test(html);
        const usable = hasJson || hasTestid || hasFormatted;
        console.log(`[cashapp] $${cashtag} html=${html.length}b usable=${usable} hasJson=${hasJson} hasTestid=${hasTestid} round=${round} ua=${ua.slice(0, 30)}`);
        if (debugInfo) debugInfo.attempts.push({
          round, ua: ua.slice(0, 30),
          status: response.status,
          bytes: html.length,
          hasJson, hasTestid, hasFormatted,
          snippet: html.slice(0, 400),
        });
        if (usable) return html;
        lastErr = 'unusable_html';
      } catch (err) {
        lastErr = err && err.message || 'fetch_err';
        if (debugInfo) debugInfo.attempts.push({ round, ua: ua.slice(0, 30), error: lastErr });
        console.warn(`[cashapp] $${cashtag} fetch threw round=${round}: ${lastErr}`);
      }
    }
    // Backoff before the next round: 150ms, 450ms (with light jitter)
    if (round < MAX_ROUNDS - 1) {
      const backoff = 150 * Math.pow(3, round) + Math.floor(Math.random() * 100);
      await sleep(backoff);
    }
  }
  if (debugInfo) debugInfo.lastErr = lastErr;
  console.warn(`[cashapp] $${cashtag} all rounds failed: ${lastErr}`);
  return null;
}

async function scrapeCashAppProfile(cashtag, debugInfo) {
  try {
    const html = await fetchCashAppHTML(cashtag, debugInfo);
    if (!html) return null;

    let fullName = '';
    let avatar = '';
    let displayTag = `$${cashtag}`;
    let initial = '';
    let accentColor = '';
    let isVerified = false;
    
    // Primary method: Extract from JavaScript variable "var profile = {...}"
    const profileJsonMatch = html.match(/var\s+profile\s*=\s*(\{[^;]+\});/);
    if (profileJsonMatch) {
      try {
        const profileData = JSON.parse(profileJsonMatch[1]);
        if (profileData.display_name) {
          fullName = profileData.display_name;
        }
        if (profileData.formatted_cashtag) {
          displayTag = profileData.formatted_cashtag;
        }
        if (profileData.avatar) {
          if (profileData.avatar.image_url) {
            avatar = profileData.avatar.image_url;
          }
          if (profileData.avatar.initial) {
            initial = String(profileData.avatar.initial).slice(0, 2);
          }
          if (profileData.avatar.accent_color) {
            accentColor = String(profileData.avatar.accent_color);
          }
        }
        if (typeof profileData.is_verified_account === 'boolean') {
          isVerified = profileData.is_verified_account;
        }
      } catch (e) {
        console.warn('Failed to parse Cash App profile JSON:', e.message);
      }
    }

    // Modern React markup: <span data-testid="cashtags-profile-title"><div>Name</div></span>
    if (!fullName) {
      const titleMatch = html.match(/data-testid=["']cashtags-profile-title["'][^>]*>\s*(?:<[^>]+>\s*)*([^<]+?)\s*</i);
      if (titleMatch && titleMatch[1]) {
        const candidate = titleMatch[1].trim();
        if (candidate && candidate !== 'Pay me on Cash App') fullName = candidate;
      }
    }
    // Modern React markup: <span data-testid="cashtags-profile-subtitle">$max</span>
    if (displayTag === `$${cashtag}`) {
      const subtitleMatch = html.match(/data-testid=["']cashtags-profile-subtitle["'][^>]*>\s*([^<]+?)\s*</i);
      if (subtitleMatch && subtitleMatch[1]) {
        const candidate = subtitleMatch[1].trim();
        if (candidate.startsWith('$')) displayTag = candidate;
      }
    }
    // Modern React markup: <img alt="avatar image" src="...">
    if (!avatar) {
      const imgMatch = html.match(/<img[^>]*alt=["']avatar image["'][^>]*src=["']([^"']+)["']/i)
        || html.match(/<img[^>]*src=["']([^"']+)["'][^>]*alt=["']avatar image["']/i);
      if (imgMatch) avatar = imgMatch[1];
    }
    
    // Fallback: Try meta tags if JS variable not found
    if (!fullName) {
      const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
      if (ogTitleMatch) {
        const title = ogTitleMatch[1].replace(/\s*[-|]\s*Cash App.*$/i, '').trim();
        if (title && title !== 'Pay me on Cash App') {
          fullName = title;
        }
      }
    }
    
    // Fallback: Look for franklin-assets avatar URLs
    if (!avatar) {
      const franklinMatch = html.match(/["'](https:\/\/franklin-assets\.s3\.amazonaws\.com\/[^"']+)["']/i);
      if (franklinMatch) {
        avatar = franklinMatch[1];
      }
    }
    
    // Fallback: Look for cash-images squarecdn URLs  
    if (!avatar) {
      const squarecdnMatch = html.match(/["'](https:\/\/cash-images-f\.squarecdn\.com\/[^"']+)["']/i);
      if (squarecdnMatch) {
        avatar = squarecdnMatch[1];
      }
    }
    
    // Only return a profile if we actually found real data (real name OR avatar OR initial).
    // Otherwise the caller should treat it as "not found" and fall back (e.g., to TikTok).
    const hasRealData = !!(fullName || avatar || initial);
    if (!hasRealData) return null;

    return {
      username: cashtag,
      fullName: fullName || `$${cashtag}`,
      displayTag,
      avatar: avatar ? `/api/cashapp/avatar?url=${encodeURIComponent(avatar)}` : '',
      initial: initial || (fullName ? fullName.trim().charAt(0).toUpperCase() : cashtag.charAt(0).toUpperCase()),
      accentColor: accentColor || '',
      isVerified,
    };
  } catch (err) {
    console.error('Cash App profile scrape error:', err.message);
    return null;
  }
}

app.get('/api/cashapp/profile/:cashtag', async (req, res) => {
  // Disable Safari/iOS heuristic caching of this JSON endpoint.
  // Without these headers Safari can replay a previously cached `{success:false}`
  // response forever (Chrome does not exhibit this).
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  // Build marker so we can confirm a fresh deploy is live from the browser.
  res.set('X-Cashapp-Lookup-Build', '2026-06-12-bulletproof');

  const rawCashtag = req.params.cashtag || '';
  const cleanCashtag = rawCashtag.replace(/^\$+/, '').trim();

  if (!cleanCashtag || cleanCashtag.length < 1) {
    return res.status(400).json({ error: 'Invalid cashtag' });
  }

  // ?nocache=1 bypasses the in-memory cache (useful for debugging stale results)
  const skipCache = req.query.nocache === '1';
  const wantDebug = req.query.debug === '1';
  const debugInfo = wantDebug ? { attempts: [], lastErr: null } : null;
  const key = cleanCashtag.toLowerCase();

  // Positive cache: serve a previously-resolved profile immediately.
  if (!skipCache) {
    const cached = cashappProfileCache.get(key);
    if (cached && Date.now() - cached.ts < CASHAPP_CACHE_TTL) {
      return res.json({ success: true, data: cached.data, cached: true });
    }
    // Short negative cache: a known-missing cashtag — don't re-hit cash.app
    // for 30s. Prevents hammering when the user is mid-typing.
    const neg = cashappNegativeCache.get(key);
    if (neg && Date.now() - neg.ts < CASHAPP_NEG_CACHE_TTL) {
      return res.json({ success: false, notFound: true, cached: true });
    }
  }

  // In-flight dedup: collapse concurrent requests for the same cashtag onto
  // a single upstream scrape so a search burst doesn't multiply our outbound
  // traffic (which is what triggers cash.app rate limits in the first place).
  if (!cashappInflight.has(key)) {
    cashappInflight.set(key, scrapeCashAppProfile(cleanCashtag, debugInfo).finally(() => {
      // Tiny delay before clearing so two near-simultaneous requests dedup.
      setTimeout(() => cashappInflight.delete(key), 50);
    }));
  }

  try {
    const profile = await cashappInflight.get(key);

    if (profile) {
      cashappProfileCache.set(key, { data: profile, ts: Date.now() });
      cashappNegativeCache.delete(key);
      const out = { success: true, data: profile };
      if (debugInfo) out.debug = debugInfo;
      return res.json(out);
    } else {
      // Profile not found — cache the miss briefly + return success:false so
      // the client can fall back (e.g., to TikTok).
      cashappNegativeCache.set(key, { ts: Date.now() });
      const out = { success: false, notFound: true };
      if (debugInfo) out.debug = debugInfo;
      return res.json(out);
    }
  } catch (err) {
    console.error('Cash App profile fetch error:', err.message);
    const out = { success: false, error: err?.message || 'fetch_error' };
    if (debugInfo) out.debug = debugInfo;
    return res.json(out);
  }
});

// Cash App avatar proxy to bypass CORS
app.get('/api/cashapp/avatar', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    const upstream = await fetch(url, {
      headers: {
        'User-Agent': CASHAPP_UAS[0],
        'Referer': 'https://cash.app/',
      },
    });

    if (!upstream.ok) return res.status(502).json({ error: 'Failed to fetch avatar' });

    const contentType = upstream.headers.get('content-type') || 'image/jpeg';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    const arrayBuffer = await upstream.arrayBuffer();
    res.end(Buffer.from(arrayBuffer));
  } catch (err) {
    res.status(502).json({ error: 'Cash App avatar proxy error', message: err?.message || 'unknown' });
  }
});

// Serve static assets after API routes so /api paths aren't intercepted
app.use(express.static(path.join(__dirname)));

// Export for Vercel serverless
module.exports = app;

// Start server (for local development)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 Cash Clone server running on http://localhost:${PORT}`);
    if (mongoUri) {
      console.log(`📊 Database: MongoDB (${process.env.NODE_ENV || 'development'})`);
    } else {
      console.log(`⚠️  Running without database - set MONGO_URI to use MongoDB`);
    }
  });
}