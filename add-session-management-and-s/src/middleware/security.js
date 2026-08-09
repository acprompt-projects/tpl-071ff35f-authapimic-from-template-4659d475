const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const csrf = require('csurf');
const { createClient } = require('redis');

// ── Rate Limiting ──────────────────────────────────────────────────────────
let limiterRedisClient = null;

async function createRateLimiterRedis() {
  if (limiterRedisClient) return limiterRedisClient;
  limiterRedisClient = createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
  limiterRedisClient.on('error', (err) => console.error('[Redis] Rate-limit error:', err.message));
  await limiterRedisClient.connect();
  return limiterRedisClient;
}

async function authRateLimiter() {
  const client = await createRateLimiterRedis();
  return rateLimit({
    store: new RedisStore({ sendCommand: (...args) => client.sendCommand(args), prefix: 'rl:' }),
    windowMs: 15 * 60 * 1000,
    max: parseInt(process.env.AUTH_RATE_MAX || '10', 10),
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false,
    keyGenerator: (req) => req.ip + ':' + (req.body?.email || ''),
    handler: (req, res) => res.status(429).json({ error: 'Too many attempts. Try again later.' }),
  });
}

function passwordResetLimiter() {
  return rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => res.status(429).json({ error: 'Too many reset requests.' }),
  });
}

// ── CORS ───────────────────────────────────────────────────────────────────
function corsOptions() {
  const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map((o) => o.trim()).filter(Boolean);
  return {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error('CORS origin not allowed'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    credentials: true,
    maxAge: 86400,
  };
}

// ── CSRF ───────────────────────────────────────────────────────────────────
function csrfProtection() {
  const protect = csrf({ cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' } });
  return (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    protect(req, res, next);
  };
}

function csrfTokenHandler() {
  return (req, res) => res.json({ csrfToken: req.csrfToken() });
}

// ── Account Lockout ────────────────────────────────────────────────────────
const LOCKOUT_MAX_ATTEMPTS = parseInt(process.env.LOCKOUT_MAX_ATTEMPTS || '5', 10);
const LOCKOUT_WINDOW_MS = parseInt(process.env.LOCKOUT_WINDOW_MS || '900000', 10);
const lockoutStore = new Map();

function _lockoutKey(email) { return `lock:${email.toLowerCase()}`; }

function checkAccountLockout() {
  return (req, res, next) => {
    const email = req.body?.email;
    if (!email) return next();
    const entry = lockoutStore.get(_lockoutKey(email));
    if (!entry) return next();
    if (entry.lockedUntil && Date.now() < entry.lockedUntil) {
      const remaining = Math.ceil((entry.lockedUntil - Date.now()) / 1000);
      return res.status(423).json({ error: 'Account temporarily locked', retryAfterSeconds: remaining });
    }
    if (entry.lockedUntil && Date.now() >= entry.lockedUntil) {
      lockoutStore.delete(_lockoutKey(email));
    }
    next();
  };
}

function recordFailedAttempt(email) {
  const key = _lockoutKey(email);
  const entry = lockoutStore.get(key) || { attempts: 0, lockedUntil: null };
  entry.attempts += 1;
  if (entry.attempts >= LOCKOUT_MAX_ATTEMPTS) {
    entry.lockedUntil = Date.now() + LOCKOUT_WINDOW_MS;
  }
  lockoutStore.set(key, entry);
  return entry;
}

function resetFailedAttempts(email) {
  lockoutStore.delete(_lockoutKey(email));
}

function cleanupLockoutStore() {
  const now = Date.now();
  for (const [key, entry] of lockoutStore) {
    if (entry.lockedUntil && now >= entry.lockedUntil) lockoutStore.delete(key);
  }
}

setInterval(cleanupLockoutStore, 5 * 60 * 1000).unref();

// ── Security Headers ──────────────────────────────────────────────────────
function securityHeaders() {
  return (req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (process.env.NODE_ENV === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
    next();
  };
}

module.exports = {
  authRateLimiter,
  passwordResetLimiter,
  corsOptions,
  csrfProtection,
  csrfTokenHandler,
  checkAccountLockout,
  recordFailedAttempt,
  resetFailedAttempts,
  securityHeaders,
};