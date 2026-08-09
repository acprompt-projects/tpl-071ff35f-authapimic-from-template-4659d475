const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

let redisClient = null;
let store = null;

async function initRedis() {
  if (redisClient) return redisClient;

  redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: {
      reconnectStrategy: (retries) => {
        if (retries > 10) return new Error('Redis max reconnection attempts reached');
        return Math.min(retries * 150, 5000);
      },
      connectTimeout: 10000,
    },
  });

  redisClient.on('error', (err) => console.error('[Redis] Session store error:', err.message));
  redisClient.on('connect', () => console.info('[Redis] Session store connected'));

  await redisClient.connect();

  store = new RedisStore({
    client: redisClient,
    prefix: 'sess:',
    ttl: parseInt(process.env.SESSION_TTL || '86400', 10),
  });

  return redisClient;
}

function sessionMiddleware() {
  if (!store) throw new Error('Call initRedis() before sessionMiddleware()');

  const isProd = process.env.NODE_ENV === 'production';

  return session({
    store,
    name: process.env.SESSION_COOKIE_NAME || '__Host.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'strict' : 'lax',
      maxAge: parseInt(process.env.SESSION_MAX_AGE || '86400000', 10),
      path: '/',
      ...(isProd && { domain: process.env.COOKIE_DOMAIN }),
    },
    genid: () => require('crypto').randomBytes(24).toString('hex'),
  });
}

async function shutdownRedis() {
  if (redisClient) {
    await redisClient.quit().catch(() => redisClient.disconnect());
    redisClient = null;
    store = null;
  }
}

module.exports = { initRedis, sessionMiddleware, shutdownRedis, getStore: () => store };