const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const PRIVATE_KEY_PATH = process.env.JWT_PRIVATE_KEY_PATH || path.join(__dirname, "..", "keys", "private.pem");
const PUBLIC_KEY_PATH = process.env.JWT_PUBLIC_KEY_PATH || path.join(__dirname, "..", "keys", "public.pem");
const ACCESS_TTL = process.env.JWT_ACCESS_TTL || "15m";
const REFRESH_TTL = process.env.JWT_REFRESH_TTL || "7d";
const ISSUER = process.env.JWT_ISSUER || "auth-microservice";

let _privateKey = null;
let _publicKey = null;

function loadKeys() {
  if (_privateKey && _publicKey) return { privateKey: _privateKey, publicKey: _publicKey };
  try {
    _privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf8");
    _publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf8");
  } catch (err) {
    throw new Error(`JWT key load failed: ${err.message}. Set JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH.`);
  }
  return { privateKey: _privateKey, publicKey: _publicKey };
}

function generateTokenPair(payload) {
  const { privateKey } = loadKeys();
  const jti = cryptoRandom();
  const base = { iss: ISSUER, sub: String(payload.userId), role: payload.role || "user" };

  const accessToken = jwt.sign({ ...base, type: "access" }, privateKey, {
    algorithm: "RS256",
    expiresIn: ACCESS_TTL,
    keyid: jti,
  });

  const refreshToken = jwt.sign({ ...base, type: "refresh", jti }, privateKey, {
    algorithm: "RS256",
    expiresIn: REFRESH_TTL,
    keyid: jti,
  });

  return { accessToken, refreshToken };
}

function verifyToken(token, expectedType = "access") {
  const { publicKey } = loadKeys();
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer: ISSUER });
    if (decoded.type !== expectedType) {
      return { valid: false, error: `Expected ${expectedType} token, got ${decoded.type}` };
    }
    return { valid: true, payload: decoded };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

function refreshAccessToken(refreshToken) {
  const result = verifyToken(refreshToken, "refresh");
  if (!result.valid) return { success: false, error: result.error };

  const { privateKey } = loadKeys();
  const { sub, role, jti } = result.payload;
  const accessToken = jwt.sign({ iss: ISSUER, sub, role, type: "access" }, privateKey, {
    algorithm: "RS256",
    expiresIn: ACCESS_TTL,
    keyid: jti,
  });

  return { success: true, accessToken };
}

function decodeTokenHeader(token) {
  try {
    return jwt.decode(token, { complete: true })?.header || null;
  } catch {
    return null;
  }
}

function cryptoRandom() {
  const { randomBytes } = require("crypto");
  return randomBytes(16).toString("hex");
}

function resetKeyCache() {
  _privateKey = null;
  _publicKey = null;
}

module.exports = { generateTokenPair, verifyToken, refreshAccessToken, decodeTokenHeader, resetKeyCache };