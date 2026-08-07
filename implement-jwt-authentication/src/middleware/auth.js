const { verifyToken } = require("../auth/jwt");

function extractBearerToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice(7);
}

function requireAuth(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    return res.status(401).json({ error: "Unauthorized", message: "Missing or malformed Authorization header" });
  }

  const result = verifyToken(token, "access");
  if (!result.valid) {
    const status = result.error.includes("expired") ? 401 : 403;
    return res.status(status).json({ error: status === 401 ? "TokenExpired" : "Forbidden", message: result.error });
  }

  req.user = {
    userId: result.payload.sub,
    role: result.payload.role,
    issuer: result.payload.iss,
    tokenId: result.payload.kid,
  };
  next();
}

function requireRole(...allowedRoles) {
  const roles = allowedRoles.flat().map((r) => r.toLowerCase());
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized", message: "Authentication required" });
    }
    if (!roles.includes(req.user.role.toLowerCase())) {
      return res.status(403).json({ error: "Forbidden", message: `Role '${req.user.role}' is not permitted` });
    }
    next();
  };
}

function optionalAuth(req, res, next) {
  const token = extractBearerToken(req);
  if (!token) {
    req.user = null;
    return next();
  }
  const result = verifyToken(token, "access");
  if (result.valid) {
    req.user = {
      userId: result.payload.sub,
      role: result.payload.role,
      issuer: result.payload.iss,
      tokenId: result.payload.kid,
    };
  } else {
    req.user = null;
  }
  next();
}

module.exports = { requireAuth, requireRole, optionalAuth };