import jwt from "jsonwebtoken";
import { config } from "../config/index.js";

// ─── REST route middleware ─────────────────────────────────────
export function verifyToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }
  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, config.jwt.secret);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ─── Admin-only middleware ─────────────────────────────────────
export function requireAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.user?.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }
    next();
  });
}

// ─── Socket.io handshake auth ─────────────────────────────────
// Used in: io.use(socketAuth)
// After this, socket.user = { userId, username, role }
export function socketAuth(socket, next) {
  const token = socket.handshake.auth?.token;

  // Allow unauthenticated connections in dev (guest mode)
  if (!token && config.isDev) {
    socket.user = { userId: socket.id, username: "guest_" + socket.id.slice(0, 5), role: "user" };
    return next();
  }

  if (!token) return next(new Error("Authentication required"));

  try {
    socket.user = jwt.verify(token, config.jwt.secret);
    next();
  } catch {
    next(new Error("Invalid token"));
  }
}

// ─── JWT generator ────────────────────────────────────────────
export function signToken(payload) {
  return jwt.sign(payload, config.jwt.secret, { expiresIn: config.jwt.expiresIn });
}
