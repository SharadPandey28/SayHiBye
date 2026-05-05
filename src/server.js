import "dotenv/config";
import express from "express";
import { createServer } from "http";
import { Server } from "socket.io";
import { createAdapter } from "@socket.io/redis-adapter";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

import { config } from "./config/index.js";
import { logger } from "./config/logger.js";
import { connectMongo } from "./db/mongo.js";
import { connectRedis, redis, redisSub } from "./db/redis.js";
import { socketAuth } from "./middleware/auth.js";
import { registerHandlers } from "./socket/handlers.js";
import { AuditLog, Room } from "./db/mongo.js";
import { SocketStore } from "./socket/store.js";

import authRoutes from "./routes/auth.js";
import adminRoutes from "./routes/admin.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────
//  EXPRESS APP
// ─────────────────────────────────────────────────────────────
const app = express();
const httpServer = createServer(app);

// ── Security middleware ───────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],

      scriptSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],

      // 👇 ADD THIS LINE
      scriptSrcAttr: ["'unsafe-inline'"],

      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://fonts.gstatic.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],

      connectSrc: ["'self'", "wss:", "ws:", "https://sayhibye.onrender.com"],
    },
  },
}));

app.use(cors({
  origin: config.cors.origin,
  credentials: true,
}));

app.use(express.json({ limit: "10kb" }));

// ── Request logging ───────────────────────────────────────────
if (config.isDev) {
  app.use(morgan("dev"));
} else {
  app.use(morgan("combined", { stream: { write: msg => logger.info(msg.trim()) } }));
}

// ── REST rate limiting ────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.max,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please try again later." },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20, // stricter for auth endpoints
  message: { error: "Too many auth attempts. Please wait 15 minutes." },
});

// ── Static files ──────────────────────────────────────────────
app.use(express.static(join(__dirname, "../public")));

// ── API Routes ────────────────────────────────────────────────
app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/admin", apiLimiter, adminRoutes);

// ── Health check (public) ─────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    env: config.nodeEnv,
    rooms: SocketStore.roomCount(),
  });
});

// ── 404 handler ───────────────────────────────────────────────
app.use((req, res) => {
  if (req.path.startsWith("/api")) return res.status(404).json({ error: "Not found" });
  // SPA fallback — serve index.html for all non-API routes
  res.sendFile(join(__dirname, "../public/index.html"));
});

// ── Global error handler ──────────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: config.isDev ? err.message : "Internal server error" });
});

// ─────────────────────────────────────────────────────────────
//  SOCKET.IO
// ─────────────────────────────────────────────────────────────
const io = new Server(httpServer, {
  cors: {
    origin: "https://sayhibye.onrender.com", 
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"], 
  pingTimeout: 30000,
  pingInterval: 10000,
  maxHttpBufferSize: 1e5,
});

// Auth middleware — runs before any socket connects
io.use(socketAuth);

// Register handlers for each connection
io.on("connection", (socket) => {
  logger.debug({ socketId: socket.id, user: socket.user?.username }, "Socket connected");
  registerHandlers(io, socket);
});

// ─────────────────────────────────────────────────────────────
//  STARTUP
// ─────────────────────────────────────────────────────────────
async function start() {
  // 1. Connect MongoDB (required)
  await connectMongo();

  // 2. Connect Redis (optional — graceful degradation if unavailable)
  await connectRedis();

  // 3. Wire Socket.io Redis adapter if Redis is available
  if (redis.status === "ready") {
    io.adapter(createAdapter(redis, redisSub));
    logger.info("Socket.io Redis adapter active");
  }

  // 4. Room cleanup — every 10 minutes remove stale in-memory rooms
  setInterval(async () => {
    const closed = await Room.find({ status: "closed", closedAt: { $lt: new Date(Date.now() - 60 * 60 * 1000) } }).lean();
    closed.forEach(r => SocketStore.deleteRoom(r.roomId));
    if (closed.length) logger.info(`Cleaned ${closed.length} stale rooms`);
  }, 10 * 60 * 1000);

  // 5. Start server
  httpServer.listen(config.port, () => {
    logger.info(`🔐 DH Secure Chat running on port ${config.port}`);
    logger.info(`🌍 ${config.isDev ? `http://localhost:${config.port}` : "Production mode"}`);
    logger.info(`📊 Admin: /admin.html`);
  });
}

start().catch(err => {
  logger.error({ err }, "Fatal startup error");
  process.exit(1);
});
