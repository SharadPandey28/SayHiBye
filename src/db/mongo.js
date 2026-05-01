import mongoose from "mongoose";
import bcrypt from "bcrypt";
import { config } from "../config/index.js";
import { logger } from "../config/logger.js";

// ─────────────────────────────────────────────────────────────
//  CONNECTION
// ─────────────────────────────────────────────────────────────
export async function connectMongo() {
  try {
    await mongoose.connect(config.mongo.uri, {
      serverSelectionTimeoutMS: 5000,
      maxPoolSize: 10,
    });
    logger.info("MongoDB connected");
    await seedAdmin();
  } catch (err) {
    logger.error({ err }, "MongoDB connection failed");
    process.exit(1);
  }
}

// ─────────────────────────────────────────────────────────────
//  SCHEMAS & MODELS
// ─────────────────────────────────────────────────────────────

// ── User ──────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 1,
    maxlength: 20,
    match: /^[a-zA-Z0-9\-_]+$/,
  },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
  createdAt: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  isBlocked: { type: Boolean, default: false },
  blockReason: { type: String, default: "" },
}, { versionKey: false });

userSchema.index({ username: 1 }, { unique: true });
export const User = mongoose.model("User", userSchema);

// ── Room ──────────────────────────────────────────────────────
const roomSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true, trim: true },
  type: { type: String, enum: ["direct", "group"], default: "group" },
  hostUsername: { type: String, required: true },
  maxMembers: { type: Number, default: 2, min: 2, max: 10 },
  status: { type: String, enum: ["active", "closed"], default: "active" },
  memberCount: { type: Number, default: 1 },
  messageCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  closedAt: { type: Date, default: null },
  lastActivity: { type: Date, default: Date.now },
}, { versionKey: false });

roomSchema.index({ roomId: 1 }, { unique: true });
roomSchema.index({ status: 1, lastActivity: -1 });
export const Room = mongoose.model("Room", roomSchema);

// ── Session (who was in which room) ──────────────────────────
const sessionSchema = new mongoose.Schema({
  username: { type: String, required: true },
  roomId: { type: String, required: true },
  joinedAt: { type: Date, default: Date.now },
  leftAt: { type: Date, default: null },
  socketId: { type: String },
}, { versionKey: false });

// TTL index: auto-delete sessions older than 30 days
sessionSchema.index({ joinedAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });
sessionSchema.index({ roomId: 1, username: 1 });
export const Session = mongoose.model("Session", sessionSchema);

// ── Audit Log ────────────────────────────────────────────────
// Replaces the in-memory eventLog array — survives server restarts
const auditSchema = new mongoose.Schema({
  time: { type: Date, default: Date.now },
  event: { type: String, required: true },
  roomId: { type: String, default: "global" },
  detail: { type: String, default: "" },
  username: { type: String, default: "" },
}, { versionKey: false });

auditSchema.index({ time: -1 });
auditSchema.index({ roomId: 1, time: -1 });
// TTL: auto-delete audit logs older than 90 days
auditSchema.index({ time: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });
export const AuditLog = mongoose.model("AuditLog", auditSchema);

// ─────────────────────────────────────────────────────────────
//  SEED ADMIN USER (runs on first startup only)
// ─────────────────────────────────────────────────────────────
async function seedAdmin() {
  const exists = await User.findOne({ role: "admin" });
  if (exists) return;

  const passwordHash = await bcrypt.hash(config.admin.password, 12);
  await User.create({ username: "admin", passwordHash, role: "admin" });
  logger.info("Admin user created — change password immediately in production");
}
