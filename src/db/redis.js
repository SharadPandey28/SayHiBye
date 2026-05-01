import Redis from "ioredis";
import { config } from "../config/index.js";
import { logger } from "../config/logger.js";

// ─────────────────────────────────────────────────────────────
//  CONNECTION  (two clients needed: one for adapter, one for app)
// ─────────────────────────────────────────────────────────────
const redisOptions = {
  maxRetriesPerRequest: 3,
  retryStrategy: (times) => Math.min(times * 200, 3000),
  enableOfflineQueue: false,
  lazyConnect: true,
};

// Main app Redis client
export const redis = new Redis(config.redis.url, redisOptions);

// Second client specifically for Socket.io pub/sub adapter
export const redisSub = new Redis(config.redis.url, redisOptions);

export async function connectRedis() {
  try {
    await redis.connect();
    await redisSub.connect();
    await redis.ping();
    logger.info("Redis connected");
  } catch (err) {
    logger.warn({ err }, "Redis unavailable — running without Redis (rate limiting will be in-memory only)");
    // App continues without Redis — graceful degradation
  }
}

// ─────────────────────────────────────────────────────────────
//  SOCKET RATE LIMITER
//  Falls back to in-memory Map if Redis is unavailable
// ─────────────────────────────────────────────────────────────
const memRateMap = new Map();

export async function checkSocketRateLimit(socketId) {
  const key = `rl:socket:${socketId}`;
  const limit = config.rateLimit.socketEventsPerSec;
  const windowMs = 1000;

  try {
    if (redis.status !== "ready") throw new Error("Redis not ready");

    const now = Date.now();
    const windowKey = `${key}:${Math.floor(now / windowMs)}`;
    const count = await redis.incr(windowKey);
    if (count === 1) await redis.pexpire(windowKey, windowMs * 2);
    return count <= limit;
  } catch {
    // In-memory fallback
    const now = Date.now();
    const state = memRateMap.get(socketId) || { count: 0, resetAt: now + windowMs };
    if (now > state.resetAt) { state.count = 0; state.resetAt = now + windowMs; }
    state.count++;
    memRateMap.set(socketId, state);
    // Cleanup stale entries periodically
    if (memRateMap.size > 1000) {
      for (const [k, v] of memRateMap) { if (now > v.resetAt) memRateMap.delete(k); }
    }
    return state.count <= limit;
  }
}

// Cleanup rate limit keys when socket disconnects
export async function clearSocketRateLimit(socketId) {
  memRateMap.delete(socketId);
  try {
    const keys = await redis.keys(`rl:socket:${socketId}:*`);
    if (keys.length) await redis.del(...keys);
  } catch { /* ignore */ }
}
