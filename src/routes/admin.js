import { Router } from "express";
import { requireAdmin } from "../middleware/auth.js";
import { Room, User, AuditLog, Session } from "../db/mongo.js";

const router = Router();

// All admin routes require admin JWT role
router.use(requireAdmin);

// ── GET /api/admin/stats ──────────────────────────────────────
router.get("/stats", async (req, res) => {
  try {
    const [
      totalUsers,
      activeRooms,
      totalRooms,
      recentEvents,
      totalMessages,
    ] = await Promise.all([
      User.countDocuments(),
      Room.countDocuments({ status: "active" }),
      Room.countDocuments(),
      AuditLog.find().sort({ time: -1 }).limit(50).lean(),
      Room.aggregate([{ $group: { _id: null, total: { $sum: "$messageCount" } } }]),
    ]);

    const rooms = await Room.find({ status: "active" })
      .sort({ lastActivity: -1 })
      .limit(50)
      .lean();

    res.json({
      totalUsers,
      activeRooms,
      totalRooms,
      totalMessages: totalMessages[0]?.total || 0,
      rooms: rooms.map(r => ({
        id: r.roomId,
        type: r.type,
        host: r.hostUsername,
        maxMembers: r.maxMembers,
        memberCount: r.memberCount,
        pendingCount: 0, // live data from socket store
        messageCount: r.messageCount,
        startTime: r.createdAt,
        lastActivity: r.lastActivity,
        status: r.status,
      })),
      recentEvents: recentEvents.map(e => ({
        time: e.time,
        event: e.event,
        roomId: e.roomId,
        detail: e.detail,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to load stats" });
  }
});

// ── GET /api/admin/users ──────────────────────────────────────
router.get("/users", async (req, res) => {
  const users = await User.find()
    .select("-passwordHash")
    .sort({ createdAt: -1 })
    .limit(100)
    .lean();
  res.json(users);
});

// ── POST /api/admin/users/:id/block ──────────────────────────
router.post("/users/:id/block", async (req, res) => {
  const { reason = "Blocked by admin" } = req.body;
  await User.updateOne({ _id: req.params.id }, { isBlocked: true, blockReason: reason });
  res.json({ ok: true });
});

// ── POST /api/admin/users/:id/unblock ────────────────────────
router.post("/users/:id/unblock", async (req, res) => {
  await User.updateOne({ _id: req.params.id }, { isBlocked: false, blockReason: "" });
  res.json({ ok: true });
});

// ── GET /api/admin/rooms ──────────────────────────────────────
router.get("/rooms", async (req, res) => {
  const rooms = await Room.find()
    .sort({ createdAt: -1 })
    .limit(100)
    .lean();
  res.json(rooms);
});

// ── DELETE /api/admin/rooms/:roomId ──────────────────────────
router.delete("/rooms/:roomId", async (req, res) => {
  await Room.updateOne({ roomId: req.params.roomId }, { status: "closed", closedAt: new Date() });
  res.json({ ok: true });
});

export default router;
