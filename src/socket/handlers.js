import { SocketStore } from "./store.js";
import { Room, AuditLog, Session } from "../db/mongo.js";
import { checkSocketRateLimit, clearSocketRateLimit } from "../db/redis.js";
import { logger } from "../config/logger.js";

const MAX_ROOMS = 100;
const MAX_PENDING_PER_ROOM = 10;

// ─────────────────────────────────────────────────────────────
//  AUDIT HELPER
// ─────────────────────────────────────────────────────────────
async function audit(event, roomId, detail = "", username = "") {
  logger.info({ event, roomId, detail });
  try {
    await AuditLog.create({ event, roomId: roomId || "global", detail, username });
  } catch { /* never crash on audit failure */ }
}

// ─────────────────────────────────────────────────────────────
//  SANITIZE
// ─────────────────────────────────────────────────────────────
function sanitizeRoom(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9\-_]/g, "").slice(0, 24);
}
function sanitizeName(s) {
  return String(s || "").replace(/[^a-zA-Z0-9\-_]/g, "").slice(0, 20);
}

// ─────────────────────────────────────────────────────────────
//  REGISTER ALL SOCKET HANDLERS
// ─────────────────────────────────────────────────────────────
export function registerHandlers(io, socket) {
  // Username comes from JWT (verified in socketAuth middleware)
  // In dev guest mode it's auto-assigned
  const authUser = socket.user;

  // ── Rate limit middleware ──────────────────────────────────
  socket.use(async (_, next) => {
    const ok = await checkSocketRateLimit(socket.id);
    if (!ok) return socket.emit("error_notice", "Rate limit exceeded. Slow down.");
    next();
  });

  // ══════════════════════════════════════════════════════════
  //  CREATE ROOM
  // ══════════════════════════════════════════════════════════
  socket.on("create_room", async ({ roomId, maxMembers, type }) => {
    roomId = sanitizeRoom(roomId);
    const username = authUser.username;

    if (!roomId) return socket.emit("create_error", "Invalid room name.");
    if (SocketStore.roomCount() >= MAX_ROOMS)
      return socket.emit("create_error", "Server at room capacity. Try again later.");

    const existing = SocketStore.getRoom(roomId);
    if (existing && existing.members.length > 0)
      return socket.emit("create_error", `Room "${roomId}" is already active.`);

    const max = Math.min(Math.max(parseInt(maxMembers) || 2, 2), 10);

    SocketStore.createRoom(roomId, {
      hostId: socket.id,
      hostName: username,
      maxMembers: max,
      type: type || "group",
    });

    _joinRoom(socket, roomId, username);

    // Persist to MongoDB
    await Room.findOneAndUpdate(
      { roomId },
      { roomId, type: type || "group", hostUsername: username, maxMembers: max, status: "active", createdAt: new Date(), lastActivity: new Date() },
      { upsert: true, new: true }
    );

    await audit("ROOM_CREATED", roomId, `host=${username} max=${max} type=${type}`, username);

    socket.emit("room_created", { roomId, maxMembers: max, type: type || "group", isHost: true });
  });

  // ══════════════════════════════════════════════════════════
  //  CHECK ROOM
  // ══════════════════════════════════════════════════════════
  socket.on("check_room", ({ roomId }) => {
    roomId = sanitizeRoom(roomId);
    const room = SocketStore.getRoom(roomId);
    if (!room)
      return socket.emit("room_check_result", { ok: false, reason: `Room "${roomId}" does not exist.` });
    if (room.members.length === 0)
      return socket.emit("room_check_result", { ok: false, reason: `Room "${roomId}" has no active host.` });
    if (room.members.length >= room.maxMembers)
      return socket.emit("room_check_result", { ok: false, reason: `Room is full (${room.members.length}/${room.maxMembers}).` });

    socket.emit("room_check_result", {
      ok: true, roomId, type: room.type,
      maxMembers: room.maxMembers,
      currentMembers: room.members.length,
      hostName: room.hostName,
    });
  });

  // ══════════════════════════════════════════════════════════
  //  REQUEST JOIN
  // ══════════════════════════════════════════════════════════
  socket.on("request_join", async ({ roomId }) => {
    roomId = sanitizeRoom(roomId);
    const username = authUser.username;
    const room = SocketStore.getRoom(roomId);

    if (!room) return socket.emit("join_error", "Room not found.");
    if (room.members.length >= room.maxMembers) return socket.emit("join_error", "Room is now full.");
    if (SocketStore.isNameTaken(roomId, username)) return socket.emit("name_taken");
    if (SocketStore.getPendingCount(roomId) >= MAX_PENDING_PER_ROOM)
      return socket.emit("join_error", "Request queue is full. Try again shortly.");

    const reqId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    SocketStore.addPendingRequest(roomId, { reqId, socketId: socket.id, name: username });
    socket.data.pendingRoomId = roomId;

    await audit("JOIN_REQUEST", roomId, `from=${username}`, username);

    socket.emit("request_pending", { roomId, hostName: room.hostName });

    const hostSocket = io.sockets.sockets.get(room.hostId);
    if (hostSocket) {
      hostSocket.emit("join_request", { reqId, username, socketId: socket.id });
    } else {
      SocketStore.removePendingRequest(roomId, reqId);
      socket.emit("join_error", "Host is no longer connected.");
    }
  });

  // ══════════════════════════════════════════════════════════
  //  CANCEL REQUEST
  // ══════════════════════════════════════════════════════════
  socket.on("cancel_request", async ({ roomId }) => {
    roomId = sanitizeRoom(roomId);
    const room = SocketStore.getRoom(roomId);
    if (!room) return;

    const req = room.pendingRequests.find(r => r.socketId === socket.id);
    if (!req) return;

    SocketStore.removePendingRequest(roomId, req.reqId);
    await audit("REQUEST_CANCELLED", roomId, `by=${authUser.username}`, authUser.username);

    const hostSocket = io.sockets.sockets.get(room.hostId);
    if (hostSocket) hostSocket.emit("request_cancelled", { socketId: socket.id, username: authUser.username });
  });

  // ══════════════════════════════════════════════════════════
  //  APPROVE REQUEST
  // ══════════════════════════════════════════════════════════
  socket.on("approve_request", async ({ reqId }) => {
    const roomId = socket.data.roomId;
    const room = SocketStore.getRoom(roomId);
    if (!room || room.hostId !== socket.id) return;

    const req = SocketStore.removePendingRequest(roomId, reqId);
    if (!req) return;

    if (SocketStore.isNameTaken(roomId, req.name)) {
      const joiner = io.sockets.sockets.get(req.socketId);
      if (joiner) joiner.emit("join_error", "Your username is now taken. Please rejoin with a different name.");
      return;
    }

    const joiner = io.sockets.sockets.get(req.socketId);
    if (!joiner) return;

    _joinRoom(joiner, roomId, req.name);
    await audit("APPROVED", roomId, `user=${req.name}`, authUser.username);

    // Update MongoDB member count
    await Room.updateOne({ roomId }, { memberCount: SocketStore.getMemberCount(roomId), lastActivity: new Date() });
    await Session.create({ username: req.name, roomId, socketId: joiner.id });

    joiner.emit("request_approved", {
      roomId, type: room.type, maxMembers: room.maxMembers,
      currentMembers: SocketStore.getMemberCount(roomId),
      memberNames: SocketStore.getMemberNames(roomId),
    });

    // Send existing public keys to new joiner
    for (const [sid, { key, name: kn }] of SocketStore.getPublicKeys(roomId)) {
      if (sid !== joiner.id) joiner.emit("peer_key", { key, username: kn });
    }

    joiner.to(roomId).emit("peer_joined", {
      username: req.name,
      currentMembers: SocketStore.getMemberCount(roomId),
      maxMembers: room.maxMembers,
    });

    if (SocketStore.getMemberCount(roomId) >= room.maxMembers) {
      io.to(roomId).emit("room_full", { memberNames: SocketStore.getMemberNames(roomId) });
    }
  });

  // ══════════════════════════════════════════════════════════
  //  REJECT REQUEST
  // ══════════════════════════════════════════════════════════
  socket.on("reject_request", async ({ reqId }) => {
    const roomId = socket.data.roomId;
    const room = SocketStore.getRoom(roomId);
    if (!room || room.hostId !== socket.id) return;

    const req = SocketStore.removePendingRequest(roomId, reqId);
    if (!req) return;

    await audit("REJECTED", roomId, `user=${req.name}`, authUser.username);

    const joiner = io.sockets.sockets.get(req.socketId);
    if (joiner) joiner.emit("request_rejected", {
      roomId, hostName: room.hostName,
      reason: `Host rejected your request to join "${roomId}".`,
    });
  });

  // ══════════════════════════════════════════════════════════
  //  PUBLIC KEY (DH exchange)
  // ══════════════════════════════════════════════════════════
  socket.on("public_key", (key) => {
    const roomId = socket.data.roomId;
    if (!roomId) return;
    if (typeof key !== "string" || key.length > 4096) return;

    SocketStore.storePublicKey(roomId, socket.id, key, authUser.username);
    socket.to(roomId).emit("peer_key", { key, username: authUser.username });
  });

  // ══════════════════════════════════════════════════════════
  //  MESSAGE RELAY (server never reads content)
  // ══════════════════════════════════════════════════════════
  socket.on("message", async (data) => {
    const roomId = socket.data.roomId;
    if (!roomId) return;
    if (!data?.iv || !data?.data || !Array.isArray(data.iv) || !Array.isArray(data.data)) return;

    socket.to(roomId).emit("message", { iv: data.iv, data: data.data, senderName: authUser.username });

    // Only increment counter — never store content
    await Room.updateOne({ roomId }, { $inc: { messageCount: 1 }, lastActivity: new Date() });
  });

  // ══════════════════════════════════════════════════════════
  //  TYPING INDICATOR
  // ══════════════════════════════════════════════════════════
  socket.on("typing", ({ roomId }) => {
    roomId = sanitizeRoom(roomId);
    if (socket.data.roomId !== roomId) return;
    socket.to(roomId).emit("typing", { username: authUser.username });
  });

  // ══════════════════════════════════════════════════════════
  //  DISCONNECT
  // ══════════════════════════════════════════════════════════
  socket.on("disconnect", async () => {
    await clearSocketRateLimit(socket.id);
    const roomId = socket.data.roomId;
    const room = SocketStore.getRoom(roomId);

    if (roomId && room) {
      SocketStore.removeMember(roomId, socket.id);
      socket.to(roomId).emit("peer_left", { username: authUser.username });

      await Session.updateOne(
        { username: authUser.username, roomId, leftAt: null },
        { leftAt: new Date() }
      );

      const memberCount = SocketStore.getMemberCount(roomId);
      await Room.updateOne({ roomId }, { memberCount, lastActivity: new Date() });

      if (room.hostId === socket.id && memberCount > 0) {
        const result = SocketStore.transferHost(roomId);
        if (result) {
          io.to(roomId).emit("host_changed", { newHost: result.newHost.name });
          result.oldPending.forEach(req => {
            const s = io.sockets.sockets.get(req.socketId);
            if (s) s.emit("request_rejected", { roomId, reason: "Host disconnected. Please send a new request." });
          });
          await audit("HOST_TRANSFERRED", roomId, `→${result.newHost.name}`, authUser.username);
        }
      } else if (memberCount === 0) {
        await Room.updateOne({ roomId }, { status: "closed", closedAt: new Date() });
        await audit("ROOM_CLOSED", roomId, "all members left");
      }
    }

    // Clean up pending requests from this socket in all rooms
    const affected = SocketStore.removePendingBySocket(socket.id);
    for (const { roomId: rId, req } of affected) {
      const hostSocket = io.sockets.sockets.get(SocketStore.getHostId(rId));
      if (hostSocket) hostSocket.emit("request_cancelled", { socketId: socket.id, username: req.name });
    }

    await audit("DISCONNECT", roomId || null, `user=${authUser.username}`);
  });

  // ── Internal helper ────────────────────────────────────────
  function _joinRoom(sock, rId, uname) {
    sock.join(rId);
    sock.data.roomId = rId;
    SocketStore.addMember(rId, sock.id, uname);
  }
}
