const express = require("express");
const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

app.use(express.static("public"));

// ─── Config ────────────────────────────────────────────────────────────────
const MAX_ROOMS = 100;
const MAX_PENDING_PER_ROOM = 10;
const ROOM_TTL_MS = 60 * 60 * 1000;       // 1 h idle (empty room) → recyclable
const ROOM_MAX_AGE_MS = 6 * 60 * 60 * 1000;  // fix #13: 6 h absolute max lifetime
const RATE_LIMIT_WINDOW = 1000;                  // 1 second
const RATE_LIMIT_MAX = 15;                    // max events / second / socket
const CLEANUP_INTERVAL = 10 * 60 * 1000;        // cleanup every 10 min
const MAX_MSG_IV_LEN = 32;                    // fix #14: IV array max elements
const MAX_MSG_DATA_LEN = 8192;                  // fix #14: data array max elements

// fix #7: admin token — set ADMIN_TOKEN env var in production
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "change-me-in-production";

// ─── Stores ────────────────────────────────────────────────────────────────
const rooms = {};
const eventLog = [];
let totalConnections = 0, activeSessions = 0;
const rateLimitMap = new Map(); // socketId → { count, resetAt }

// ─── Logging ───────────────────────────────────────────────────────────────
function log(event, roomId, detail = "") {
  const entry = { time: new Date().toISOString(), event, roomId: roomId || "global", detail };
  eventLog.unshift(entry);
  if (eventLog.length > 300) eventLog.pop();
  console.log(`[${entry.time}] [${event}] ${roomId || "global"} — ${detail}`);
}

// ─── Rate Limiter ──────────────────────────────────────────────────────────
function checkRateLimit(socketId) {
  const now = Date.now();
  let state = rateLimitMap.get(socketId);
  if (!state || now > state.resetAt) {
    state = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
    rateLimitMap.set(socketId, state);
  }
  state.count++;
  return state.count <= RATE_LIMIT_MAX;
}

// ─── Memory Cleanup ────────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  Object.keys(rooms).forEach(id => {
    const room = rooms[id];
    const idle = now - new Date(room.lastActivity).getTime();
    const age = now - new Date(room.startTime).getTime();
    // fix #13: clean empty+idle rooms OR rooms older than absolute max
    if ((room.members.length === 0 && idle > ROOM_TTL_MS) || age > ROOM_MAX_AGE_MS) {
      delete rooms[id];
      cleaned++;
    }
  });
  if (cleaned > 0) log("CLEANUP", null, `removed ${cleaned} rooms`);
}, CLEANUP_INTERVAL);

// ─── Admin API — fix #7: token auth ────────────────────────────────────────
app.get("/admin/stats", (req, res) => {
  const token = req.headers["x-admin-token"] || req.query.token;
  if (token !== ADMIN_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  res.json({
    totalConnections, activeSessions,
    activeRooms: Object.values(rooms).filter(r => r.members.length > 0).length,
    totalRooms: Object.keys(rooms).length,
    rooms: Object.values(rooms).map(r => ({
      id: r.id, type: r.type, host: r.hostName,
      maxMembers: r.maxMembers, memberCount: r.members.length,
      members: r.members.map(m => m.name),
      pendingCount: r.pendingRequests.length,
      messageCount: r.messageCount,
      startTime: r.startTime, lastActivity: r.lastActivity,
    })),
    recentEvents: eventLog.slice(0, 50),
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), rooms: Object.keys(rooms).length, sessions: activeSessions });
});

// ─── Socket Logic ──────────────────────────────────────────────────────────
io.on("connection", (socket) => {
  totalConnections++;
  activeSessions++;
  log("CONNECT", null, `socket=${socket.id}`);

  // Middleware: rate limit all events
  socket.use((_, next) => {
    if (!checkRateLimit(socket.id)) {
      socket.emit("error_notice", "Rate limit exceeded. Slow down.");
      return;
    }
    next();
  });

  // ── CREATE ROOM ──────────────────────────────────────────────
  socket.on("create_room", ({ roomId, username, maxMembers, type }) => {
    roomId = sanitize(roomId, 24);
    username = sanitizeName(username);
    // fix #6: whitelist-validate room type
    const safeType = ["direct", "group"].includes(type) ? type : "group";

    if (!roomId || !username) return socket.emit("create_error", "Invalid room name or username.");
    if (Object.keys(rooms).length >= MAX_ROOMS)
      return socket.emit("create_error", "Server is at room capacity. Try again later.");

    const existing = rooms[roomId];
    if (existing && existing.members.length > 0)
      return socket.emit("create_error", `Room "${roomId}" is already active. Choose a different name.`);
    if (existing) log("ROOM_RECYCLED", roomId, `by=${username}`);

    rooms[roomId] = {
      id: roomId, type: safeType,
      maxMembers: Math.min(Math.max(parseInt(maxMembers) || 2, 2), 10),
      hostId: socket.id, hostName: username,
      members: [], pendingRequests: [], publicKeys: {},
      messageCount: 0,
      startTime: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
    };

    _addMember(socket, roomId, username);
    log("ROOM_CREATED", roomId, `host=${username} max=${maxMembers} type=${safeType}`);
    socket.emit("room_created", { roomId, maxMembers: rooms[roomId].maxMembers, type: safeType, isHost: true });
  });

  // ── CHECK ROOM ───────────────────────────────────────────────
  socket.on("check_room", ({ roomId }) => {
    roomId = sanitize(roomId, 24);
    const room = rooms[roomId];
    if (!room)
      return socket.emit("room_check_result", { ok: false, reason: `Room "${roomId}" does not exist.` });
    if (room.members.length === 0)
      return socket.emit("room_check_result", { ok: false, reason: `Room "${roomId}" has no active host.` });
    if (room.members.length >= room.maxMembers)
      return socket.emit("room_check_result", { ok: false, reason: `Room is full (${room.members.length}/${room.maxMembers}).` });
    socket.emit("room_check_result", {
      ok: true, roomId, type: room.type, maxMembers: room.maxMembers,
      currentMembers: room.members.length, hostName: room.hostName,
    });
  });

  // ── REQUEST JOIN ─────────────────────────────────────────────
  socket.on("request_join", ({ roomId, username }) => {
    roomId = sanitize(roomId, 24);
    username = sanitizeName(username);
    const room = rooms[roomId];

    if (!room) return socket.emit("join_error", "Room not found.");
    if (room.members.length >= room.maxMembers) return socket.emit("join_error", "Room is now full.");
    if (room.pendingRequests.find(r => r.socketId === socket.id)) return socket.emit("join_error", "Request already pending.");
    if (room.pendingRequests.length >= MAX_PENDING_PER_ROOM) return socket.emit("join_error", "Request queue is full. Try again shortly.");
    if (room.members.find(m => m.name.toLowerCase() === username.toLowerCase()))
      return socket.emit("name_taken");

    const reqId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    room.pendingRequests.push({ reqId, socketId: socket.id, name: username });
    socket.pendingRoomId = roomId;
    socket.pendingUsername = username;

    log("JOIN_REQUEST", roomId, `from=${username}`);
    socket.emit("request_pending", { roomId, hostName: room.hostName });

    const hostSocket = io.sockets.sockets.get(room.hostId);
    if (hostSocket) {
      hostSocket.emit("join_request", { reqId, username, socketId: socket.id });
    } else {
      room.pendingRequests = room.pendingRequests.filter(r => r.socketId !== socket.id);
      socket.emit("join_error", "Host is no longer connected.");
    }
  });

  // ── CANCEL REQUEST ───────────────────────────────────────────
  socket.on("cancel_request", ({ roomId }) => {
    roomId = sanitize(roomId, 24);
    const room = rooms[roomId];
    if (!room) return;
    const req = room.pendingRequests.find(r => r.socketId === socket.id);
    if (!req) return;
    room.pendingRequests = room.pendingRequests.filter(r => r.socketId !== socket.id);
    log("REQUEST_CANCELLED", roomId, `by=${req.name}`);
    const hostSocket = io.sockets.sockets.get(room.hostId);
    if (hostSocket) hostSocket.emit("request_cancelled", { socketId: socket.id, username: req.name });
  });

  // ── APPROVE ──────────────────────────────────────────────────
  socket.on("approve_request", ({ reqId }) => {
    const roomId = socket.roomId;
    const room = rooms[roomId];
    if (!room || room.hostId !== socket.id) return;

    const req = room.pendingRequests.find(r => r.reqId === reqId);
    if (!req) return;
    room.pendingRequests = room.pendingRequests.filter(r => r.reqId !== reqId);

    const joiner = io.sockets.sockets.get(req.socketId);
    if (!joiner) return;

    if (room.members.find(m => m.name.toLowerCase() === req.name.toLowerCase())) {
      joiner.emit("join_error", "Your username is now taken. Please rejoin with a different name.");
      return;
    }

    _addMember(joiner, roomId, req.name);
    log("APPROVED", roomId, `user=${req.name}`);

    joiner.emit("request_approved", {
      roomId, type: room.type, maxMembers: room.maxMembers,
      currentMembers: room.members.length, memberNames: room.members.map(m => m.name),
    });

    Object.entries(room.publicKeys).forEach(([sid, { key, name: kn }]) => {
      if (sid !== joiner.id) joiner.emit("peer_key", { key, username: kn });
    });
    joiner.to(roomId).emit("peer_joined", { username: req.name, currentMembers: room.members.length, maxMembers: room.maxMembers });

    if (room.members.length >= room.maxMembers)
      io.to(roomId).emit("room_full", { memberNames: room.members.map(m => m.name) });
  });

  // ── REJECT ───────────────────────────────────────────────────
  socket.on("reject_request", ({ reqId }) => {
    const roomId = socket.roomId;
    const room = rooms[roomId];
    if (!room || room.hostId !== socket.id) return;
    const req = room.pendingRequests.find(r => r.reqId === reqId);
    if (!req) return;
    room.pendingRequests = room.pendingRequests.filter(r => r.reqId !== reqId);
    log("REJECTED", roomId, `user=${req.name}`);
    const joiner = io.sockets.sockets.get(req.socketId);
    if (joiner) joiner.emit("request_rejected", { roomId, hostName: room.hostName, reason: `Host rejected your request to join "${roomId}".` });
  });

  // ── REJOIN (reconnect after network drop) ────────────────────
  socket.on("rejoin_room", ({ roomId, username }) => {
    roomId = sanitize(roomId, 24);
    username = sanitizeName(username);
    const room = rooms[roomId];
    if (!room) return socket.emit("join_error", "Room expired. Please create a new room.");

    const wasHere = room.members.find(m => m.name === username);
    if (!wasHere && room.members.length >= room.maxMembers)
      return socket.emit("join_error", "Room is full.");
    if (!wasHere)
      return socket.emit("join_error", "Session expired. Please request to join again.");

    _addMember(socket, roomId, username);
    log("REJOIN", roomId, `user=${username}`);
    socket.emit("request_approved", {
      roomId, type: room.type, maxMembers: room.maxMembers,
      currentMembers: room.members.length, memberNames: room.members.map(m => m.name),
    });
    Object.entries(room.publicKeys).forEach(([sid, { key, name: kn }]) => {
      if (sid !== socket.id) socket.emit("peer_key", { key, username: kn });
    });
    socket.to(roomId).emit("peer_joined", { username, currentMembers: room.members.length, maxMembers: room.maxMembers });
  });

  // ── DH KEY ───────────────────────────────────────────────────
  socket.on("public_key", (key) => {
    const roomId = socket.roomId;
    const room = rooms[roomId];
    if (!roomId || !room) return;
    if (typeof key !== "string" || key.length > 4096) return;
    room.publicKeys[socket.id] = { key, name: socket.username };
    log("KEY_EXCHANGE", roomId, `user=${socket.username}`);
    socket.to(roomId).emit("peer_key", { key, username: socket.username });
  });

  // ── MESSAGE RELAY (1-on-1) ───────────────────────────────────
  socket.on("message", (data) => {
    const roomId = socket.roomId;
    const room = rooms[roomId];
    if (!roomId || !room) return;
    // fix #14: validate structure + size
    if (!data?.iv || !data?.data || !Array.isArray(data.iv) || !Array.isArray(data.data)) return;
    if (data.iv.length > MAX_MSG_IV_LEN || data.data.length > MAX_MSG_DATA_LEN) return;
    room.messageCount++;
    room.lastActivity = new Date().toISOString();
    log("MSG_RELAYED", roomId, `from=${socket.username}`);
    socket.to(roomId).emit("message", { iv: data.iv, data: data.data, senderName: socket.username });
  });

  // ── GROUP MESSAGE RELAY — fix #1: per-peer encrypted payloads ─
  socket.on("group_message", (payloads) => {
    const roomId = socket.roomId;
    const room = rooms[roomId];
    if (!roomId || !room) return;
    if (typeof payloads !== "object" || Array.isArray(payloads)) return;

    room.messageCount++;
    room.lastActivity = new Date().toISOString();
    log("GROUP_MSG", roomId, `from=${socket.username} peers=${Object.keys(payloads).length}`);

    // Send each member only their own ciphertext
    room.members.forEach(member => {
      if (member.id === socket.id) return;
      const payload = payloads[member.name];
      if (!payload?.iv || !payload?.data) return;
      if (!Array.isArray(payload.iv) || !Array.isArray(payload.data)) return;
      // fix #14: size check on group payloads too
      if (payload.iv.length > MAX_MSG_IV_LEN || payload.data.length > MAX_MSG_DATA_LEN) return;
      const memberSocket = io.sockets.sockets.get(member.id);
      if (memberSocket) {
        memberSocket.emit("message", { iv: payload.iv, data: payload.data, senderName: socket.username });
      }
    });
  });

  // ── TYPING INDICATOR ─────────────────────────────────────────
  socket.on("typing", ({ roomId }) => {
    roomId = sanitize(roomId, 24);
    if (socket.roomId !== roomId) return;
    socket.to(roomId).emit("typing", { username: socket.username });
  });

  // ── LEAVE ROOM (voluntary) ───────────────────────────────────
  socket.on("leave_room", () => {
    // fix #5: use server-authoritative socket.roomId, not client payload
    const rid = socket.roomId;
    const room = rooms[rid];
    if (!rid || !room) return;
    const member = room.members.find(m => m.id === socket.id);
    if (!member) return;

    socket.leaving = true; // fix #2: prevent duplicate processing in disconnect
    room.members = room.members.filter(m => m.id !== socket.id);
    delete room.publicKeys[socket.id];
    socket.leave(rid);
    log("LEFT", rid, `user=${member.name} remaining=${room.members.length}`);
    // fix #3: include currentMembers so clients can update their counter
    socket.to(rid).emit("peer_left", { username: member.name, currentMembers: room.members.length });

    // Host transfer
    if (room.hostId === socket.id && room.members.length > 0) {
      const newHost = room.members[0];
      room.hostId = newHost.id;
      room.hostName = newHost.name;
      log("HOST_TRANSFERRED", rid, `→${newHost.name}`);
      io.to(rid).emit("host_changed", { newHost: newHost.name });
      room.pendingRequests.forEach(req => {
        const s = io.sockets.sockets.get(req.socketId);
        if (s) s.emit("request_rejected", { roomId: rid, reason: "Host left. Please send a new request." });
      });
      room.pendingRequests = [];
    }

    socket.roomId = null;
    socket.username = null;
  });

  // ── DISCONNECT ───────────────────────────────────────────────
  socket.on("disconnect", () => {
    activeSessions--;
    rateLimitMap.delete(socket.id);
    const roomId = socket.roomId;
    const room = rooms[roomId];

    // fix #2: skip if already handled by leave_room
    if (!socket.leaving && roomId && room) {
      room.members = room.members.filter(m => m.id !== socket.id);
      delete room.publicKeys[socket.id];
      // fix #3: include currentMembers
      socket.to(roomId).emit("peer_left", { username: socket.username, currentMembers: room.members.length });
      log("DISCONNECT", roomId, `user=${socket.username}`);

      if (room.hostId === socket.id && room.members.length > 0) {
        const newHost = room.members[0];
        room.hostId = newHost.id;
        room.hostName = newHost.name;
        log("HOST_TRANSFERRED", roomId, `→${newHost.name}`);
        io.to(roomId).emit("host_changed", { newHost: newHost.name });
        room.pendingRequests.forEach(req => {
          const s = io.sockets.sockets.get(req.socketId);
          if (s) s.emit("request_rejected", { roomId, reason: "Host disconnected. Please send a new request." });
        });
        room.pendingRequests = [];
      }
    } else if (!socket.leaving) {
      log("DISCONNECT", null, `socket=${socket.id}`);
    }

    // Clean up pending requests from this socket in any room
    Object.values(rooms).forEach(r => {
      const pending = r.pendingRequests.find(req => req.socketId === socket.id);
      if (pending) {
        r.pendingRequests = r.pendingRequests.filter(req => req.socketId !== socket.id);
        const hostSock = io.sockets.sockets.get(r.hostId);
        if (hostSock) hostSock.emit("request_cancelled", { socketId: socket.id, username: pending.name });
      }
    });
  });

  // ── Helpers ──────────────────────────────────────────────────
  function _addMember(sock, rId, uname) {
    sock.join(rId);
    sock.roomId = rId;
    sock.username = uname;
    const room = rooms[rId];
    if (!room.members.find(m => m.id === sock.id))
      room.members.push({ id: sock.id, name: uname });
    // fix #13: update lastActivity on every join, not just messages
    room.lastActivity = new Date().toISOString();
  }
});

// ── Input sanitization ─────────────────────────────────────
function sanitize(s, max = 100) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9\-_]/g, "").slice(0, max);
}
function sanitizeName(s) {
  return String(s || "").replace(/[^a-zA-Z0-9\-_]/g, "").slice(0, 20);
}

http.listen(3001, () => {
  console.log("🔐 SayHiBye  → http://localhost:3001");
  console.log("📊 Admin Dashboard → http://localhost:3001/admin.html");
  console.log("💚 Health Check    → http://localhost:3001/health");
  if (ADMIN_TOKEN === "change-me-in-production")
    console.warn("⚠️  ADMIN_TOKEN not set. Set ADMIN_TOKEN env var in production.");
});