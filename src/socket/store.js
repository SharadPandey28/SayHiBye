// ─────────────────────────────────────────────────────────────
//  SOCKET STORE  — in-memory live state for active rooms
//
//  This holds data that is only meaningful while the server
//  is running: pending requests, public keys, member socket IDs.
//
//  Durable data (room metadata, audit logs) goes to MongoDB.
//  This store is wiped on server restart — that is intentional.
// ─────────────────────────────────────────────────────────────

const store = new Map();

export const SocketStore = {
  // ── Room lifecycle ─────────────────────────────────────────
  createRoom(roomId, { hostId, hostName, maxMembers, type }) {
    store.set(roomId, {
      roomId, hostId, hostName,
      maxMembers, type,
      members: [],           // [{ id: socketId, name: username }]
      pendingRequests: [],   // [{ reqId, socketId, name }]
      publicKeys: {},        // socketId → { key, name }
    });
  },

  getRoom(roomId) { return store.get(roomId) || null; },

  deleteRoom(roomId) { store.delete(roomId); },

  // ── Members ────────────────────────────────────────────────
  addMember(roomId, socketId, username) {
    const room = store.get(roomId);
    if (!room) return;
    if (!room.members.find(m => m.id === socketId)) {
      room.members.push({ id: socketId, name: username });
    }
  },

  removeMember(roomId, socketId) {
    const room = store.get(roomId);
    if (!room) return;
    room.members = room.members.filter(m => m.id !== socketId);
    delete room.publicKeys[socketId];
  },

  getMemberNames(roomId) {
    return (store.get(roomId)?.members || []).map(m => m.name);
  },

  getMemberCount(roomId) {
    return store.get(roomId)?.members.length || 0;
  },

  isNameTaken(roomId, username) {
    const room = store.get(roomId);
    if (!room) return false;
    return room.members.some(m => m.name.toLowerCase() === username.toLowerCase());
  },

  // ── Public keys ────────────────────────────────────────────
  storePublicKey(roomId, socketId, key, username) {
    const room = store.get(roomId);
    if (!room) return;
    room.publicKeys[socketId] = { key, name: username };
  },

  getPublicKeys(roomId) {
    return Object.entries(store.get(roomId)?.publicKeys || {});
  },

  // ── Pending requests ───────────────────────────────────────
  addPendingRequest(roomId, req) {
    store.get(roomId)?.pendingRequests.push(req);
  },

  removePendingRequest(roomId, reqId) {
    const room = store.get(roomId);
    if (!room) return null;
    const req = room.pendingRequests.find(r => r.reqId === reqId);
    room.pendingRequests = room.pendingRequests.filter(r => r.reqId !== reqId);
    return req || null;
  },

  getPendingRequest(roomId, reqId) {
    return store.get(roomId)?.pendingRequests.find(r => r.reqId === reqId) || null;
  },

  removePendingBySocket(socketId) {
    // Remove pending request from any room when requester disconnects
    // Returns array of { roomId, req } for notifying hosts
    const affected = [];
    for (const [roomId, room] of store) {
      const req = room.pendingRequests.find(r => r.socketId === socketId);
      if (req) {
        room.pendingRequests = room.pendingRequests.filter(r => r.socketId !== socketId);
        affected.push({ roomId, req });
      }
    }
    return affected;
  },

  getPendingCount(roomId) {
    return store.get(roomId)?.pendingRequests.length || 0;
  },

  // ── Host management ────────────────────────────────────────
  transferHost(roomId) {
    const room = store.get(roomId);
    if (!room || room.members.length === 0) return null;
    const newHost = room.members[0];
    room.hostId = newHost.id;
    room.hostName = newHost.name;
    // Clear pending requests — new host will receive fresh requests
    const oldPending = [...room.pendingRequests];
    room.pendingRequests = [];
    return { newHost, oldPending };
  },

  // ── Helpers ────────────────────────────────────────────────
  getHostId(roomId) { return store.get(roomId)?.hostId || null; },

  getAllRooms() { return [...store.values()]; },

  roomCount() { return store.size; },
};
