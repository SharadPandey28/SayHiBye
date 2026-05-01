import { Router } from "express";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import { User } from "../db/mongo.js";
import { signToken, verifyToken } from "../middleware/auth.js";

const router = Router();

// ── Validation rules ──────────────────────────────────────────
const nameRules = body("username")
  .trim()
  .isLength({ min: 1, max: 20 })
  .matches(/^[a-zA-Z0-9\-_]+$/)
  .withMessage("Username: 1-20 chars, letters/numbers/hyphens only");

const passRules = body("password")
  .isLength({ min: 6, max: 100 })
  .withMessage("Password must be 6-100 characters");

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
}

// ── POST /api/auth/register ───────────────────────────────────
router.post("/register", [nameRules, passRules, validate], async (req, res) => {
  try {
    const { username, password } = req.body;

    const exists = await User.findOne({ username: new RegExp(`^${username}$`, "i") });
    if (exists) return res.status(409).json({ error: "Username already taken" });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ username, passwordHash });

    const token = signToken({ userId: user._id.toString(), username: user.username, role: user.role });
    res.status(201).json({ token, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// ── POST /api/auth/login ──────────────────────────────────────
router.post("/login", [nameRules, passRules, validate], async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username: new RegExp(`^${username}$`, "i") });
    if (!user) return res.status(401).json({ error: "Invalid username or password" });

    if (user.isBlocked) return res.status(403).json({ error: "Account suspended" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Invalid username or password" });

    await User.updateOne({ _id: user._id }, { lastSeen: new Date() });

    const token = signToken({ userId: user._id.toString(), username: user.username, role: user.role });
    res.json({ token, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────
router.get("/me", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.userId).select("-passwordHash");
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ username: user.username, role: user.role, createdAt: user.createdAt });
});

export default router;
