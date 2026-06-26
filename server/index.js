const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const { execFile } = require("child_process");

const PORT = Number(process.env.PORT) || 3001;

// ─────────────────────────────────────────────────────────────
// ENV CHECK
// ─────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ENCRYPTION_KEY_HEX = process.env.ENCRYPTION_KEY;

if (!JWT_SECRET || !JWT_REFRESH_SECRET) {
  console.error("JWT secrets missing");
  process.exit(1);
}

if (
  !ENCRYPTION_KEY_HEX ||
  ENCRYPTION_KEY_HEX.length !== 64 ||
  !/^[0-9a-fA-F]+$/.test(ENCRYPTION_KEY_HEX)
) {
  console.error("ENCRYPTION_KEY must be 64 hex chars");
  process.exit(1);
}

const ENCRYPTION_KEY = Buffer.from(ENCRYPTION_KEY_HEX, "hex");
const ALGORITHM = "aes-256-gcm";

// ─────────────────────────────────────────────────────────────
// ENCRYPT / DECRYPT
// ─────────────────────────────────────────────────────────────
function encrypt(text) {
  if (!text) return text;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(String(text), "utf8"),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString("hex");
}

function decrypt(hex) {
  if (!hex) return hex;

  try {
    const buf = Buffer.from(hex, "hex");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const data = buf.subarray(28);

    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);

    return decipher.update(data, null, "utf8") + decipher.final("utf8");
  } catch {
    return hex;
  }
}

function decryptMessage(msg) {
  if (!msg) return msg;
  return { ...msg, content: decrypt(msg.content) };
}

// ─────────────────────────────────────────────────────────────
// APP INIT
// ─────────────────────────────────────────────────────────────
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";

const app = express();
app.set("trust proxy", 1);

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CLIENT_ORIGIN, methods: ["GET", "POST", "DELETE"] },
});

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(compression());
app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(express.json({ limit: "1mb" }));

// ─────────────────────────────────────────────────────────────
// RATE LIMIT
// ─────────────────────────────────────────────────────────────
app.use(
  "/api/auth",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
  })
);

app.use(
  "/api",
  rateLimit({
    windowMs: 60 * 1000,
    max: 600,
  })
);

// ─────────────────────────────────────────────────────────────
// FILE STORAGE
// ─────────────────────────────────────────────────────────────
const UPLOADS_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Отдаём файлы из uploads с правильным Content-Type
// express.static для .mp4 ставит video/mp4 — Safari не грузит метаданные аудио
app.get("/uploads/:filename", (req, res) => {
  const filename = path.basename(req.params.filename); // защита от path traversal
  const filePath = path.join(UPLOADS_DIR, filename);
  const ext = path.extname(filename).toLowerCase();

  const audioExts = { ".mp4": "audio/mp4", ".m4a": "audio/mp4", ".aac": "audio/aac", ".ogg": "audio/ogg", ".webm": "audio/webm" };
  const imageExts = { ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp" };

  const contentType = audioExts[ext] || imageExts[ext] || "application/octet-stream";
  res.setHeader("Content-Type", contentType);
  res.sendFile(filePath, { root: "/" }, (err) => {
    if (err && !res.headersSent) res.status(404).json({ error: "File not found" });
  });
});

// safe delete helper
function safeUnlink(file) {
  try {
    fs.unlinkSync(path.join(UPLOADS_DIR, file));
  } catch {}
}

// ─────────────────────────────────────────────────────────────
// MULTER
// ─────────────────────────────────────────────────────────────
const imageUpload = multer({
  storage: multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, UPLOADS_DIR),
    filename: (_r, file, cb) => {
      const ext = path.extname(file.originalname || "") || ".jpg";
      cb(null, Date.now() + "-" + Math.random().toString(36) + ext);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

const audioUpload = multer({
  storage: multer.diskStorage({
    destination: (_r, _f, cb) => cb(null, UPLOADS_DIR),
    filename: (_r, file, cb) => {
      const ext = path.extname(file.originalname || "") || ".webm";
      cb(null, Date.now() + "-" + Math.random().toString(36) + ext);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
});

// ─────────────────────────────────────────────────────────────
// DATABASE
// ─────────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, "data", "messenger.db");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

// sync wrappers (ВАЖНО: better-sqlite3 sync only)
const run = (sql, params = []) => db.prepare(sql).run(...params);
const get = (sql, params = []) => db.prepare(sql).get(...params);
const all = (sql, params = []) => db.prepare(sql).all(...params);

// FIXED PRAGMA SAFE
function tableInfo(table) {
  return db.prepare(`PRAGMA table_info(${table})`).all();
}

function ensureColumnExists(table, column, def) {
  const cols = tableInfo(table);
  if (!cols.find((c) => c.name === column)) {
    db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${def}`).run();
  }
}

// ─────────────────────────────────────────────────────────────
// ONLINE USERS
// ─────────────────────────────────────────────────────────────
const onlineUsers = new Map();

// ─────────────────────────────────────────────────────────────
// AUTH HELPERS
// ─────────────────────────────────────────────────────────────
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, login: user.login },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  const token = header.replace("Bearer ", "");

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ─────────────────────────────────────────────────────────────
// DB INIT
// ─────────────────────────────────────────────────────────────
function initDb() {
  run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    last_seen TEXT
  )`);

  run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  run(`CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_user_id, to_user_id)
  )`);

  run(`CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user1_id, user2_id)
  )`);

  run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    is_direct INTEGER DEFAULT 1
  )`);

  run(`CREATE TABLE IF NOT EXISTS chat_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_read_message_id INTEGER,
    UNIQUE(chat_id, user_id)
  )`);

  run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    deleted_for_everyone INTEGER DEFAULT 0
  )`);

  ensureColumnExists("messages", "message_type", "TEXT DEFAULT 'text'");
  ensureColumnExists("messages", "image_path", "TEXT");
  ensureColumnExists("messages", "audio_path", "TEXT");

  run(`CREATE TABLE IF NOT EXISTS message_deletions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(message_id, user_id)
  )`);
}

//////////////////////////////
// JWT TOKENS
//////////////////////////////
function generateRefreshToken(userId) {
  const token = jwt.sign({ id: userId }, JWT_REFRESH_SECRET, {
    expiresIn: "30d",
  });

  const hash = bcrypt.hashSync(token, 8);
  const expires = new Date(Date.now() + 30 * 86400000).toISOString();

  run(
    "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
    [userId, hash, expires]
  );

  return token;
}

//////////////////////////////
// AUTH ROUTES
//////////////////////////////

app.post("/api/auth/register", async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || login.length < 3)
      return res.status(400).json({ error: "Invalid login" });

    if (!password || password.length < 6)
      return res.status(400).json({ error: "Invalid password" });

    const hash = await bcrypt.hash(password, 12);

    const result = run(
      "INSERT INTO users (login, password_hash) VALUES (?, ?)",
      [login, hash]
    );

    const user = { id: result.lastInsertRowid, login };

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user.id);

    res.json({ accessToken, refreshToken, user });
  } catch (e) {
    if (String(e).includes("UNIQUE")) {
      return res.status(400).json({ error: "Login exists" });
    }
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { login, password } = req.body;

    const user = get("SELECT * FROM users WHERE login = ?", [login]);

    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user.id);

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, login: user.login },
    });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(400).json({ error: "No refresh token" });

  try {
    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const rows = all(
      "SELECT * FROM refresh_tokens WHERE user_id = ?",
      [payload.id]
    );

    let valid = null;

    for (const r of rows) {
      if (bcrypt.compareSync(refreshToken, r.token_hash)) {
        valid = r;
        break;
      }
    }

    if (!valid)
      return res.status(401).json({ error: "Invalid refresh token" });

    run("DELETE FROM refresh_tokens WHERE id = ?", [valid.id]);

    const user = get("SELECT id, login FROM users WHERE id = ?", [
      payload.id,
    ]);

    const newAccess = generateAccessToken(user);
    const newRefresh = generateRefreshToken(user.id);

    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    const rows = all(
      "SELECT * FROM refresh_tokens WHERE user_id = ?",
      [req.user.id]
    );

    for (const r of rows) {
      if (bcrypt.compareSync(refreshToken, r.token_hash)) {
        run("DELETE FROM refresh_tokens WHERE id = ?", [r.id]);
        break;
      }
    }
  }

  res.json({ ok: true });
});

//////////////////////////////
// DELETE ACCOUNT
//////////////////////////////
app.delete("/api/auth/account", authMiddleware, (req, res) => {
  const userId = req.user.id;

  const deleteTx = db.transaction(() => {
    // Файлы (фото/голосовые), которые отправил пользователь — удаляем с диска
    const ownMessages = all(
      "SELECT image_path, audio_path FROM messages WHERE sender_id=?",
      [userId]
    );
    for (const m of ownMessages) {
      safeUnlink(m.image_path);
      safeUnlink(m.audio_path);
    }

    // Чаты, где пользователь участвует — понадобятся, чтобы оповестить собеседников
    const userChats = all(
      "SELECT chat_id FROM chat_participants WHERE user_id=?",
      [userId]
    );

    // Сообщения этого пользователя стираем целиком (аккаунта больше не будет)
    run("DELETE FROM messages WHERE sender_id=?", [userId]);

    // Отметки "удалено для меня", оставленные этим пользователем
    run("DELETE FROM message_deletions WHERE user_id=?", [userId]);

    // Участие в чатах
    run("DELETE FROM chat_participants WHERE user_id=?", [userId]);

    // Дружбы и заявки в друзья (в обе стороны)
    run(
      "DELETE FROM friendships WHERE user1_id=? OR user2_id=?",
      [userId, userId]
    );
    run(
      "DELETE FROM friend_requests WHERE from_user_id=? OR to_user_id=?",
      [userId, userId]
    );

    // Refresh-токены
    run("DELETE FROM refresh_tokens WHERE user_id=?", [userId]);

    // Сам пользователь
    run("DELETE FROM users WHERE id=?", [userId]);

    return userChats;
  });

  let userChats;
  try {
    userChats = deleteTx();
  } catch (e) {
    console.error("Account deletion failed:", e);
    return res.status(500).json({ error: "Не удалось удалить аккаунт" });
  }

  // Оповещаем собеседников и отключаем все сокеты удалённого пользователя
  for (const c of userChats) {
    io.to(`chat:${c.chat_id}`).emit("chat:deleted", { chatId: c.chat_id, userId });
  }

  const sockets = onlineUsers.get(userId);
  if (sockets) {
    for (const socketId of sockets) {
      const s = io.sockets.sockets.get(socketId);
      if (s) s.disconnect(true);
    }
    onlineUsers.delete(userId);
  }

  io.emit("presence:update", { userId, online: false });

  res.json({ ok: true });
});

//////////////////////////////
// FRIEND SYSTEM
//////////////////////////////

app.get("/api/friends/search", authMiddleware, (req, res) => {
  const { login } = req.query;

  if (!login) return res.json({ user: null });

  const user = get("SELECT id, login FROM users WHERE login = ?", [login]);

  if (!user || user.id === req.user.id)
    return res.json({ user: null });

  const friendship = get(
    `SELECT * FROM friendships 
     WHERE (user1_id = ? AND user2_id = ?) 
        OR (user1_id = ? AND user2_id = ?)`,
    [req.user.id, user.id, user.id, req.user.id]
  );

  if (friendship)
    return res.json({ user, relationship: "friend" });

  const reqRow = get(
    `SELECT * FROM friend_requests
     WHERE status='pending'
     AND ((from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?))`,
    [req.user.id, user.id, user.id, req.user.id]
  );

  if (reqRow) {
    return res.json({
      user,
      relationship:
        reqRow.from_user_id === req.user.id
          ? "outgoing_pending"
          : "incoming_pending",
    });
  }

  res.json({ user, relationship: "none" });
});

app.post("/api/friends/request/:id", authMiddleware, (req, res) => {
  const target = Number(req.params.id);

  if (!target || target === req.user.id)
    return res.status(400).json({ error: "Invalid" });

  run(
    "INSERT OR IGNORE INTO friend_requests (from_user_id,to_user_id) VALUES (?,?)",
    [req.user.id, target]
  );

  // Оповещаем получателя в реальном времени
  const request = get(
    "SELECT fr.id, fr.from_user_id, u.login as from_login FROM friend_requests fr JOIN users u ON u.id = fr.from_user_id WHERE fr.from_user_id = ? AND fr.to_user_id = ?",
    [req.user.id, target]
  );
  io.to(`user:${target}`).emit("friend:request", request);

  res.json({ ok: true });
});


// ─── Список входящих заявок ─────────────────────────────────
app.get("/api/friends/requests", authMiddleware, (req, res) => {
  const rows = all(
    `SELECT fr.id, fr.from_user_id, u.login as from_login
     FROM friend_requests fr
     JOIN users u ON u.id = fr.from_user_id
     WHERE fr.to_user_id = ? AND fr.status = 'pending'
     ORDER BY fr.created_at DESC`,
    [req.user.id]
  );
  return res.json({ requests: rows });
});

// ─── Ответ на заявку (новый путь) ───────────────────────────
app.post("/api/friends/request/:id/respond", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const { action } = req.body;
  const fr = get("SELECT * FROM friend_requests WHERE id=? AND to_user_id=?", [id, req.user.id]);
  if (!fr) return res.status(404).json({ error: "Not found" });
  if (action === "accept") {
    const [a, b] = [fr.from_user_id, fr.to_user_id].sort((x, y) => x - y);
    run("INSERT OR IGNORE INTO friendships (user1_id,user2_id) VALUES (?,?)", [a, b]);
    const chat = db.prepare("INSERT INTO chats (is_direct) VALUES (1)").run();
    const chatId = chat.lastInsertRowid;
    run("INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)", [chatId, a]);
    run("INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)", [chatId, b]);
    run("UPDATE friend_requests SET status='accepted' WHERE id=?", [id]);

    const userA = get("SELECT id, login FROM users WHERE id=?", [a]);
    const userB = get("SELECT id, login FROM users WHERE id=?", [b]);

    // Добавляем сокеты обоих пользователей в комнату нового чата
    const roomA = io.sockets.adapter.rooms.get(`user:${a}`);
    const roomB = io.sockets.adapter.rooms.get(`user:${b}`);

    if (roomA) {
      for (const socketId of roomA) {
        const s = io.sockets.sockets.get(socketId);
        if (s) s.join(`chat:${chatId}`);
      }
    }

    if (roomB) {
      for (const socketId of roomB) {
        const s = io.sockets.sockets.get(socketId);
        if (s) s.join(`chat:${chatId}`);
      }
    }

    // Оповещаем обоих — у каждого появится новый чат
    io.to(`user:${a}`).emit("chat:new", {
      chatId,
      friend: { id: userB.id, login: userB.login, online: onlineUsers.has(userB.id) },
      lastMessage: null,
    });
    io.to(`user:${b}`).emit("chat:new", {
      chatId,
      friend: { id: userA.id, login: userA.login, online: onlineUsers.has(userA.id) },
      lastMessage: null,
    });
  } else {
    run("UPDATE friend_requests SET status='rejected' WHERE id=?", [id]);
  }
  res.json({ ok: true });
});

app.post("/api/friends/respond/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const { action } = req.body;

  const fr = get(
    "SELECT * FROM friend_requests WHERE id=? AND to_user_id=?",
    [id, req.user.id]
  );

  if (!fr) return res.status(404).json({ error: "Not found" });

  if (action === "accept") {
    const [a, b] = [fr.from_user_id, fr.to_user_id].sort((x, y) => x - y);

    run(
      "INSERT OR IGNORE INTO friendships (user1_id,user2_id) VALUES (?,?)",
      [a, b]
    );

    const chat = db.prepare(
      "INSERT INTO chats (is_direct) VALUES (1)"
    ).run();

    run(
      "INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)",
      [chat.lastInsertRowid, a]
    );

    run(
      "INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)",
      [chat.lastInsertRowid, b]
    );

    run("UPDATE friend_requests SET status='accepted' WHERE id=?", [id]);
  } else {
    run("UPDATE friend_requests SET status='rejected' WHERE id=?", [id]);
  }

  res.json({ ok: true });
});

app.get("/api/friends", authMiddleware, (req, res) => {
  const rows = all(
    `SELECT u.id,u.login
     FROM friendships f
     JOIN users u
     ON u.id = CASE WHEN f.user1_id=? THEN f.user2_id ELSE f.user1_id END
     WHERE f.user1_id=? OR f.user2_id=?`,
    [req.user.id, req.user.id, req.user.id]
  );

  res.json({
    friends: rows.map((u) => ({
      ...u,
      online: onlineUsers.has(u.id),
    })),
  });
});
//////////////////////////////
// CHAT HELPERS
//////////////////////////////
function getOrCreateDirectChat(a, b) {
  const sorted = [a, b].sort((x, y) => x - y);

  const existing = get(
    `SELECT c.id FROM chats c
     JOIN chat_participants p1 ON p1.chat_id=c.id AND p1.user_id=?
     JOIN chat_participants p2 ON p2.chat_id=c.id AND p2.user_id=?
     WHERE c.is_direct=1`,
    sorted
  );

  if (existing) return existing.id;

  const chat = db.prepare("INSERT INTO chats (is_direct) VALUES (1)").run();

  run(
    "INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)",
    [chat.lastInsertRowid, sorted[0]]
  );

  run(
    "INSERT INTO chat_participants (chat_id,user_id) VALUES (?,?)",
    [chat.lastInsertRowid, sorted[1]]
  );

  return chat.lastInsertRowid;
}

//////////////////////////////
// CHAT LIST
//////////////////////////////
app.get("/api/chats", authMiddleware, (req, res) => {
  const chats = all(
    `SELECT c.id as chat_id, u.id as friend_id, u.login as friend_login
     FROM chats c
     JOIN chat_participants me ON me.chat_id=c.id AND me.user_id=?
     JOIN chat_participants other ON other.chat_id=c.id AND other.user_id!=?
     JOIN users u ON u.id=other.user_id
     WHERE c.is_direct=1`,
    [req.user.id, req.user.id]
  );

  const result = chats.map((c) => {
    const last = get(
      `SELECT * FROM messages
       WHERE chat_id=?
       ORDER BY id DESC LIMIT 1`,
      [c.chat_id]
    );

    return {
      chatId: c.chat_id,
      friend: {
        id: c.friend_id,
        login: c.friend_login,
        online: onlineUsers.has(c.friend_id),
      },
      lastMessage: decryptMessage(last),
    };
  });

  res.json({ chats: result });
});

//////////////////////////////
// MESSAGES
//////////////////////////////
app.get("/api/chats/:id/messages", authMiddleware, (req, res) => {
  const chatId = Number(req.params.id);
  const limit = Math.min(Number(req.query.limit || 50), 100);
  const before = req.query.before ? Number(req.query.before) : null;

  const member = get(
    "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
    [chatId, req.user.id]
  );

  if (!member) return res.status(403).json({ error: "Forbidden" });

  const rows = before
    ? all(
        `SELECT m.* FROM messages m
         WHERE m.chat_id=? AND m.id<?
           AND NOT EXISTS (
             SELECT 1 FROM message_deletions d
             WHERE d.message_id = m.id AND d.user_id = ?
           )
         ORDER BY m.id DESC
         LIMIT ?`,
        [chatId, before, req.user.id, limit + 1]
      )
    : all(
        `SELECT m.* FROM messages m
         WHERE m.chat_id=?
           AND NOT EXISTS (
             SELECT 1 FROM message_deletions d
             WHERE d.message_id = m.id AND d.user_id = ?
           )
         ORDER BY m.id DESC
         LIMIT ?`,
        [chatId, req.user.id, limit + 1]
      );

  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  res.json({
    messages: page.reverse().map(decryptMessage),
    hasMore,
  });
});

//////////////////////////////
// IMAGE UPLOAD
//////////////////////////////
app.post(
  "/api/chats/:id/image",
  authMiddleware,
  imageUpload.single("image"),
  (req, res) => {
    const chatId = Number(req.params.id);

    const member = get(
      "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
      [chatId, req.user.id]
    );

    if (!member) return res.status(403).json({ error: "Forbidden" });
    if (!req.file) return res.status(400).json({ error: "No file" });

    const r = run(
      `INSERT INTO messages (chat_id,sender_id,content,message_type,image_path)
       VALUES (?,?,?,?,?)`,
      [
        chatId,
        req.user.id,
        encrypt(req.file.originalname || "image"),
        "image",
        req.file.filename,
      ]
    );

    const msg = get("SELECT * FROM messages WHERE id=?", [
      r.lastInsertRowid,
    ]);

    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(msg));

    res.json({ ok: true, message: decryptMessage(msg) });
  }
);

//////////////////////////////
// AUDIO UPLOAD
//////////////////////////////

// Конвертируем любой аудиоформат в mp4/aac через ffmpeg
// mp4/aac воспроизводится везде: Chrome, Firefox, Safari, iOS, Android
function convertToMp4(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    execFile("ffmpeg", [
      "-y",
      "-analyzeduration", "100M",  // больше времени на анализ потока (нужно для webm без duration)
      "-probesize", "100M",         // больше данных для определения формата
      "-i", inputPath,
      "-c:a", "aac",
      "-b:a", "64k",
      "-vn",
      "-movflags", "+faststart",    // duration в начале файла — сразу виден таймер
      outputPath
    ], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

app.post(
  "/api/chats/:id/voice",
  authMiddleware,
  audioUpload.single("audio"),
  async (req, res) => {
    const chatId = Number(req.params.id);

    const member = get(
      "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
      [chatId, req.user.id]
    );

    if (!member) return res.status(403).json({ error: "Forbidden" });
    if (!req.file) return res.status(400).json({ error: "No file" });

    const originalPath = req.file.path;
    const mp4Filename = req.file.filename.replace(/\.[^.]+$/, ".mp4");
    const mp4Path = path.join(UPLOADS_DIR, mp4Filename);

    let finalFilename = mp4Filename;

    try {
      await convertToMp4(originalPath, mp4Path);
      fs.unlink(originalPath, () => {}); // удаляем оригинал
    } catch (e) {
      console.error("ffmpeg conversion failed, using original:", e.message);
      finalFilename = req.file.filename; // фолбэк — оставляем как есть
    }

    const r = run(
      `INSERT INTO messages (chat_id,sender_id,content,message_type,audio_path)
       VALUES (?,?,?,?,?)`,
      [chatId, req.user.id, encrypt("voice"), "voice", finalFilename]
    );

    const msg = get("SELECT * FROM messages WHERE id=?", [r.lastInsertRowid]);

    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(msg));

    res.json({ ok: true, message: decryptMessage(msg) });
  }
);

//////////////////////////////
// DELETE MESSAGE
//////////////////////////////
app.delete("/api/messages/:id", authMiddleware, (req, res) => {
  const id = Number(req.params.id);
  const mode = req.query.mode;

  const msg = get("SELECT * FROM messages WHERE id=?", [id]);
  if (!msg) return res.status(404).json({ error: "Not found" });

  const member = get(
    "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
    [msg.chat_id, req.user.id]
  );

  if (!member) return res.status(403).json({ error: "Forbidden" });

  if (mode === "all") {
    safeUnlink(msg.image_path);
    safeUnlink(msg.audio_path);

    run("DELETE FROM messages WHERE id=?", [id]);

    io.to(`chat:${msg.chat_id}`).emit("message:deleted_for_all", { messageId: id });

    return res.json({ ok: true });
  }

  run(
    "INSERT OR IGNORE INTO message_deletions (message_id,user_id) VALUES (?,?)",
    [id, req.user.id]
  );

  return res.json({ ok: true });
});

//////////////////////////////
// DELETE CHAT HISTORY
//////////////////////////////
app.delete("/api/chats/:id/messages", authMiddleware, (req, res) => {
  const chatId = Number(req.params.id);

  const member = get(
    "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
    [chatId, req.user.id]
  );

  if (!member) return res.status(403).json({ error: "Forbidden" });

  const msgs = all("SELECT * FROM messages WHERE chat_id=?", [chatId]);

  for (const m of msgs) {
    safeUnlink(m.image_path);
    safeUnlink(m.audio_path);
  }

  run("DELETE FROM messages WHERE chat_id=?", [chatId]);

  io.to(`chat:${chatId}`).emit("chat:cleared", { chatId });

  res.json({ ok: true });
});

//////////////////////////////
// READ RECEIPT
//////////////////////////////
app.post("/api/chats/:id/read", authMiddleware, (req, res) => {
  const chatId = Number(req.params.id);
  const { messageId } = req.body;

  run(
    "UPDATE chat_participants SET last_read_message_id=? WHERE chat_id=? AND user_id=?",
    [messageId, chatId, req.user.id]
  );

  io.to(`chat:${chatId}`).emit("message:read", {
    chatId,
    userId: req.user.id,
    messageId,
  });

  res.json({ ok: true });
});

//////////////////////////////
// SOCKET EVENTS
//////////////////////////////
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user.id;

  if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
  onlineUsers.get(userId).add(socket.id);

  const chats = all(
    "SELECT chat_id FROM chat_participants WHERE user_id=?",
    [userId]
  );

  chats.forEach((c) => socket.join(`chat:${c.chat_id}`));

  // Личная комната для уведомлений
  socket.join(`user:${userId}`);

  // Оповещаем всех что пользователь онлайн
  io.emit("presence:update", { userId, online: true });

  socket.on("typing:start", ({ chatId }) => {
    socket.to(`chat:${chatId}`).emit("typing", {
      chatId,
      userId,
      typing: true,
    });
  });

  socket.on("typing:stop", ({ chatId }) => {
    socket.to(`chat:${chatId}`).emit("typing", {
      chatId,
      userId,
      typing: false,
    });
  });

  socket.on("message:send", (data) => {
    const { chatId, content } = data;

    if (!content?.trim()) return;

    const member = get(
      "SELECT * FROM chat_participants WHERE chat_id=? AND user_id=?",
      [chatId, userId]
    );

    if (!member) return;

    const r = run(
      "INSERT INTO messages (chat_id,sender_id,content) VALUES (?,?,?)",
      [chatId, userId, encrypt(content.slice(0, 4000))]
    );

    const msg = get("SELECT * FROM messages WHERE id=?", [
      r.lastInsertRowid,
    ]);

    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(msg));
  });

  socket.on("disconnect", () => {
    const set = onlineUsers.get(userId);
    if (!set) return;

    set.delete(socket.id);

    if (set.size === 0) {
      onlineUsers.delete(userId);
      run("UPDATE users SET last_seen=CURRENT_TIMESTAMP WHERE id=?", [userId]);
      // Оповещаем всех что пользователь офлайн
      io.emit("presence:update", { userId, online: false });
    }
  });
});

//////////////////////////////
// START SERVER
//////////////////////////////
initDb();

server.listen(PORT, () => {
  console.log("Server running on " + PORT);
});