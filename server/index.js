const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const { Server } = require("socket.io");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");

const PORT = Number(process.env.PORT) || 3001;

// ─── Секреты из переменных окружения ───────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ENCRYPTION_KEY_HEX = process.env.ENCRYPTION_KEY;

if (!JWT_SECRET || !JWT_REFRESH_SECRET) {
  console.error("FATAL: JWT_SECRET and JWT_REFRESH_SECRET must be set in environment variables.");
  console.error("Run: cp .env.example .env  and fill in the values.");
  process.exit(1);
}

if (!ENCRYPTION_KEY_HEX || ENCRYPTION_KEY_HEX.length !== 64) {
  console.error("FATAL: ENCRYPTION_KEY must be set as a 64-character hex string (32 bytes).");
  console.error("Generate one with: node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
  process.exit(1);
}

const ENCRYPTION_KEY = Buffer.from(ENCRYPTION_KEY_HEX, "hex");
const ALGORITHM = "aes-256-gcm";

// ─── Шифрование / дешифрование ─────────────────────────────────────────────
function encrypt(text) {
  if (!text) return text;
  const iv = crypto.randomBytes(12); // 96-bit IV для GCM
  const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Формат: iv(12) + tag(16) + encrypted — всё в hex
  return Buffer.concat([iv, tag, encrypted]).toString("hex");
}

function decrypt(hex) {
  if (!hex) return hex;
  try {
    const buf = Buffer.from(hex, "hex");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const encrypted = buf.subarray(28);
    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch {
    // Если не удалось расшифровать — вернуть как есть (старые незашифрованные сообщения)
    return hex;
  }
}

function decryptMessage(msg) {
  if (!msg) return msg;
  return { ...msg, content: decrypt(msg.content) };
}

const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || /^http:\/\/(localhost|127\.0\.0\.1):\d+$/;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CLIENT_ORIGIN, methods: ["GET", "POST", "DELETE"] },
});

// ─── Безопасные HTTP-заголовки ──────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }, // разрешаем отдачу файлов
}));
app.use(compression());

app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(express.json({ limit: "1mb" }));

// ─── Rate limiting ──────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 30,                   // не более 30 попыток авторизации
  message: { error: "Too many requests, try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600, // 600 запросов в минуту
  message: { error: "Too many requests" },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use("/api/auth", authLimiter);
app.use("/api", apiLimiter);

// ─── БД и загрузки ─────────────────────────────────────────────────────────
const db = new sqlite3.Database("./messenger.db");
const UPLOADS_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOADS_DIR));

// ─── Multer: загрузка изображений ──────────────────────────────────────────
const imageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const safeExt = path.extname(file.originalname || "").toLowerCase() || ".jpg";
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${safeExt}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype?.startsWith("image/")) return cb(new Error("Only image files allowed"));
    return cb(null, true);
  },
});

// ─── Multer: загрузка аудио ─────────────────────────────────────────────────
const audioUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const safeExt = path.extname(file.originalname || "").toLowerCase() || ".webm";
      cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${safeExt}`);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype?.startsWith("audio/")) return cb(new Error("Only audio files allowed"));
    return cb(null, true);
  },
});

// ─── Вспомогательные функции БД ────────────────────────────────────────────
const run = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const get = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

const all = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });

const onlineUsers = new Map();

// ─── Валидация ──────────────────────────────────────────────────────────────
function validateLogin(login) {
  return typeof login === "string" && login.length >= 3 && login.length <= 32 && /^[a-zA-Z0-9_]+$/.test(login);
}

function validatePassword(password) {
  return typeof password === "string" && password.length >= 6 && password.length <= 128;
}

// ─── Работа с файлами сообщений ────────────────────────────────────────────
async function ensureColumnExists(tableName, columnName, definition) {
  const columns = await all(`PRAGMA table_info(${tableName})`);
  const exists = columns.some((column) => column.name === columnName);
  if (!exists) {
    await run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

async function removeMessageFile(message) {
  const files = [];
  if (message?.image_path) files.push(message.image_path);
  if (message?.audio_path) files.push(message.audio_path);

  for (const file of files) {
    const absoluteFilePath = path.join(UPLOADS_DIR, file);
    try {
      await fs.promises.unlink(absoluteFilePath);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

// ─── Инициализация БД ──────────────────────────────────────────────────────
async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    last_seen TEXT
  )`);

  // Таблица refresh-токенов
  await run(`CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  await run(`CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_user_id, to_user_id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user1_id, user2_id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    is_direct INTEGER NOT NULL DEFAULT 1
  )`);

  await run(`CREATE TABLE IF NOT EXISTS chat_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_read_message_id INTEGER,
    UNIQUE(chat_id, user_id)
  )`);

  await run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    content TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_for_everyone INTEGER NOT NULL DEFAULT 0
  )`);

  await ensureColumnExists("messages", "message_type", "TEXT NOT NULL DEFAULT 'text'");
  await ensureColumnExists("messages", "image_path", "TEXT");
  await ensureColumnExists("messages", "audio_path", "TEXT");

  await run(`CREATE TABLE IF NOT EXISTS message_deletions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    UNIQUE(message_id, user_id)
  )`);

  // Индексы для ускорения запросов
  await run("CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id)");
  await run("CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id)");
  await run("CREATE INDEX IF NOT EXISTS idx_messages_chat_id_id ON messages(chat_id, id)");
  await run("CREATE INDEX IF NOT EXISTS idx_message_deletions_message_id ON message_deletions(message_id)");
  await run("CREATE INDEX IF NOT EXISTS idx_chat_participants_user_id ON chat_participants(user_id)");
  await run("CREATE INDEX IF NOT EXISTS idx_chat_participants_chat_id ON chat_participants(chat_id)");
  await run("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)");

  // Удаляем просроченные refresh-токены при старте
  await run("DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP");
}

// ─── JWT: генерация токенов ─────────────────────────────────────────────────
function generateAccessToken(user) {
  return jwt.sign({ id: user.id, login: user.login }, JWT_SECRET, { expiresIn: "15m" });
}

async function generateRefreshToken(userId) {
  const token = jwt.sign({ id: userId }, JWT_REFRESH_SECRET, { expiresIn: "30d" });
  // Храним хэш токена в БД (не сам токен)
  const tokenHash = await bcrypt.hash(token, 8);
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  await run(
    "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
    [userId, tokenHash, expiresAt]
  );
  return token;
}

// ─── Middleware: проверка access-токена ────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ─── Вспомогательная функция чатов ─────────────────────────────────────────
async function getOrCreateDirectChat(userA, userB) {
  const sorted = [userA, userB].sort((a, b) => a - b);
  const existing = await get(
    `SELECT c.id FROM chats c
     JOIN chat_participants p1 ON p1.chat_id = c.id AND p1.user_id = ?
     JOIN chat_participants p2 ON p2.chat_id = c.id AND p2.user_id = ?
     WHERE c.is_direct = 1`,
    sorted
  );
  if (existing) return existing.id;

  const chat = await run("INSERT INTO chats (is_direct) VALUES (1)");
  await run("INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?)", [chat.lastID, sorted[0]]);
  await run("INSERT INTO chat_participants (chat_id, user_id) VALUES (?, ?)", [chat.lastID, sorted[1]]);
  return chat.lastID;
}

// ═══════════════════════════════════════════════════════════════════════════
// МАРШРУТЫ
// ═══════════════════════════════════════════════════════════════════════════

// ─── Регистрация ────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!validateLogin(login)) {
      return res.status(400).json({ error: "Login must be 3–32 characters, letters/numbers/underscore only" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({ error: "Password must be 6–128 characters" });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await run("INSERT INTO users (login, password_hash) VALUES (?, ?)", [login, hash]);

    const user = { id: result.lastID, login };
    const accessToken = generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user.id);

    return res.json({ accessToken, refreshToken, user });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(400).json({ error: "Login already exists" });
    }
    return res.status(500).json({ error: "Server error" });
  }
});

// ─── Вход ───────────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || !password) {
      return res.status(400).json({ error: "Login and password are required" });
    }

    const user = await get("SELECT * FROM users WHERE login = ?", [login]);
    // Одинаковое сообщение — не раскрываем существование пользователя
    if (!user) {
      await bcrypt.hash(password, 12); // timing attack protection
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const accessToken = generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user.id);

    return res.json({ accessToken, refreshToken, user: { id: user.id, login: user.login } });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
});

// ─── Обновление access-токена через refresh-токен ──────────────────────────
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "Refresh token required" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid or expired refresh token" });
    }

    // Проверяем токен в БД
    const storedTokens = await all(
      "SELECT * FROM refresh_tokens WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP",
      [payload.id]
    );

    let validRecord = null;
    for (const record of storedTokens) {
      const match = await bcrypt.compare(refreshToken, record.token_hash);
      if (match) { validRecord = record; break; }
    }

    if (!validRecord) return res.status(401).json({ error: "Refresh token not found or revoked" });

    // Ротация: удаляем старый, выдаём новые
    await run("DELETE FROM refresh_tokens WHERE id = ?", [validRecord.id]);

    const user = await get("SELECT id, login FROM users WHERE id = ?", [payload.id]);
    if (!user) return res.status(401).json({ error: "User not found" });

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = await generateRefreshToken(user.id);

    return res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
});

// ─── Выход (инвалидация refresh-токена) ────────────────────────────────────
app.post("/api/auth/logout", authMiddleware, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const storedTokens = await all(
        "SELECT * FROM refresh_tokens WHERE user_id = ?",
        [req.user.id]
      );
      for (const record of storedTokens) {
        const match = await bcrypt.compare(refreshToken, record.token_hash);
        if (match) {
          await run("DELETE FROM refresh_tokens WHERE id = ?", [record.id]);
          break;
        }
      }
    }
    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: "Server error" });
  }
});

// ─── Удаление аккаунта ──────────────────────────────────────────────────────
app.delete("/api/auth/account", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    // Находим все чаты пользователя
    const userChats = await all(
      "SELECT chat_id FROM chat_participants WHERE user_id = ?",
      [userId]
    );

    for (const { chat_id } of userChats) {
      // Проверяем есть ли другие участники кроме удаляемого
      const otherParticipants = await all(
        "SELECT user_id FROM chat_participants WHERE chat_id = ? AND user_id != ?",
        [chat_id, userId]
      );

      if (otherParticipants.length === 0) {
        // Чат только у этого пользователя — удаляем полностью
        const messages = await all("SELECT * FROM messages WHERE chat_id = ?", [chat_id]);
        for (const message of messages) await removeMessageFile(message);
        await run("DELETE FROM message_deletions WHERE message_id IN (SELECT id FROM messages WHERE chat_id = ?)", [chat_id]);
        await run("DELETE FROM messages WHERE chat_id = ?", [chat_id]);
        await run("DELETE FROM chat_participants WHERE chat_id = ?", [chat_id]);
        await run("DELETE FROM chats WHERE id = ?", [chat_id]);
      } else {
        // В чате есть другой участник — удаляем только сообщения этого пользователя
        // и помечаем их удалёнными для всех
        const userMessages = await all(
          "SELECT * FROM messages WHERE chat_id = ? AND sender_id = ?",
          [chat_id, userId]
        );
        for (const message of userMessages) {
          await removeMessageFile(message);
          io.to(`chat:${chat_id}`).emit("message:deleted_for_all", { messageId: message.id });
        }
        await run(
          "DELETE FROM message_deletions WHERE message_id IN (SELECT id FROM messages WHERE chat_id = ? AND sender_id = ?)",
          [chat_id, userId]
        );
        await run("DELETE FROM messages WHERE chat_id = ? AND sender_id = ?", [chat_id, userId]);
        await run("DELETE FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chat_id, userId]);

        // Оповещаем собеседника
        io.to(`chat:${chat_id}`).emit("chat:cleared", { chatId: chat_id });
      }
    }

    // Удаляем дружбы и заявки
    await run(
      "DELETE FROM friendships WHERE user1_id = ? OR user2_id = ?",
      [userId, userId]
    );
    await run(
      "DELETE FROM friend_requests WHERE from_user_id = ? OR to_user_id = ?",
      [userId, userId]
    );

    // Удаляем refresh-токены
    await run("DELETE FROM refresh_tokens WHERE user_id = ?", [userId]);

    // Удаляем самого пользователя
    await run("DELETE FROM users WHERE id = ?", [userId]);

    return res.json({ ok: true });
  } catch (error) {
    console.error("Delete account error:", error);
    return res.status(500).json({ error: "Server error" });
  }
});

// ─── Друзья ─────────────────────────────────────────────────────────────────
app.get("/api/friends/search", authMiddleware, async (req, res) => {
  const { login } = req.query;
  if (!login) return res.json({ user: null });
  const user = await get("SELECT id, login FROM users WHERE login = ?", [login]);
  if (!user || user.id === req.user.id) return res.json({ user: null });

  const friendship = await get(
    "SELECT id FROM friendships WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)",
    [req.user.id, user.id, user.id, req.user.id]
  );
  if (friendship) return res.json({ user, relationship: "friend" });

  const pending = await get(
    `SELECT id, from_user_id, to_user_id FROM friend_requests
     WHERE status = 'pending'
       AND ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?))`,
    [req.user.id, user.id, user.id, req.user.id]
  );
  if (pending) {
    return res.json({
      user,
      relationship: pending.from_user_id === req.user.id ? "outgoing_pending" : "incoming_pending",
    });
  }
  return res.json({ user, relationship: "none" });
});

app.post("/api/friends/request/:targetId", authMiddleware, async (req, res) => {
  const targetId = Number(req.params.targetId);
  if (!targetId || targetId === req.user.id) return res.status(400).json({ error: "Invalid target" });

  const existingFriend = await get(
    "SELECT * FROM friendships WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)",
    [req.user.id, targetId, targetId, req.user.id]
  );
  if (existingFriend) return res.status(400).json({ error: "Already friends" });

  const existingPending = await get(
    `SELECT id FROM friend_requests
     WHERE status = 'pending'
       AND ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?))`,
    [req.user.id, targetId, targetId, req.user.id]
  );
  if (existingPending) return res.status(400).json({ error: "Request already exists" });

  try {
    await run("INSERT INTO friend_requests (from_user_id, to_user_id) VALUES (?, ?)", [req.user.id, targetId]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(400).json({ error: "Request already exists" });
  }
});

app.get("/api/friends/requests", authMiddleware, async (req, res) => {
  const rows = await all(
    `SELECT fr.id, fr.from_user_id, u.login as from_login
     FROM friend_requests fr
     JOIN users u ON u.id = fr.from_user_id
     WHERE fr.to_user_id = ? AND fr.status = 'pending'
     ORDER BY fr.created_at DESC`,
    [req.user.id]
  );
  return res.json({ requests: rows });
});

app.post("/api/friends/request/:requestId/respond", authMiddleware, async (req, res) => {
  const requestId = Number(req.params.requestId);
  const { action } = req.body;
  const request = await get("SELECT * FROM friend_requests WHERE id = ? AND to_user_id = ?", [requestId, req.user.id]);
  if (!request || request.status !== "pending") return res.status(404).json({ error: "Request not found" });

  if (action === "accept") {
    const [a, b] = [request.from_user_id, request.to_user_id].sort((x, y) => x - y);
    await run("INSERT OR IGNORE INTO friendships (user1_id, user2_id) VALUES (?, ?)", [a, b]);
    await getOrCreateDirectChat(a, b);
    await run("UPDATE friend_requests SET status = 'accepted' WHERE id = ?", [requestId]);
  } else {
    await run("UPDATE friend_requests SET status = 'rejected' WHERE id = ?", [requestId]);
  }
  return res.json({ ok: true });
});

app.get("/api/friends", authMiddleware, async (req, res) => {
  const friends = await all(
    `SELECT u.id, u.login
     FROM friendships f
     JOIN users u ON u.id = CASE WHEN f.user1_id = ? THEN f.user2_id ELSE f.user1_id END
     WHERE f.user1_id = ? OR f.user2_id = ?`,
    [req.user.id, req.user.id, req.user.id]
  );
  return res.json({
    friends: friends.map((f) => ({
      ...f,
      online: onlineUsers.has(f.id),
    })),
  });
});

// ─── Чаты ───────────────────────────────────────────────────────────────────
app.get("/api/chats", authMiddleware, async (req, res) => {
  const chats = await all(
    `SELECT c.id as chat_id, u.id as friend_id, u.login as friend_login, cp.last_read_message_id
     FROM chats c
     JOIN chat_participants me ON me.chat_id = c.id AND me.user_id = ?
     JOIN chat_participants other ON other.chat_id = c.id AND other.user_id != ?
     JOIN users u ON u.id = other.user_id
     JOIN chat_participants cp ON cp.chat_id = c.id AND cp.user_id = ?
     WHERE c.is_direct = 1`,
    [req.user.id, req.user.id, req.user.id]
  );

  const mapped = await Promise.all(
    chats.map(async (chat) => {
      const lastMessage = await get(
        `SELECT m.id, m.content, m.sender_id, m.deleted_for_everyone, m.created_at, m.message_type, m.image_path, m.audio_path
         FROM messages m
         LEFT JOIN message_deletions md ON md.message_id = m.id AND md.user_id = ?
         WHERE m.chat_id = ? AND md.id IS NULL
         ORDER BY m.id DESC LIMIT 1`,
        [req.user.id, chat.chat_id]
      );
      return {
        chatId: chat.chat_id,
        friend: { id: chat.friend_id, login: chat.friend_login, online: onlineUsers.has(chat.friend_id) },
        lastReadMessageId: chat.last_read_message_id,
        lastMessage: decryptMessage(lastMessage),
      };
    })
  );
  return res.json({ chats: mapped });
});

app.get("/api/chats/:chatId/messages", authMiddleware, async (req, res) => {
  const chatId = Number(req.params.chatId);
  const limit = Math.min(Number(req.query.limit) || 50, 100);
  const before = Number(req.query.before) || null; // ID сообщения — грузим ДО него

  const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chatId, req.user.id]);
  if (!participant) return res.status(403).json({ error: "Forbidden" });

  const rows = await all(
    `SELECT m.id, m.chat_id, m.sender_id, m.content, m.created_at, m.deleted_for_everyone, m.message_type, m.image_path, m.audio_path
     FROM messages m
     LEFT JOIN message_deletions md ON md.message_id = m.id AND md.user_id = ?
     WHERE m.chat_id = ? AND md.id IS NULL ${before ? "AND m.id < ?" : ""}
     ORDER BY m.id DESC
     LIMIT ?`,
    before ? [req.user.id, chatId, before, limit] : [req.user.id, chatId, limit]
  );

  // Разворачиваем обратно — от старых к новым
  const messages = rows.reverse();
  const hasMore = rows.length === limit;

  return res.json({ messages: messages.map(decryptMessage), hasMore });
});

// ─── Загрузка изображений ───────────────────────────────────────────────────
app.post("/api/chats/:chatId/images", authMiddleware, imageUpload.single("image"), async (req, res) => {
  try {
    const chatId = Number(req.params.chatId);
    const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chatId, req.user.id]);
    if (!participant) return res.status(403).json({ error: "Forbidden" });
    if (!req.file) return res.status(400).json({ error: "Image is required" });

    const result = await run(
      "INSERT INTO messages (chat_id, sender_id, content, message_type, image_path) VALUES (?, ?, ?, 'image', ?)",
      [chatId, req.user.id, encrypt(req.file.originalname || "Фото"), req.file.filename]
    );
    const message = await get("SELECT * FROM messages WHERE id = ?", [result.lastID]);
    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(message));
    return res.json({ ok: true, message: decryptMessage(message) });
  } catch (error) {
    if (req.file?.path) {
      try { await fs.promises.unlink(req.file.path); } catch (_) {}
    }
    return res.status(400).json({ error: error.message || "Failed to upload image" });
  }
});

// ─── Загрузка аудио ─────────────────────────────────────────────────────────
app.post("/api/chats/:chatId/voice", authMiddleware, audioUpload.single("audio"), async (req, res) => {
  try {
    const chatId = Number(req.params.chatId);
    const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chatId, req.user.id]);
    if (!participant) return res.status(403).json({ error: "Forbidden" });
    if (!req.file) return res.status(400).json({ error: "Audio is required" });

    const result = await run(
      "INSERT INTO messages (chat_id, sender_id, content, message_type, audio_path) VALUES (?, ?, ?, 'voice', ?)",
      [chatId, req.user.id, encrypt("Голосовое сообщение"), req.file.filename]
    );
    const message = await get("SELECT * FROM messages WHERE id = ?", [result.lastID]);
    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(message));
    return res.json({ ok: true, message: decryptMessage(message) });
  } catch (error) {
    if (req.file?.path) {
      try { await fs.promises.unlink(req.file.path); } catch (_) {}
    }
    return res.status(400).json({ error: error.message || "Failed to upload audio" });
  }
});

// ─── Удаление сообщений ─────────────────────────────────────────────────────
app.delete("/api/messages/:messageId", authMiddleware, async (req, res) => {
  const messageId = Number(req.params.messageId);
  const mode = req.query.mode;
  const message = await get("SELECT * FROM messages WHERE id = ?", [messageId]);
  if (!message) return res.status(404).json({ error: "Not found" });

  const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [
    message.chat_id,
    req.user.id,
  ]);
  if (!participant) return res.status(403).json({ error: "Forbidden" });

  if (mode === "all") {
    await removeMessageFile(message);
    await run("DELETE FROM message_deletions WHERE message_id = ?", [messageId]);
    await run("DELETE FROM messages WHERE id = ?", [messageId]);
    io.to(`chat:${message.chat_id}`).emit("message:deleted_for_all", { messageId });
    return res.json({ ok: true });
  }

  // Удалить у меня
  await run("INSERT OR IGNORE INTO message_deletions (message_id, user_id) VALUES (?, ?)", [messageId, req.user.id]);
  const participantsCountRow = await get("SELECT COUNT(*) as total FROM chat_participants WHERE chat_id = ?", [message.chat_id]);
  const deletionsCountRow = await get("SELECT COUNT(*) as total FROM message_deletions WHERE message_id = ?", [messageId]);

  if (participantsCountRow?.total && deletionsCountRow?.total >= participantsCountRow.total) {
    await removeMessageFile(message);
    await run("DELETE FROM message_deletions WHERE message_id = ?", [messageId]);
    await run("DELETE FROM messages WHERE id = ?", [messageId]);
    io.to(`chat:${message.chat_id}`).emit("message:deleted_for_all", { messageId });
  }

  return res.json({ ok: true });
});

// ─── Очистка диалога ────────────────────────────────────────────────────────
app.delete("/api/chats/:chatId/messages", authMiddleware, async (req, res) => {
  const chatId = Number(req.params.chatId);

  const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chatId, req.user.id]);
  if (!participant) return res.status(403).json({ error: "Forbidden" });

  // Получаем все сообщения с файлами и удаляем их с диска
  const allMessages = await all("SELECT * FROM messages WHERE chat_id = ?", [chatId]);
  for (const message of allMessages) {
    await removeMessageFile(message);
  }

  // Удаляем все сообщения и связанные записи из БД
  await run("DELETE FROM message_deletions WHERE message_id IN (SELECT id FROM messages WHERE chat_id = ?)", [chatId]);
  await run("DELETE FROM messages WHERE chat_id = ?", [chatId]);

  // Сбрасываем last_read у обоих участников
  await run("UPDATE chat_participants SET last_read_message_id = NULL WHERE chat_id = ?", [chatId]);

  // Оповещаем обоих участников
  io.to(`chat:${chatId}`).emit("chat:cleared", { chatId });

  return res.json({ ok: true });
});


app.post("/api/chats/:chatId/read", authMiddleware, async (req, res) => {
  const chatId = Number(req.params.chatId);
  const { messageId } = req.body;
  await run("UPDATE chat_participants SET last_read_message_id = ? WHERE chat_id = ? AND user_id = ?", [
    messageId,
    chatId,
    req.user.id,
  ]);
  io.to(`chat:${chatId}`).emit("message:read", { chatId, userId: req.user.id, messageId });
  return res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
// SOCKET.IO
// ═══════════════════════════════════════════════════════════════════════════
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const user = jwt.verify(token, JWT_SECRET);
    socket.user = user;
    return next();
  } catch (error) {
    return next(new Error("Unauthorized"));
  }
});

io.on("connection", async (socket) => {
  const userId = socket.user.id;
  if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
  onlineUsers.get(userId).add(socket.id);
  io.emit("presence:update", { userId, online: true });

  const chats = await all("SELECT chat_id FROM chat_participants WHERE user_id = ?", [userId]);
  chats.forEach((chat) => socket.join(`chat:${chat.chat_id}`));

  socket.on("typing:start", ({ chatId }) => {
    socket.to(`chat:${chatId}`).emit("typing:update", { chatId, userId, typing: true });
  });

  socket.on("typing:stop", ({ chatId }) => {
    socket.to(`chat:${chatId}`).emit("typing:update", { chatId, userId, typing: false });
  });

  socket.on("message:send", async ({ chatId, content }) => {
    if (!content || !String(content).trim()) return;
    // Ограничение длины сообщения
    const trimmed = String(content).trim().slice(0, 4000);
    const participant = await get("SELECT * FROM chat_participants WHERE chat_id = ? AND user_id = ?", [chatId, userId]);
    if (!participant) return;

    const result = await run("INSERT INTO messages (chat_id, sender_id, content) VALUES (?, ?, ?)", [
      chatId,
      userId,
      encrypt(trimmed),
    ]);
    const message = await get("SELECT * FROM messages WHERE id = ?", [result.lastID]);
    io.to(`chat:${chatId}`).emit("message:new", decryptMessage(message));
  });

  socket.on("disconnect", async () => {
    const sockets = onlineUsers.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
        await run("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", [userId]);
        io.emit("presence:update", { userId, online: false });
      }
    }
  });
});

// ─── Запуск ─────────────────────────────────────────────────────────────────
initDb().then(() => {
  server.listen(PORT, () => {
    console.log(`Server on http://localhost:${PORT}`);
  });
});
