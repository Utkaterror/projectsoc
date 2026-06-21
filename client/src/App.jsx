import { useEffect, useMemo, useRef, useState } from "react";
import { io } from "socket.io-client";
import { useVoiceRecorder } from "./hooks/useVoiceRecorder";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:3001";
const API_URL = `${API_BASE}/api`;
const SOCKET_URL = API_BASE;
const buildFileUrl = (filePath) => `${API_BASE}/uploads/${filePath}`;

const authHeaders = (token, isJson = true) => ({
  ...(isJson ? { "Content-Type": "application/json" } : {}),
  Authorization: `Bearer ${token}`,
});

function VoiceMessage({ src, isMine }) {
  const audioRef = useRef(null);
  const [playing, setPlaying] = useState(false);
  const [progress, setProgress] = useState(0);
  const [duration, setDuration] = useState(0);
  const [current, setCurrent] = useState(0);

  const fmt = (s) => {
    const m = Math.floor(s / 60);
    const sec = Math.floor(s % 60);
    return `${m}:${sec.toString().padStart(2, "0")}`;
  };

  const toggle = () => {
    const a = audioRef.current;
    if (!a) return;
    if (playing) { a.pause(); setPlaying(false); }
    else { a.play(); setPlaying(true); }
  };

  const onTimeUpdate = () => {
    const a = audioRef.current;
    if (!a) return;
    setCurrent(a.currentTime);
    setProgress(a.duration ? (a.currentTime / a.duration) * 100 : 0);
  };

  const onLoaded = () => {
    const a = audioRef.current;
    if (a && isFinite(a.duration)) setDuration(a.duration);
  };

  const onEnded = () => { setPlaying(false); setProgress(0); setCurrent(0); };

  const seek = (e) => {
    const a = audioRef.current;
    if (!a) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const ratio = (e.clientX - rect.left) / rect.width;
    a.currentTime = ratio * a.duration;
  };

  return (
    <div className={`voice-player ${isMine ? "mine" : ""}`}>
      <audio ref={audioRef} src={src} onTimeUpdate={onTimeUpdate} onLoadedMetadata={onLoaded} onEnded={onEnded} />
      <button className="voice-play-btn" onClick={toggle}>
        {playing ? (
          <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>
        ) : (
          <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M8 5.14v14l11-7-11-7z"/></svg>
        )}
      </button>
      <div className="voice-track" onClick={seek}>
        <div className="voice-progress" style={{ width: `${progress}%` }} />
      </div>
      <span className="voice-time">{fmt(playing ? current : duration)}</span>
    </div>
  );
}

function App() {
  const [mode, setMode] = useState("login");
  const [authForm, setAuthForm] = useState({ login: "", password: "" });
  const [token, setToken] = useState(localStorage.getItem("token") || "");
  const [user, setUser] = useState(JSON.parse(localStorage.getItem("user") || "null"));
  const [chats, setChats] = useState([]);
  const [requests, setRequests] = useState([]);
  const [friends, setFriends] = useState([]);
  const [searchLogin, setSearchLogin] = useState("");
  const [searchResult, setSearchResult] = useState(null);
  const [activeChatId, setActiveChatId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState("");
  const [typingByChat, setTypingByChat] = useState({});
  const [error, setError] = useState("");
  const [menuState, setMenuState] = useState(null);
  const socketRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const activeChatIdRef = useRef(activeChatId);
  const imageInputRef = useRef(null);
  const { isRecording, startRecording, stopRecording } = useVoiceRecorder();

  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const messagesContainerRef = useRef(null);
  const messagesEndRef = useRef(null);

  const activeChat = useMemo(() => chats.find((c) => c.chatId === activeChatId) || null, [chats, activeChatId]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "instant" });
  };

  // ── Ключевое исправление: используем ref чтобы loadAppData
  //    не сбрасывал активный чат при каждом обновлении ────────
  const loadAppData = async (authToken) => {
    const [chatsRes, requestsRes, friendsRes] = await Promise.all([
      fetch(`${API_URL}/chats`, { headers: authHeaders(authToken) }),
      fetch(`${API_URL}/friends/requests`, { headers: authHeaders(authToken) }),
      fetch(`${API_URL}/friends`, { headers: authHeaders(authToken) }),
    ]);

    const chatsData = await chatsRes.json();
    const requestsData = await requestsRes.json();
    const friendsData = await friendsRes.json();
    setChats(chatsData.chats || []);
    setRequests(requestsData.requests || []);
    setFriends(friendsData.friends || []);
  };

  const loadMessages = async (chatId, authToken = token, before = null) => {
    if (!chatId || !authToken) return;
    const url = `${API_URL}/chats/${chatId}/messages?limit=50${before ? `&before=${before}` : ""}`;
    const res = await fetch(url, { headers: authHeaders(authToken) });
    const data = await res.json();
    const newMessages = data.messages || [];

    if (before) {
      // Догружаем старые — сохраняем позицию скролла
      const container = messagesContainerRef.current;
      const prevScrollHeight = container?.scrollHeight || 0;
      setMessages((prev) => [...newMessages, ...prev]);
      setHasMore(data.hasMore || false);
      // Восстанавливаем позицию скролла
      requestAnimationFrame(() => {
        if (container) container.scrollTop = container.scrollHeight - prevScrollHeight;
      });
    } else {
      setMessages(newMessages);
      setHasMore(data.hasMore || false);
    }

    const lastMessage = newMessages.slice(-1)[0];
    if (lastMessage && !before) {
      await fetch(`${API_URL}/chats/${chatId}/read`, {
        method: "POST",
        headers: authHeaders(authToken),
        body: JSON.stringify({ messageId: lastMessage.id }),
      });
    }
  };

  useEffect(() => {
    if (token && "Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, [token]);

  const audioCtxRef = useRef(null);

  const getAudioCtx = () => {
    if (!audioCtxRef.current) {
      audioCtxRef.current = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioCtxRef.current.state === "suspended") {
      audioCtxRef.current.resume();
    }
    return audioCtxRef.current;
  };

  // Разблокируем AudioContext при первом клике пользователя
  useEffect(() => {
    const unlock = () => { getAudioCtx(); };
    window.addEventListener("click", unlock, { once: true });
    return () => window.removeEventListener("click", unlock);
  }, []);

  const playNotificationSound = () => {
    try {
      const ctx = getAudioCtx();
      const notes = [660, 880, 1100];
      notes.forEach((freq, i) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = "sine";
        osc.frequency.setValueAtTime(freq, ctx.currentTime + i * 0.08);
        gain.gain.setValueAtTime(0, ctx.currentTime + i * 0.08);
        gain.gain.linearRampToValueAtTime(0.25, ctx.currentTime + i * 0.08 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.08 + 0.15);
        osc.start(ctx.currentTime + i * 0.08);
        osc.stop(ctx.currentTime + i * 0.08 + 0.15);
      });
    } catch (e) {
      console.warn("Audio error:", e);
    }
  };

  const showNotification = (message, senderLogin) => {
    if (document.hasFocus()) return;
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    const text = message.message_type === "image" ? "📷 Фото"
      : message.message_type === "voice" ? "🎤 Голосовое"
      : message.content;
    new Notification(senderLogin, {
      body: text,
      icon: "/favicon.ico",
    });
  };

  const chatsRef = useRef([]);
  useEffect(() => { chatsRef.current = chats; }, [chats]);

  const loadMoreMessages = async () => {
    if (!hasMore || loadingMore || !activeChatId || messages.length === 0) return;
    setLoadingMore(true);
    await loadMessages(activeChatId, token, messages[0].id);
    setLoadingMore(false);
  };

  const authSubmit = async (event) => {
    event.preventDefault();
    setError("");
    const login = authForm.login.trim();
    const password = authForm.password;

    if (mode === "register") {
      if (login.length < 3) return setError("Логин должен быть не короче 3 символов");
      if (password.length < 6) return setError("Пароль должен быть не короче 6 символов");
    }

    const endpoint = mode === "login" ? "login" : "register";
    const res = await fetch(`${API_URL}/auth/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ login, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) return setError(data.error || "Auth failed");
    localStorage.setItem("token", data.accessToken);
    localStorage.setItem("user", JSON.stringify(data.user));
    setToken(data.accessToken);
    setUser(data.user);
    setAuthForm({ login: "", password: "" });
  };

  const deleteAccount = async () => {
    if (!window.confirm("Удалить аккаунт? Все данные будут удалены без возможности восстановления.")) return;
    if (!window.confirm("Вы уверены? Это действие необратимо.")) return;

    const res = await fetch(`${API_URL}/auth/account`, {
      method: "DELETE",
      headers: authHeaders(token),
    });

    if (res.ok) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      socketRef.current?.disconnect();
      setToken("");
      setUser(null);
      setChats([]);
      setMessages([]);
    } else {
      const data = await res.json().catch(() => ({}));
      setError(data.error || "Не удалось удалить аккаунт");
    }
  };

  const logout = () => {
    setToken("");
    setUser(null);
    setChats([]);
    setMessages([]);
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    socketRef.current?.disconnect();
  };

  const sendFriendRequest = async (targetUserId) => {
    await fetch(`${API_URL}/friends/request/${targetUserId}`, { method: "POST", headers: authHeaders(token) });
    setSearchResult(null);
    setSearchLogin("");
  };

  const searchFriend = async () => {
    const login = searchLogin.trim();
    if (!login) return;
    const res = await fetch(`${API_URL}/friends/search?login=${encodeURIComponent(login)}`, {
      headers: authHeaders(token),
    });
    const data = await res.json();
    setSearchResult(data.user ? { ...data.user, relationship: data.relationship || "none" } : null);
  };

  const respondToRequest = async (requestId, action) => {
    await fetch(`${API_URL}/friends/request/${requestId}/respond`, {
      method: "POST",
      headers: authHeaders(token),
      body: JSON.stringify({ action }),
    });
    // Убираем заявку из списка локально
    setRequests((prev) => prev.filter((r) => r.id !== requestId));
  };

  const sendMessage = () => {
    if (!messageText.trim() || !activeChatId) return;
    socketRef.current?.emit("message:send", { chatId: activeChatId, content: messageText });
    setMessageText("");
    socketRef.current?.emit("typing:stop", { chatId: activeChatId });
  };

  const handleTyping = (value) => {
    setMessageText(value);
    if (!activeChatId) return;
    socketRef.current?.emit("typing:start", { chatId: activeChatId });
    clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      socketRef.current?.emit("typing:stop", { chatId: activeChatId });
    }, 1000);
  };

  const deleteMessage = async (messageId, modeDelete) => {
    const res = await fetch(`${API_URL}/messages/${messageId}?mode=${modeDelete}`, {
      method: "DELETE",
      headers: authHeaders(token),
    });

    if (!res.ok) {
      setError("Не удалось удалить сообщение");
      return;
    }

    // При удалении у меня — сервер уже сохранил это в message_deletions,
    // убираем локально сразу, чтобы не ждать перезагрузки
    if (modeDelete === "me") {
      setMessages((prev) => prev.filter((m) => m.id !== messageId));
    }
    // При удалении у всех — сервер пришлёт message:deleted_for_all через сокет
  };

  const clearChat = async (chatId) => {
    if (!window.confirm("Очистить диалог? Все сообщения будут удалены у обоих пользователей.")) return;
    await fetch(`${API_URL}/chats/${chatId}/messages`, {
      method: "DELETE",
      headers: authHeaders(token),
    });
  };

  const uploadImage = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file || !activeChatId) return;

    const formData = new FormData();
    formData.append("image", file);
    const res = await fetch(`${API_URL}/chats/${activeChatId}/images`, {
      method: "POST",
      headers: authHeaders(token, false),
      body: formData,
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.error || "Не удалось загрузить фото");
    }
  };

  const uploadVoice = async () => {
    if (!activeChatId) return;
    const blob = await stopRecording();
    if (!blob) return;

    const file = new File([blob], `voice-${Date.now()}.webm`, { type: "audio/webm;codecs=opus" });
    const formData = new FormData();
    formData.append("audio", file);

    const res = await fetch(`${API_URL}/chats/${activeChatId}/voice`, {
      method: "POST",
      headers: authHeaders(token, false),
      body: formData,
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      setError(data.error || "Не удалось отправить голосовое");
    }
  };

  const touchTimeoutRef = useRef(null);

  const openMessageMenu = (event, messageId, isMine) => {
    event.preventDefault();
    const menuWidth = 200;
    const menuHeight = 92;
    const clientX = event.clientX ?? event.touches?.[0]?.clientX ?? 0;
    const clientY = event.clientY ?? event.touches?.[0]?.clientY ?? 0;
    const safeX = Math.min(clientX, window.innerWidth - menuWidth - 12);
    const safeY = Math.min(clientY, window.innerHeight - menuHeight - 12);
    setMenuState({ x: Math.max(12, safeX), y: Math.max(12, safeY), messageId, isMine });
  };

  const handleTouchStart = (event, messageId, isMine) => {
    touchTimeoutRef.current = setTimeout(() => {
      openMessageMenu(event, messageId, isMine);
    }, 500);
  };

  const handleTouchEnd = () => {
    clearTimeout(touchTimeoutRef.current);
  };

  const closeMessageMenu = () => setMenuState(null);

  // Синхронизируем ref с state
  useEffect(() => {
    activeChatIdRef.current = activeChatId;
  }, [activeChatId]);

  useEffect(() => {
    window.addEventListener("click", closeMessageMenu);
    return () => window.removeEventListener("click", closeMessageMenu);
  }, []);

  useEffect(() => {
    if (!token) return;
    loadAppData(token);
    const socket = io(SOCKET_URL, { auth: { token } });
    socketRef.current = socket;

    socket.on("presence:update", ({ userId: onlineUserId, online }) => {
      setChats((prev) =>
        prev.map((chat) =>
          chat.friend.id === onlineUserId ? { ...chat, friend: { ...chat.friend, online } } : chat
        )
      );
      setFriends((prev) => prev.map((f) => (f.id === onlineUserId ? { ...f, online } : f)));
    });

    socket.on("friend:request", (request) => {
      setRequests((prev) => {
        const exists = prev.find((r) => r.id === request.id);
        if (exists) return prev;
        return [request, ...prev];
      });
    });

    socket.on("chat:new", (chat) => {
      setChats((prev) => {
        const exists = prev.find((c) => c.chatId === chat.chatId);
        if (exists) return prev;
        return [chat, ...prev];
      });
      setFriends((prev) => {
        const exists = prev.find((f) => f.id === chat.friend.id);
        if (exists) return prev;
        return [...prev, chat.friend];
      });
    });

    socket.on("typing", ({ chatId, userId: typingUserId, typing }) => {
      if (typingUserId === user?.id) return;
      setTypingByChat((prev) => ({ ...prev, [chatId]: typing }));
    });

    socket.on("message:new", async (message) => {
      if (message.chat_id === activeChatIdRef.current) {
        setMessages((prev) => [...prev, message]);
        await fetch(`${API_URL}/chats/${activeChatIdRef.current}/read`, {
          method: "POST",
          headers: authHeaders(token),
          body: JSON.stringify({ messageId: message.id }),
        });
      } else if (message.sender_id !== user?.id) {
        const chat = chatsRef.current?.find((c) => c.chatId === message.chat_id);
        showNotification(message, chat?.friend?.login || "Новое сообщение");
        playNotificationSound();
      }
      setChats((prev) => prev.map((chat) =>
        chat.chatId === message.chat_id
          ? { ...chat, lastMessage: message }
          : chat
      ));
    });

    socket.on("message:deleted_for_all", ({ messageId }) => {
      setMessages((prev) => prev.filter((msg) => msg.id !== messageId));
      setChats((prev) => prev.map((chat) =>
        chat.lastMessage?.id === messageId
          ? { ...chat, lastMessage: null }
          : chat
      ));
    });

    socket.on("chat:cleared", ({ chatId }) => {
      if (chatId === activeChatIdRef.current) setMessages([]);
      setChats((prev) => prev.map((chat) =>
        chat.chatId === chatId
          ? { ...chat, lastMessage: null }
          : chat
      ));
    });

    socket.on("message:read", ({ chatId, userId: readUserId, messageId }) => {
      if (readUserId === user?.id) return;
      setChats((prev) => prev.map((chat) => (chat.chatId === chatId ? { ...chat, lastReadMessageId: messageId } : chat)));
    });

    return () => socket.disconnect();
  }, [token, user?.id]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    setMessages([]);
    setHasMore(false);
    if (activeChatId && token) loadMessages(activeChatId, token);
  }, [activeChatId, token]);

  useEffect(() => {
    const container = messagesContainerRef.current;
    if (!container) return;
    const handleScroll = () => {
      if (container.scrollTop < 80) loadMoreMessages();
    };
    container.addEventListener("scroll", handleScroll);
    return () => container.removeEventListener("scroll", handleScroll);
  }, [hasMore, loadingMore, activeChatId, messages.length]);

  if (!token || !user) {
    return (
      <main className="auth-layout">
        <form className="card auth-card" onSubmit={authSubmit}>
          <h1 className="auth-title">Whisp</h1>
          <p className="muted auth-hint">Логин: от 3 до 32 символов, пароль: от 6 символов</p>
          <label className="auth-label" htmlFor="auth-login">Логин</label>
          <input
            id="auth-login"
            placeholder={mode === "register" ? "Придумайте ваш логин" : "Введите логин"}
            value={authForm.login}
            onChange={(e) => setAuthForm((p) => ({ ...p, login: e.target.value }))}
          />
          <label className="auth-label" htmlFor="auth-password">Пароль</label>
          <input
            id="auth-password"
            placeholder={mode === "register" ? "Придумайте пароль" : "Введите пароль"}
            type="password"
            value={authForm.password}
            onChange={(e) => setAuthForm((p) => ({ ...p, password: e.target.value }))}
          />
          {error && <p className="error">{error}</p>}
          <button type="submit">{mode === "login" ? "Войти" : "Зарегистрироваться"}</button>
          <button type="button" className="ghost" onClick={() => setMode(mode === "login" ? "register" : "login")}>
            {mode === "login" ? "Регистрация" : "Назад"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className="app-layout">
      <aside className="sidebar">
        <div className="card section">
          <div className="top-row">
            <h2>Чаты</h2>
            <button className="ghost" onClick={logout}>Выйти</button>
          </div>
          <div className="chat-list">
            {chats.map((chat) => {
                const hasUnread = chat.lastMessage
                  && chat.lastMessage.sender_id !== user.id
                  && chat.chatId !== activeChatId
                  && (!chat.lastReadMessageId || chat.lastReadMessageId < chat.lastMessage.id);
                return (
                  <button
                    key={chat.chatId}
                    className={`chat-item ${chat.chatId === activeChatId ? "active" : ""}`}
                    onClick={() => setActiveChatId(chat.chatId)}
                  >
                    <div>
                      {chat.friend.login}{" "}
                      <span className={chat.friend.online ? "online" : "offline"}>
                        {chat.friend.online ? "online" : "offline"}
                      </span>
                      {hasUnread && <span className="unread-dot" />}
                    </div>
                    <small>
                      {chat.lastMessage?.deleted_for_everyone
                        ? "Сообщение удалено"
                        : chat.lastMessage?.message_type === "image"
                        ? "Фото"
                        : chat.lastMessage?.message_type === "voice"
                        ? "Голосовое"
                        : chat.lastMessage?.content || "Пусто"}
                    </small>
                  </button>
                );
              })}
          </div>
        </div>

        <div className="card section">
          <h2>Поиск друзей</h2>
          <div className="row">
            <input value={searchLogin} onChange={(e) => setSearchLogin(e.target.value)} placeholder="Точный логин" />
            <button onClick={searchFriend}>Найти</button>
          </div>
          {searchResult && (
            <div className="request-item">
              <span>
                {searchResult.login}
                {searchResult.relationship === "friend" ? " (уже друг)" : ""}
                {searchResult.relationship === "outgoing_pending" ? " (заявка отправлена)" : ""}
                {searchResult.relationship === "incoming_pending" ? " (ждет вашего решения)" : ""}
              </span>
              <button
                onClick={() => sendFriendRequest(searchResult.id)}
                disabled={searchResult.relationship !== "none"}
              >
                Добавить
              </button>
            </div>
          )}
          <h3>Входящие заявки</h3>
          {requests.map((request) => (
            <div className="request-item" key={request.id}>
              <span>{request.from_login}</span>
              <div className="row tight">
                <button onClick={() => respondToRequest(request.id, "accept")}>Принять</button>
                <button className="ghost" onClick={() => respondToRequest(request.id, "reject")}>Отклонить</button>
              </div>
            </div>
          ))}
          <h3>Друзья</h3>
          {friends.map((f) => (
            <div key={f.id} className="friend-item">
              {f.login}{" "}
              <span className={f.online ? "online" : "offline"}>{f.online ? "online" : "offline"}</span>
            </div>
          ))}
        </div>

        <div className="card section settings-section">
          <h2>Настройки</h2>
          <div className="settings-user">
            <span className="settings-login">👤 {user.login}</span>
          </div>
          <button className="danger-btn" onClick={deleteAccount}>
            🗑 Удалить аккаунт
          </button>
        </div>
      </aside>

      <section className="card chat-window">
        {activeChat ? (
          <>
            <header className="chat-header">
              <h2>{activeChat.friend.login}</h2>
              <span className={activeChat.friend.online ? "online" : "offline"}>
                {activeChat.friend.online ? "online" : "не в сети"}
              </span>
              <button className="ghost" onClick={() => clearChat(activeChatId)}>
                🗑 Очистить
              </button>
            </header>
            <div className="messages" ref={messagesContainerRef}>
              {loadingMore && <p className="muted" style={{textAlign:"center"}}>Загрузка...</p>}
              {messages.map((msg) => {
                const isMine = msg.sender_id === user.id;
                const isRead = activeChat?.lastReadMessageId >= msg.id;
                const date = new Date(msg.created_at);
                const time = date.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
                const today = new Date();
                const yesterday = new Date(today);
                yesterday.setDate(yesterday.getDate() - 1);
                const msgDate = date.toDateString();
                const prevMsg = messages[messages.indexOf(msg) - 1];
                const prevDate = prevMsg ? new Date(prevMsg.created_at).toDateString() : null;
                let dateLabel = null;
                if (msgDate !== prevDate) {
                  if (msgDate === today.toDateString()) dateLabel = "Сегодня";
                  else if (msgDate === yesterday.toDateString()) dateLabel = "Вчера";
                  else dateLabel = date.toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric" });
                }
                return (
                  <>
                    {dateLabel && <div key={`date-${msg.id}`} className="date-divider"><span>{dateLabel}</span></div>}
                    <div
                      key={msg.id}
                      className={`msg ${isMine ? "mine" : ""}`}
                      onContextMenu={(event) => openMessageMenu(event, msg.id, isMine)}
                      onTouchStart={(event) => handleTouchStart(event, msg.id, isMine)}
                      onTouchEnd={handleTouchEnd}
                      onTouchMove={handleTouchEnd}
                    >
                      {msg.message_type === "image" && msg.image_path ? (
                        <img className="msg-image" src={buildFileUrl(msg.image_path)} alt={msg.content || "Фото"} />
                      ) : msg.message_type === "voice" && msg.audio_path ? (
                        <VoiceMessage src={buildFileUrl(msg.audio_path)} isMine={isMine} />
                      ) : (
                        <p>{msg.content}</p>
                      )}
                      <div className="msg-meta">
                        <span className="msg-time">{time}</span>
                        {isMine && (
                          <span className={`msg-status ${isRead ? "read" : ""}`}>
                            {isRead ? (
                              <svg viewBox="0 0 16 11" width="16" height="11" fill="currentColor">
                                <path d="M11.071.653a.75.75 0 0 1 .976 1.138l-6.5 6a.75.75 0 0 1-1.094-.062l-2.5-3a.75.75 0 1 1 1.147-.956l1.976 2.37 5.995-5.49z"/>
                                <path d="M14.071.653a.75.75 0 0 1 .976 1.138l-6.5 6a.75.75 0 0 1-1.008-.046L5.584 5.8a.75.75 0 1 1 1.05-1.072l1.6 1.565 5.837-5.64z"/>
                              </svg>
                            ) : (
                              <svg viewBox="0 0 12 11" width="12" height="11" fill="currentColor">
                                <path d="M10.071.653a.75.75 0 0 1 .976 1.138l-6.5 6a.75.75 0 0 1-1.094-.062l-2.5-3a.75.75 0 1 1 1.147-.956l1.976 2.37 5.995-5.49z"/>
                              </svg>
                            )}
                          </span>
                        )}
                      </div>
                    </div>
                  </>
                );
              })}
              {typingByChat[activeChatId] && <p className="muted">Печатает...</p>}
              <div ref={messagesEndRef} />
            </div>
            <footer className="row">
              <input ref={imageInputRef} type="file" accept="image/*" onChange={uploadImage} className="file-input-hidden" />

              <div className="input-wrap">
                <input
                  placeholder="Сообщение..."
                  value={messageText}
                  onChange={(e) => handleTyping(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                />
                <button
                  className="attach-inside"
                  onClick={() => imageInputRef.current?.click()}
                  title="Прикрепить файл"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" width="22" height="22"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                </button>
              </div>

              {messageText.trim() ? (
                <button className="send-btn" onClick={sendMessage} title="Отправить">
                  <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"/></svg>
                </button>
              ) : (
                <button
                  className={isRecording ? "send-btn recording-active" : "icon-btn ghost"}
                  onClick={async () => {
                    if (isRecording) await uploadVoice();
                    else await startRecording();
                  }}
                  title={isRecording ? "Отправить голосовое" : "Записать голосовое"}
                >
                  {isRecording ? (
                    <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
                  ) : (
                    <svg viewBox="0 0 24 24" fill="currentColor" width="20" height="20"><path d="M12 1a4 4 0 0 1 4 4v6a4 4 0 0 1-8 0V5a4 4 0 0 1 4-4zm0 2a2 2 0 0 0-2 2v6a2 2 0 0 0 4 0V5a2 2 0 0 0-2-2zm7 8a1 1 0 0 1 1 1 8 8 0 0 1-7 7.938V21h2a1 1 0 0 1 0 2H9a1 1 0 0 1 0-2h2v-1.062A8 8 0 0 1 4 12a1 1 0 0 1 2 0 6 6 0 0 0 12 0 1 1 0 0 1 1-1z"/></svg>
                  )}
                </button>
              )}
            </footer>
          </>
        ) : (
          <div className="empty">
            <div className="empty-icon">💬</div>
            <p className="empty-title">Выберите чат</p>
            <p className="empty-hint">Выберите диалог из списка слева<br />или найдите друга через поиск</p>
          </div>
        )}
      </section>

      {menuState && (
        <div className="context-menu" style={{ top: `${menuState.y}px`, left: `${menuState.x}px` }}>
          <button className="ghost" onClick={() => { deleteMessage(menuState.messageId, "me"); closeMessageMenu(); }}>
            Удалить у меня
          </button>
          <button className="ghost" onClick={() => { deleteMessage(menuState.messageId, "all"); closeMessageMenu(); }}>
            Удалить у всех
          </button>
        </div>
      )}
    </main>
  );
}

export default App;
