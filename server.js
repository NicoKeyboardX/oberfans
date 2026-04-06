/**
 * OberFans – Backend Server
 * Starte mit: node server.js
 * Benötigt: npm install express multer bcryptjs jsonwebtoken cors
 */

const express = require('express');
const multer  = require('multer');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'oberfans_secret_aendere_mich_in_produktion';

// ─── Verzeichnisse ──────────────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const POSTS_FILE  = path.join(DATA_DIR, 'posts.json');

[DATA_DIR, UPLOADS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(POSTS_FILE)) fs.writeFileSync(POSTS_FILE, '[]');

// ─── Hilfsfunktionen ────────────────────────────────────────────────────────
const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
const saveUsers = d  => fs.writeFileSync(USERS_FILE, JSON.stringify(d, null, 2));
const readPosts = () => JSON.parse(fs.readFileSync(POSTS_FILE, 'utf8'));
const savePosts = d  => fs.writeFileSync(POSTS_FILE, JSON.stringify(d, null, 2));

function calcAge(birthStr) {
  const b = new Date(birthStr), t = new Date();
  let a = t.getFullYear() - b.getFullYear();
  if (
    t.getMonth() - b.getMonth() < 0 ||
    (t.getMonth() - b.getMonth() === 0 && t.getDate() < b.getDate())
  ) a--;
  return a;
}

// ─── Middleware ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '15mb' })); // für base64-Avatare
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(__dirname));

// Multer – Medien-Upload (Bilder & Videos)
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename:    (_, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB (für Videos)
  fileFilter: (_, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|webm|ogg|mov/;
    const ok = allowed.test(file.mimetype) || allowed.test(path.extname(file.originalname).toLowerCase());
    cb(null, ok);
  }
});

// JWT-Auth Middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Nicht eingeloggt' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Ungültiger Token' });
  }
}

// ─── Auth Routen ────────────────────────────────────────────────────────────

// Registrierung
app.post('/api/register', async (req, res) => {
  const { username, password, bio, gender, birthdate, avatar } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'Felder fehlen' });
  if (username.length < 2)
    return res.status(400).json({ error: 'Benutzername zu kurz (min. 2 Zeichen)' });
  if (!/^[a-zA-Z0-9_.-]+$/.test(username))
    return res.status(400).json({ error: 'Benutzername darf nur Buchstaben, Zahlen, _ . - enthalten' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Passwort zu kurz (min. 6 Zeichen)' });
  if (!birthdate)
    return res.status(400).json({ error: 'Geburtsdatum erforderlich' });
  if (!gender)
    return res.status(400).json({ error: 'Geschlecht erforderlich' });

  const age = calcAge(birthdate);
  if (age < 13)
    return res.status(400).json({ error: 'Du musst mindestens 13 Jahre alt sein.' });

  const users = readUsers();
  if (users[username])
    return res.status(409).json({ error: 'Benutzername existiert bereits' });

  // Avatar: entweder hochgeladenes Base64-Bild oder DiceBear-Fallback
  const avatarUrl = (avatar && avatar.startsWith('data:'))
    ? avatar
    : `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(username)}`;

  users[username] = {
    passwordHash: await bcrypt.hash(password, 10),
    bio:          bio || '',
    gender:       gender || '',
    birthdate:    birthdate || '',
    age:          age,
    avatar:       avatarUrl,
    createdAt:    new Date().toISOString()
  };
  saveUsers(users);
  res.json({ message: 'Konto erstellt!' });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readUsers();
  const user  = users[username];

  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: 'Falscher Benutzername oder Passwort' });

  // Alter bei Login neu berechnen (kann sich jährlich ändern)
  if (user.birthdate) {
    user.age = calcAge(user.birthdate);
    saveUsers(users);
  }

  const tokenPayload = {
    username,
    avatar:  user.avatar,
    bio:     user.bio    || '',
    gender:  user.gender || '',
    age:     user.age    || ''
  };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    token,
    username,
    avatar:  user.avatar,
    bio:     user.bio    || '',
    gender:  user.gender || '',
    age:     user.age    || ''
  });
});

// Profil aktualisieren
app.put('/api/profile', auth, async (req, res) => {
  const { bio, gender, age, avatar } = req.body;
  const users = readUsers();
  const user  = users[req.user.username];
  if (!user) return res.status(404).json({ error: 'Nutzer nicht gefunden' });

  if (age !== undefined && age !== '' && (isNaN(age) || Number(age) < 13))
    return res.status(400).json({ error: 'Alter muss mind. 13 sein' });

  if (bio     !== undefined) user.bio    = bio;
  if (gender  !== undefined) user.gender = gender;
  if (age     !== undefined) user.age    = age ? Number(age) : '';
  if (avatar  !== undefined && avatar.startsWith('data:')) user.avatar = avatar;

  saveUsers(users);

  const updatedUser = users[req.user.username];
  const newToken = jwt.sign(
    { username: req.user.username, avatar: updatedUser.avatar, bio: updatedUser.bio, gender: updatedUser.gender, age: updatedUser.age },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    message: 'Profil aktualisiert',
    token:   newToken,
    avatar:  updatedUser.avatar,
    bio:     updatedUser.bio,
    gender:  updatedUser.gender,
    age:     updatedUser.age
  });
});

// Öffentliches Profil abrufen
app.get('/api/users/:username', auth, (req, res) => {
  const users = readUsers();
  const user  = users[req.params.username];
  if (!user) return res.status(404).json({ error: 'Nutzer nicht gefunden' });

  // Keine sensiblen Daten zurückgeben
  res.json({
    username: req.params.username,
    avatar:   user.avatar,
    bio:      user.bio    || '',
    gender:   user.gender || '',
    age:      user.age    || '',
    createdAt: user.createdAt
  });
});

// ─── Post Routen ────────────────────────────────────────────────────────────

// Alle Posts laden
app.get('/api/posts', auth, (_, res) => {
  res.json(readPosts().reverse());
});

// Neuen Post erstellen (Bild oder Video)
app.post('/api/posts', auth, upload.single('image'), (req, res) => {
  const { caption } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  if (!caption && !imageUrl)
    return res.status(400).json({ error: 'Bild, Video oder Text erforderlich' });

  const posts   = readPosts();
  const newPost = {
    id:        'post_' + Date.now(),
    author:    req.user.username,
    avatar:    req.user.avatar,
    caption:   caption || '',
    imageUrl,
    likes:     [],
    dislikes:  [],
    comments:  [],
    createdAt: new Date().toISOString()
  };
  posts.push(newPost);
  savePosts(posts);
  res.json(newPost);
});

// Like / Dislike
app.post('/api/posts/:id/react', auth, (req, res) => {
  const { type } = req.body; // 'like' | 'dislike'
  const posts = readPosts();
  const post  = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post nicht gefunden' });

  const user     = req.user.username;
  const opposite = type === 'like' ? 'dislikes' : 'likes';
  const current  = type === 'like' ? 'likes'    : 'dislikes';

  if (!post[opposite]) post[opposite] = [];
  if (!post[current])  post[current]  = [];

  post[opposite] = post[opposite].filter(u => u !== user);
  const idx = post[current].indexOf(user);
  idx === -1 ? post[current].push(user) : post[current].splice(idx, 1);

  savePosts(posts);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});

// Kommentar hinzufügen
app.post('/api/posts/:id/comment', auth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Kommentar leer' });

  const posts = readPosts();
  const post  = posts.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post nicht gefunden' });

  const comment = {
    user:      req.user.username,
    avatar:    req.user.avatar,
    text:      text.trim(),
    createdAt: new Date().toISOString(),
    replies:   []
  };
  post.comments.push(comment);
  savePosts(posts);
  res.json(comment);
});

// ─── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  OberFans läuft auf http://localhost:${PORT}`);
  console.log(`📁  Nutzerdaten: ${USERS_FILE}`);
  console.log(`📁  Posts:       ${POSTS_FILE}`);
  console.log(`📂  Uploads:     ${UPLOADS_DIR}\n`);
});
