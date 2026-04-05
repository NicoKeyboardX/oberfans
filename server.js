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
const PORT = 3000;
const JWT_SECRET = 'oberfans_secret_aendere_mich_in_produktion';

// ─── Verzeichnisse ──────────────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const POSTS_FILE  = path.join(DATA_DIR, 'posts.json');

[DATA_DIR, UPLOADS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}');
if (!fs.existsSync(POSTS_FILE)) fs.writeFileSync(POSTS_FILE, '[]');

// ─── Hilfsfunktionen ────────────────────────────────────────────────────────
const readUsers  = () => JSON.parse(fs.readFileSync(USERS_FILE));
const saveUsers  = d  => fs.writeFileSync(USERS_FILE, JSON.stringify(d, null, 2));
const readPosts  = () => JSON.parse(fs.readFileSync(POSTS_FILE));
const savePosts  = d  => fs.writeFileSync(POSTS_FILE, JSON.stringify(d, null, 2));

// ─── Middleware ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(__dirname)); // Liefert index.html

// Multer – Bild-Upload
const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOADS_DIR),
    filename:    (_, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
    fileFilter: (_, file, cb) => {
        const allowed = /jpeg|jpg|png|gif|webp/;
        cb(null, allowed.test(file.mimetype));
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
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Felder fehlen' });
    if (username.length < 3)     return res.status(400).json({ error: 'Benutzername zu kurz (min. 3)' });
    if (password.length < 6)     return res.status(400).json({ error: 'Passwort zu kurz (min. 6)' });

    const users = readUsers();
    if (users[username]) return res.status(409).json({ error: 'Benutzername existiert bereits' });

    users[username] = {
        passwordHash: await bcrypt.hash(password, 10),
        createdAt: new Date().toISOString(),
        avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${username}`
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

    const token = jwt.sign({ username, avatar: user.avatar }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username, avatar: user.avatar });
});

// ─── Post Routen ────────────────────────────────────────────────────────────

// Alle Posts laden
app.get('/api/posts', auth, (_, res) => {
    res.json(readPosts().reverse()); // Neueste zuerst
});

// Neuen Post erstellen (mit Bild)
app.post('/api/posts', auth, upload.single('image'), (req, res) => {
    const { caption } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    if (!caption && !imageUrl)
        return res.status(400).json({ error: 'Bild oder Text erforderlich' });

    const posts = readPosts();
    const newPost = {
        id: 'post_' + Date.now(),
        author: req.user.username,
        avatar: req.user.avatar,
        caption: caption || '',
        imageUrl,
        likes: [],
        dislikes: [],
        comments: [],
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

    const user = req.user.username;
    const opposite = type === 'like' ? 'dislikes' : 'likes';
    const current  = type === 'like' ? 'likes'    : 'dislikes';

    // Toggle: entfernen falls schon reagiert, sonst hinzufügen
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

    const comment = { user: req.user.username, text, createdAt: new Date().toISOString() };
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
