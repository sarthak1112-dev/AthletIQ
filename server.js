/**
 * AthletIQ Full-Stack Backend Server
 * Built with native Node.js (node:http & node:sqlite)
 * Zero external npm dependencies required!
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'athletiq.db');

// --- Initialize SQLite Database ---
const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    sport TEXT DEFAULT '',
    location TEXT DEFAULT '',
    team TEXT DEFAULT '',
    experience TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    passwordHash TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    author TEXT NOT NULL,
    role TEXT NOT NULL,
    sport TEXT DEFAULT '',
    text TEXT NOT NULL,
    mediaType TEXT DEFAULT '',
    mediaData TEXT DEFAULT '',
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    fromEmail TEXT NOT NULL,
    toEmail TEXT NOT NULL,
    status TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    toEmail TEXT NOT NULL,
    fromEmail TEXT NOT NULL,
    type TEXT NOT NULL,
    isRead INTEGER DEFAULT 0,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    fromEmail TEXT NOT NULL,
    toEmail TEXT NOT NULL,
    text TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

console.log('✓ SQLite database initialized at:', DB_PATH);

// --- Helpers ---
function hashPassword(email, password) {
  const text = email.trim().toLowerCase() + ':' + password;
  return crypto.createHash('sha256').update(text).digest('hex');
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) { // 50MB max limit
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

// --- MIME Types for Static Files ---
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// --- HTTP Server ---
const server = http.createServer(async (req, res) => {
  // CORS Pre-flight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // ========================================================
  // REST API ENDPOINTS
  // ========================================================

  // --- Auth: Register ---
  if (req.method === 'POST' && pathname === '/api/auth/register') {
    try {
      const { name, email, role, password } = await parseJsonBody(req);
      if (!name || !email || !password) {
        return sendJson(res, 400, { error: 'Name, email, and password are required.' });
      }
      const cleanEmail = email.trim().toLowerCase();
      const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
      if (existing) {
        return sendJson(res, 400, { error: 'An account with this email already exists.' });
      }

      const hash = hashPassword(cleanEmail, password);
      const createdAt = new Date().toISOString();
      const insert = db.prepare(`
        INSERT INTO users (email, name, role, passwordHash, createdAt)
        VALUES (?, ?, ?, ?, ?)
      `);
      insert.run(cleanEmail, name.trim(), role || 'player', hash, createdAt);

      return sendJson(res, 201, {
        success: true,
        user: { email: cleanEmail, name: name.trim(), role: role || 'player' }
      });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Auth: Login ---
  if (req.method === 'POST' && pathname === '/api/auth/login') {
    try {
      const { email, password } = await parseJsonBody(req);
      if (!email || !password) {
        return sendJson(res, 400, { error: 'Email and password are required.' });
      }
      const cleanEmail = email.trim().toLowerCase();
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(cleanEmail);
      if (!user) {
        return sendJson(res, 401, { error: 'Incorrect credentials' });
      }

      const hash = hashPassword(cleanEmail, password);
      if (user.passwordHash !== hash) {
        return sendJson(res, 401, { error: 'Incorrect credentials' });
      }

      const { passwordHash, ...safeUser } = user;
      return sendJson(res, 200, { success: true, user: safeUser });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Auth: Get Profile /api/users/profile?email=... ---
  if (req.method === 'GET' && pathname === '/api/users/profile') {
    const email = (parsedUrl.searchParams.get('email') || '').trim().toLowerCase();
    if (!email) return sendJson(res, 400, { error: 'Email parameter required.' });

    const user = db.prepare('SELECT id, email, name, role, sport, location, team, experience, bio, createdAt FROM users WHERE email = ?').get(email);
    if (!user) return sendJson(res, 404, { error: 'User not found.' });

    return sendJson(res, 200, user);
  }

  // --- Update Profile ---
  if (req.method === 'PUT' && pathname === '/api/users/profile') {
    try {
      const data = await parseJsonBody(req);
      const email = (data.email || '').trim().toLowerCase();
      if (!email) return sendJson(res, 400, { error: 'Email is required.' });

      db.prepare(`
        UPDATE users
        SET name = COALESCE(?, name),
            role = COALESCE(?, role),
            sport = COALESCE(?, sport),
            location = COALESCE(?, location),
            team = COALESCE(?, team),
            experience = COALESCE(?, experience),
            bio = COALESCE(?, bio)
        WHERE email = ?
      `).run(data.name, data.role, data.sport, data.location, data.team, data.experience, data.bio, email);

      const updated = db.prepare('SELECT id, email, name, role, sport, location, team, experience, bio, createdAt FROM users WHERE email = ?').get(email);
      return sendJson(res, 200, { success: true, user: updated });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Get All Users (For Connect Page) ---
  if (req.method === 'GET' && pathname === '/api/users') {
    const exclude = (parsedUrl.searchParams.get('exclude') || '').trim().toLowerCase();
    const query = (parsedUrl.searchParams.get('q') || '').trim().toLowerCase();

    let users = db.prepare('SELECT id, email, name, role, sport, location, team, experience, bio, createdAt FROM users').all();
    if (exclude) {
      users = users.filter(u => u.email !== exclude);
    }
    if (query) {
      users = users.filter(u => u.email.includes(query) || (u.name && u.name.toLowerCase().includes(query)));
    }
    return sendJson(res, 200, users);
  }

  // --- Posts: List ---
  if (req.method === 'GET' && pathname === '/api/posts') {
    const posts = db.prepare('SELECT * FROM posts ORDER BY id DESC').all();
    return sendJson(res, 200, posts);
  }

  // --- Posts: Create ---
  if (req.method === 'POST' && pathname === '/api/posts') {
    try {
      const data = await parseJsonBody(req);
      if (!data.text && !data.mediaData) {
        return sendJson(res, 400, { error: 'Post must contain text or media.' });
      }
      const createdAt = new Date().toISOString();
      const insert = db.prepare(`
        INSERT INTO posts (email, author, role, sport, text, mediaType, mediaData, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const result = insert.run(
        (data.email || '').trim().toLowerCase(),
        data.author || 'Athlete',
        data.role || 'player',
        data.sport || '',
        data.text || '',
        data.mediaType || '',
        data.mediaData || '',
        createdAt
      );

      return sendJson(res, 201, { success: true, id: Number(result.lastInsertRowid) });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Posts: Delete ---
  if (req.method === 'DELETE' && pathname.startsWith('/api/posts/')) {
    const id = parseInt(pathname.slice('/api/posts/'.length), 10);
    const email = (parsedUrl.searchParams.get('email') || '').trim().toLowerCase();

    if (!id) return sendJson(res, 400, { error: 'Invalid post id.' });
    const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
    if (!post) return sendJson(res, 404, { error: 'Post not found.' });

    if (email && post.email !== email) {
      return sendJson(res, 403, { error: 'Unauthorized to delete this post.' });
    }

    db.prepare('DELETE FROM posts WHERE id = ?').run(id);
    return sendJson(res, 200, { success: true });
  }

  // --- Connections: Status ---
  if (req.method === 'GET' && pathname === '/api/connections/status') {
    const me = (parsedUrl.searchParams.get('me') || '').trim().toLowerCase();
    const other = (parsedUrl.searchParams.get('other') || '').trim().toLowerCase();

    const conn = db.prepare(`
      SELECT * FROM connections
      WHERE (fromEmail = ? AND toEmail = ?) OR (fromEmail = ? AND toEmail = ?)
    `).get(me, other, other, me);

    if (!conn) return sendJson(res, 200, { status: 'none' });
    if (conn.status === 'accepted') return sendJson(res, 200, { status: 'connected' });
    return sendJson(res, 200, { status: conn.fromEmail === me ? 'sent' : 'received' });
  }

  // --- Connections: Send Request ---
  if (req.method === 'POST' && pathname === '/api/connections/request') {
    try {
      const { fromEmail, toEmail } = await parseJsonBody(req);
      const me = fromEmail.trim().toLowerCase();
      const other = toEmail.trim().toLowerCase();

      const existing = db.prepare(`
        SELECT * FROM connections
        WHERE (fromEmail = ? AND toEmail = ?) OR (fromEmail = ? AND toEmail = ?)
      `).get(me, other, other, me);

      if (existing) return sendJson(res, 200, { message: 'Already requested or connected' });

      const id = Date.now() + '-' + Math.random().toString(36).slice(2, 6);
      const createdAt = new Date().toISOString();

      db.prepare(`
        INSERT INTO connections (id, fromEmail, toEmail, status, createdAt)
        VALUES (?, ?, ?, 'pending', ?)
      `).run(id, me, other, createdAt);

      // Create notification for other user
      const noteId = Date.now() + '-' + Math.random().toString(36).slice(2, 6);
      db.prepare(`
        INSERT INTO notifications (id, toEmail, fromEmail, type, isRead, createdAt)
        VALUES (?, ?, ?, 'request', 0, ?)
      `).run(noteId, other, me, createdAt);

      return sendJson(res, 201, { success: true, status: 'sent' });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Connections: Accept / Decline / Disconnect ---
  if (req.method === 'POST' && pathname === '/api/connections/respond') {
    try {
      const { me, other, action } = await parseJsonBody(req);
      const myEmail = me.trim().toLowerCase();
      const otherEmail = other.trim().toLowerCase();

      if (action === 'accept') {
        db.prepare(`
          UPDATE connections SET status = 'accepted'
          WHERE fromEmail = ? AND toEmail = ? AND status = 'pending'
        `).run(otherEmail, myEmail);

        // Add accepted notification
        const noteId = Date.now() + '-' + Math.random().toString(36).slice(2, 6);
        db.prepare(`
          INSERT INTO notifications (id, toEmail, fromEmail, type, isRead, createdAt)
          VALUES (?, ?, ?, 'accepted', 0, ?)
        `).run(noteId, otherEmail, myEmail, new Date().toISOString());

        return sendJson(res, 200, { success: true, status: 'connected' });
      }

      if (action === 'decline' || action === 'cancel' || action === 'disconnect') {
        db.prepare(`
          DELETE FROM connections
          WHERE (fromEmail = ? AND toEmail = ?) OR (fromEmail = ? AND toEmail = ?)
        `).run(myEmail, otherEmail, otherEmail, myEmail);

        return sendJson(res, 200, { success: true, status: 'none' });
      }

      return sendJson(res, 400, { error: 'Unknown action.' });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Notifications ---
  if (req.method === 'GET' && pathname === '/api/notifications') {
    const email = (parsedUrl.searchParams.get('email') || '').trim().toLowerCase();
    const notes = db.prepare(`
      SELECT n.*, u.name as fromName
      FROM notifications n
      LEFT JOIN users u ON u.email = n.fromEmail
      WHERE n.toEmail = ?
      ORDER BY n.createdAt DESC
    `).all(email);

    return sendJson(res, 200, notes);
  }

  if (req.method === 'POST' && pathname === '/api/notifications/mark-read') {
    try {
      const { email } = await parseJsonBody(req);
      db.prepare('UPDATE notifications SET isRead = 1 WHERE toEmail = ?').run(email.trim().toLowerCase());
      return sendJson(res, 200, { success: true });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // --- Messages: History ---
  if (req.method === 'GET' && pathname === '/api/messages') {
    const me = (parsedUrl.searchParams.get('me') || '').trim().toLowerCase();
    const other = (parsedUrl.searchParams.get('other') || '').trim().toLowerCase();

    const messages = db.prepare(`
      SELECT * FROM messages
      WHERE (fromEmail = ? AND toEmail = ?) OR (fromEmail = ? AND toEmail = ?)
      ORDER BY createdAt ASC
    `).all(me, other, other, me);

    return sendJson(res, 200, messages);
  }

  // --- Messages: Send ---
  if (req.method === 'POST' && pathname === '/api/messages') {
    try {
      const { fromEmail, toEmail, text } = await parseJsonBody(req);
      if (!text || !fromEmail || !toEmail) {
        return sendJson(res, 400, { error: 'fromEmail, toEmail, and text are required.' });
      }

      const id = Date.now() + '-' + Math.random().toString(36).slice(2, 6);
      const createdAt = new Date().toISOString();

      db.prepare(`
        INSERT INTO messages (id, fromEmail, toEmail, text, createdAt)
        VALUES (?, ?, ?, ?, ?)
      `).run(id, fromEmail.trim().toLowerCase(), toEmail.trim().toLowerCase(), text.trim(), createdAt);

      return sendJson(res, 201, { success: true, id, createdAt });
    } catch (err) {
      return sendJson(res, 500, { error: err.message });
    }
  }

  // ========================================================
  // STATIC FILE SERVING
  // ========================================================
  let filePath = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  filePath = decodeURIComponent(filePath);
  const fullPath = path.join(__dirname, filePath);

  // Security check: ensure path stays within workspace root
  if (!fullPath.startsWith(__dirname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Access denied');
    return;
  }

  fs.stat(fullPath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<h1>404 - Not Found</h1><p>File not found: ${pathname}</p>`);
      return;
    }

    const ext = path.extname(fullPath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    const stream = fs.createReadStream(fullPath);
    stream.pipe(res);
  });
});

server.listen(PORT, () => {
  console.log(`\n==================================================`);
  console.log(`🚀 AthletIQ Full-Stack Server running!`);
  console.log(`🌐 Open in your browser: http://localhost:${PORT}`);
  console.log(`📁 Database: SQLite (${DB_PATH})`);
  console.log(`==================================================\n`);
});
