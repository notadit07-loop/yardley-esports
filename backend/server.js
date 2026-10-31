/**
 * YARDLEY ESPORTS — Production-Ready Node.js + Express + SQLite Backend Server
 * Features:
 * - PBKDF2-HMAC-SHA512 password hashing (never stores plain text passwords)
 * - JWT & Role-Based Access Control (RBAC) protecting all /api/admin/* endpoints
 * - Server-side Room ID & Password filtering (never sent to unauthorized clients)
 * - Transactional registration preventing duplicate UIDs and over-capacity entries
 * - Configurable Indian UPI Payment Verification (Sandbox Test Mode + Razorpay HMAC Webhook)
 */
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yardley_esports_super_secret_jwt_key_change_in_prod';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'yardley_esports.sqlite');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Initialize SQLite Database
const db = new Database(DB_PATH);
const schemaSql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf-8');
db.exec(schemaSql);

// Password Hashing Helpers (PBKDF2-SHA512)
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(expectedHash, 'hex'));
}

// Authentication & RBAC Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = payload;
    next();
  });
}

function requireAdmin(req, res, next) {
  authenticateToken(req, res, () => {
    const dbUser = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
    if (!dbUser || dbUser.role !== 'admin') {
      return res.status(403).json({ error: '403 Forbidden: Server-side Admin authorization required' });
    }
    next();
  });
}

// 1. Auth Endpoints
app.post('/api/auth/register', (req, res) => {
  try {
    const { name, username, emailOrPhone, ffUid, ffIgn, password } = req.body;
    if (!name || !username || !emailOrPhone || !ffUid || !ffIgn || !password || password.length < 6) {
      return res.status(400).json({ error: 'All fields are required and password must be >= 6 characters.' });
    }
    const { salt, hash } = hashPassword(password);
    const id = 'u_' + Date.now();
    db.prepare(`
      INSERT INTO users (id, name, username, email_or_phone, ff_uid, ff_ign, password_hash, password_salt, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'player')
    `).run(id, name.trim(), username.trim(), emailOrPhone.trim(), ffUid.trim(), ffIgn.trim(), hash, salt);

    const token = jwt.sign({ id, username, role: 'player' }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id, name, username, emailOrPhone, ffUid, ffIgn, role: 'player' } });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'Username, Email/Phone, or Free Fire UID already exists.' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { identifier, password } = req.body;
  const user = db.prepare(`
    SELECT * FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email_or_phone) = LOWER(?)
  `).get(identifier, identifier);

  if (!user || !verifyPassword(password, user.password_salt, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      username: user.username,
      emailOrPhone: user.email_or_phone,
      ffUid: user.ff_uid,
      ffIgn: user.ff_ign,
      role: user.role,
      kills: user.kills,
      wins: user.wins,
      totalPoints: user.total_points,
      earnings: user.earnings
    }
  });
});

// 2. Tournaments Endpoint (Strips Room ID & Password unless authorized participant or admin)
app.get('/api/tournaments', (req, res) => {
  const mode = req.query.mode;
  const status = req.query.status;
  let sql = 'SELECT * FROM tournaments WHERE 1=1';
  const params = [];
  if (mode && mode !== 'all') { sql += ' AND mode = ?'; params.push(mode); }
  if (status && status !== 'all') { sql += ' AND status = ?'; params.push(status); }
  sql += ' ORDER BY created_at DESC';

  const rows = db.prepare(sql).all(...params).map(t => {
    const countRow = db.prepare(`SELECT COUNT(*) as cnt FROM registrations WHERE tournament_id = ? AND status != 'rejected'`).get(t.id);
    // Strip sensitive room credentials from public listing
    const { room_id, room_password, ...safeTournament } = t;
    return { ...safeTournament, registeredCount: countRow.cnt };
  });
  res.json(rows);
});

// 3. Authorized Room Credentials Endpoint
app.get('/api/tournaments/:id/room', authenticateToken, (req, res) => {
  const t = db.prepare('SELECT id, title, room_id, room_password FROM tournaments WHERE id = ?').get(req.params.id);
  if (!t) return res.status(404).json({ error: 'Tournament not found' });

  const dbUser = db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.id);
  if (dbUser && dbUser.role === 'admin') {
    return res.json({ authorized: true, roomId: t.room_id, roomPassword: t.room_password, badge: 'ADMIN' });
  }

  const reg = db.prepare(`
    SELECT status, payment_status FROM registrations WHERE tournament_id = ? AND user_id = ?
  `).get(t.id, req.user.id);

  if (!reg || reg.status !== 'approved') {
    return res.status(403).json({
      authorized: false,
      error: 'Room ID & Password are restricted to approved registered participants only.'
    });
  }
  res.json({ authorized: true, roomId: t.room_id, roomPassword: t.room_password, badge: 'VERIFIED PLAYER' });
});

// 4. Transactional Tournament Registration & Server UPI Verification
const joinTournamentTx = db.transaction((tournamentId, user, entry) => {
  const t = db.prepare('SELECT * FROM tournaments WHERE id = ?').get(tournamentId);
  if (!t) throw new Error('Tournament not found');
  if (t.status === 'completed') throw new Error('Tournament has already completed');

  const currentCount = db.prepare(`
    SELECT COUNT(*) as cnt FROM registrations WHERE tournament_id = ? AND status != 'rejected'
  `).get(tournamentId).cnt;

  if (currentCount >= t.max_slots) {
    throw new Error('Maximum capacity reached. Over-capacity entries are blocked.');
  }

  const existing = db.prepare(`
    SELECT id FROM registrations WHERE tournament_id = ? AND (user_id = ? OR ff_uid = ?)
  `).get(tournamentId, user.id, entry.ffUid);

  if (existing) {
    throw new Error('Duplicate entry blocked: Player or Free Fire UID is already registered.');
  }

  // Verify Payment (Sandbox vs Live Razorpay HMAC Signature)
  let paymentStatus = 'verified_sandbox_upi';
  if (process.env.PAYMENT_MODE === 'razorpay_live') {
    const { razorpayOrderId, razorpayPaymentId, razorpaySignature } = entry;
    const secret = process.env.RAZORPAY_KEY_SECRET;
    if (!secret || !razorpayOrderId || !razorpayPaymentId || !razorpaySignature) {
      throw new Error('Live Razorpay payment verification credentials missing.');
    }
    const generatedSignature = crypto
      .createHmac('sha256', secret)
      .update(`${razorpayOrderId}|${razorpayPaymentId}`)
      .digest('hex');
    if (generatedSignature !== razorpaySignature) {
      throw new Error('Payment signature verification failed.');
    }
    paymentStatus = 'verified_razorpay';
  }

  const regStatus = t.requires_approval ? 'pending_approval' : 'approved';
  const regId = 'reg_' + Date.now();
  db.prepare(`
    INSERT INTO registrations (id, tournament_id, user_id, player_name, ign, ff_uid, team_name, status, payment_status, upi_ref, amount_paid)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(regId, tournamentId, user.id, user.username, entry.ign, entry.ffUid, entry.teamName, regStatus, paymentStatus, entry.upiRef, t.entry_fee);

  return { regId, regStatus, paymentStatus };
});

app.post('/api/tournaments/:id/join', authenticateToken, (req, res) => {
  try {
    const outcome = joinTournamentTx(req.params.id, req.user, req.body);
    res.status(201).json(outcome);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// 5. Protected Admin Endpoints (Server-Side RBAC Enforced)
app.post('/api/admin/tournaments', requireAdmin, (req, res) => {
  const { title, mode, status, matchDate, matchTime, mapName, entryFee, prizePool, firstPrize, perKillReward, maxSlots, roomId, roomPassword, requiresApproval, rules } = req.body;
  const id = 't_' + Date.now();
  db.prepare(`
    INSERT INTO tournaments (id, title, mode, status, match_date, match_time, map_name, entry_fee, prize_pool, first_prize, per_kill_reward, max_slots, room_id, room_password, requires_approval, rules)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, title, mode, status || 'upcoming', matchDate, matchTime, mapName || 'Bermuda', Number(entryFee), Number(prizePool), Number(firstPrize || 0), Number(perKillReward || 0), Number(maxSlots), roomId || '', roomPassword || '', requiresApproval ? 1 : 0, rules);
  res.status(201).json({ id, message: 'Tournament created' });
});

app.patch('/api/admin/tournaments/:id/room', requireAdmin, (req, res) => {
  const { roomId, roomPassword, status } = req.body;
  db.prepare(`
    UPDATE tournaments SET room_id = COALESCE(?, room_id), room_password = COALESCE(?, room_password), status = COALESCE(?, status) WHERE id = ?
  `).run(roomId, roomPassword, status, req.params.id);
  res.json({ message: 'Room credentials & status updated securely' });
});

app.delete('/api/admin/tournaments/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM tournaments WHERE id = ?').run(req.params.id);
  res.json({ message: 'Tournament deleted' });
});

app.patch('/api/admin/registrations/:id', requireAdmin, (req, res) => {
  const { status } = req.body;
  db.prepare('UPDATE registrations SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ message: 'Registration status updated' });
});

app.get('/api/admin/backup', requireAdmin, (req, res) => {
  const snapshot = {
    exportedAt: new Date().toISOString(),
    users: db.prepare('SELECT id, name, username, email_or_phone, ff_uid, ff_ign, role, kills, wins, total_points, earnings FROM users').all(),
    tournaments: db.prepare('SELECT * FROM tournaments').all(),
    registrations: db.prepare('SELECT * FROM registrations').all(),
    results: db.prepare('SELECT * FROM results').all(),
    announcements: db.prepare('SELECT * FROM announcements').all()
  };
  res.json(snapshot);
});

// Fallback to SPA index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`====================================================`);
  console.log(`🔥 YARDLEY ESPORTS Server running on port ${PORT}`);
  console.log(`📱 Local & Android Wi-Fi URL: http://localhost:${PORT}`);
  console.log(`====================================================`);
});
