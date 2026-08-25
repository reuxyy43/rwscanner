const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../database/init');
const { generateToken, authMiddleware, logAudit } = require('../auth/auth');

const router = express.Router();

router.post('/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
    }

    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
    logAudit(user.id, 'LOGIN', null, `User ${user.username} logged in`, req.ip);

    const token = generateToken(user);
    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

router.get('/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

router.get('/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'HEAD_ADMIN') {
    return res.status(403).json({ error: 'Yalnızca baş admin kullanıcıları görebilir' });
  }
  const db = getDb();
  const users = db.prepare('SELECT id, username, role, created_by, created_at, last_login FROM users ORDER BY created_at DESC').all();
  res.json({ users });
});

router.post('/users', authMiddleware, (req, res) => {
  if (req.user.role !== 'HEAD_ADMIN') {
    return res.status(403).json({ error: 'Yalnızca baş admin kullanıcı oluşturabilir' });
  }
  const { username, password, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
  }
  const userRole = (role === 'ADMIN' || role === 'MODERATOR') ? role : 'MODERATOR';

  const db = getDb();
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) {
    return res.status(409).json({ error: 'Bu kullanıcı adı zaten var' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash, role, created_by) VALUES (?, ?, ?, ?)').run(username, hash, userRole, req.user.id);
  logAudit(req.user.id, 'USER_CREATED', null, `Created user ${username} with role ${userRole}`, req.ip);
  res.json({ id: result.lastInsertRowid, username, role: userRole, message: 'Kullanıcı oluşturuldu' });
});

router.delete('/users/:id', authMiddleware, (req, res) => {
  if (req.user.role !== 'HEAD_ADMIN') {
    return res.status(403).json({ error: 'Yalnızca baş admin kullanıcı silebilir' });
  }
  const db = getDb();
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  if (user.role === 'HEAD_ADMIN') return res.status(403).json({ error: 'Baş admin silinemez' });

  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  logAudit(req.user.id, 'USER_DELETED', null, `Deleted user ${user.username}`, req.ip);
  res.json({ message: 'Kullanıcı silindi' });
});

module.exports = router;
