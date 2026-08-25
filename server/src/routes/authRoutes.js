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

module.exports = router;
