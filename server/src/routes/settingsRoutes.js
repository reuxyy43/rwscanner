const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../database/init');
const { authMiddleware, adminOnly, logAudit } = require('../auth/auth');

const router = express.Router();

router.get('/', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const settings = db.prepare('SELECT * FROM system_settings').all();
    const settingsObj = {};
    settings.forEach(s => { settingsObj[s.key] = s.value; });
    res.json({ settings: settingsObj });
  } catch (err) {
    console.error('[SETTINGS] Get error:', err);
    res.status(500).json({ error: 'Ayarlar alınamadı' });
  }
});

router.put('/', authMiddleware, adminOnly, (req, res) => {
  try {
    const db = getDb();
    const { settings } = req.body;

    const upsert = db.prepare(
      'INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP'
    );

    const transaction = db.transaction(() => {
      for (const [key, value] of Object.entries(settings)) {
        upsert.run(key, String(value));
      }
    });
    transaction();

    logAudit(req.user.id, 'SETTINGS_UPDATED', null, `Settings updated: ${Object.keys(settings).join(', ')}`, req.ip);

    res.json({ message: 'Ayarlar güncellendi' });
  } catch (err) {
    console.error('[SETTINGS] Update error:', err);
    res.status(500).json({ error: 'Ayarlar güncellenemedi' });
  }
});

// User management
router.get('/users', authMiddleware, adminOnly, (req, res) => {
  try {
    const db = getDb();
    const users = db.prepare('SELECT id, username, role, created_at, last_login FROM users ORDER BY created_at DESC').all();
    res.json({ users });
  } catch (err) {
    console.error('[USERS] List error:', err);
    res.status(500).json({ error: 'Kullanıcı listesi alınamadı' });
  }
});

router.post('/users', authMiddleware, adminOnly, (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
    }

    const db = getDb();
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return res.status(400).json({ error: 'Bu kullanıcı adı zaten mevcut' });

    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(
      username, hash, role || 'MODERATOR'
    );

    logAudit(req.user.id, 'USER_CREATED', null, `User ${username} created`, req.ip);

    res.json({ message: 'Kullanıcı oluşturuldu' });
  } catch (err) {
    console.error('[USERS] Create error:', err);
    res.status(500).json({ error: 'Kullanıcı oluşturulamadı' });
  }
});

router.delete('/users/:id', authMiddleware, adminOnly, (req, res) => {
  try {
    const db = getDb();
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    if (user.id === req.user.id) return res.status(400).json({ error: 'Kendi hesabınızı silemezsiniz' });

    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    logAudit(req.user.id, 'USER_DELETED', null, `User ${user.username} deleted`, req.ip);

    res.json({ message: 'Kullanıcı silindi' });
  } catch (err) {
    console.error('[USERS] Delete error:', err);
    res.status(500).json({ error: 'Kullanıcı silinemedi' });
  }
});

// Audit logs
router.get('/audit', authMiddleware, adminOnly, (req, res) => {
  try {
    const db = getDb();
    const { page = 1, limit = 100 } = req.query;
    const offset = (page - 1) * limit;

    const logs = db.prepare(`
      SELECT a.*, u.username
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      ORDER BY a.timestamp DESC
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), parseInt(offset));

    const total = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get();

    res.json({ logs, total: total.count, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('[AUDIT] List error:', err);
    res.status(500).json({ error: 'Audit logları alınamadı' });
  }
});

module.exports = router;
