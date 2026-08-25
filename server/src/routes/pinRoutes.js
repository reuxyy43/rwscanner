const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { getDb } = require('../database/init');
const { authMiddleware, logAudit } = require('../auth/auth');
const { generatePin } = require('../../../shared/models');

const router = express.Router();

router.post('/', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const { expires_in_hours, max_uses } = req.body;

    const pinCode = generatePin();
    const pinHash = bcrypt.hashSync(pinCode, 10);

    const expiryHours = expires_in_hours || parseInt(db.prepare("SELECT value FROM system_settings WHERE key = 'pin_expiry_hours'").get()?.value || '24');
    const maxUseCount = max_uses || parseInt(db.prepare("SELECT value FROM system_settings WHERE key = 'max_scans_per_pin'").get()?.value || '1');

    const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString();

    const result = db.prepare(
      'INSERT INTO pins (pin_code, pin_hash, created_by, expires_at, max_uses) VALUES (?, ?, ?, ?, ?)'
    ).run(pinCode, pinHash, req.user.id, expiresAt, maxUseCount);

    logAudit(req.user.id, 'PIN_CREATED', null, `PIN ${pinCode} created`, req.ip);

    res.json({
      id: result.lastInsertRowid,
      pin_code: pinCode,
      expires_at: expiresAt,
      max_uses: maxUseCount,
      created_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[PIN] Create error:', err);
    res.status(500).json({ error: 'PIN oluşturulamadı' });
  }
});

router.get('/', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const { status, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT p.*, u.username as created_by_name 
      FROM pins p 
      LEFT JOIN users u ON p.created_by = u.id
    `;
    const params = [];

    if (status) {
      query += ' WHERE p.status = ?';
      params.push(status);
    }

    query += ' ORDER BY p.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));

    const pins = db.prepare(query).all(...params);
    const total = db.prepare('SELECT COUNT(*) as count FROM pins' + (status ? ' WHERE status = ?' : '')).get(...(status ? [status] : []));

    res.json({ pins, total: total.count, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('[PIN] List error:', err);
    res.status(500).json({ error: 'PIN listesi alınamadı' });
  }
});

router.put('/:id/cancel', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.id);
    if (!pin) return res.status(404).json({ error: 'PIN bulunamadı' });

    db.prepare("UPDATE pins SET status = 'CANCELLED' WHERE id = ?").run(req.params.id);
    logAudit(req.user.id, 'PIN_CANCELLED', null, `PIN ${pin.pin_code} cancelled`, req.ip);

    res.json({ message: 'PIN iptal edildi' });
  } catch (err) {
    console.error('[PIN] Cancel error:', err);
    res.status(500).json({ error: 'PIN iptal edilemedi' });
  }
});

router.delete('/:id', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.id);
    if (!pin) return res.status(404).json({ error: 'PIN bulunamadı' });

    db.prepare('DELETE FROM pins WHERE id = ?').run(req.params.id);
    logAudit(req.user.id, 'PIN_DELETED', null, `PIN ${pin.pin_code} deleted`, req.ip);

    res.json({ message: 'PIN silindi' });
  } catch (err) {
    console.error('[PIN] Delete error:', err);
    res.status(500).json({ error: 'PIN silinemedi' });
  }
});

module.exports = router;
