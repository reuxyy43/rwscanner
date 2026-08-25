const express = require('express');
const { getDb } = require('../database/init');
const { authMiddleware, logAudit } = require('../auth/auth');

const router = express.Router();

router.get('/', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const signatures = db.prepare('SELECT * FROM signatures ORDER BY created_at DESC').all();
    res.json({ signatures });
  } catch (err) {
    console.error('[SIG] List error:', err);
    res.status(500).json({ error: 'İmza listesi alınamadı' });
  }
});

router.post('/', authMiddleware, (req, res) => {
  try {
    const { signature_code, type, risk_level, description, hash_value } = req.body;
    if (!signature_code || !type) {
      return res.status(400).json({ error: 'İmza kodu ve türü gerekli' });
    }

    const db = getDb();
    const result = db.prepare(
      'INSERT INTO signatures (signature_code, type, risk_level, description, hash_value) VALUES (?, ?, ?, ?, ?)'
    ).run(signature_code, type, risk_level || 'LOW', description || null, hash_value || null);

    logAudit(req.user.id, 'SIGNATURE_CREATED', null, `Signature ${signature_code} created`, req.ip);

    res.json({ id: result.lastInsertRowid, message: 'İmza oluşturuldu' });
  } catch (err) {
    console.error('[SIG] Create error:', err);
    res.status(500).json({ error: 'İmza oluşturulamadı' });
  }
});

router.put('/:id', authMiddleware, (req, res) => {
  try {
    const { signature_code, type, risk_level, description, hash_value } = req.body;
    const db = getDb();

    const existing = db.prepare('SELECT * FROM signatures WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'İmza bulunamadı' });

    db.prepare(
      `UPDATE signatures SET 
        signature_code = COALESCE(?, signature_code),
        type = COALESCE(?, type),
        risk_level = COALESCE(?, risk_level),
        description = COALESCE(?, description),
        hash_value = COALESCE(?, hash_value),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?`
    ).run(signature_code, type, risk_level, description, hash_value, req.params.id);

    logAudit(req.user.id, 'SIGNATURE_UPDATED', null, `Signature ${req.params.id} updated`, req.ip);

    res.json({ message: 'İmza güncellendi' });
  } catch (err) {
    console.error('[SIG] Update error:', err);
    res.status(500).json({ error: 'İmza güncellenemedi' });
  }
});

router.delete('/:id', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const existing = db.prepare('SELECT * FROM signatures WHERE id = ?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'İmza bulunamadı' });

    db.prepare('DELETE FROM signatures WHERE id = ?').run(req.params.id);
    logAudit(req.user.id, 'SIGNATURE_DELETED', null, `Signature ${req.params.id} deleted`, req.ip);

    res.json({ message: 'İmza silindi' });
  } catch (err) {
    console.error('[SIG] Delete error:', err);
    res.status(500).json({ error: 'İmza silinemedi' });
  }
});

// Client-facing: get active signatures (for scanner updates)
router.get('/active', (req, res) => {
  try {
    const db = getDb();
    const signatures = db.prepare('SELECT id, signature_code, type, risk_level, hash_value FROM signatures ORDER BY created_at DESC').all();
    res.json({ signatures });
  } catch (err) {
    console.error('[SIG] Active list error:', err);
    res.status(500).json({ error: 'İmza listesi alınamadı' });
  }
});

module.exports = router;
