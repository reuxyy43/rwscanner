const express = require('express');
const bcrypt = require('bcryptjs');
const { getDb } = require('../database/init');
const { authMiddleware, logAudit } = require('../auth/auth');
const { generateScanId } = require('../../../shared/models');

const router = express.Router();

// Client-facing: verify PIN and start scan
router.post('/start', (req, res) => {
  try {
    const { pin, scanner_version } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN gerekli' });

    const db = getDb();

    // Check scanner version
    const minVersion = db.prepare("SELECT value FROM system_settings WHERE key = 'scanner_min_version'").get()?.value;
    if (minVersion && scanner_version && compareVersions(scanner_version, minVersion) < 0) {
      return res.status(400).json({ error: 'UPDATE_REQUIRED', message: 'RwScanner\'ın yeni sürümü mevcut. Lütfen uygulamayı güncelleyin.' });
    }

    // Find pin - try all active pins and compare hash
    const activePins = db.prepare("SELECT * FROM pins WHERE status = 'ACTIVE'").all();
    let matchedPin = null;

    for (const p of activePins) {
      if (bcrypt.compareSync(pin, p.pin_hash)) {
        matchedPin = p;
        break;
      }
    }

    if (!matchedPin) {
      // Check if pin was already used
      const usedPin = db.prepare("SELECT * FROM pins WHERE status = 'USED'").all();
      for (const p of usedPin) {
        if (bcrypt.compareSync(pin, p.pin_hash)) {
          return res.status(400).json({ error: 'Bu PIN zaten kullanılmış' });
        }
      }
      return res.status(401).json({ error: 'Geçersiz PIN' });
    }

    // Check expiry
    if (matchedPin.expires_at && new Date(matchedPin.expires_at) < new Date()) {
      db.prepare("UPDATE pins SET status = 'EXPIRED' WHERE id = ?").run(matchedPin.id);
      return res.status(401).json({ error: 'PIN süresi dolmuş' });
    }

    // Check usage count
    if (matchedPin.use_count >= matchedPin.max_uses) {
      db.prepare("UPDATE pins SET status = 'USED' WHERE id = ?").run(matchedPin.id);
      return res.status(401).json({ error: 'Bu PIN kullanım hakkını doldurmuş' });
    }

    // Update pin usage
    db.prepare('UPDATE pins SET use_count = use_count + 1, used_at = CURRENT_TIMESTAMP WHERE id = ?').run(matchedPin.id);
    if (matchedPin.use_count + 1 >= matchedPin.max_uses) {
      db.prepare("UPDATE pins SET status = 'USED' WHERE id = ?").run(matchedPin.id);
    }

    // Create scan
    const scanId = generateScanId();
    db.prepare(
      'INSERT INTO scans (scan_id, pin_id, scanner_version, status) VALUES (?, ?, ?, ?)'
    ).run(scanId, matchedPin.id, scanner_version, 'IN_PROGRESS');

    logAudit(null, 'SCAN_STARTED', null, `Scan ${scanId} started with PIN`, req.ip);

    res.json({ scan_id: scanId, status: 'IN_PROGRESS' });
  } catch (err) {
    console.error('[SCAN] Start error:', err);
    res.status(500).json({ error: 'Tarama başlatılamadı' });
  }
});

// Client-facing: submit scan results (sends data, receives only status)
router.post('/submit', (req, res) => {
  try {
    const { scan_id, detections, system_info } = req.body;
    if (!scan_id) return res.status(400).json({ error: 'Scan ID gerekli' });

    const db = getDb();
    const scan = db.prepare('SELECT * FROM scans WHERE scan_id = ?').get(scan_id);
    if (!scan) return res.status(404).json({ error: 'Tarama bulunamadı' });

    // Calculate overall risk
    let overallRisk = 'CLEAN';
    const riskOrder = { 'CLEAN': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };

    if (detections && Array.isArray(detections)) {
      for (const det of detections) {
        const detRisk = det.risk_level || 'LOW';
        if (riskOrder[detRisk] > riskOrder[overallRisk]) {
          overallRisk = detRisk;
        }

        db.prepare(
          'INSERT INTO detections (scan_id, detection_type, title, description, risk_level, data) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(
          scan.id,
          det.type || 'UNKNOWN',
          det.title || 'Unknown detection',
          det.description || null,
          detRisk,
          JSON.stringify(det.data || null)
        );
      }
    }

    // Update scan
    db.prepare(
      "UPDATE scans SET status = 'COMPLETED', risk_level = ?, system_info = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?"
    ).run(overallRisk, system_info ? JSON.stringify(system_info) : null, scan.id);

    logAudit(null, 'SCAN_COMPLETED', scan.id, `Scan ${scan_id} completed with risk: ${overallRisk}`, req.ip);

    // Return ONLY status to client - no detection details
    res.json({ scan_status: 'completed' });
  } catch (err) {
    console.error('[SCAN] Submit error:', err);
    res.status(500).json({ error: 'Sonuçlar gönderilemedi' });
  }
});

// Client-facing: get scan status only
router.get('/status/:scanId', (req, res) => {
  try {
    const db = getDb();
    const scan = db.prepare('SELECT status FROM scans WHERE scan_id = ?').get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Tarama bulunamadı' });

    // Return ONLY status
    res.json({ scan_status: scan.status.toLowerCase() });
  } catch (err) {
    console.error('[SCAN] Status error:', err);
    res.status(500).json({ error: 'Durum alınamadı' });
  }
});

// Admin: get scan details with detections
router.get('/admin/:scanId', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const scan = db.prepare(`
      SELECT s.*, p.pin_code, u.username as created_by_name
      FROM scans s
      LEFT JOIN pins p ON s.pin_id = p.id
      LEFT JOIN users u ON p.created_by = u.id
      WHERE s.scan_id = ?
    `).get(req.params.scanId);

    if (!scan) return res.status(404).json({ error: 'Tarama bulunamadı' });

    const detections = db.prepare('SELECT * FROM detections WHERE scan_id = ? ORDER BY risk_level DESC').all(scan.id);
    const notes = db.prepare(`
      SELECT n.*, u.username 
      FROM scan_notes n 
      LEFT JOIN users u ON n.user_id = u.id 
      WHERE n.scan_id = ? 
      ORDER BY n.created_at DESC
    `).all(scan.id);

    logAudit(req.user.id, 'SCAN_VIEWED', scan.id, `Viewed scan ${req.params.scanId}`, req.ip);

    res.json({ scan, detections, notes });
  } catch (err) {
    console.error('[SCAN] Admin view error:', err);
    res.status(500).json({ error: 'Tarama detayı alınamadı' });
  }
});

// Admin: list scans
router.get('/admin', authMiddleware, (req, res) => {
  try {
    const db = getDb();
    const { status, risk_level, page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    let whereClauses = [];
    let params = [];

    if (status) { whereClauses.push('s.status = ?'); params.push(status); }
    if (risk_level) { whereClauses.push('s.risk_level = ?'); params.push(risk_level); }

    const whereStr = whereClauses.length ? 'WHERE ' + whereClauses.join(' AND ') : '';

    const scans = db.prepare(`
      SELECT s.*, p.pin_code, u.username as created_by_name
      FROM scans s
      LEFT JOIN pins p ON s.pin_id = p.id
      LEFT JOIN users u ON p.created_by = u.id
      ${whereStr}
      ORDER BY s.started_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, parseInt(limit), parseInt(offset));

    const total = db.prepare(`SELECT COUNT(*) as count FROM scans s ${whereStr}`).get(...params);

    res.json({ scans, total: total.count, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    console.error('[SCAN] Admin list error:', err);
    res.status(500).json({ error: 'Tarama listesi alınamadı' });
  }
});

// Admin: add note to scan
router.post('/admin/:scanId/notes', authMiddleware, (req, res) => {
  try {
    const { note } = req.body;
    if (!note) return res.status(400).json({ error: 'Not gerekli' });

    const db = getDb();
    const scan = db.prepare('SELECT id FROM scans WHERE scan_id = ?').get(req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Tarama bulunamadı' });

    db.prepare('INSERT INTO scan_notes (scan_id, user_id, note) VALUES (?, ?, ?)').run(scan.id, req.user.id, note);
    logAudit(req.user.id, 'NOTE_ADDED', scan.id, `Note added to scan ${req.params.scanId}`, req.ip);

    res.json({ message: 'Not eklendi' });
  } catch (err) {
    console.error('[SCAN] Add note error:', err);
    res.status(500).json({ error: 'Not eklenemedi' });
  }
});

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

module.exports = router;
