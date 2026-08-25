const express = require('express');
const { getDb } = require('../database/init');
const { authMiddleware } = require('../auth/auth');

const router = express.Router();

router.get('/', authMiddleware, (req, res) => {
  try {
    const db = getDb();

    const activeScans = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status = 'IN_PROGRESS'").get();
    const todayScans = db.prepare(
      "SELECT COUNT(*) as count FROM scans WHERE DATE(started_at) = DATE('now')"
    ).get();
    const suspiciousScans = db.prepare(
      "SELECT COUNT(*) as count FROM scans WHERE risk_level IN ('MEDIUM', 'HIGH', 'CRITICAL') AND DATE(started_at) = DATE('now')"
    ).get();
    const criticalDetections = db.prepare(
      "SELECT COUNT(*) as count FROM detections WHERE risk_level IN ('HIGH', 'CRITICAL') AND DATE(created_at) = DATE('now')"
    ).get();
    const lastScan = db.prepare(
      "SELECT started_at FROM scans ORDER BY started_at DESC LIMIT 1"
    ).get();

    const recentScans = db.prepare(`
      SELECT s.scan_id, s.status, s.risk_level, s.started_at, s.completed_at,
        (SELECT COUNT(*) FROM detections d WHERE d.scan_id = s.id) as detection_count
      FROM scans s
      ORDER BY s.started_at DESC
      LIMIT 10
    `).all();

    const riskDistribution = db.prepare(`
      SELECT risk_level, COUNT(*) as count
      FROM scans
      WHERE DATE(started_at) = DATE('now')
      GROUP BY risk_level
    `).all();

    let lastScanTime = null;
    if (lastScan && lastScan.started_at) {
      const diff = Date.now() - new Date(lastScan.started_at).getTime();
      const minutes = Math.floor(diff / 60000);
      if (minutes < 1) lastScanTime = 'Az önce';
      else if (minutes < 60) lastScanTime = `${minutes} dakika önce`;
      else lastScanTime = `${Math.floor(minutes / 60)} saat önce`;
    }

    const totalPins = db.prepare("SELECT COUNT(*) as count FROM pins").get();
    const activePins = db.prepare("SELECT COUNT(*) as count FROM pins WHERE status = 'ACTIVE'").get();
    const usedPins = db.prepare("SELECT COUNT(*) as count FROM pins WHERE status = 'USED'").get();
    const recentPins = db.prepare(`
      SELECT p.pin_code, p.status, p.use_count, p.max_uses, p.created_at, u.username as created_by_name
      FROM pins p
      LEFT JOIN users u ON p.created_by = u.id
      ORDER BY p.created_at DESC
      LIMIT 10
    `).all();

    res.json({
      active_scans: activeScans.count,
      today_scans: todayScans.count,
      suspicious_scans: suspiciousScans.count,
      critical_detections: criticalDetections.count,
      last_scan: lastScanTime,
      recent_scans: recentScans,
      risk_distribution: riskDistribution,
      total_pins: totalPins.count,
      active_pins: activePins.count,
      used_pins: usedPins.count,
      recent_pins: recentPins
    });
  } catch (err) {
    console.error('[DASHBOARD] Error:', err);
    res.status(500).json({ error: 'Dashboard verisi alınamadı' });
  }
});

module.exports = router;
