const jwt = require('jsonwebtoken');
const { getDb } = require('../database/init');

const JWT_SECRET = process.env.JWT_SECRET || 'rwscanner-secret-key-change-in-production';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Yetkilendirme gerekli' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = getDb();
    const user = db.prepare('SELECT id, username, role FROM users WHERE id = ?').get(decoded.id);
    if (!user) {
      return res.status(401).json({ error: 'Kullanıcı bulunamadı' });
    }
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Yönetici yetkisi gerekli' });
  }
  next();
}

function logAudit(userId, action, scanId, details, ipAddress) {
  const db = getDb();
  db.prepare(
    'INSERT INTO audit_logs (user_id, action, scan_id, details, ip_address) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, action, scanId || null, details || null, ipAddress || null);
}

module.exports = { generateToken, authMiddleware, adminOnly, logAudit, JWT_SECRET };
