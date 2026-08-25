const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { initializeDatabase, getDb } = require('./database/init');

const authRoutes = require('./routes/authRoutes');
const pinRoutes = require('./routes/pinRoutes');
const scanRoutes = require('./routes/scanRoutes');
const signatureRoutes = require('./routes/signatureRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const settingsRoutes = require('./routes/settingsRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Çok fazla istek. Lütfen bekleyin.' }
});

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Çok fazla tarama isteği.' }
});

// Serve static files
app.use('/landing', express.static(path.join(__dirname, '..', '..', 'web', 'landing')));
app.use('/panel', express.static(path.join(__dirname, '..', '..', 'web', 'panel')));

// Downloads directory
const DOWNLOADS_DIR = path.join(__dirname, '..', 'downloads');
if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });

// Serve downloads
app.use('/downloads', express.static(DOWNLOADS_DIR));

// API Routes
app.use('/api/auth', apiLimiter, authRoutes);
app.use('/api/pins', apiLimiter, pinRoutes);
app.use('/api/scans', scanLimiter, scanRoutes);
app.use('/api/signatures', apiLimiter, signatureRoutes);
app.use('/api/dashboard', apiLimiter, dashboardRoutes);
app.use('/api/settings', apiLimiter, settingsRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Version check endpoint for scanner
app.get('/api/version', (req, res) => {
  try {
    const db = getDb();
    const version = db.prepare("SELECT value FROM system_settings WHERE key = 'scanner_version'").get();
    const minVersion = db.prepare("SELECT value FROM system_settings WHERE key = 'scanner_min_version'").get();
    res.json({
      current_version: version?.value || '1.0.0',
      min_version: minVersion?.value || '1.0.0'
    });
  } catch (e) {
    res.json({ current_version: '1.0.0', min_version: '1.0.0' });
  }
});

// Root redirect
app.get('/', (req, res) => {
  res.redirect('/landing');
});

// Start server after DB initialization
async function start() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`[RwScanner] Server running on port ${PORT}`);
      console.log(`[RwScanner] Landing: http://localhost:${PORT}/landing`);
      console.log(`[RwScanner] Panel: http://localhost:${PORT}/panel`);
      console.log(`[RwScanner] API: http://localhost:${PORT}/api`);
    });
  } catch (err) {
    console.error('[RwScanner] Failed to start:', err);
    process.exit(1);
  }
}

start();
