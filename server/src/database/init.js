const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', '..', 'data', 'rwscanner.db');

let db = null;
let sqlPromise = null;

function ensureDataDir() {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadDatabaseBuffer() {
  ensureDataDir();
  try {
    if (fs.existsSync(DB_PATH)) {
      return fs.readFileSync(DB_PATH);
    }
  } catch (e) {}
  return null;
}

function saveDatabase() {
  if (!db) return;
  try {
    const data = db.export();
    const buffer = Buffer.from(data);
    ensureDataDir();
    fs.writeFileSync(DB_PATH, buffer);
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}

// Auto-save every 5 seconds
setInterval(saveDatabase, 5000);

process.on('exit', saveDatabase);
process.on('SIGINT', () => { saveDatabase(); process.exit(); });

class PreparedLike {
  constructor(database, sql) {
    this.database = database;
    this.sql = sql;
  }

  run(...params) {
    try {
      this.database.run(this.sql, params);
      saveDatabase();
      return {
        changes: this.database.getRowsModified(),
        lastInsertRowid: this.database.exec("SELECT last_insert_rowid() as id")[0]?.values[0][0] || 0
      };
    } catch (e) {
      console.error('[DB] Run error:', e.message, this.sql);
      throw e;
    }
  }

  get(...params) {
    try {
      const stmt = this.database.prepare(this.sql);
      if (params.length > 0) stmt.bind(params);
      if (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        stmt.free();
        const row = {};
        cols.forEach((c, i) => row[c] = vals[i]);
        return row;
      }
      stmt.free();
      return undefined;
    } catch (e) {
      return undefined;
    }
  }

  all(...params) {
    try {
      const results = [];
      const stmt = this.database.prepare(this.sql);
      if (params.length > 0) stmt.bind(params);
      while (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        const row = {};
        cols.forEach((c, i) => row[c] = vals[i]);
        results.push(row);
      }
      stmt.free();
      return results;
    } catch (e) {
      console.error('[DB] All error:', e.message, this.sql);
      return [];
    }
  }
}

class DatabaseWrapper {
  constructor(sqlJsDb) {
    this.sqlJsDb = sqlJsDb;
  }

  prepare(sql) {
    return new PreparedLike(this.sqlJsDb, sql);
  }

  exec(sql) {
    this.sqlJsDb.run(sql);
    saveDatabase();
  }

  transaction(fn) {
    return (...args) => {
      this.sqlJsDb.run('BEGIN TRANSACTION');
      try {
        fn(...args);
        this.sqlJsDb.run('COMMIT');
        saveDatabase();
      } catch (e) {
        this.sqlJsDb.run('ROLLBACK');
        throw e;
      }
    };
  }

  pragma(str) {
    try { this.sqlJsDb.run(`PRAGMA ${str}`); } catch (e) {}
  }
}

let wrapper = null;

async function initializeDatabase() {
  const SQL = await initSqlJs();
  const buf = loadDatabaseBuffer();
  const sqlDb = buf ? new SQL.Database(buf) : new SQL.Database();

  wrapper = new DatabaseWrapper(sqlDb);
  wrapper.pragma('foreign_keys = ON');

  wrapper.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'MODERATOR',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    );

    CREATE TABLE IF NOT EXISTS pins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pin_code TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      expires_at DATETIME,
      max_uses INTEGER DEFAULT 1,
      use_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      used_at DATETIME,
      FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id TEXT UNIQUE NOT NULL,
      pin_id INTEGER NOT NULL,
      scanner_version TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING',
      risk_level TEXT DEFAULT 'CLEAN',
      player_identifier TEXT,
      system_info TEXT,
      started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (pin_id) REFERENCES pins(id)
    );

    CREATE TABLE IF NOT EXISTS detections (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      detection_type TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      risk_level TEXT NOT NULL DEFAULT 'LOW',
      signature_id INTEGER,
      data TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id),
      FOREIGN KEY (signature_id) REFERENCES signatures(id)
    );

    CREATE TABLE IF NOT EXISTS signatures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      signature_code TEXT NOT NULL,
      type TEXT NOT NULL,
      risk_level TEXT NOT NULL DEFAULT 'LOW',
      description TEXT,
      hash_value TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      scan_id INTEGER,
      details TEXT,
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS scan_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      note TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (scan_id) REFERENCES scans(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS system_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Insert default settings
  const settings = [
    ['scanner_version', '1.0.0'],
    ['scanner_min_version', '1.0.0'],
    ['pin_expiry_hours', '24'],
    ['max_scans_per_pin', '1'],
    ['rate_limit_window_ms', '60000'],
    ['rate_limit_max_requests', '30']
  ];

  for (const [key, value] of settings) {
    wrapper.prepare("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)").run(key, value);
  }

  // Create default admin
  const adminExists = wrapper.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 10);
    wrapper.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run('admin', hash, 'ADMIN');
    console.log('[DB] Default admin user created (admin / admin123)');
  }

  saveDatabase();
  console.log('[DB] Database initialized successfully');
  return wrapper;
}

function getDb() {
  if (!wrapper) throw new Error('Database not initialized. Call initializeDatabase() first.');
  return wrapper;
}

module.exports = { getDb, initializeDatabase, DB_PATH, saveDatabase };
