const { initializeDatabase, getDb, saveDatabase } = require('./init');
const bcrypt = require('bcryptjs');

async function seed() {
  console.log('[SEED] Initializing database...');
  await initializeDatabase();

  const db = getDb();

  // Create additional test users
  const users = [
    { username: 'moderator1', password: 'mod123', role: 'MODERATOR' },
    { username: 'moderator2', password: 'mod123', role: 'MODERATOR' }
  ];

  for (const user of users) {
    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(user.username);
    if (!existing) {
      const hash = bcrypt.hashSync(user.password, 10);
      db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)').run(user.username, hash, user.role);
      console.log(`[SEED] User created: ${user.username} / ${user.password}`);
    } else {
      console.log(`[SEED] User already exists: ${user.username}`);
    }
  }

  // Create sample signatures
  const signatures = [
    { code: 'cheatengine', type: 'PROCESS', risk: 'HIGH', desc: 'Cheat Engine process tespiti' },
    { code: 'injector', type: 'PROCESS', risk: 'HIGH', desc: 'DLL enjektör tespiti' },
    { code: 'speedhack', type: 'PROCESS', risk: 'CRITICAL', desc: 'Speed hack aracı tespiti' },
    { code: 'aimbot_module', type: 'PROCESS', risk: 'HIGH', desc: 'Aimbot modülü tespiti' },
    { code: 'wallhack_dll', type: 'FILE', risk: 'HIGH', desc: 'Wallhack DLL dosyası' },
    { code: 'trainer_asi', type: 'FILE', risk: 'MEDIUM', desc: 'Trainer ASI dosyası' }
  ];

  for (const sig of signatures) {
    const existing = db.prepare('SELECT id FROM signatures WHERE signature_code = ?').get(sig.code);
    if (!existing) {
      db.prepare(
        'INSERT INTO signatures (signature_code, type, risk_level, description) VALUES (?, ?, ?, ?)'
      ).run(sig.code, sig.type, sig.risk, sig.desc);
      console.log(`[SEED] Signature created: ${sig.code}`);
    }
  }

  saveDatabase();
  console.log('[SEED] Database seeding complete!');
  console.log('[SEED] Admin login: admin / admin123');
  console.log('[SEED] Moderator login: moderator1 / mod123');
  process.exit(0);
}

seed().catch(err => {
  console.error('[SEED] Error:', err);
  process.exit(1);
});
