const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class IntegrityScanner {
  constructor() {
    this.knownHashes = new Map();
    this.setupKnownHashes();
  }

  setupKnownHashes() {
    // Known clean FiveM file hashes (examples)
    // In production, these would be loaded from the backend
    this.knownHashes.set('FiveM.exe', {
      expectedHash: null, // Would be set in production
      description: 'FiveM ana executable'
    });
  }

  async scan() {
    const detections = [];
    const fivemPaths = this.getFiveMPaths();

    for (const fivemPath of fivemPaths) {
      if (!fs.existsSync(fivemPath)) continue;
      this.checkFileIntegrity(fivemPath, detections);
    }

    return detections;
  }

  getFiveMPaths() {
    const home = os.homedir();
    return [
      path.join(home, 'AppData', 'Local', 'FiveM'),
      'C:\\Program Files\\FiveM',
      'C:\\Program Files (x86)\\FiveM'
    ];
  }

  checkFileIntegrity(basePath, detections) {
    try {
      const entries = fs.readdirSync(basePath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile()) {
          const fullPath = path.join(basePath, entry.name);
          const known = this.knownHashes.get(entry.name);

          if (known && known.expectedHash) {
            const currentHash = this.computeHash(fullPath);
            if (currentHash !== known.expectedHash) {
              detections.push({
                type: 'INTEGRITY',
                title: `Bütünlük ihlali: ${entry.name}`,
                description: `"${entry.name}" dosyasının hash değeri beklenenden farklı.`,
                risk_level: 'HIGH',
                data: {
                  name: entry.name,
                  path: fullPath,
                  expected_hash: known.expectedHash,
                  actual_hash: currentHash
                }
              });
            }
          }

          // Check for recently modified files
          try {
            const stats = fs.statSync(fullPath);
            const age = Date.now() - stats.mtimeMs;
            const oneDay = 24 * 60 * 60 * 1000;

            if (age < oneDay && entry.name.endsWith('.dll')) {
              detections.push({
                type: 'INTEGRITY',
                title: `Son 24 saatte değiştirilmiş DLL: ${entry.name}`,
                description: `"${entry.name}" dosyası son 24 saat içinde değiştirilmiş.`,
                risk_level: 'LOW',
                data: {
                  name: entry.name,
                  path: fullPath,
                  modified: stats.mtime.toISOString()
                }
              });
            }
          } catch (err) {}
        }
      }
    } catch (err) {}
  }

  computeHash(filePath) {
    try {
      const content = fs.readFileSync(filePath);
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return null;
    }
  }
}

module.exports = IntegrityScanner;
