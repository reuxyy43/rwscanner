const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class FileScanner {
  constructor() {
    this.scanPaths = this.getScanPaths();
    this.suspiciousExtensions = ['.dll', '.asi', '.lua', '.exe'];
    this.suspiciousFileNames = [
      'inject', 'hack', 'cheat', 'exploit', 'trainer', 'modmenu',
      'aimbot', 'wallhack', 'speedhack', 'noclip', 'godmode'
    ];
  }

  getScanPaths() {
    const paths = [];
    const home = os.homedir();

    // FiveM related paths
    const fivemPaths = [
      path.join(home, 'AppData', 'Local', 'FiveM'),
      path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data'),
      'C:\\Program Files\\FiveM',
      'C:\\Program Files (x86)\\FiveM'
    ];

    // Also check common game directories
    const gamePaths = [
      path.join(home, 'Documents', 'Rockstar Games'),
      path.join(home, 'AppData', 'Local', 'Rockstar Games')
    ];

    [...fivemPaths, ...gamePaths].forEach(p => {
      if (fs.existsSync(p)) paths.push(p);
    });

    return paths;
  }

  async scan() {
    const detections = [];

    for (const scanPath of this.scanPaths) {
      try {
        this.scanDirectory(scanPath, detections, 0);
      } catch (err) {
        // Skip inaccessible directories
      }
    }

    return detections;
  }

  scanDirectory(dirPath, detections, depth) {
    if (depth > 5) return;

    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
          this.scanDirectory(fullPath, detections, depth + 1);
        } else if (entry.isFile()) {
          this.checkFile(fullPath, entry.name, detections);
        }
      }
    } catch (err) {
      // Skip inaccessible directories
    }
  }

  checkFile(filePath, fileName, detections) {
    const ext = path.extname(fileName).toLowerCase();
    const baseName = path.basename(fileName, ext).toLowerCase();

    // Check suspicious file names
    for (const suspicious of this.suspiciousFileNames) {
      if (baseName.includes(suspicious)) {
        try {
          const stats = fs.statSync(filePath);
          const hash = this.computeHash(filePath);

          detections.push({
            type: 'FILE',
            title: `Şüpheli dosya: ${fileName}`,
            description: `"${fileName}" dosyası şüpheli isim kalıbı içeriyor.`,
            risk_level: 'MEDIUM',
            data: {
              name: fileName,
              path: filePath,
              size: stats.size,
              hash: hash,
              extension: ext
            }
          });
        } catch (err) {
          // Skip files we can't read
        }
        break;
      }
    }

    // Check for DLL files in suspicious locations
    if (ext === '.dll' && depth < 3) {
      try {
        const stats = fs.statSync(filePath);
        // Small DLLs in FiveM directories can be suspicious
        if (stats.size < 1024 * 1024 && stats.size > 0) {
          detections.push({
            type: 'FILE',
            title: `FiveM dizininde DLL dosyası: ${fileName}`,
            description: `"${fileName}" FiveM ile ilişkili bir dizinde bulunuyor.`,
            risk_level: 'LOW',
            data: {
              name: fileName,
              path: filePath,
              size: stats.size,
              extension: ext
            }
          });
        }
      } catch (err) {}
    }
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

module.exports = FileScanner;
