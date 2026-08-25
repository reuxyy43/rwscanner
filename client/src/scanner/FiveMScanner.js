const fs = require('fs');
const path = require('path');
const os = require('os');

class FiveMScanner {
  constructor() {
    this.fivemPaths = this.findFiveMPaths();
  }

  findFiveMPaths() {
    const paths = [];
    const home = os.homedir();

    const candidates = [
      path.join(home, 'AppData', 'Local', 'FiveM'),
      path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data'),
      'C:\\Program Files\\FiveM',
      'C:\\Program Files (x86)\\FiveM'
    ];

    candidates.forEach(p => {
      if (fs.existsSync(p)) paths.push(p);
    });

    return paths;
  }

  async scan() {
    const detections = [];

    if (this.fivemPaths.length === 0) {
      return detections;
    }

    for (const fivemPath of this.fivemPaths) {
      this.checkFiveMDirectory(fivemPath, detections);
    }

    return detections;
  }

  checkFiveMDirectory(basePath, detections) {
    try {
      // Check for unauthorized resource folders
      const resourcesPath = path.join(basePath, 'Application Data', 'resources');
      if (fs.existsSync(resourcesPath)) {
        this.checkResources(resourcesPath, detections);
      }

      // Check for suspicious cache files
      const cachePath = path.join(basePath, 'Application Data', 'cache');
      if (fs.existsSync(cachePath)) {
        this.checkCache(cachePath, detections);
      }

      // Check for modifiedCitizen directory
      const citizenPath = path.join(basePath, 'Application Data', 'citizen');
      if (fs.existsSync(citizenPath)) {
        this.checkCitizen(citizenPath, detections);
      }
    } catch (err) {
      // Skip errors
    }
  }

  checkResources(resourcesPath, detections) {
    try {
      const entries = fs.readdirSync(resourcesPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const resourcePath = path.join(resourcesPath, entry.name);
          this.checkResourceFolder(resourcePath, entry.name, detections);
        }
      }
    } catch (err) {}
  }

  checkResourceFolder(resourcePath, name, detections) {
    try {
      const files = fs.readdirSync(resourcePath);

      // Check for nativeUI or other commonly abused resources
      const suspiciousResources = ['nativeui', 'menus', 'executor', 'script'];
      for (const sr of suspiciousResources) {
        if (name.toLowerCase().includes(sr)) {
          detections.push({
            type: 'RESOURCE',
            title: `Şüpheli FiveM kaynağı: ${name}`,
            description: `"${name}" kaynağı şüpheli olarak işaretlendi.`,
            risk_level: 'MEDIUM',
            data: { name, path: resourcePath, files }
          });
          break;
        }
      }

      // Check for binary files in resource root
      for (const file of files) {
        const ext = path.extname(file).toLowerCase();
        if (['.exe', '.dll', '.asi'].includes(ext)) {
          detections.push({
            type: 'RESOURCE',
            title: `FiveM kaynağında çalıştırılabilir dosya: ${name}/${file}`,
            description: `"${name}" kaynağında "${file}" çalıştırılabilir dosyası bulundu.`,
            risk_level: 'HIGH',
            data: { name: file, path: path.join(resourcePath, file), resource: name }
          });
        }
      }
    } catch (err) {}
  }

  checkCache(cachePath, detections) {
    try {
      const entries = fs.readdirSync(cachePath);
      // Check for unusually large cache entries
      for (const entry of entries) {
        const fullPath = path.join(cachePath, entry);
        try {
          const stats = fs.statSync(fullPath);
          if (stats.isFile() && stats.size > 50 * 1024 * 1024) {
            detections.push({
              type: 'FIVEM',
              title: 'Olağanüstü büyük cache dosyası',
              description: `FiveM cache dizininde beklenmedik büyüklükte dosya bulundu.`,
              risk_level: 'LOW',
              data: { name: entry, path: fullPath, size: stats.size }
            });
          }
        } catch (err) {}
      }
    } catch (err) {}
  }

  checkCitizen(citizenPath, detections) {
    try {
      const entries = fs.readdirSync(citizenPath);
      // Look for modified core files
      for (const entry of entries) {
        const fullPath = path.join(citizenPath, entry);
        try {
          const stats = fs.statSync(fullPath);
          if (stats.isFile() && path.extname(entry).toLowerCase() === '.dll') {
            detections.push({
              type: 'FIVEM',
              title: `FiveM citizen dizininde DLL: ${entry}`,
              description: `"citizen" dizininde "${entry}" dosyası bulunuyor.`,
              risk_level: 'LOW',
              data: { name: entry, path: fullPath, size: stats.size }
            });
          }
        } catch (err) {}
      }
    } catch (err) {}
  }
}

module.exports = FiveMScanner;
