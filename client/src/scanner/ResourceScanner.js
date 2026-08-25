const fs = require('fs');
const path = require('path');

class ResourceScanner {
  async scan() {
    const detections = [];
    const fivemPaths = this.getFiveMResourcePaths();

    for (const resourcesPath of fivemPaths) {
      if (!fs.existsSync(resourcesPath)) continue;

      try {
        const entries = fs.readdirSync(resourcesPath, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            this.analyzeResource(path.join(resourcesPath, entry.name), entry.name, detections);
          }
        }
      } catch (err) {}
    }

    return detections;
  }

  getFiveMResourcePaths() {
    const os = require('os');
    const home = os.homedir();
    return [
      path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data', 'resources'),
      path.join(home, 'AppData', 'Local', 'FiveM', 'resources')
    ];
  }

  analyzeResource(resourcePath, name, detections) {
    try {
      const files = fs.readdirSync(resourcePath, { withFileTypes: true });

      // Check fxmanifest.lua / __resource.lua
      const manifestFiles = ['fxmanifest.lua', '__resource.lua'];
      let hasManifest = false;

      for (const f of files) {
        if (manifestFiles.includes(f.name)) {
          hasManifest = true;
          this.checkManifest(path.join(resourcePath, f.name), name, detections);
        }
      }

      // Resource without manifest
      if (!hasManifest && files.length > 0) {
        detections.push({
          type: 'RESOURCE',
          title: `Manifestosuz kaynak: ${name}`,
          description: `"${name}" kaynağında fxmanifest.lua bulunamadı.`,
          risk_level: 'LOW',
          data: { name, path: resourcePath }
        });
      }
    } catch (err) {}
  }

  checkManifest(manifestPath, resourceName, detections) {
    try {
      const content = fs.readFileSync(manifestPath, 'utf8');

      // Check for client scripts that load external resources
      const suspiciousPatterns = [
        { pattern: /LoadResourceFile\s*\(\s*['"]?.*http/i, desc: 'Dış kaynak yükleme' },
        { pattern: /PerformHttpRequest/i, desc: 'HTTP isteği' },
        { pattern: /Websocket/i, desc: 'WebSocket bağlantısı' },
        { pattern: /Citizen\.Trace.*Execute/i, desc: 'Dinamik kod yürütme' },
        { pattern: /load\s*\(\s*['"] http/i, desc: 'Uzak kod yükleme' }
      ];

      for (const { pattern, desc } of suspiciousPatterns) {
        if (pattern.test(content)) {
          detections.push({
            type: 'RESOURCE',
            title: `Şüpheli kaynak manifestosu: ${resourceName}`,
            description: `"${resourceName}" kaynağında ${desc} tespit edildi.`,
            risk_level: 'MEDIUM',
            data: { name: resourceName, path: manifestPath, indicator: desc }
          });
        }
      }
    } catch (err) {}
  }
}

module.exports = ResourceScanner;
