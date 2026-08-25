const ProcessScanner = require('./ProcessScanner');
const FileScanner = require('./FileScanner');
const FiveMScanner = require('./FiveMScanner');
const ResourceScanner = require('./ResourceScanner');
const IntegrityScanner = require('./IntegrityScanner');
const SignatureScanner = require('./SignatureScanner');

class Scanner {
  constructor() {
    this.modules = {
      process: new ProcessScanner(),
      file: new FileScanner(),
      fivem: new FiveMScanner(),
      resource: new ResourceScanner(),
      integrity: new IntegrityScanner(),
      signature: new SignatureScanner()
    };

    this.onProgress = null;
  }

  setProgressCallback(callback) {
    this.onProgress = callback;
  }

  setSignatures(signatures) {
    this.modules.signature.setSignatures(signatures);
  }

  async runAll() {
    const allDetections = [];
    const moduleKeys = Object.keys(this.modules);
    const totalModules = moduleKeys.length;

    for (let i = 0; i < moduleKeys.length; i++) {
      const key = moduleKeys[i];
      const module = this.modules[key];
      const progress = Math.round(((i + 1) / totalModules) * 100);

      if (this.onProgress) {
        this.onProgress({
          module: key,
          progress,
          message: this.getModuleName(key)
        });
      }

      try {
        const detections = await module.scan();
        allDetections.push(...detections);
      } catch (err) {
        // Module failed, continue
      }
    }

    return allDetections;
  }

  getModuleName(key) {
    const names = {
      process: 'Process analizi gerçekleştiriliyor...',
      file: 'Dosya taraması yapılıyor...',
      fivem: 'FiveM ortamı kontrol ediliyor...',
      resource: 'Kaynaklar analiz ediliyor...',
      integrity: 'Bütünlük kontrolü yapılıyor...',
      signature: 'İmza taraması gerçekleştiriliyor...'
    };
    return names[key] || key;
  }

  getSystemInfo() {
    const os = require('os');
    return {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      totalMemory: os.totalmem(),
      freeMemory: os.freemem(),
      cpus: os.cpus().length,
      uptime: os.uptime()
    };
  }
}

module.exports = Scanner;
