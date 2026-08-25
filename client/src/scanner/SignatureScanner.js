const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class SignatureScanner {
  constructor() {
    this.signatures = [];
  }

  setSignatures(sigs) {
    this.signatures = sigs || [];
  }

  async scan() {
    const detections = [];
    if (this.signatures.length === 0) return detections;

    // Scan processes for signature matches
    this.checkProcessSignatures(detections);

    // Scan files for hash matches
    this.checkFileSignatures(detections);

    return detections;
  }

  checkProcessSignatures(detections) {
    try {
      const { execSync } = require('child_process');
      let processList = [];

      if (os.platform() === 'win32') {
        const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf8', timeout: 10000 });
        processList = output.split('\n')
          .filter(line => line.trim())
          .map(line => {
            const parts = line.split('","').map(p => p.replace(/"/g, ''));
            return parts[0];
          });
      }

      for (const procName of processList) {
        for (const sig of this.signatures) {
          if (sig.type === 'PROCESS' && procName.toLowerCase().includes(sig.signature_code.toLowerCase())) {
            detections.push({
              type: 'SIGNATURE',
              title: `İmza eşleşmesi: ${procName}`,
              description: `"${procName}" bilinen şüpheli imza ile eşleşiyor.`,
              risk_level: sig.risk_level,
              data: { name: procName, signature: sig.signature_code, signature_id: sig.id }
            });
          }
        }
      }
    } catch (err) {}
  }

  checkFileSignatures(detections) {
    const home = os.homedir();
    const checkPaths = [
      path.join(home, 'AppData', 'Local', 'FiveM'),
      path.join(home, 'AppData', 'Local', 'Temp')
    ];

    const hashSigs = this.signatures.filter(s => s.type === 'HASH' && s.hash_value);

    for (const checkPath of checkPaths) {
      if (!fs.existsSync(checkPath)) continue;

      try {
        this.walkAndHash(checkPath, hashSigs, detections, 0);
      } catch (err) {}
    }
  }

  walkAndHash(dirPath, hashSigs, detections, depth) {
    if (depth > 3) return;

    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isFile()) {
          const fullPath = path.join(dirPath, entry.name);
          try {
            const content = fs.readFileSync(fullPath);
            const fileHash = crypto.createHash('sha256').update(content).digest('hex');

            for (const sig of hashSigs) {
              if (sig.hash_value === fileHash) {
                detections.push({
                  type: 'SIGNATURE',
                  title: `Hash eşleşmesi: ${entry.name}`,
                  description: `"${entry.name}" dosyasının hash'i bilinen imza ile eşleşiyor.`,
                  risk_level: sig.risk_level,
                  data: { name: entry.name, path: fullPath, hash: fileHash, signature: sig.signature_code }
                });
              }
            }
          } catch (err) {}
        } else if (entry.isDirectory()) {
          this.walkAndHash(path.join(dirPath, entry.name), hashSigs, detections, depth + 1);
        }
      }
    } catch (err) {}
  }
}

module.exports = SignatureScanner;
