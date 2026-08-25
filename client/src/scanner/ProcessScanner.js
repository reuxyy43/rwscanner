const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

class ProcessScanner {
  constructor() {
    this.suspiciousPatterns = [
      { pattern: /cheatengine/i, name: 'Cheat Engine', risk: 'HIGH' },
      { pattern: /inject/i, name: 'Enjektör', risk: 'MEDIUM' },
      { pattern: /hack/i, name: 'Hack Aracı', risk: 'MEDIUM' },
      { pattern: /exploit/i, name: 'Exploit', risk: 'HIGH' },
      { pattern: /speedhack/i, name: 'Speed Hack', risk: 'HIGH' },
      { pattern: /aimbot/i, name: 'Aimbot', risk: 'HIGH' },
      { pattern: /wallhack/i, name: 'Wallhack', risk: 'HIGH' },
      { pattern: /trainer/i, name: 'Trainer', risk: 'MEDIUM' },
      { pattern: /xmem/i, name: 'XMem', risk: 'HIGH' },
      { pattern: /extreme/i, name: 'Extreme Injector', risk: 'HIGH' },
      { pattern: /process\s*hacker/i, name: 'Process Hacker', risk: 'MEDIUM' },
      { pattern: /ollydbg/i, name: 'OllyDbg', risk: 'MEDIUM' },
      { pattern: /x64dbg/i, name: 'x64dbg', risk: 'LOW' },
      { pattern: /dnspy/i, name: 'dnSpy', risk: 'LOW' },
      { pattern: /httpdebuggerpro/i, name: 'HTTP Debugger', risk: 'MEDIUM' },
      { pattern: /fiddler/i, name: 'Fiddler', risk: 'LOW' },
      { pattern: /wireshark/i, name: 'Wireshark', risk: 'LOW' }
    ];
  }

  async scan() {
    const detections = [];
    try {
      let processes = [];
      if (os.platform() === 'win32') {
        const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf8', timeout: 10000 });
        processes = output.split('\n')
          .filter(line => line.trim())
          .map(line => {
            const parts = line.split('","').map(p => p.replace(/"/g, ''));
            return { name: parts[0], pid: parts[1], memory: parts[4] };
          });
      } else {
        const output = execSync('ps aux', { encoding: 'utf8', timeout: 10000 });
        processes = output.split('\n')
          .filter(line => line.trim())
          .slice(1)
          .map(line => {
            const parts = line.split(/\s+/);
            return { name: parts[parts.length - 1], pid: parts[1], memory: parts[5] };
          });
      }

      for (const proc of processes) {
        for (const { pattern, name, risk } of this.suspiciousPatterns) {
          if (pattern.test(proc.name)) {
            detections.push({
              type: 'PROCESS',
              title: `Şüpheli process tespit edildi: ${proc.name}`,
              description: `"${proc.name}" process'i "${name}" ile eşleşiyor.`,
              risk_level: risk,
              data: { name: proc.name, pid: proc.pid, matched_pattern: name }
            });
            break;
          }
        }
      }
    } catch (err) {
      // Process scanning failed silently
    }
    return detections;
  }
}

module.exports = ProcessScanner;
