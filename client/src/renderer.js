let currentScanId = null;
let signatures = [];

// Version check on load
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const v = await window.rwscanner.checkVersion();
    if (v.current !== v.latest) {
      showError('Güncelleme Gerekli', "RwScanner'ın yeni sürümü mevcut: v" + v.latest);
    }
  } catch (e) {}
});

// PIN formatting
document.getElementById('pinInput').addEventListener('input', function(e) {
  let raw = e.value.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
  if (raw.length <= 2) {
    e.value = raw;
  } else if (raw.length <= 6) {
    e.value = raw.substring(0, 2) + '-' + raw.substring(2);
  } else if (raw.length <= 10) {
    e.value = raw.substring(0, 2) + '-' + raw.substring(2, 6) + '-' + raw.substring(6);
  } else {
    e.value = raw.substring(0, 2) + '-' + raw.substring(2, 6) + '-' + raw.substring(6, 10) + '-' + raw.substring(10);
  }
});

document.getElementById('pinInput').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') startScan();
});

async function startScan() {
  const pin = document.getElementById('pinInput').value.trim();
  const errEl = document.getElementById('pinError');

  if (!pin || pin.length < 8) {
    errEl.textContent = 'Geçerli bir PIN girin';
    errEl.style.display = 'block';
    return;
  }
  errEl.style.display = 'none';

  showStep('step-scanning');
  setStatus('PIN doğrulanıyor...', 'Sunucu ile bağlantınız kuruluyor.');
  setProgress(5);

  try {
    // Start scan session
    const result = await window.rwscanner.startScan(pin);
    currentScanId = result.scan_id;
    setProgress(10);

    // Get signatures
    setStatus('İmzalar alınıyor...', '');
    try {
      const sigData = await window.rwscanner.getSignatures();
      signatures = sigData.signatures || [];
    } catch (e) { signatures = []; }

    setProgress(15);

    // Run scanner modules
    const modules = [
      { name: 'Process analizi', fn: scanProcesses },
      { name: 'Dosya taraması', fn: scanFiles },
      { name: 'FiveM kontrolü', fn: scanFiveM },
      { name: 'Kaynak analizi', fn: scanResources },
      { name: 'Bütünlük kontrolü', fn: scanIntegrity },
      { name: 'İmza taraması', fn: scanSignatures }
    ];

    let allDetections = [];
    for (let i = 0; i < modules.length; i++) {
      setStatus(modules[i].name + '...', 'Tarama devam ediyor');
      try {
        const dets = await modules[i].fn();
        allDetections = allDetections.concat(dets);
      } catch (e) {}
      setProgress(15 + Math.round(((i + 1) / modules.length) * 75));
    }

    // Submit
    setStatus('Sonuçlar gönderiliyor...', 'Tarama sonuçları analiz ediliyor.');
    setProgress(95);

    await window.rwscanner.submitResults({
      scan_id: currentScanId,
      detections: allDetections,
      system_info: { platform: 'win32', app: 'RwScanner', version: '1.0.0' }
    });

    setProgress(100);
    showStep('step-done');
  } catch (err) {
    showError('Tarama Hatası', err.message || 'Tarama sırasında bir hata oluştu.');
  }
}

function showStep(id) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function setStatus(title, msg) {
  document.getElementById('scanTitle').textContent = title;
  document.getElementById('scanMsg').textContent = msg;
}

function setProgress(pct) {
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressText').textContent = '%' + pct;
}

function showError(title, msg) {
  document.getElementById('errorTitle').textContent = title;
  document.getElementById('errorMsg').textContent = msg;
  showStep('step-error');
}

function goToPin() {
  document.getElementById('pinInput').value = '';
  document.getElementById('pinError').style.display = 'none';
  showStep('step-pin');
}

// ---- SCANNER MODULES (client-side, no details sent to user) ----

function runCommand(cmd, args) {
  return new Promise((resolve) => {
    try {
      const { execSync } = require('child_process');
      const output = execSync(cmd + ' ' + args, { encoding: 'utf8', timeout: 10000, windowsHide: true });
      resolve(output);
    } catch (e) {
      resolve('');
    }
  });
}

function getOs() {
  try { return require('os'); } catch (e) { return {}; }
}

async function scanProcesses() {
  const detections = [];
  const output = await runCommand('tasklist', '/FO CSV /NH');
  if (!output) return detections;

  const patterns = [
    [/cheatengine/i, 'HIGH'], [/inject/i, 'MEDIUM'], [/hack/i, 'MEDIUM'],
    [/exploit/i, 'HIGH'], [/speedhack/i, 'HIGH'], [/aimbot/i, 'HIGH'],
    [/wallhack/i, 'HIGH'], [/trainer/i, 'MEDIUM'], [/xmem/i, 'HIGH'],
    [/extreme/i, 'HIGH'], [/process\s*hacker/i, 'MEDIUM'],
    [/ollydbg/i, 'MEDIUM'], [/x64dbg/i, 'LOW'], [/dnspy/i, 'LOW'],
    [/httpdebuggerpro/i, 'MEDIUM'], [/fiddler/i, 'LOW'], [/wireshark/i, 'LOW']
  ];

  output.split('\n').filter(l => l.trim()).forEach(line => {
    const parts = line.split('","').map(p => p.replace(/"/g, ''));
    const name = parts[0] || '';
    const pid = parts[1] || '';
    for (const [re, risk] of patterns) {
      if (re.test(name)) {
        detections.push({ type: 'PROCESS', title: 'Şüpheli process: ' + name, description: name + ' tespit edildi', risk_level: risk, data: { name: name, pid: pid } });
        break;
      }
    }
  });

  return detections;
}

async function scanFiles() {
  const detections = [];
  const os = getOs();
  const home = os.homedir ? os.homedir() : '';
  const paths = [];

  try {
    const path = require('path');
    const fs = require('fs');
    const fivem = path.join(home, 'AppData', 'Local', 'FiveM');
    if (fs.existsSync(fivem)) paths.push(fivem);
    const fivemApp = path.join(fivem, 'Application Data');
    if (fs.existsSync(fivemApp)) paths.push(fivemApp);

    const suspicious = ['inject', 'hack', 'cheat', 'exploit', 'trainer', 'modmenu', 'aimbot', 'wallhack', 'speedhack', 'noclip', 'godmode'];

    for (const basePath of paths) {
      try {
        const walk = (dir, depth) => {
          if (depth > 4) return;
          try {
            fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
              const full = require('path').join(dir, entry.name);
              if (entry.isDirectory()) {
                walk(full, depth + 1);
              } else if (entry.isFile()) {
                const ext = require('path').extname(entry.name).toLowerCase();
                const base = require('path').basename(entry.name, ext).toLowerCase();
                for (const s of suspicious) {
                  if (base.includes(s)) {
                    try {
                      const st = fs.statSync(full);
                      detections.push({ type: 'FILE', title: 'Şüpheli dosya: ' + entry.name, description: 'İsim kalıbı: ' + s, risk_level: 'MEDIUM', data: { name: entry.name, path: full, size: st.size } });
                    } catch (e) {}
                    break;
                  }
                }
                if (ext === '.dll') {
                  try {
                    const st = fs.statSync(full);
                    if (st.size < 1048576 && st.size > 0) {
                      detections.push({ type: 'FILE', title: 'FiveM dizininde DLL: ' + entry.name, description: 'Küçük DLL dosyası', risk_level: 'LOW', data: { name: entry.name, path: full, size: st.size } });
                    }
                  } catch (e) {}
                }
              }
            });
          } catch (e) {}
        };
        walk(basePath, 0);
      } catch (e) {}
    }
  } catch (e) {}

  return detections;
}

async function scanFiveM() {
  const detections = [];
  try {
    const os = getOs();
    const path = require('path');
    const fs = require('fs');
    const home = os.homedir ? os.homedir() : '';
    const fivemPath = path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data');
    if (!fs.existsSync(fivemPath)) return detections;

    // Resources
    const resPath = path.join(fivemPath, 'resources');
    if (fs.existsSync(resPath)) {
      fs.readdirSync(resPath, { withFileTypes: true }).forEach(entry => {
        if (!entry.isDirectory()) return;
        try {
          const dirPath = path.join(resPath, entry.name);
          fs.readdirSync(dirPath).forEach(file => {
            const ext = path.extname(file).toLowerCase();
            if (['.exe', '.dll', '.asi'].includes(ext)) {
              detections.push({ type: 'RESOURCE', title: 'FiveM kaynağında çalıştırılabilir: ' + entry.name + '/' + file, description: 'Kaynak: ' + entry.name, risk_level: 'HIGH', data: { name: file, resource: entry.name } });
            }
          });
        } catch (e) {}
      });
    }

    // Citizen
    const citPath = path.join(fivemPath, 'citizen');
    if (fs.existsSync(citPath)) {
      fs.readdirSync(citPath).forEach(file => {
        if (path.extname(file).toLowerCase() === '.dll') {
          try {
            const st = fs.statSync(path.join(citPath, file));
            detections.push({ type: 'FIVEM', title: 'Citizen DLL: ' + file, description: 'FiveM citizen dizininde DLL', risk_level: 'LOW', data: { name: file, size: st.size } });
          } catch (e) {}
        }
      });
    }
  } catch (e) {}
  return detections;
}

async function scanResources() { return []; }

async function scanIntegrity() {
  const detections = [];
  try {
    const os = getOs();
    const path = require('path');
    const fs = require('fs');
    const home = os.homedir ? os.homedir() : '';
    const fivemPath = path.join(home, 'AppData', 'Local', 'FiveM');
    if (!fs.existsSync(fivemPath)) return detections;

    fs.readdirSync(fivemPath).forEach(file => {
      if (path.extname(file).toLowerCase() === '.dll') {
        try {
          const st = fs.statSync(path.join(fivemPath, file));
          if (st.mtime > new Date(Date.now() - 86400000)) {
            detections.push({ type: 'INTEGRITY', title: 'Son 24 saatte değişmiş: ' + file, description: 'Değişiklik: ' + st.mtime.toISOString(), risk_level: 'LOW', data: { name: file, modified: st.mtime.toISOString() } });
          }
        } catch (e) {}
      }
    });
  } catch (e) {}
  return detections;
}

async function scanSignatures() {
  const detections = [];
  if (!signatures.length) return detections;

  try {
    const output = await runCommand('tasklist', '/FO CSV /NH');
    if (!output) return detections;

    output.split('\n').filter(l => l.trim()).forEach(line => {
      const procName = (line.split('","')[0] || '').replace(/"/g, '').toLowerCase();
      for (const sig of signatures) {
        if (sig.type === 'PROCESS' && procName.includes((sig.signature_code || '').toLowerCase())) {
          detections.push({ type: 'SIGNATURE', title: 'İmza eşleşmesi: ' + procName, description: 'İmza: ' + sig.signature_code, risk_level: sig.risk_level, data: { name: procName, signature: sig.signature_code } });
        }
      }
    });
  } catch (e) {}

  return detections;
}
