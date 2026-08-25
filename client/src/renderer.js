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
      const output = execSync(cmd + ' ' + args, { encoding: 'utf8', timeout: 15000, windowsHide: true });
      resolve(output);
    } catch (e) {
      resolve('');
    }
  });
}

function getOs() {
  try { return require('os'); } catch (e) { return {}; }
}

function addDetection(detections, type, title, description, risk_level, data) {
  detections.push({ type, title, description, risk_level, data: data || {} });
}

// 1. PROCESS TARAMASI - Genişletilmiş
async function scanProcesses() {
  const detections = [];
  const output = await runCommand('tasklist', '/FO CSV /NH');
  if (!output) return detections;

  const knownSafe = [
    'svchost.exe', 'csrss.exe', 'smss.exe', 'lsass.exe', 'services.exe',
    'wininit.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe', 'taskhostw.exe',
    'conhost.exe', 'RuntimeBroker.exe', 'ShellExperienceHost.exe', 'SearchUI.exe',
    'sihost.exe', 'fontdrvhost.exe', 'Memory Compression', 'Registry', 'System',
    'Idle', 'System Idle Process', 'NOT IMPLEMENTED'
  ];

  const cheatProcesses = [
    { re: /cheat\s*engine/i, risk: 'CRITICAL', desc: 'Cheat Engine tespit edildi' },
    { re: /ce\s*main/i, risk: 'CRITICAL', desc: 'Cheat Engine ana process' },
    { re: /cheatengine/i, risk: 'CRITICAL', desc: 'Cheat Engine tespit edildi' },
    { re: /xenos\d*/i, risk: 'CRITICAL', desc: 'Xenos injector tespit edildi' },
    { re: /x64dbg|x32dbg/i, risk: 'HIGH', desc: 'Debugger tespit edildi' },
    { re: /ollydbg/i, risk: 'HIGH', desc: 'OllyDbg debugger tespit edildi' },
    { re: /dnspy/i, risk: 'HIGH', desc: '.NET spy/decompiler tespit edildi' },
    { re: /process\s*hacker/i, risk: 'HIGH', desc: 'Process Hacker tespit edildi' },
    { re: /inject/i, risk: 'HIGH', desc: 'Enjeksiyon aracı tespit edildi' },
    { re: /exploit/i, risk: 'HIGH', desc: 'Exploit aracı tespit edildi' },
    { re: /aimbot/i, risk: 'CRITICAL', desc: 'Aimbot tespit edildi' },
    { re: /wallhack/i, risk: 'CRITICAL', desc: 'Wallhack tespit edildi' },
    { re: /speedhack/i, risk: 'CRITICAL', desc: 'Speed hack tespit edildi' },
    { re: /trainer/i, risk: 'HIGH', desc: 'Trainer/menü tespit edildi' },
    { re: /noclip/i, risk: 'CRITICAL', desc: 'Noclip tespit edildi' },
    { re: /godmode/i, risk: 'CRITICAL', desc: 'God mode tespit edildi' },
    { re: /extreme\s*injector/i, risk: 'CRITICAL', desc: 'Extreme Injector tespit edildi' },
    { re: /dark\s*comet/i, risk: 'CRITICAL', desc: 'DarkComet RAT tespit edildi' },
    { re: /quantum\s*(speed|hack)/i, risk: 'CRITICAL', desc: 'Quantum speed hack tespit edildi' },
    { re: /http\s*debugger/i, risk: 'HIGH', desc: 'HTTP Debugging aracı tespit edildi' },
    { re: /fiddler/i, risk: 'MEDIUM', desc: 'Fiddler HTTP proxy tespit edildi' },
    { re: /wireshark/i, risk: 'MEDIUM', desc: 'Wireshark paket analizi tespit edildi' },
    { re: /charles\s*proxy/i, risk: 'MEDIUM', desc: 'Charles Proxy tespit edildi' },
    { re: /mitmproxy/i, risk: 'HIGH', desc: 'MITM proxy tespit edildi' },
    { re: /frida/i, risk: 'HIGH', desc: 'Frida hook framework tespit edildi' },
    { re: /x96dbg/i, risk: 'HIGH', desc: 'x96dbg tespit edildi' },
    { re: /hxd|hex\s*editor/i, risk: 'MEDIUM', desc: 'Hex editor tespit edildi' },
    { re: /reclass/i, risk: 'HIGH', desc: 'ReClass memory analysis tespit edildi' },
    { re: /diover.*inject|xqm.injector/i, risk: 'CRITICAL', desc: 'Injector tespit edildi' },
    { re: /dbgview/i, risk: 'MEDIUM', desc: 'DebugView tespit edildi' },
    { re: /sandboxie/i, risk: 'MEDIUM', desc: 'Sandboxie tespit edildi' },
    { re: /task\s*manager|taskmgr/i, risk: 'LOW', desc: 'Görev Yöneticisi açık' },
    { re: /luna\s*cheat|luna\s*menu/i, risk: 'CRITICAL', desc: 'Luna cheat tespit edildi' },
    { re: /panther|panthera/i, risk: 'CRITICAL', desc: 'Panther cheat tespit edildi' },
    { re: /spectrum\s*cheat/i, risk: 'CRITICAL', desc: 'Spectrum cheat tespit edildi' },
    { re: /nighthawk/i, risk: 'CRITICAL', desc: 'Nighthawk cheat tespit edildi' },
    { re: /oxide\s*cheat/i, risk: 'CRITICAL', desc: 'Oxide cheat tespit edildi' },
    { re: /planb\s*(cheat|menu)/i, risk: 'CRITICAL', desc: 'PlanB cheat tespit edildi' },
    { re: /datdrop|datweb/i, risk: 'HIGH', desc: 'Şüpheli_MATCHtespit edildi' },
    { re: /roblox.*exploit|krnl|synapse/i, risk: 'HIGH', desc: 'Exploit aracı tespit edildi' },
  ];

  output.split('\n').filter(l => l.trim()).forEach(line => {
    const parts = line.split('","').map(p => p.replace(/"/g, ''));
    const name = parts[0] || '';
    const pid = parts[1] || '';

    if (knownSafe.includes(name)) return;

    for (const { re, risk, desc } of cheatProcesses) {
      if (re.test(name)) {
        addDetection(detections, 'PROCESS', 'Şüpheli process: ' + name, desc, risk, { name: name, pid: pid });
        break;
      }
    }
  });

  return detections;
}

// 2. DOSYA TARAMASI - Genişletilmiş
async function scanFiles() {
  const detections = [];
  const os = getOs();
  const home = os.homedir ? os.homedir() : '';

  try {
    const path = require('path');
    const fs = require('fs');

    const scanPaths = [
      path.join(home, 'AppData', 'Local', 'FiveM'),
      path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data'),
      path.join(home, 'AppData', 'Roaming'),
      path.join(home, 'Desktop'),
      path.join(home, 'Downloads'),
      path.join(home, 'Documents'),
      path.join('C:', 'Program Files'),
      path.join('C:', 'Program Files (x86)')
    ];

    const cheatKeywords = [
      'inject', 'hack', 'cheat', 'exploit', 'trainer', 'modmenu', 'mod_menu',
      'aimbot', 'wallhack', 'speedhack', 'noclip', 'godmode', 'god_mode',
      'esp', 'triggerbot', 'silentaim', 'magic_bullet', 'lagswitch',
      'rage', 'legit', 'custom_aim', 'breakable_noshoot', 'anti_aim',
      'menu_builder', 'overlay', 'internal', 'external', 'hwid_spoof',
      'spoof', 'bypass', 'protect', 'cleaner', 'stealth', 'undetected',
      'fivem_hack', 'gta_hack', 'rp_hack'
    ];

    const cheatExtensions = ['.asi', '.lua', '.luac'];

    const cheatFileNames = [
      'dinput8.dll', 'ScriptHookV.dll', 'dinput8.asi', 'nativeTrainer.asi',
      'NativeTrainer.asi', 'dinput8.asi', 'openiv.asi'
    ];

    for (const basePath of scanPaths) {
      if (!fs.existsSync(basePath)) continue;
      try {
        const walk = (dir, depth) => {
          if (depth > 5) return;
          try {
            fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
              const full = path.join(dir, entry.name);
              if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                walk(full, depth + 1);
              } else if (entry.isFile()) {
                const ext = path.extname(entry.name).toLowerCase();
                const base = path.basename(entry.name, ext).toLowerCase();
                const fullPath = full.toLowerCase();

                for (const kw of cheatKeywords) {
                  if (base.includes(kw)) {
                    try {
                      const st = fs.statSync(full);
                      const risk = (kw === 'inject' || kw === 'cheat' || kw === 'exploit' || kw === 'aimbot' || kw === 'wallhack' || kw === 'speedhack' || kw === 'godmode' || kw === 'noclip') ? 'CRITICAL' : 'HIGH';
                      addDetection(detections, 'FILE', 'Şüpheli dosya: ' + entry.name, 'İsim kalıbı: ' + kw, risk, { name: entry.name, path: full, size: st.size });
                    } catch (e) {}
                    break;
                  }
                }

                if (cheatExtensions.includes(ext) && (fullPath.includes('fivem') || fullPath.includes('gta'))) {
                  try {
                    const st = fs.statSync(full);
                    addDetection(detections, 'FILE', 'Oyun dizininde çalıştırılabilir: ' + entry.name, 'Uzantı: ' + ext, 'HIGH', { name: entry.name, path: full, size: st.size });
                  } catch (e) {}
                }

                if (ext === '.dll' && fullPath.includes('fivem')) {
                  try {
                    const st = fs.statSync(full);
                    if (st.size > 0 && st.size < 5242880) {
                      const isKnownCheatDll = cheatFileNames.some(cn => cn.toLowerCase() === base + ext);
                      if (isKnownCheatDll) {
                        addDetection(detections, 'FILE', 'Bilinen hile DLL: ' + entry.name, 'Tanınan hile dosyası', 'CRITICAL', { name: entry.name, path: full, size: st.size });
                      } else {
                        addDetection(detections, 'FILE', 'FiveM dizininde DLL: ' + entry.name, 'Şüpheli DLL boyutu: ' + Math.round(st.size/1024) + 'KB', 'LOW', { name: entry.name, path: full, size: st.size });
                      }
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

// 3. FIVEM TARAMASI
async function scanFiveM() {
  const detections = [];
  try {
    const os = getOs();
    const path = require('path');
    const fs = require('fs');
    const home = os.homedir ? os.homedir() : '';
    const fivemPath = path.join(home, 'AppData', 'Local', 'FiveM');
    const fivemApp = path.join(fivemPath, 'Application Data');

    if (!fs.existsSync(fivemPath)) return detections;

    // FiveM.exe konumu kontrolü
    const fivemExe = path.join(fivemPath, 'FiveM.exe');
    if (fs.existsSync(fivemExe)) {
      try {
        const st = fs.statSync(fivemExe);
        if (st.size < 100000) {
          addDetection(detections, 'FIVEM', 'FiveM.exeboyutu anormal: ' + Math.round(st.size/1024) + 'KB', 'Olağandışı küçük boyut', 'HIGH', { path: fivemExe, size: st.size });
        }
      } catch (e) {}
    }

    // Resources kontrolü
    const resPath = path.join(fivemApp, 'resources');
    if (fs.existsSync(resPath)) {
      try {
        const categories = fs.readdirSync(resPath, { withFileTypes: true });
        categories.forEach(cat => {
          if (!cat.isDirectory()) return;
          const catPath = path.join(resPath, cat.name);
          try {
            const resources = fs.readdirSync(catPath, { withFileTypes: true });
            resources.forEach(res => {
              if (!res.isDirectory()) return;
              const resPath2 = path.join(catPath, res.name);
              try {
                const files = fs.readdirSync(resPath2);
                files.forEach(file => {
                  const ext = path.extname(file).toLowerCase();
                  if (['.exe', '.dll', '.asi', '.luac'].includes(ext)) {
                    addDetection(detections, 'RESOURCE', 'Kaynakta çalıştırılabilir: ' + cat.name + '/' + res.name + '/' + file, 'İzin verilmeyen dosya türü', 'HIGH', { resource: res.name, file: file });
                  }
                });

                const fxmanifest = path.join(resPath2, 'fxmanifest.lua');
                const __resource = path.join(resPath2, '__resource.lua');
                if (!fs.existsSync(fxmanifest) && !fs.existsSync(__resource)) {
                  const luaFiles = files.filter(f => f.endsWith('.lua') || f.endsWith('.js'));
                  if (luaFiles.length > 0) {
                    addDetection(detections, 'RESOURCE', 'Manifestsiz kaynak: ' + res.name, 'fxmanifest.lua bulunamadı', 'MEDIUM', { resource: res.name });
                  }
                }
              } catch (e) {}
            });
          } catch (e) {}
        });
      } catch (e) {}
    }

    // Citizen klasörü
    const citPath = path.join(fivemApp, 'citizen');
    if (fs.existsSync(citPath)) {
      try {
        const scanCitDir = (dir) => {
          if (!fs.existsSync(dir)) return;
          fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
            const full = path.join(dir, entry.name);
            if (entry.isFile()) {
              const ext = path.extname(entry.name).toLowerCase();
              if (ext === '.dll') {
                try {
                  const st = fs.statSync(full);
                  if (st.size > 0 && st.size < 2097152) {
                    addDetection(detections, 'FIVEM', 'Citizen DLL: ' + entry.name, 'Boyut: ' + Math.round(st.size/1024) + 'KB', 'LOW', { name: entry.name, path: full, size: st.size });
                  }
                } catch (e) {}
              }
            }
          });
        };
        scanCitDir(citPath);
        scanCitDir(path.join(citPath, 'common'));
        scanCitDir(path.join(citPath, 'common', 'data'));
      } catch (e) {}
    }

    // Cache dosyaları
    const cachePath = path.join(fivemApp, 'data', 'cache');
    if (fs.existsSync(cachePath)) {
      try {
        fs.readdirSync(cachePath, { withFileTypes: true }).forEach(entry => {
          if (!entry.isFile()) return;
          const full = path.join(cachePath, entry.name);
          try {
            const st = fs.statSync(full);
            if (st.size > 52428800) {
              addDetection(detections, 'FIVEM', 'Büyük cache dosyası: ' + entry.name, 'Boyut: ' + Math.round(st.size/1048576) + 'MB', 'MEDIUM', { name: entry.name, path: full, size: st.size });
            }
            if (st.mtime > new Date(Date.now() - 86400000)) {
              addDetection(detections, 'FIVEM', 'Son 24 saatte değişmiş cache: ' + entry.name, 'Değişiklik: ' + st.mtime.toISOString(), 'LOW', { name: entry.name, modified: st.mtime.toISOString() });
            }
          } catch (e) {}
        });
      } catch (e) {}
    }

    //FiveM Application Data'da izinsiz DLL
    try {
      fs.readdirSync(fivemApp).forEach(file => {
        if (path.extname(file).toLowerCase() === '.dll') {
          const st = fs.statSync(path.join(fivemApp, file));
          addDetection(detections, 'FIVEM', 'Application Data DLL: ' + file, 'Boyut: ' + Math.round(st.size/1024) + 'KB', 'LOW', { name: file, size: st.size });
        }
      });
    } catch (e) {}
  } catch (e) {}
  return detections;
}

// 4. KAYNAK İÇERİK TARAMASI
async function scanResources() {
  const detections = [];
  try {
    const os = getOs();
    const path = require('path');
    const fs = require('fs');
    const home = os.homedir ? os.homedir() : '';
    const resPath = path.join(home, 'AppData', 'Local', 'FiveM', 'Application Data', 'resources');
    if (!fs.existsSync(resPath)) return detections;

    const suspiciousPatterns = [
      { re: /LoadResourceFile\s*\([^)]*https?:\/\//i, risk: 'CRITICAL', desc: 'Uzak URL\'den kaynak yükleme' },
      { re: /PerformHttpRequest\s*\(/i, risk: 'HIGH', desc: 'HTTP isteği (veri gönderimi)' },
      { re: /Websocket/i, risk: 'HIGH', desc: 'WebSocket bağlantısı' },
      { re: /io\.popen|os\.execute|io\.open\s*\([^)]*['"]w['"]/i, risk: 'CRITICAL', desc: 'Sistem komutu çalıştırma' },
      { re: /RegisterNUICallback/i, risk: 'MEDIUM', desc: 'NUI callback kaydı' },
      { re: /SetTimeout\s*\(\s*0/i, risk: 'MEDIUM', desc: 'Süresiz timeout' },
      { re: /debug\.getinfo|loadstring|load\s*\(/i, risk: 'HIGH', desc: 'Dinamik kod yükleme' },
      { re: /string\.dump|load\s*\(/i, risk: 'HIGH', desc: 'Dinamik kod yükleme' },
      { re: /GetPlayerPed\s*\(\s*-1\s*\)/i, risk: 'LOW', desc: 'Oyuncu ped erişimi' },
      { re: /Citizen\.Trace/i, risk: 'LOW', desc: 'Trace çıktısı' },
    ];

    const walkResources = (dir, depth) => {
      if (depth > 6) return;
      try {
        fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walkResources(full, depth + 1);
          } else if (entry.isFile() && (entry.name.endsWith('.lua') || entry.name.endsWith('.js') || entry.name.endsWith('.ts'))) {
            try {
              const content = fs.readFileSync(full, 'utf8');
              for (const { re, risk, desc } of suspiciousPatterns) {
                if (re.test(content)) {
                  addDetection(detections, 'RESOURCE', 'Şüpheli kaynak kodu: ' + entry.name, desc, risk, { name: entry.name, path: full });
                  break;
                }
              }
            } catch (e) {}
          }
        });
      } catch (e) {}
    };

    walkResources(resPath, 0);
  } catch (e) {}
  return detections;
}

// 5. BÜTÜNÜLÜK + SİSTEM TARAMASI
async function scanIntegrity() {
  const detections = [];
  try {
    const os = getOs();
    const path = require('path');
    const fs = require('fs');
    const home = os.homedir ? os.homedir() : '';

    // Registry AutoRun kontrolü
    try {
      const { execSync } = require('child_process');
      const regOutput = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul', { encoding: 'utf8', timeout: 5000, windowsHide: true });
      const suspiciousReg = ['cheat', 'inject', 'hack', 'exploit', 'trainer', 'overlay', 'injector', 'xenos', 'extreme'];
      regOutput.split('\n').forEach(line => {
        for (const kw of suspiciousReg) {
          if (line.toLowerCase().includes(kw)) {
            addDetection(detections, 'SYSTEM', 'Şüpheli AutoRun girişi: ' + line.trim(), 'Registry startupEntry', 'HIGH', { entry: line.trim() });
            break;
          }
        }
      });
    } catch (e) {}

    // HKCU Run
    try {
      const { execSync } = require('child_process');
      const regOutput = execSync('reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul', { encoding: 'utf8', timeout: 5000, windowsHide: true });
      const suspiciousReg = ['cheat', 'inject', 'hack', 'exploit', 'trainer', 'overlay', 'injector'];
      regOutput.split('\n').forEach(line => {
        for (const kw of suspiciousReg) {
          if (line.toLowerCase().includes(kw)) {
            addDetection(detections, 'SYSTEM', 'Şüpheli HKCU AutoRun: ' + line.trim(), 'Kullanıcı startup girişi', 'HIGH', { entry: line.trim() });
            break;
          }
        }
      });
    } catch (e) {}

    // FiveM'e ait dosyalarda son değişiklikler
    const fivemPath = path.join(home, 'AppData', 'Local', 'FiveM');
    if (fs.existsSync(fivemPath)) {
      try {
        const scanModified = (dir, depth) => {
          if (depth > 3) return;
          try {
            fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
              const full = path.join(dir, entry.name);
              if (entry.isDirectory()) {
                scanModified(full, depth + 1);
              } else if (entry.isFile()) {
                try {
                  const st = fs.statSync(full);
                  const hoursSince = (Date.now() - st.mtime.getTime()) / 3600000;
                  if (hoursSince < 6 && st.mtime.getTime() !== st.birthtime.getTime()) {
                    const ext = path.extname(entry.name).toLowerCase();
                    if (['.dll', '.exe', '.asi', '.lua', '.js'].includes(ext)) {
                      addDetection(detections, 'INTEGRITY', 'Son 6 saatte değişmiş: ' + entry.name, 'Değişiklik: ' + st.mtime.toISOString(), 'MEDIUM', { name: entry.name, path: full, modified: st.mtime.toISOString() });
                    }
                  }
                } catch (e) {}
              }
            });
          } catch (e) {}
        };
        scanModified(fivemPath, 0);
      } catch (e) {}
    }

    // GTA V dizinindeki Modifications klasörü
    const gtaPaths = [
      path.join('C:', 'Program Files', 'Rockstar Games', 'Grand Theft Auto V'),
      path.join('C:', 'Program Files (x86)', 'Rockstar Games', 'Grand Theft Auto V'),
      path.join(home, 'Desktop', 'GTAV'),
      path.join(home, 'Desktop', 'GTA5')
    ];
    for (const gtaPath of gtaPaths) {
      if (!fs.existsSync(gtaPath)) continue;
      try {
        const modsDir = path.join(gtaPath, 'mods');
        if (fs.existsSync(modsDir)) {
          addDetection(detections, 'INTEGRITY', 'GTA V mods klasörü mevcut: ' + modsDir, 'OIV/OpenIV mods dizini', 'MEDIUM', { path: modsDir });
        }
        const updateDir = path.join(gtaPath, 'update', 'x64', 'dlcpacks');
        if (fs.existsSync(updateDir)) {
          fs.readdirSync(updateDir).forEach(dlc => {
            const dlcPath = path.join(updateDir, dlc);
            try {
              const st = fs.statSync(dlcPath);
              if (st.isDirectory() && st.size === 0) {
                const rpfFiles = fs.readdirSync(dlcPath).filter(f => f.endsWith('.rpf'));
                if (rpfFiles.length === 0) {
                  addDetection(detections, 'INTEGRITY', 'Boş DLC paketi: ' + dlc, 'Muhtemel hile DLC\'si', 'HIGH', { name: dlc, path: dlcPath });
                }
              }
            } catch (e) {}
          });
        }
      } catch (e) {}
    }

    // Sistem temp klasöründe şüpheli dosyalar
    try {
      const tempPath = os.tmpdir ? os.tmpdir() : path.join(home, 'AppData', 'Local', 'Temp');
      if (fs.existsSync(tempPath)) {
        const cheatTempFiles = ['inject', 'hack', 'cheat', 'exploit', 'dinput8', 'xenos'];
        fs.readdirSync(tempPath, { withFileTypes: true }).forEach(entry => {
          if (!entry.isFile()) return;
          const base = path.basename(entry.name, path.extname(entry.name)).toLowerCase();
          for (const kw of cheatTempFiles) {
            if (base.includes(kw)) {
              try {
                const st = fs.statSync(path.join(tempPath, entry.name));
                addDetection(detections, 'SYSTEM', 'Temp\'te şüpheli dosya: ' + entry.name, 'Boyut: ' + Math.round(st.size/1024) + 'KB', 'HIGH', { name: entry.name, path: path.join(tempPath, entry.name), size: st.size });
              } catch (e) {}
              break;
            }
          }
        });
      }
    } catch (e) {}

    // Ağ bağlantıları
    try {
      const { execSync } = require('child_process');
      const netstat = execSync('netstat -ano 2>nul', { encoding: 'utf8', timeout: 10000, windowsHide: true });
      const suspiciousPorts = ['4444', '5555', '1234', '6666', '7777', '8888', '9999', '1337', '31337', '44444', '55555'];
      const localEstablished = netstat.split('\n').filter(l => l.includes('ESTABLISHED') && l.includes('127.0.0.1'));
      if (localEstablished.length > 5) {
        addDetection(detections, 'NETWORK', 'Fazla yerel bağlantı: ' + localEstablished.length, 'Yerel ağda aktif bağlantlar tespit edildi', 'MEDIUM', { count: localEstablished.length });
      }
    } catch (e) {}
  } catch (e) {}
  return detections;
}

// 6. İMZA TARAMASI
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
          addDetection(detections, 'SIGNATURE', 'İmza eşleşmesi: ' + procName, 'İmza: ' + sig.signature_code, sig.risk_level, { name: procName, signature: sig.signature_code });
        }
      }
    });
  } catch (e) {}

  return detections;
}
