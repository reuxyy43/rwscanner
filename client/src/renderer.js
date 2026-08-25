let currentScanId = null;
let signatures = [];

window.addEventListener('DOMContentLoaded', async () => {
  try {
    const v = await window.rwscanner.checkVersion();
    if (v.current !== v.latest) {
      showError('Güncelleme Gerekli', "RwScanner'ın yeni sürümü mevcut: v" + v.latest);
    }
  } catch (e) {}
});

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
    const result = await window.rwscanner.startScan(pin);
    currentScanId = result.scan_id;
    setProgress(10);

    setStatus('İmzalar alınıyor...', '');
    try {
      const sigData = await window.rwscanner.getSignatures();
      signatures = sigData.signatures || [];
    } catch (e) { signatures = []; }

    setProgress(15);

    const modules = [
      { name: 'Process + modül taraması', fn: scanProcesses },
      { name: 'FiveM modül taraması', fn: scanModules },
      { name: 'Dosya taraması', fn: scanFiles },
      { name: 'FiveM kontrolü', fn: scanFiveM },
      { name: 'GTA V kök dizin taraması', fn: scanGTARoot },
      { name: 'Kaynak analizi', fn: scanResources },
      { name: 'Bütünlük + sistem kontrolü', fn: scanIntegrity },
      { name: 'İmza taraması', fn: scanSignatures },
      { name: 'Ağ + servis taraması', fn: scanNetwork },
      { name: 'Otomatik başlangıç taraması', fn: scanStartup }
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

    setStatus('Sonuçlar gönderiliyor...', 'Tarama sonuçları analiz ediliyor.');
    setProgress(95);

    await window.rwscanner.submitResults({
      scan_id: currentScanId,
      detections: allDetections,
      system_info: { platform: 'win32', app: 'RwScanner', version: '1.1.0' }
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

// ---- SCANNER MODULES v1.1 ----

function runCmd(cmd, timeout) {
  return new Promise((resolve) => {
    try {
      const { execSync } = require('child_process');
      const output = execSync(cmd, { encoding: 'utf8', timeout: timeout || 20000, windowsHide: true });
      resolve(output);
    } catch (e) { resolve(''); }
  });
}

function getOs() { try { return require('os'); } catch (e) { return {}; } }
function getPath() { try { return require('path'); } catch (e) { return {}; } }
function getFs() { try { return require('fs'); } catch (e) { return {}; } }
function getCrypto() { try { return require('crypto'); } catch (e) { return {}; } }

function addDet(d, type, title, desc, risk, data) {
  d.push({ type, title, description: desc, risk_level: risk, data: data || {} });
}

const CHEAT_DLL_NAMES = [
  'dinput8.dll', 'dsound.dll', 'd3d11.dll', 'd3d9.dll',
  'xinput1_3.dll', 'version.dll', 'winhttp.dll', 'winmm.dll',
  'dbghelp.dll', 'msvcr100.dll', 'msvcp140.dll', 'vcruntime140.dll',
  'lua51.dll', 'lua54.dll', 'scripthookv.dll', 'scripthookvdotnet.dll',
  'kinectdll.dll', 'openiv.asi', 'scripthookv.asi', 'dinput8.asi',
  'dsound.asi', 'trilogy.asi', 'heapadjuster.asi', 'packfilelimitadjuster.asi',
  'mf.dll', 'menyoo.asi', 'lolhack.dll', 'lolly.dll',
  'ntdll.dll', 'kernelbase.dll'
];

const LEGITIMATE_DLL_NAMES = [
  'dbghelp.dll', 'version.dll', 'winhttp.dll', 'winmm.dll',
  'dinput8.dll', 'dsound.dll', 'd3d11.dll', 'd3d9.dll',
  'xinput1_3.dll', 'msvcr100.dll', 'msvcp140.dll', 'vcruntime140.dll'
];

const KNOWN_CHEAT_PROCESSES = [
  { re: /cheat\s*engine|cheatengine|ce\s*main/i, risk: 'CRITICAL', desc: 'Cheat Engine' },
  { re: /xenos\d*|xenos64/i, risk: 'CRITICAL', desc: 'Xenos injector' },
  { re: /extreme\s*injector/i, risk: 'CRITICAL', desc: 'Extreme Injector' },
  { re: /process\s*hacker|processhacker/i, risk: 'HIGH', desc: 'Process Hacker' },
  { re: /x64dbg|x32dbg|x96dbg|ollydbg/i, risk: 'HIGH', desc: 'Debugger' },
  { re: /dnspy|dnSpy/i, risk: 'HIGH', desc: '.NET Decompiler' },
  { re: /frida/i, risk: 'HIGH', desc: 'Frida injection framework' },
  { re: /reclass/i, risk: 'HIGH', desc: 'ReClass memory tool' },
  { re: /http\s*debugger|httpdebugger/i, risk: 'HIGH', desc: 'HTTP Debugger' },
  { re: /charles\s*proxy/i, risk: 'MEDIUM', desc: 'Charles Proxy' },
  { re: /mitmproxy/i, risk: 'HIGH', desc: 'MITM Proxy' },
  { re: /fiddler/i, risk: 'MEDIUM', desc: 'Fiddler' },
  { re: /wireshark/i, risk: 'MEDIUM', desc: 'Wireshark' },
  { re: /dbgview/i, risk: 'MEDIUM', desc: 'DebugView' },
  { re: /sandboxie/i, risk: 'MEDIUM', desc: 'Sandboxie' },
  { re: /aimbot|wallhack|speedhack|triggerbot|silentaim/i, risk: 'CRITICAL', desc: 'Hile aracı' },
  { re: /noclip|godmode|god_mode/i, risk: 'CRITICAL', desc: 'Hile aracı' },
  { re: /trainer|modmenu|mod_menu/i, risk: 'HIGH', desc: 'Mod menü' },
  { re: /luna\s*(cheat|menu)|luna\.lua/i, risk: 'CRITICAL', desc: 'Luna cheat' },
  { re: /panther|panthera/i, risk: 'CRITICAL', desc: 'Panther cheat' },
  { re: /spectrum\s*cheat/i, risk: 'CRITICAL', desc: 'Spectrum cheat' },
  { re: /nighthawk/i, risk: 'CRITICAL', desc: 'Nighthawk cheat' },
  { re: /oxide\s*cheat/i, risk: 'CRITICAL', desc: 'Oxide cheat' },
  { re: /planb\s*(cheat|menu)/i, risk: 'CRITICAL', desc: 'PlanB cheat' },
  { re: /dark\s*comet/i, risk: 'CRITICAL', desc: 'DarkComet RAT' },
  { re: /synapse|krnl|scriptware/i, risk: 'HIGH', desc: 'Script exploit' },
  { re: /exploit|inject.*dll|dll.*inject/i, risk: 'HIGH', desc: 'Inject/Exploit aracı' },
  { re: /hwid\s*spoofer|spoofer/i, risk: 'HIGH', desc: 'HWID Spoofer' },
  { re: /cleaner.*fivem|fivem.*cleaner/i, risk: 'HIGH', desc: 'Fivem cleaner' },
];

const CHEAT_FILE_KEYWORDS = [
  'inject', 'hack', 'cheat', 'exploit', 'trainer', 'modmenu', 'mod_menu',
  'aimbot', 'wallhack', 'speedhack', 'noclip', 'godmode', 'god_mode',
  'esp', 'triggerbot', 'silentaim', 'magic_bullet', 'lagswitch',
  'rage', 'legit', 'custom_aim', 'menu_builder', 'overlay',
  'hwid_spoof', 'spoof', 'bypass', 'stealth', 'undetected',
  'fivem_hack', 'gta_hack', 'rp_hack', 'luaexecutor',
  'executor', 'synapse', 'krnl', 'fluxus'
];

// Known cheat DLL hashes (SHA-256, lowercase) — add more as identified
const KNOWN_CHEAT_HASHES = {
};

// 1. PROCESS TARAMASI — process list + WMIC komut satırı
async function scanProcesses() {
  const d = [];
  const output = await runCmd('tasklist /FO CSV /NH');
  if (!output) return d;

  const knownSafe = new Set([
    'svchost.exe', 'csrss.exe', 'smss.exe', 'lsass.exe', 'services.exe',
    'wininit.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe', 'taskhostw.exe',
    'conhost.exe', 'runtimebroker.exe', 'shellexperiencehost.exe',
    'sihost.exe', 'fontdrvhost.exe', 'system', 'idle',
    'system idle process', 'not implemented', 'searchapp.exe', 'searchui.exe',
    'textinputhost.exe', 'applicationframehost.exe', 'ctfmon.exe',
    'dllhost.exe', 'wmiprvse.exe', 'spoolsv.exe', 'taskeng.exe',
    'taskw92.exe', 'unsecapp.exe', 'werfault.exe', 'wudfhost.exe',
    'audiodg.exe', 'dasHost.exe', 'SearchHost.exe', 'StartMenuExperienceHost.exe',
    'LockApp.exe', 'SecurityHealthService.exe', 'SecurityHealthSystray.exe',
    'NisSrv.exe', 'MpCmdRun.exe', 'MsMpEng.exe', 'SearchIndexer.exe',
    'SearchProtocolHost.exe', 'SearchFilterHost.exe', 'WmiPrvSE.exe',
    'msdtc.exe', 'lsaiso.exe', 'csrss.exe', 'winlogon.exe',
    'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'cmd.exe',
    'powershell.exe', 'pwsh.exe', 'node.exe', 'electron.exe',
    'rwscanner.exe', 'chrome.exe', 'firefox.exe', 'msedge.exe',
    'brave.exe', 'opera.exe', 'steam.exe', 'steamwebhelper.exe',
    'discord.exe', 'slack.exe', 'spotify.exe', 'obs64.exe', 'obs32.exe',
    'rtkmp.exe', 'razer synapse.exe', 'razer central.exe',
    'nvidia web helper.exe', 'nvcontainer.exe', 'nvsphelper64.exe',
    'lgsoftwareupdater.exe', 'lghub.exe', 'ghub.exe',
    'onedrive.exe', 'teams.exe', 'outlook.exe', 'winword.exe',
    'excel.exe', 'powerpnt.exe', 'acrobat.exe', 'acrodist.exe',
    'acrotray.exe', 'ccxprocess.exe', 'creative cloud.exe',
    'googleupdate.exe', 'googlecrashhandler.exe', 'googlecrashhandler64.exe',
    'dropbox.exe', 'googledrivesync.exe', 'onedrive.exe',
    'service_hub.exe', 'devenv.exe', 'msbuild.exe',
  ]);

  for (const line of output.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('","').map(p => p.replace(/"/g, ''));
    const name = parts[0] || '';
    const pid = parts[1] || '';
    if (knownSafe.has(name.toLowerCase())) continue;

    for (const { re, risk, desc } of KNOWN_CHEAT_PROCESSES) {
      if (re.test(name)) {
        addDet(d, 'PROCESS', 'Şüpheli process: ' + name, desc, risk, { name, pid });
        break;
      }
    }
  }

  // WMIC ile tam komut satırı kontrolü
  try {
    const wmic = await runCmd('wmic process get Name,ExecutablePath,CommandLine /FORMAT:CSV 2>nul');
    if (wmic) {
      const lines = wmic.split('\n').filter(l => l.trim());
      for (const line of lines) {
        const lower = line.toLowerCase();
        if (lower.includes('cheatengine') || lower.includes('xenos') || lower.includes('injector') ||
            lower.includes('hack') || lower.includes('exploit') || lower.includes('trainer') ||
            lower.includes('aimbot') || lower.includes('wallhack') || lower.includes('speedhack') ||
            lower.includes('modmenu') || lower.includes('godmode') || lower.includes('noclip') ||
            lower.includes('lua51.dll') || lower.includes('scripthookv') || lower.includes('dinput8.asi')) {
          const match = line.match(/,([^,]+\.exe)/i);
          const procName = match ? match[1].trim() : 'Unknown';
          if (!knownSafe.has(procName.toLowerCase())) {
            addDet(d, 'PROCESS', 'WMIC şüpheli komut: ' + procName, 'Komut satırında şüpheli içerik', 'CRITICAL', { command: line.trim() });
          }
        }
      }
    }
  } catch (e) {}

  return d;
}

// 2. MODÜL TARAMASI — FiveM.exe/GTA5.exe içine yüklü DLL'ler
async function scanModules() {
  const d = [];
  const gameProcesses = ['FiveM.exe', 'FiveM_Child.exe', 'GTA5.exe', 'playgtav.exe'];

  for (const proc of gameProcesses) {
    // tasklist /m ile yüklü modülleri al
    const modules = await runCmd('tasklist /m /fi "imagename eq ' + proc + '" /FO CSV 2>nul');
    if (!modules || !modules.includes(proc.toLowerCase().replace('.exe', ''))) {
      // process zaten yok, devam et
    }

    if (!modules || modules.trim().length < 50) continue;

    const lines = modules.split('\n').filter(l => l.trim());
    for (const line of lines) {
      const lower = line.toLowerCase();

      // Known cheat DLL isimleri kontrolü (Game Root'ta olmayan yerlerden gelenler)
      for (const dllName of CHEAT_DLL_NAMES) {
        if (lower.includes(dllName) && !lower.includes('system32') && !lower.includes('syswow64') && !lower.includes('\\windows\\')) {
          const isInSystem = lower.includes('c:\\windows') || lower.includes('c:\\program files');
          if (!isInSystem) {
            addDet(d, 'MODULE', proc + ' içinde şüpheli modül: ' + dllName, 'Sistem dışı yoldan yüklenmiş', 'CRITICAL', { process: proc, module: dllName, line: line.trim().substring(0, 200) });
          }
        }
      }

      // Özel可疑 DLL pattern'ları — kendinden doğrulamalı
      const suspiciousModulePatterns = [
        /dinput8\.dll/i, /dsound\.dll/i, /xinput1_3\.dll/i,
        /lua5[14]\.dll/i, /scripthookv/i, /menyoo/i,
        /addon[\s_-]?spawner/i, /trainer[\s_/]/i, /nativeui/i,
        /lolly\.dll/i, /lolhack/i, /mf\.dll/i,
        /\.asi\b/i
      ];

      for (const pat of suspiciousModulePatterns) {
        if (pat.test(line)) {
          const dllMatch = line.match(/([A-Za-z0-9_\-\.]+\.(dll|asi))/i);
          const dllName = dllMatch ? dllMatch[1] : 'unknown';
          const pathMatch = line.match(/([A-Z]:\\[^\s,"]+)/i);
          const dllPath = pathMatch ? pathMatch[1] : '';

          if (dllPath && !dllPath.toLowerCase().includes('\\windows\\') && !dllPath.toLowerCase().includes('\\program files')) {
            addDet(d, 'MODULE', proc + ' içinde şüpheli modül: ' + dllName, 'Oyun dizininde/../modül', 'CRITICAL', { process: proc, module: dllName, path: dllPath });
          }
        }
      }
    }
  }

  // WMIC ile modül listesi (daha detaylı)
  for (const proc of gameProcesses) {
    try {
      const wmicModules = await runCmd('wmic process where "name=\'' + proc + '\'" get CommandLine,ExecutablePath /FORMAT:CSV 2>nul');
      if (wmicModules && wmicModules.length > 10) {
        const execPath = wmicModules.split('\n')[1];
        if (execPath) {
          const match = execPath.match(/,([^,]+)$/);
          if (match && match[1]) {
            addDet(d, 'MODULE', proc + ' yolu tespit edildi', match[1].trim(), 'LOW', { process: proc, path: match[1].trim() });
          }
        }
      }
    } catch (e) {}
  }

  return d;
}

// 3. DOSYA TARAMASI — FiveM, GTA V, Downloads, Desktop
async function scanFiles() {
  const d = [];
  const os = getOs();
  const p = getPath();
  const fs = getFs();
  const crypto = getCrypto();
  const home = os.homedir ? os.homedir() : '';

  const scanPaths = [
    p.join(home, 'AppData', 'Local', 'FiveM'),
    p.join(home, 'AppData', 'Local', 'FiveM', 'Application Data'),
    p.join(home, 'Downloads'),
    p.join(home, 'Desktop'),
    p.join(home, 'Documents'),
  ];

  for (const basePath of scanPaths) {
    if (!fs.existsSync(basePath)) continue;
    try {
      const walk = (dir, depth) => {
        if (depth > 5) return;
        try {
          fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
            const full = p.join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
              walk(full, depth + 1);
            } else if (entry.isFile()) {
              const ext = p.extname(entry.name).toLowerCase();
              const base = p.basename(entry.name, ext).toLowerCase();

              // Cheat keyword kontrolü
              for (const kw of CHEAT_FILE_KEYWORDS) {
                if (base.includes(kw)) {
                  try {
                    const st = fs.statSync(full);
                    const risk = ['inject', 'cheat', 'exploit', 'aimbot', 'wallhack', 'speedhack', 'godmode', 'noclip', 'bypass', 'spoof'].includes(kw) ? 'CRITICAL' : 'HIGH';
                    addDet(d, 'FILE', 'Şüpheli dosya: ' + entry.name, 'Kalıp: ' + kw + ' | ' + Math.round(st.size / 1024) + 'KB', risk, { name: entry.name, path: full, size: st.size });
                  } catch (e) {}
                  break;
                }
              }

              // ASI dosyaları
              if (ext === '.asi' && (full.toLowerCase().includes('fivem') || full.toLowerCase().includes('gta'))) {
                try {
                  const st = fs.statSync(full);
                  addDet(d, 'FILE', 'ASI dosyası: ' + entry.name, Math.round(st.size / 1024) + 'KB', 'HIGH', { name: entry.name, path: full, size: st.size });
                } catch (e) {}
              }

              // FiveM dizinindeki bilinen hile DLL'leri (sistem yolu dışı)
              if ((ext === '.dll' || ext === '.asi') && full.toLowerCase().includes('fivem')) {
                try {
                  const st = fs.statSync(full);
                  if (st.size > 0) {
                    const dllBase = base + ext;
                    const isSuspicious = CHEAT_DLL_NAMES.some(cn => cn.toLowerCase() === dllBase);
                    if (isSuspicious) {
                      addDet(d, 'FILE', 'Potansiyel hile dosyası: ' + entry.name, Math.round(st.size / 1024) + 'KB', 'CRITICAL', { name: entry.name, path: full, size: st.size });
                    } else if (ext === '.dll' && st.size < 1048576) {
                      addDet(d, 'FILE', 'FiveM dizininde küçük DLL: ' + entry.name, Math.round(st.size / 1024) + 'KB', 'LOW', { name: entry.name, path: full, size: st.size });
                    }
                  }
                } catch (e) {}
              }

              // Hash kontrolü
              if ((ext === '.dll' || ext === '.asi' || ext === '.exe') && full.toLowerCase().includes('fivem')) {
                try {
                  const buf = fs.readFileSync(full);
                  const hash = crypto.createHash('sha256').update(buf).digest('hex');
                  if (KNOWN_CHEAT_HASHES[hash]) {
                    addDet(d, 'FILE', 'Bilinen hile hash eşleşmesi: ' + entry.name, KNOWN_CHEAT_HASHES[hash], 'CRITICAL', { name: entry.name, path: full, hash });
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

  return d;
}

// 4. FIVEM TARAMASI — resources, citizen, cache, dll
async function scanFiveM() {
  const d = [];
  const os = getOs();
  const p = getPath();
  const fs = getFs();
  const home = os.homedir ? os.homedir() : '';
  const fivemPath = p.join(home, 'AppData', 'Local', 'FiveM');
  const fivemApp = p.join(fivemPath, 'Application Data');

  if (!fs.existsSync(fivemPath)) return d;

  // FiveM.exe boyut kontrolü
  const fivemExe = p.join(fivemPath, 'FiveM.exe');
  if (fs.existsSync(fivemExe)) {
    try {
      const st = fs.statSync(fivemExe);
      if (st.size < 100000) {
        addDet(d, 'FIVEM', 'FiveM.exe boyutu anormal: ' + Math.round(st.size / 1024) + 'KB', 'Olağandışı küçük boyut', 'HIGH', { path: fivemExe, size: st.size });
      }
    } catch (e) {}
  }

  // Resources taraması — çalıştırılabilir dosyalar + manifestsiz kaynaklar
  const resPath = p.join(fivemApp, 'resources');
  if (fs.existsSync(resPath)) {
    try {
      fs.readdirSync(resPath, { withFileTypes: true }).forEach(cat => {
        if (!cat.isDirectory()) return;
        const catPath = p.join(resPath, cat.name);
        try {
          fs.readdirSync(catPath, { withFileTypes: true }).forEach(res => {
            if (!res.isDirectory()) return;
            const resDir = p.join(catPath, res.name);
            try {
              const files = fs.readdirSync(resDir);

              // Çalıştırılabilir dosya kontrolü
              files.forEach(file => {
                const ext = p.extname(file).toLowerCase();
                if (['.exe', '.dll', '.asi', '.luac'].includes(ext)) {
                  addDet(d, 'RESOURCE', 'Kaynakta çalıştırılabilir: ' + cat.name + '/' + res.name + '/' + file, 'İzin verilmeyen dosya türü', 'HIGH', { resource: res.name, file });
                }
              });

              // fxmanifest.lua içeriği
              const fxmanifest = p.join(resDir, 'fxmanifest.lua');
              if (fs.existsSync(fxmanifest)) {
                try {
                  const content = fs.readFileSync(fxmanifest, 'utf8');
                  const lower = content.toLowerCase();
                  if (lower.includes('loadresourcefile') && (lower.includes('http://') || lower.includes('https://'))) {
                    addDet(d, 'RESOURCE', 'Kaynakta uzak yükleme: ' + res.name, 'fxmanifest.lua URL yükleme', 'CRITICAL', { resource: res.name, path: fxmanifest });
                  }
                  if (lower.includes('loadstring') || lower.includes('load(') || lower.includes('io.popen') || lower.includes('os.execute')) {
                    addDet(d, 'RESOURCE', 'Dinamik kod: ' + res.name, 'fxmanifest.lua dinamik kod çalıştırma', 'CRITICAL', { resource: res.name, path: fxmanifest });
                  }
                } catch (e) {}
              }

              // __resource.lua (eski format)
              const oldResource = p.join(resDir, '__resource.lua');
              if (!fs.existsSync(fxmanifest) && !fs.existsSync(oldResource)) {
                const luaFiles = files.filter(f => f.endsWith('.lua') || f.endsWith('.js'));
                if (luaFiles.length > 0) {
                  addDet(d, 'RESOURCE', 'Manifestsiz kaynak: ' + res.name, 'fxmanifest.lua bulunamadı', 'MEDIUM', { resource: res.name });
                }
              }
            } catch (e) {}
          });
        } catch (e) {}
      });
    } catch (e) {}
  }

  // Citizen dizinindeki DLL'ler
  const citPath = p.join(fivemApp, 'citizen');
  if (fs.existsSync(citPath)) {
    try {
      const scanCit = (dir) => {
        if (!fs.existsSync(dir)) return;
        fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
          if (!entry.isFile()) return;
          const ext = p.extname(entry.name).toLowerCase();
          if (ext !== '.dll') return;
          const full = p.join(dir, entry.name);
          try {
            const st = fs.statSync(full);
            if (st.size > 0 && st.size < 2097152) {
              const isSuspicious = CHEAT_DLL_NAMES.some(cn => cn.toLowerCase() === entry.name.toLowerCase());
              if (isSuspicious) {
                addDet(d, 'FIVEM', 'Citizen\'da şüpheli DLL: ' + entry.name, Math.round(st.size / 1024) + 'KB', 'HIGH', { name: entry.name, path: full, size: st.size });
              }
            }
          } catch (e) {}
        });
      };
      scanCit(citPath);
      scanCit(p.join(citPath, 'common'));
      scanCit(p.join(citPath, 'common', 'data'));
    } catch (e) {}
  }

  // Cache dosyaları
  const cachePath = p.join(fivemApp, 'data', 'cache');
  if (fs.existsSync(cachePath)) {
    try {
      fs.readdirSync(cachePath, { withFileTypes: true }).forEach(entry => {
        if (!entry.isFile()) return;
        const full = p.join(cachePath, entry.name);
        try {
          const st = fs.statSync(full);
          if (st.size > 52428800) {
            addDet(d, 'FIVEM', 'Büyük cache dosyası: ' + entry.name, Math.round(st.size / 1048576) + 'MB', 'MEDIUM', { name: entry.name, path: full, size: st.size });
          }
          if (st.mtime > new Date(Date.now() - 86400000)) {
            addDet(d, 'FIVEM', 'Son 24 saatte değişmiş cache: ' + entry.name, st.mtime.toISOString(), 'LOW', { name: entry.name, modified: st.mtime.toISOString() });
          }
        } catch (e) {}
      });
    } catch (e) {}
  }

  // Application Data'da izinsiz DLL
  try {
    fs.readdirSync(fivemApp).forEach(file => {
      if (p.extname(file).toLowerCase() === '.dll') {
        try {
          const st = fs.statSync(p.join(fivemApp, file));
          addDet(d, 'FIVEM', 'Application Data DLL: ' + file, Math.round(st.size / 1024) + 'KB', 'LOW', { name: file, size: st.size });
        } catch (e) {}
      }
    });
  } catch (e) {}

  return d;
}

// 5. GTA V KÖK DİZİN TARAMASI
async function scanGTARoot() {
  const d = [];
  const p = getPath();
  const fs = getFs();
  const os = getOs();
  const home = os.homedir ? os.homedir() : '';

  const possibleRoots = [
    p.join('C:', 'Program Files', 'Rockstar Games', 'Grand Theft Auto V'),
    p.join('C:', 'Program Files (x86)', 'Rockstar Games', 'Grand Theft Auto V'),
    p.join('D:', 'Games', 'Grand Theft Auto V'),
    p.join('D:', 'GTA V'),
    p.join('D:', 'GTAV'),
    p.join('E:', 'Games', 'Grand Theft Auto V'),
    p.join('E:', 'GTA V'),
    p.join('E:', 'GTAV'),
    p.join('C:', 'GTA V'),
    p.join('C:', 'GTAV'),
    p.join(home, 'Desktop', 'GTA V'),
    p.join(home, 'Desktop', 'GTAV'),
  ];

  for (const root of possibleRoots) {
    if (!fs.existsSync(root)) continue;
    try {
      fs.readdirSync(root).forEach(file => {
        const ext = p.extname(file).toLowerCase();
        const base = p.basename(file, ext).toLowerCase();
        const full = p.join(root, file);

        // ASI dosyaları
        if (ext === '.asi') {
          try {
            const st = fs.statSync(full);
            addDet(d, 'GTA', 'GTA V kökünde ASI: ' + file, Math.round(st.size / 1024) + 'KB', 'CRITICAL', { name: file, path: full, size: st.size });
          } catch (e) {}
        }

        // ScriptHookV, dinput8, dsound
        if (['scripthookv.dll', 'dinput8.dll', 'dsound.dll', 'xinput1_3.dll', 'version.dll'].includes(base + ext)) {
          try {
            const st = fs.statSync(full);
            addDet(d, 'GTA', 'GTA V kökünde injector/loader: ' + file, Math.round(st.size / 1024) + 'KB', 'CRITICAL', { name: file, path: full, size: st.size });
          } catch (e) {}
        }

        // mods klasörü
        if (file === 'mods' && fs.existsSync(full)) {
          addDet(d, 'GTA', 'GTA V mods klasörü: ' + full, 'OpenIV/OIV mods dizini', 'MEDIUM', { path: full });
        }

        // Cheat keyword'leri
        for (const kw of CHEAT_FILE_KEYWORDS) {
          if (base.includes(kw)) {
            try {
              const st = fs.statSync(full);
              addDet(d, 'GTA', 'GTA V kökünde şüpheli dosya: ' + file, 'Kalıp: ' + kw, 'HIGH', { name: file, path: full, size: st.size });
            } catch (e) {}
            break;
          }
        }
      });

      // dlcpacks kontrolü
      const dlcDir = p.join(root, 'update', 'x64', 'dlcpacks');
      if (fs.existsSync(dlcDir)) {
        fs.readdirSync(dlcDir).forEach(dlc => {
          const dlcPath = p.join(dlcDir, dlc);
          try {
            const st = fs.statSync(dlcPath);
            if (st.isDirectory() && st.size === 0) {
              const rpfFiles = fs.readdirSync(dlcPath).filter(f => f.endsWith('.rpf'));
              if (rpfFiles.length === 0) {
                addDet(d, 'GTA', 'Boş DLC paketi: ' + dlc, 'Muhtemel hile DLC\'si', 'HIGH', { name: dlc, path: dlcPath });
              }
            }
          } catch (e) {}
        });
      }
    } catch (e) {}
  }

  return d;
}

// 6. KAYNAK İÇERİK TARAMASI — Lua/JS dosyaları
async function scanResources() {
  const d = [];
  const os = getOs();
  const p = getPath();
  const fs = getFs();
  const home = os.homedir ? os.homedir() : '';
  const resPath = p.join(home, 'AppData', 'Local', 'FiveM', 'Application Data', 'resources');
  if (!fs.existsSync(resPath)) return d;

  const suspiciousPatterns = [
    { re: /LoadResourceFile\s*\([^)]*https?:\/\//i, risk: 'CRITICAL', desc: 'Uzak URL\'den kaynak yükleme' },
    { re: /PerformHttpRequest\s*\(/i, risk: 'HIGH', desc: 'HTTP isteği' },
    { re: /Websocket/i, risk: 'HIGH', desc: 'WebSocket bağlantısı' },
    { re: /io\.popen|os\.execute/i, risk: 'CRITICAL', desc: 'Sistem komutu çalıştırma' },
    { re: /io\.open\s*\([^)]*['"]w['"]/i, risk: 'CRITICAL', desc: 'Dosya yazma' },
    { re: /debug\.getinfo|loadstring|load\s*\(/i, risk: 'HIGH', desc: 'Dinamik kod yükleme' },
    { re: /string\.dump/i, risk: 'HIGH', desc: 'Kod dump' },
    { re: /RegisterNUICallback/i, risk: 'MEDIUM', desc: 'NUI callback' },
    { re: /SetTimeout\s*\(\s*0/i, risk: 'LOW', desc: 'Süresiz timeout' },
    { re: /Citizen\.Trace/i, risk: 'LOW', desc: 'Trace çıktısı' },
  ];

  const walk = (dir, depth) => {
    if (depth > 6) return;
    try {
      fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
        const full = p.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full, depth + 1);
        } else if (entry.isFile() && (entry.name.endsWith('.lua') || entry.name.endsWith('.js') || entry.name.endsWith('.ts'))) {
          try {
            const content = fs.readFileSync(full, 'utf8');
            for (const { re, risk, desc } of suspiciousPatterns) {
              if (re.test(content)) {
                addDet(d, 'RESOURCE', 'Şüpheli kaynak kodu: ' + entry.name, desc, risk, { name: entry.name, path: full });
                break;
              }
            }
          } catch (e) {}
        }
      });
    } catch (e) {}
  };

  walk(resPath, 0);
  return d;
}

// 7. BÜTÜNÜLÜK + SİSTEM TARAMASI
async function scanIntegrity() {
  const d = [];
  const os = getOs();
  const p = getPath();
  const fs = getFs();
  const home = os.homedir ? os.homedir() : '';

  // Registry AutoRun
  try {
    const reg1 = await runCmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul');
    const reg2 = await runCmd('reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 2>nul');
    const reg3 = await runCmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" 2>nul');
    const reg4 = await runCmd('reg query "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" 2>nul');
    const allReg = reg1 + '\n' + reg2 + '\n' + reg3 + '\n' + reg4;
    const suspReg = ['cheat', 'inject', 'hack', 'exploit', 'trainer', 'overlay', 'injector', 'xenos', 'extreme', 'fivem', 'lua', 'trainer'];
    allReg.split('\n').forEach(line => {
      for (const kw of suspReg) {
        if (line.toLowerCase().includes(kw)) {
          addDet(d, 'SYSTEM', 'Şüpheli AutoRun: ' + line.trim(), 'Registry startup girişi', 'HIGH', { entry: line.trim() });
          break;
        }
      }
    });
  } catch (e) {}

  // FiveM son değişiklikler
  const fivemPath = p.join(home, 'AppData', 'Local', 'FiveM');
  if (fs.existsSync(fivemPath)) {
    try {
      const scanMod = (dir, depth) => {
        if (depth > 3) return;
        try {
          fs.readdirSync(dir, { withFileTypes: true }).forEach(entry => {
            const full = p.join(dir, entry.name);
            if (entry.isDirectory()) {
              scanMod(full, depth + 1);
            } else if (entry.isFile()) {
              try {
                const st = fs.statSync(full);
                const hoursSince = (Date.now() - st.mtime.getTime()) / 3600000;
                if (hoursSince < 6 && st.mtime.getTime() !== st.birthtime.getTime()) {
                  const ext = p.extname(entry.name).toLowerCase();
                  if (['.dll', '.exe', '.asi', '.lua', '.js'].includes(ext)) {
                    addDet(d, 'INTEGRITY', 'Son 6 saatte değişmiş: ' + entry.name, st.mtime.toISOString(), 'MEDIUM', { name: entry.name, path: full, modified: st.mtime.toISOString() });
                  }
                }
              } catch (e) {}
            }
          });
        } catch (e) {}
      };
      scanMod(fivemPath, 0);
    } catch (e) {}
  }

  // Temp klasörü
  try {
    const tempPath = os.tmpdir ? os.tmpdir() : p.join(home, 'AppData', 'Local', 'Temp');
    if (fs.existsSync(tempPath)) {
      const cheatTemp = ['inject', 'hack', 'cheat', 'exploit', 'dinput8', 'xenos', 'lua51', 'scripthook'];
      fs.readdirSync(tempPath, { withFileTypes: true }).forEach(entry => {
        if (!entry.isFile()) return;
        const base = p.basename(entry.name, p.extname(entry.name)).toLowerCase();
        for (const kw of cheatTemp) {
          if (base.includes(kw)) {
            try {
              const st = fs.statSync(p.join(tempPath, entry.name));
              addDet(d, 'SYSTEM', 'Temp\'te şüpheli: ' + entry.name, Math.round(st.size / 1024) + 'KB', 'HIGH', { name: entry.name, size: st.size });
            } catch (e) {}
            break;
          }
        }
      });
    }
  } catch (e) {}

  return d;
}

// 8. İMZA TARAMASI
async function scanSignatures() {
  const d = [];
  if (!signatures.length) return d;

  try {
    const output = await runCmd('tasklist /FO CSV /NH');
    if (!output) return d;

    output.split('\n').filter(l => l.trim()).forEach(line => {
      const procName = (line.split('","')[0] || '').replace(/"/g, '').toLowerCase();
      for (const sig of signatures) {
        if (sig.type === 'PROCESS' && procName.includes((sig.signature_code || '').toLowerCase())) {
          addDet(d, 'SIGNATURE', 'İmza eşleşmesi: ' + procName, 'İmza: ' + sig.signature_code, sig.risk_level, { name: procName, signature: sig.signature_code });
        }
      }
    });
  } catch (e) {}

  // Modül imzaları
  try {
    for (const sig of signatures) {
      if (sig.type !== 'MODULE') continue;
      const modCheck = await runCmd('tasklist /m 2>nul');
      if (modCheck && modCheck.toLowerCase().includes((sig.signature_code || '').toLowerCase())) {
        addDet(d, 'SIGNATURE', 'Modül imzası: ' + sig.signature_code, sig.risk_level, { signature: sig.signature_code });
      }
    }
  } catch (e) {}

  return d;
}

// 9. AĞ + SERVİS TARAMASI
async function scanNetwork() {
  const d = [];

  // Dinamik portlu dinleyiciler
  try {
    const netstat = await runCmd('netstat -ano');
    if (netstat) {
      const listening = netstat.split('\n').filter(l => l.includes('LISTENING'));
      const established = netstat.split('\n').filter(l => l.includes('ESTABLISHED'));

      // FiveM process'leri için ağ bağlantıları
      const fiveMPids = [];
      try {
        const tl = await runCmd('tasklist /FO CSV /NH');
        if (tl) {
          tl.split('\n').forEach(line => {
            const parts = line.split('","').map(p => p.replace(/"/g, ''));
            if (parts[0] && (parts[0].toLowerCase().includes('fivem') || parts[0].toLowerCase().includes('gta5'))) {
              fiveMPids.push(parts[1]);
            }
          });
        }
      } catch (e) {}

      // FiveM dışı şüpheli portlar
      const suspPorts = listening.filter(l => {
        const portMatch = l.match(/:(\d+)/);
        if (!portMatch) return false;
        const port = parseInt(portMatch[1]);
        return port >= 4444 && port <= 9999 && port !== 53 && port !== 80 && port !== 443;
      });

      if (suspPorts.length > 3) {
        addDet(d, 'NETWORK', 'Şüpheli portlar dinleniyor: ' + suspPorts.length, 'Dinleyici portlar tespit edildi', 'MEDIUM', { count: suspPorts.length });
      }

      // Yerel bağlantı fazlalığı
      if (established.length > 20) {
        addDet(d, 'NETWORK', 'Fazla aktif bağlantı: ' + established.length, 'ESTABLISHED bağlantılarda fazlalık', 'LOW', { count: established.length });
      }
    }
  } catch (e) {}

  // FiveM dışı şüpheli servisler
  try {
    const services = await runCmd('sc query type= service state= all 2>nul');
    if (services) {
      const suspServices = ['cheat', 'inject', 'hack', 'exploit', 'xenos', 'extreme'];
      const lines = services.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const nameMatch = lines[i].match(/SERVICE_NAME:\s*(.+)/i);
        if (nameMatch) {
          const svcName = nameMatch[1].trim().toLowerCase();
          for (const kw of suspServices) {
            if (svcName.includes(kw)) {
              addDet(d, 'NETWORK', 'Şüpheli servis: ' + nameMatch[1].trim(), 'Windows servisi tespit edildi', 'HIGH', { service: nameMatch[1].trim() });
              break;
            }
          }
        }
      }
    }
  } catch (e) {}

  return d;
}

// 10. OTOMATİK BAŞLANGIÇ TARAMASI
async function scanStartup() {
  const d = [];

  const startupPaths = [
    '%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
    '%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
  ];

  for (const sp of startupPaths) {
    try {
      const output = await runCmd('dir /b "' + sp + '" 2>nul');
      if (!output) continue;
      output.split('\n').filter(l => l.trim()).forEach(file => {
        const f = file.trim().toLowerCase();
        const suspStart = ['cheat', 'inject', 'hack', 'exploit', 'trainer', 'lua', 'dinput8', 'xenos', 'fivem'];
        for (const kw of suspStart) {
          if (f.includes(kw)) {
            addDet(d, 'STARTUP', 'Başlangıç klasöründe şüpheli: ' + file.trim(), 'Otomatik başlangıç girişi', 'HIGH', { file: file.trim(), path: sp });
            break;
          }
        }

        // .lnk dosyalarının hedefini kontrol et
        if (f.endsWith('.lnk')) {
          try {
            const { execSync } = require('child_process');
            const ps = execSync('powershell -Command "$sh = New-Object -ComObject WScript.Shell; $lnk = $sh.CreateShortcut(\'' + sp + '\\' + file.trim() + '\'); Write-Output $lnk.TargetPath"', { encoding: 'utf8', timeout: 5000, windowsHide: true }).trim();
            if (ps) {
              const lowerPs = ps.toLowerCase();
              for (const kw of suspStart) {
                if (lowerPs.includes(kw)) {
                  addDet(d, 'STARTUP', 'Şüpheli kısayol hedefi: ' + ps, file.trim() + ' -> ' + ps, 'HIGH', { target: ps, shortcut: file.trim() });
                  break;
                }
              }
            }
          } catch (e) {}
        }
      });
    } catch (e) {}
  }

  // Scheduled Tasks
  try {
    const schtasks = await runCmd('schtasks /query /FO CSV 2>nul');
    if (schtasks) {
      const suspTasks = ['cheat', 'inject', 'hack', 'exploit', 'xenos'];
      schtasks.split('\n').filter(l => l.trim()).forEach(line => {
        const lower = line.toLowerCase();
        for (const kw of suspTasks) {
          if (lower.includes(kw)) {
            const parts = line.split('","');
            const taskName = (parts[1] || 'Unknown').replace(/"/g, '');
            addDet(d, 'STARTUP', 'Şüpheli zamanlanmış görev: ' + taskName, 'Scheduled Task', 'HIGH', { task: taskName });
            break;
          }
        }
      });
    }
  } catch (e) {}

  return d;
}
