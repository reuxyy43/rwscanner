const readline = require('readline');
const https = require('https');
const http = require('http');
const Scanner = require('./scanner/index');

const API_BASE = process.env.RW_API_URL || 'http://localhost:3000';
const SCANNER_VERSION = '1.0.0';

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(resolve => rl.question(q, resolve));

function clear() { process.stdout.write('\x1Bc'); }
function print(text) { console.log(text); }
function printCenter(text) {
  const pad = Math.max(0, Math.floor((56 - text.length) / 2));
  console.log(' '.repeat(pad) + text);
}
function progressBar(pct, width = 30) {
  const filled = Math.floor((pct / 100) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

async function apiRequest(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${API_BASE}${endpoint}`);
    const lib = url.protocol === 'https:' ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000
    };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode >= 400) reject(new Error(json.error || 'API hatası'));
          else resolve(json);
        } catch { reject(new Error('Geçersiz sunucu yanıtı')); }
      });
    });
    req.on('error', () => reject(new Error('Sunucuya bağlanılamadı')));
    req.on('timeout', () => { req.destroy(); reject(new Error('Bağlantı zaman aşımı')); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function main() {
  clear();
  print('');
  printCenter('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  printCenter('              RwScanner v' + SCANNER_VERSION);
  printCenter('           FiveM Security Scanner');
  printCenter('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  print('');

  // Server check
  process.stdout.write('  ⟳ Sunucu kontrol ediliyor...\r');
  const serverOk = await apiRequest('/api/health').then(() => true).catch(() => false);
  if (!serverOk) {
    print('  ❌ Sunucuya bağlanılamadı!');
    print('     Sunucunun çalıştığından emin olun.');
    print('     (start.bat ile sunucuyu başlatın)');
    print('');
    rl.close();
    return;
  }
  print('  ✓ Sunucu bağlantısı başarılı          ');
  print('');

  // Version check
  const versionInfo = await apiRequest('/api/version').catch(() => ({ current_version: SCANNER_VERSION }));
  if (versionInfo.current_version !== SCANNER_VERSION) {
    print(`  ⚠ RwScanner'ın yeni sürümü mevcut: v${versionInfo.current_version}`);
    print('    Lütfen uygulamayı güncelleyin.');
    print('');
    rl.close();
    return;
  }

  // PIN
  print('  ┌──────────────────────────────────────────────┐');
  print('  │  PIN Kodunuzu girin                         │');
  print('  └──────────────────────────────────────────────┘');
  print('');
  const pin = await ask('  PIN > ');

  if (!pin || pin.trim().length < 5) {
    print('  ❌ Geçersiz PIN');
    print('');
    rl.close();
    return;
  }

  print('');
  process.stdout.write('  ⟳ PIN doğrulanıyor...\r');

  let scanId;
  try {
    const result = await apiRequest('/api/scans/start', 'POST', {
      pin: pin.trim(),
      scanner_version: SCANNER_VERSION
    });
    scanId = result.scan_id;
  } catch (err) {
    print(`  ❌ ${err.message}              `);
    print('');
    rl.close();
    return;
  }
  print(`  ✓ Tarama başlatıldı — ${scanId}     `);
  print('');

  // Init scanner
  const scanner = new Scanner();

  // Fetch signatures
  process.stdout.write('  ⟳ İmzalar alınıyor...\r');
  try {
    const sigData = await apiRequest('/api/signatures/active');
    if (sigData.signatures) scanner.setSignatures(sigData.signatures);
  } catch {}
  print('  ✓ İmzalar yüklendi                  ');
  print('');

  // Progress tracking
  let currentModule = 0;
  const totalModules = 6;
  scanner.setProgressCallback((info) => {
    currentModule++;
    const pct = Math.round((currentModule / totalModules) * 100);
    process.stdout.write(`  ${progressBar(pct)} %${String(pct).padStart(3)}  ${info.message.padEnd(40)}\r`);
  });

  print('  ┌──────────────────────────────────────────────┐');
  print('  │  Tarama yapılıyor... Lütfen bekleyin.        │');
  print('  └──────────────────────────────────────────────┘');
  print('');

  // Run scan
  const detections = await scanner.runAll();
  process.stdout.write('  ' + ' '.repeat(70) + '\r');
  print(`  ✓ Tarama tamamlandı                     `);
  print('');

  // Submit results
  process.stdout.write('  ⟳ Sonuçlar gönderiliyor...\r');
  try {
    await apiRequest('/api/scans/submit', 'POST', {
      scan_id: scanId,
      detections: detections,
      system_info: scanner.getSystemInfo()
    });
  } catch (err) {
    print(`  ❌ Sonuçlar gönderilemedi: ${err.message}`);
    print('');
    rl.close();
    return;
  }
  print('  ✓ Sonuçlar gönderildi                   ');
  print('');

  print('  ╔══════════════════════════════════════════════╗');
  print('  ║                                              ║');
  printCenter('   ✓ TARAMA TAMAMLANDI');
  print('  ║                                              ║');
  print('  ║  Sonuçlar yetkili paneline gönderildi.       ║');
  print('  ║  RwScanner\'ı kapatabilirsiniz.              ║');
  print('  ║                                              ║');
  print('  ╚══════════════════════════════════════════════╝');
  print('');

  rl.close();
}

main().catch(err => {
  print(`  ❌ Beklenmeyen hata: ${err.message}`);
  rl.close();
});
