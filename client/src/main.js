const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const https = require('https');
const http = require('http');
const fs = require('fs');

const SCANNER_VERSION = '1.0.0';
let API_BASE = 'http://localhost:3000';

try {
  const configPath = path.join(process.resourcesPath || __dirname, 'config.json');
  if (fs.existsSync(configPath)) {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (config.api_url) API_BASE = config.api_url;
  } else {
    const localConfig = path.join(path.dirname(app.getPath('exe')), 'config.json');
    if (fs.existsSync(localConfig)) {
      const config = JSON.parse(fs.readFileSync(localConfig, 'utf8'));
      if (config.api_url) API_BASE = config.api_url;
    }
  }
} catch (e) {}

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 520,
    height: 640,
    resizable: false,
    frame: false,
    transparent: false,
    backgroundColor: '#0a0a0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());

function apiRequest(endpoint, method, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(API_BASE + endpoint);
    const lib = url.protocol === 'https:' ? https : http;
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: method || 'GET',
      headers: { 'Content-Type': 'application/json' },
      timeout: 15000
    };
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode >= 400) reject(new Error(json.error || 'API hatasi'));
          else resolve(json);
        } catch (e) {
          reject(new Error('Gecersiz sunucu yaniti'));
        }
      });
    });
    req.on('error', () => reject(new Error('Sunucuya baglanilamadi')));
    req.on('timeout', () => { req.destroy(); reject(new Error('Baglanti zaman asimi')); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

ipcMain.handle('check-version', async () => {
  try {
    const data = await apiRequest('/api/version', 'GET');
    return { current: SCANNER_VERSION, latest: data.current_version, min: data.min_version };
  } catch (e) {
    return { current: SCANNER_VERSION, latest: SCANNER_VERSION, min: SCANNER_VERSION };
  }
});

ipcMain.handle('start-scan', async (event, pin) => {
  return await apiRequest('/api/scans/start', 'POST', {
    pin: pin,
    scanner_version: SCANNER_VERSION
  });
});

ipcMain.handle('get-signatures', async () => {
  try {
    return await apiRequest('/api/signatures/active', 'GET');
  } catch (e) {
    return { signatures: [] };
  }
});

ipcMain.handle('submit-results', async (event, data) => {
  return await apiRequest('/api/scans/submit', 'POST', data);
});

ipcMain.handle('get-api-url', () => { return API_BASE; });

ipcMain.handle('close-window', () => { mainWindow.close(); });
ipcMain.handle('minimize-window', () => { mainWindow.minimize(); });
