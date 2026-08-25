const API_BASE = '/api';
let token = localStorage.getItem('rwscanner_token');
let currentUser = null;
let currentScanId = null;
let allScans = [];

// Init
document.addEventListener('DOMContentLoaded', () => {
  if (token) {
    verifyToken();
  }
  setupEventListeners();
});

function setupEventListeners() {
  document.getElementById('loginForm').addEventListener('submit', handleLogin);
  document.getElementById('createPinBtn').addEventListener('click', () => openModal('createPinModal'));
  document.getElementById('createSigBtn').addEventListener('click', () => openModal('createSigModal'));
  document.getElementById('logoutBtn').addEventListener('click', handleLogout);

  document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => {
      showPage(item.dataset.page);
    });
  });
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers: { ...headers, ...options.headers } });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'API hatası');
  return data;
}

function toast(message, type = 'success') {
  const container = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = message;
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

function openModal(id) {
  document.getElementById(id).classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

function showPage(page) {
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById(`page-${page}`)?.classList.add('active');
  document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');

  if (page === 'dashboard') loadDashboard();
  if (page === 'pins') loadPins();
  if (page === 'scans') loadScans();
  if (page === 'detections') loadAllDetections();
  if (page === 'signatures') loadSignatures();
  if (page === 'settings') loadSettings();
  if (page === 'audit') loadAuditLogs();
}

// Auth
async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value;
  const password = document.getElementById('loginPassword').value;
  const errEl = document.getElementById('loginError');

  try {
    const data = await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    });
    token = data.token;
    currentUser = data.user;
    localStorage.setItem('rwscanner_token', token);
    errEl.style.display = 'none';
    showApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

async function verifyToken() {
  try {
    const data = await api('/auth/me');
    currentUser = data.user;
    showApp();
  } catch {
    token = null;
    localStorage.removeItem('rwscanner_token');
  }
}

function handleLogout() {
  token = null;
  currentUser = null;
  localStorage.removeItem('rwscanner_token');
  document.getElementById('appLayout').classList.remove('active');
  document.getElementById('loginView').style.display = 'flex';
}

function showApp() {
  document.getElementById('loginView').style.display = 'none';
  document.getElementById('appLayout').classList.add('active');
  loadDashboard();
}

// Dashboard
async function loadDashboard() {
  try {
    const data = await api('/dashboard');
    document.getElementById('statActive').textContent = data.active_scans;
    document.getElementById('statToday').textContent = data.today_scans;
    document.getElementById('statSuspicious').textContent = data.suspicious_scans;
    document.getElementById('statCritical').textContent = data.critical_detections;
    document.getElementById('statActivePins').textContent = data.active_pins;
    document.getElementById('statTotalPins').textContent = data.total_pins;

    const recentPinsBody = document.getElementById('recentPinsBody');
    if (!data.recent_pins || data.recent_pins.length === 0) {
      recentPinsBody.innerHTML = '<tr><td colspan="5" class="empty-state">Henüz PIN bulunmuyor</td></tr>';
    } else {
      recentPinsBody.innerHTML = data.recent_pins.map(p => `
        <tr>
          <td style="font-family: monospace; font-weight: 600; color: var(--accent);">${p.pin_code}</td>
          <td><span class="badge badge-${p.status.toLowerCase()}">${statusLabel(p.status)}</span></td>
          <td>${p.created_by_name || '-'}</td>
          <td>${p.use_count}/${p.max_uses}</td>
          <td>${formatTime(p.created_at)}</td>
        </tr>
      `).join('');
    }

    const tbody = document.getElementById('recentScansBody');
    if (data.recent_scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Henüz tarama bulunmuyor</td></tr>';
      return;
    }

    tbody.innerHTML = data.recent_scans.map(s => `
      <tr>
        <td style="font-family: monospace; font-weight: 600;">${s.scan_id}</td>
        <td><span class="badge badge-${s.status.toLowerCase()}">${statusLabel(s.status)}</span></td>
        <td><span class="badge badge-${s.risk_level.toLowerCase()}">${riskLabel(s.risk_level)}</span></td>
        <td>${s.detection_count}</td>
        <td>${formatTime(s.started_at)}</td>
      </tr>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Pins
async function loadPins() {
  try {
    const data = await api('/pins');
    const tbody = document.getElementById('pinsBody');
    if (data.pins.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">PIN bulunmuyor</td></tr>';
      return;
    }

    tbody.innerHTML = data.pins.map(p => `
      <tr>
        <td style="font-family: monospace; font-weight: 600; color: var(--accent);">${p.pin_code}</td>
        <td><span class="badge badge-${p.status.toLowerCase()}">${statusLabel(p.status)}</span></td>
        <td>${p.created_by_name || '-'}</td>
        <td>${p.use_count}/${p.max_uses}</td>
        <td>${p.expires_at ? formatTime(p.expires_at) : '-'}</td>
        <td>${formatTime(p.created_at)}</td>
        <td>
          ${p.status === 'ACTIVE' ? `<button class="btn btn-danger btn-sm" onclick="cancelPin(${p.id})" style="width:auto; padding: 4px 10px;">İptal</button>` : ''}
        </td>
      </tr>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function submitCreatePin() {
  try {
    const data = await api('/pins', {
      method: 'POST',
      body: JSON.stringify({
        expires_in_hours: parseInt(document.getElementById('pinExpiryHours').value),
        max_uses: parseInt(document.getElementById('pinMaxUses').value)
      })
    });
    closeModal('createPinModal');
    document.getElementById('newPinDisplay').style.display = 'block';
    document.getElementById('newPinCode').textContent = data.pin_code;
    toast('PIN oluşturuldu');
    loadPins();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function cancelPin(id) {
  if (!confirm('Bu PIN iptal edilsin mi?')) return;
  try {
    await api(`/pins/${id}/cancel`, { method: 'PUT' });
    toast('PIN iptal edildi');
    loadPins();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Scans
async function loadScans() {
  try {
    const data = await api('/scans/admin');
    allScans = data.scans;
    const tbody = document.getElementById('scansBody');
    if (data.scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Tarama bulunmuyor</td></tr>';
      return;
    }

    tbody.innerHTML = data.scans.map(s => `
      <tr>
        <td style="font-family: monospace; font-weight: 600;">${s.scan_id}</td>
        <td><span class="badge badge-${s.status.toLowerCase()}">${statusLabel(s.status)}</span></td>
        <td><span class="badge badge-${s.risk_level.toLowerCase()}">${riskLabel(s.risk_level)}</span></td>
        <td>${s.scanner_version || '-'}</td>
        <td>${s.status === 'COMPLETED' ? '-' : '-'}</td>
        <td>${formatTime(s.started_at)}</td>
        <td>${s.completed_at ? formatTime(s.completed_at) : '-'}</td>
        <td>
          <button class="btn btn-outline btn-sm" onclick="viewScan('${s.scan_id}')" style="width:auto; padding: 4px 10px;">İncele</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function viewScan(scanId) {
  try {
    const data = await api(`/scans/admin/${scanId}`);
    currentScanId = scanId;

    document.getElementById('scanDetailId').textContent = scanId;

    const scan = data.scan;
    document.getElementById('scanDetailGrid').innerHTML = `
      <div class="detail-item"><div class="label">Oyuncu</div><div class="value">${scan.player_identifier || 'Bilinmiyor'}</div></div>
      <div class="detail-item"><div class="label">Durum</div><div class="value"><span class="badge badge-${scan.status.toLowerCase()}">${statusLabel(scan.status)}</span></div></div>
      <div class="detail-item"><div class="label">Risk</div><div class="value"><span class="badge badge-${scan.risk_level.toLowerCase()}">${riskLabel(scan.risk_level)}</span></div></div>
      <div class="detail-item"><div class="label">Sürüm</div><div class="value">${scan.scanner_version || '-'}</div></div>
      <div class="detail-item"><div class="label">Başlangıç</div><div class="value">${formatTime(scan.started_at)}</div></div>
      <div class="detail-item"><div class="label">Tamamlanma</div><div class="value">${scan.completed_at ? formatTime(scan.completed_at) : '-'}</div></div>
    `;

    const detList = document.getElementById('detectionsList');
    if (data.detections.length === 0) {
      detList.innerHTML = '<div class="empty-state">Tespit bulunmuyor</div>';
    } else {
      detList.innerHTML = data.detections.map(d => {
        let parsedData = {};
        try { parsedData = d.data ? JSON.parse(d.data) : {}; } catch(e) {}
        return `
          <div class="detection-card">
            <div class="det-header">
              <div class="det-title">${d.title}</div>
              <span class="badge badge-${d.risk_level.toLowerCase()}">${riskLabel(d.risk_level)}</span>
            </div>
            <div class="det-body">
              <p><strong>Tür:</strong> ${detectionTypeLabel(d.detection_type)}</p>
              ${d.description ? `<p style="margin-top: 4px;">${d.description}</p>` : ''}
              ${parsedData.name ? `<p style="margin-top: 4px;"><strong>Ad:</strong> <code>${parsedData.name}</code></p>` : ''}
              ${parsedData.path ? `<p style="margin-top: 4px;"><strong>Yol:</strong> <code>${parsedData.path}</code></p>` : ''}
              ${parsedData.pid ? `<p style="margin-top: 4px;"><strong>PID:</strong> <code>${parsedData.pid}</code></p>` : ''}
            </div>
          </div>
        `;
      }).join('');
    }

    const notesList = document.getElementById('notesList');
    if (data.notes.length === 0) {
      notesList.innerHTML = '';
    } else {
      notesList.innerHTML = data.notes.map(n => `
        <div class="note-item">
          <div class="note-meta">${n.username} — ${formatTime(n.created_at)}</div>
          <div class="note-text">${n.note}</div>
        </div>
      `).join('');
    }

    showPage('scan-detail');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function addNote() {
  const note = document.getElementById('noteInput').value.trim();
  if (!note) return;
  try {
    await api(`/scans/admin/${currentScanId}/notes`, {
      method: 'POST',
      body: JSON.stringify({ note })
    });
    document.getElementById('noteInput').value = '';
    toast('Not eklendi');
    viewScan(currentScanId);
  } catch (err) {
    toast(err.message, 'error');
  }
}

// All Detections
async function loadAllDetections() {
  try {
    const data = await api('/scans/admin?limit=100');
    const container = document.getElementById('allDetectionsList');
    const scansWithDetections = data.scans.filter(s => s.status === 'COMPLETED');

    if (scansWithDetections.length === 0) {
      container.innerHTML = '<div class="empty-state">Tarama bulunmuyor</div>';
      return;
    }

    let html = '';
    for (const scan of scansWithDetections) {
      try {
        const detail = await api(`/scans/admin/${scan.scan_id}`);
        if (detail.detections.length > 0) {
          html += `<h3 style="margin: 16px 0 8px;">${scan.scan_id} <span class="badge badge-${scan.risk_level.toLowerCase()}">${riskLabel(scan.risk_level)}</span></h3>`;
          detail.detections.forEach(d => {
            html += `
              <div class="detection-card">
                <div class="det-header">
                  <div class="det-title">${d.title}</div>
                  <span class="badge badge-${d.risk_level.toLowerCase()}">${riskLabel(d.risk_level)}</span>
                </div>
                <div class="det-body">
                  <p><strong>Tür:</strong> ${detectionTypeLabel(d.detection_type)}</p>
                  ${d.description ? `<p style="margin-top: 4px;">${d.description}</p>` : ''}
                </div>
              </div>
            `;
          });
        }
      } catch(e) {}
    }

    container.innerHTML = html || '<div class="empty-state">Tespit bulunmuyor</div>';
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Signatures
async function loadSignatures() {
  try {
    const data = await api('/signatures');
    const tbody = document.getElementById('sigsBody');
    if (data.signatures.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">İmza bulunmuyor</td></tr>';
      return;
    }

    tbody.innerHTML = data.signatures.map(s => `
      <tr>
        <td style="font-family: monospace; font-weight: 600;">${s.signature_code}</td>
        <td>${s.type}</td>
        <td><span class="badge badge-${s.risk_level.toLowerCase()}">${riskLabel(s.risk_level)}</span></td>
        <td>${s.description || '-'}</td>
        <td>${formatTime(s.created_at)}</td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteSig(${s.id})" style="width:auto; padding: 4px 10px;">Sil</button></td>
      </tr>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function submitCreateSig() {
  try {
    await api('/signatures', {
      method: 'POST',
      body: JSON.stringify({
        signature_code: document.getElementById('sigCode').value,
        type: document.getElementById('sigType').value,
        risk_level: document.getElementById('sigRisk').value,
        description: document.getElementById('sigDescription').value,
        hash_value: document.getElementById('sigHash').value || null
      })
    });
    closeModal('createSigModal');
    toast('İmza oluşturuldu');
    loadSignatures();
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function deleteSig(id) {
  if (!confirm('Bu imza silinsin mi?')) return;
  try {
    await api(`/signatures/${id}`, { method: 'DELETE' });
    toast('İmza silindi');
    loadSignatures();
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Settings
async function loadSettings() {
  try {
    const data = await api('/settings');
    const grid = document.getElementById('settingsGrid');
    const labels = {
      scanner_version: 'Scanner Sürümü',
      scanner_min_version: 'Minimum Scanner Sürümü',
      pin_expiry_hours: 'PIN Süresi (Saat)',
      max_scans_per_pin: 'PIN Başına Maks Tarama',
      rate_limit_window_ms: 'Rate Limit Penceresi (ms)',
      rate_limit_max_requests: 'Maks İstek Sayısı'
    };

    grid.innerHTML = Object.entries(data.settings).map(([key, value]) => `
      <div class="setting-card">
        <h4>${labels[key] || key}</h4>
        <input type="text" class="form-input" data-setting-key="${key}" value="${value}">
      </div>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function saveSettings() {
  const inputs = document.querySelectorAll('[data-setting-key]');
  const settings = {};
  inputs.forEach(input => {
    settings[input.dataset.settingKey] = input.value;
  });

  try {
    await api('/settings', {
      method: 'PUT',
      body: JSON.stringify({ settings })
    });
    toast('Ayarlar kaydedildi');
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Audit
async function loadAuditLogs() {
  try {
    const data = await api('/settings/audit');
    const tbody = document.getElementById('auditBody');
    if (data.logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Log bulunmuyor</td></tr>';
      return;
    }

    tbody.innerHTML = data.logs.map(l => `
      <tr>
        <td>${formatTime(l.timestamp)}</td>
        <td>${l.username || '-'}</td>
        <td><span style="color: var(--accent); font-weight: 600;">${l.action}</span></td>
        <td style="color: var(--text-secondary);">${l.details || '-'}</td>
        <td style="color: var(--text-muted);">${l.ip_address || '-'}</td>
      </tr>
    `).join('');
  } catch (err) {
    toast(err.message, 'error');
  }
}

// Helpers
function statusLabel(s) {
  const map = { ACTIVE: 'Aktif', USED: 'Kullanıldı', EXPIRED: 'Süresi Doldu', CANCELLED: 'İptal', PENDING: 'Beklemede', IN_PROGRESS: 'Devam Ediyor', COMPLETED: 'Tamamlandı', FAILED: 'Başarısız' };
  return map[s] || s;
}

function riskLabel(r) {
  const map = { CLEAN: 'Temiz', LOW: 'Düşük', MEDIUM: 'Orta', HIGH: 'Yüksek', CRITICAL: 'Kritik' };
  return map[r] || r;
}

function detectionTypeLabel(t) {
  const map = { PROCESS: 'Process', FILE: 'Dosya', SIGNATURE: 'İmza', INTEGRITY: 'Bütünlük', FIVEM: 'FiveM', RESOURCE: 'Kaynak' };
  return map[t] || t;
}

function formatTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleString('tr-TR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}
