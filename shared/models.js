const RISK_LEVELS = {
  CLEAN: 'CLEAN',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

const PIN_STATUS = {
  ACTIVE: 'ACTIVE',
  USED: 'USED',
  EXPIRED: 'EXPIRED',
  CANCELLED: 'CANCELLED'
};

const SCAN_STATUS = {
  PENDING: 'PENDING',
  IN_PROGRESS: 'IN_PROGRESS',
  COMPLETED: 'COMPLETED',
  FAILED: 'FAILED'
};

const DETECTION_TYPES = {
  PROCESS: 'PROCESS',
  FILE: 'FILE',
  SIGNATURE: 'SIGNATURE',
  INTEGRITY: 'INTEGRITY',
  FIVEM: 'FIVEM',
  RESOURCE: 'RESOURCE'
};

const USER_ROLES = {
  HEAD_ADMIN: 'HEAD_ADMIN',
  ADMIN: 'ADMIN',
  MODERATOR: 'MODERATOR'
};

function generatePin() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = [2, 4, 4];
  return 'RW-' + segments.map(len => {
    let s = '';
    for (let i = 0; i < len; i++) {
      s += chars[Math.floor(Math.random() * chars.length)];
    }
    return s;
  }).join('-');
}

function generateScanId() {
  const hex = Math.random().toString(16).substring(2, 8).toUpperCase();
  return `RWSCAN-2026-${hex}`;
}

module.exports = { RISK_LEVELS, PIN_STATUS, SCAN_STATUS, DETECTION_TYPES, USER_ROLES, generatePin, generateScanId };
