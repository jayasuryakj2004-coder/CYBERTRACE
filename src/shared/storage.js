const STORAGE_KEYS = {
  SETTINGS: 'cybertrace_settings',
  SCAN_HISTORY: 'cybertrace_scan_history',
  CURRENT_SCAN: 'cybertrace_current_scan'
};

const DEFAULT_SETTINGS = {
  autoAnalyze: true,
  showNotifications: true,
  maxHistoryItems: 50,
  theme: 'dark',
  pdfjsWorkerUrl: '',
  aiBackendUrl: 'http://localhost:3001',
  aiBackendToken: ''
};

const MAX_HISTORY_CHARACTERS = 2000000;

function compactScan(scan) {
  const clip = (value, max = 1200) => typeof value === 'string' ? value.slice(0, max) : value;
  return {
    scanId: clip(scan.scanId, 100),
    timestamp: clip(scan.timestamp, 40),
    completedAt: clip(scan.completedAt, 40),
    status: clip(scan.status, 20),
    progress: Math.max(0, Math.min(100, Number(scan.progress) || 0)),
    fileInfo: {
      name: clip(scan.fileInfo?.name, 240),
      size: Math.max(0, Number(scan.fileInfo?.size) || 0),
      mimeType: clip(scan.fileInfo?.mimeType, 100),
      url: clip(scan.fileInfo?.url, 2000),
      sha256: clip(scan.fileInfo?.sha256, 64)
    },
    metadata: Object.fromEntries(Object.entries(scan.metadata || {}).map(([key, value]) => [
      key,
      typeof value === 'string' ? clip(value, 500) : value
    ])),
    findings: (scan.findings || []).slice(0, 100).map(finding => Object.fromEntries(
      Object.entries(finding).map(([key, value]) => [key, typeof value === 'string' ? clip(value) : value])
    )),
    riskAssessment: {
      score: Math.max(0, Math.min(100, Number(scan.riskAssessment?.score) || 0)),
      level: clip(scan.riskAssessment?.level, 20),
      factors: (scan.riskAssessment?.factors || []).slice(0, 100).map(factor =>
        typeof factor === 'string' ? clip(factor) : Object.fromEntries(Object.entries(factor).map(([key, value]) => [
          key,
          typeof value === 'string' ? clip(value) : value
        ]))
      )
    },
    limitations: (scan.limitations || []).slice(0, 100).map(item => clip(item)),
    error: clip(scan.error, 1200),
    aiAnalysis: scan.aiAnalysis || null
  };
}

function historySize(items) {
  return items.reduce((size, item) => size + JSON.stringify(item).length, 0);
}

export async function getSettings() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    return { ...DEFAULT_SETTINGS, ...result[STORAGE_KEYS.SETTINGS] };
  } catch (error) {
    console.warn('CyberTrace settings could not be read:', error.message);
    return { ...DEFAULT_SETTINGS };
  }
}

export async function setSettings(settings) {
  const current = await getSettings();
  const updated = { ...current, ...settings };
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: updated });
  return updated;
}

export async function getScanHistory() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SCAN_HISTORY);
    return result[STORAGE_KEYS.SCAN_HISTORY] || [];
  } catch (error) {
    console.warn('CyberTrace scan history could not be read:', error.message);
    return [];
  }
}

export async function addScanToHistory(scanResult) {
  const history = await getScanHistory();
  const settings = await getSettings();
  const maxItems = Math.max(1, Math.min(50, Number(settings.maxHistoryItems) || 50));
  const entry = compactScan(scanResult);
  let trimmed = [entry, ...history.filter(item => item.scanId !== entry.scanId).map(compactScan)].slice(0, maxItems);
  while (trimmed.length > 1 && historySize(trimmed) > MAX_HISTORY_CHARACTERS) trimmed.pop();
  while (trimmed.length > 0) {
    try {
      await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: trimmed });
      return trimmed;
    } catch (error) {
      console.warn('CyberTrace scan history could not be persisted:', error.message);
      if (trimmed.length === 1) break;
      trimmed.pop();
    }
  }
  return history;
}

export async function removeScanFromHistory(scanId) {
  const history = await getScanHistory();
  const filtered = history.filter(s => s.scanId !== scanId);
  await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: filtered });
  return filtered;
}

export async function clearScanHistory() {
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: [] });
  } catch (error) {
    console.warn('CyberTrace scan history could not be cleared:', error.message);
  }
  return [];
}

export async function getCurrentScan() {
  try {
    const result = await chrome.storage.local.get(STORAGE_KEYS.CURRENT_SCAN);
    return result[STORAGE_KEYS.CURRENT_SCAN] || null;
  } catch (error) {
    console.warn('CyberTrace current scan could not be read:', error.message);
    return null;
  }
}

export async function setCurrentScan(scanResult) {
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.CURRENT_SCAN]: scanResult });
  } catch (error) {
    console.warn('CyberTrace current scan could not be persisted:', error.message);
  }
  return scanResult;
}

export async function clearCurrentScan() {
  await chrome.storage.local.remove(STORAGE_KEYS.CURRENT_SCAN);
  return null;
}

export async function updateScanInHistory(scanId, updates) {
  const history = await getScanHistory();
  const index = history.findIndex(s => s.scanId === scanId);
  if (index === -1) return null;
  history[index] = compactScan({ ...history[index], ...updates });
  try {
    await chrome.storage.local.set({ [STORAGE_KEYS.SCAN_HISTORY]: history });
  } catch (error) {
    console.warn('CyberTrace scan history could not be updated:', error.message);
  }
  return history[index];
}

chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && typeof window !== 'undefined') {
    if (changes[STORAGE_KEYS.CURRENT_SCAN]) {
      window.dispatchEvent(new CustomEvent('cybertrace:scan-updated', { 
        detail: changes[STORAGE_KEYS.CURRENT_SCAN].newValue 
      }));
    }
    if (changes[STORAGE_KEYS.SCAN_HISTORY]) {
      window.dispatchEvent(new CustomEvent('cybertrace:history-updated', { 
        detail: changes[STORAGE_KEYS.SCAN_HISTORY].newValue 
      }));
    }
  }
});