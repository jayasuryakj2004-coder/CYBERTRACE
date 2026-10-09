import { 
  ScanStatus, 
  MessageType, 
  createScanResult, 
  validateScanResult,
  computeSHA256,
  createMessage
} from './shared/contracts.js';
import { 
  sendToSidePanel,
  createProgressMessage,
  createCompleteMessage,
  createErrorMessage,
  onMessage 
} from './shared/messaging.js';
import { 
  getSettings, 
  setCurrentScan, 
  getCurrentScan, 
  getScanHistory,
  addScanToHistory,
  updateScanInHistory
} from './shared/storage.js';
import { analyzePdf } from './analysis/index.js';

const activeScans = new Map();
const pdfBuffers = new Map();
const documentScans = new Map();
const MAX_PDF_BYTES = 100 * 1024 * 1024;
const MAX_BUFFERED_PDF_BYTES = 200 * 1024 * 1024;
let bufferedPdfBytes = 0;

function getDocumentKey(tabId, pdfUrl) {
  return `${tabId ?? 'unknown'}:${pdfUrl}`;
}

function isPdfUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:', 'file:'].includes(url.protocol) && (
      url.pathname.toLowerCase().endsWith('.pdf') ||
      url.pathname.toLowerCase().endsWith('.PDF') ||
      url.searchParams.get('format') === 'pdf'
    );
  } catch {
    return false;
  }
}

async function readPdfUrl(pdfUrl) {
  const parsedUrl = new URL(pdfUrl);
  if (!['http:', 'https:', 'file:'].includes(parsedUrl.protocol)) throw new Error('Only local file and HTTP(S) PDF URLs are supported');
  const response = await fetch(pdfUrl, { signal: AbortSignal.timeout(20000), credentials: 'omit' });
  if (!response.ok) throw new Error(`PDF request failed with HTTP ${response.status}`);
  const contentType = response.headers.get('content-type') || 'application/pdf';
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_PDF_BYTES) {
    await response.body?.cancel();
    throw new Error('PDF exceeds the 100 MiB analysis limit');
  }
  const reader = response.body?.getReader();
  if (!reader) {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB analysis limit');
    assertPdfMagic(buffer);
    return { buffer, finalUrl: response.url || pdfUrl, contentType };
  }
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_PDF_BYTES) {
        await reader.cancel();
        throw new Error('PDF exceeds the 100 MiB analysis limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  assertPdfMagic(bytes.buffer);
  return { buffer: bytes.buffer, finalUrl: response.url || pdfUrl, contentType };
}

// file:// responses carry no Content-Type and many servers send octet-stream,
// so identify PDFs by their "%PDF-" header (allowed within the first 1 KiB).
function assertPdfMagic(buffer) {
  const head = new Uint8Array(buffer, 0, Math.min(1024, buffer.byteLength));
  const text = String.fromCharCode(...head);
  if (!text.includes('%PDF-')) throw new Error('The response is not a PDF document (no %PDF- header)');
}

async function reportFileAccessBlocked(tabId, pdfUrl) {
  const scanResult = createScanResult({
    fileInfo: { name: decodeURIComponent(pdfUrl.split('/').pop() || 'document.pdf'), size: 0, mimeType: 'application/pdf', url: pdfUrl, sha256: '' },
    status: ScanStatus.FAILED
  });
  scanResult.tabId = tabId;
  scanResult.error = 'Chrome is blocking access to local files. Open chrome://extensions, select CyberTrace > Details, and enable "Allow access to file URLs", then reload this PDF.';
  scanResult.limitations.push(scanResult.error);
  await setCurrentScan(scanResult);
  chrome.action.setBadgeText({ tabId, text: '!' }).catch(() => {});
  sendToSidePanel(createMessage(MessageType.SCAN_STATE, { scanResult })).catch(() => {});
}

async function registerPdfScan({ pdfUrl, pdfBuffer, fileName, mimeType, tabId, deferAutoAnalyze = false }) {
  const size = pdfBuffer?.byteLength || 0;
  if (!size || size > MAX_PDF_BYTES) throw new Error('PDF is empty or exceeds the 100 MiB analysis limit');
  if (bufferedPdfBytes + size > MAX_BUFFERED_PDF_BYTES) throw new Error('CyberTrace is at its concurrent PDF memory limit; retry after an active scan completes');

  const scanResult = createScanResult({
    fileInfo: {
      name: fileName || 'document.pdf',
      size: pdfBuffer ? pdfBuffer.byteLength : 0,
      mimeType: mimeType || 'application/pdf',
      url: pdfUrl || '',
      sha256: pdfBuffer ? await computeSHA256(pdfBuffer) : ''
    },
    status: ScanStatus.QUEUED
  });
  scanResult.tabId = tabId;

  pdfBuffers.set(scanResult.scanId, pdfBuffer);
  bufferedPdfBytes += size;

  activeScans.set(scanResult.scanId, { 
    scanResult, 
    tabId,
    abortController: new AbortController()
  });

  await setCurrentScan(scanResult);
  
  sendToSidePanel(createMessage(MessageType.SCAN_STATE, { scanResult }));
  
  const settings = await getSettings();
  if (settings.autoAnalyze && !deferAutoAnalyze) {
    startAnalysis(scanResult.scanId);
  }

  return scanResult;
}

async function handlePdfDetected(message, sender) {
  const payload = message.payload || {};
  const tabId = sender.tab?.id ?? payload.tabId;
  const pdfUrl = payload.pdfUrl || sender.url || '';
  const key = getDocumentKey(tabId, pdfUrl);
  if (documentScans.has(key)) {
    const existing = await documentScans.get(key);
    return { success: true, scanId: existing.scanId };
  }
  const operation = (async () => {
    let { pdfBuffer } = payload;
    let { fileName, mimeType } = payload;
    let finalUrl = pdfUrl;
    // chrome.runtime messages are JSON-serialised, so an ArrayBuffer arrives as {}.
    if (!(pdfBuffer instanceof ArrayBuffer) || !pdfBuffer.byteLength) {
      if (pdfUrl.startsWith('file:') && !(await chrome.extension.isAllowedFileSchemeAccess())) {
        await reportFileAccessBlocked(tabId, pdfUrl);
        throw new Error('File URL access is disabled for CyberTrace');
      }
      const doc = await readPdfUrl(pdfUrl);
      pdfBuffer = doc.buffer; finalUrl = doc.finalUrl; mimeType = doc.contentType;
      fileName = fileName || new URL(finalUrl).pathname.split('/').pop() || 'document.pdf';
    }
    return registerPdfScan({ ...payload, pdfUrl: finalUrl, pdfBuffer, fileName, mimeType, tabId });
  })();
  documentScans.set(key, operation);
  try {
    const scan = await operation;
    return { success: true, scanId: scan.scanId };
  } catch (error) {
    documentScans.delete(key);
    throw error;
  }
}

async function startAnalysis(scanId) {
  const scanData = activeScans.get(scanId);
  if (!scanData || scanData.scanResult.status === ScanStatus.ANALYZING) return;

  const { scanResult, abortController } = scanData;

  scanResult.status = ScanStatus.ANALYZING;
  scanResult.progress = 0;
  await setCurrentScan(scanResult);
  sendToSidePanel(createProgressMessage(scanId, 0, ScanStatus.ANALYZING, { step: 'initializing' }));

  try {
    const pdfBuffer = pdfBuffers.get(scanId);
    if (!pdfBuffer) {
      throw new Error('PDF buffer not available for analysis');
    }

    const analysis = await runAnalysis(scanId, scanResult, pdfBuffer, abortController);

    scanResult.status = analysis.status;
    scanResult.progress = analysis.progress;
    scanResult.metadata = analysis.metadata;
    scanResult.findings = analysis.findings;
    scanResult.riskAssessment = analysis.riskAssessment;
    scanResult.limitations = analysis.limitations;
    scanResult.error = analysis.error;

    if (analysis.status === ScanStatus.COMPLETED) {
      scanResult.completedAt = new Date().toISOString();
    }

    await finalizeScan(scanId, scanResult);

  } catch (error) {
    scanResult.status = ScanStatus.FAILED;
    scanResult.error = error.message;
    scanResult.limitations.push(`Analysis failed: ${error.message}`);
    await finalizeScan(scanId, scanResult);
    sendToSidePanel(createErrorMessage(scanId, error));
  }
}

async function runAnalysis(scanId, scanResult, pdfBuffer, abortController) {
  const onProgress = ({ progress, step, detail }) => {
    scanResult.progress = progress;
    sendToSidePanel(createProgressMessage(scanId, progress, ScanStatus.ANALYZING, { step, detail }));
  };

  let pdfDoc = null;
  let pdfJsLimitations = [];
  try {
    const pdfjsLib = await import('./assets/pdfjs/pdf.mjs');
    pdfjsLib.GlobalWorkerOptions.workerSrc = chrome.runtime.getURL('src/assets/pdfjs/pdf.worker.mjs');
    pdfjsLib.GlobalWorkerOptions.cMapUrl = chrome.runtime.getURL('src/assets/pdfjs/cmaps/');
    pdfjsLib.GlobalWorkerOptions.cMapPacked = true;
    pdfDoc = await pdfjsLib.getDocument({ data: new Uint8Array(pdfBuffer.slice(0)) }).promise;
  } catch (error) {
    pdfJsLimitations = [`PDF.js cross-check unavailable: ${error.message}`];
  }

  let analysis;
  try {
    analysis = await analyzePdf(pdfBuffer, {
      onProgress,
      pdfDoc,
      signal: abortController.signal
    });
  } finally {
    await pdfDoc?.destroy();
  }

  return {
    status: analysis.status,
    progress: analysis.progress,
    metadata: mapMetadata(analysis.metadata, analysis.findings),
    findings: analysis.findings,
    riskAssessment: analysis.riskAssessment,
    limitations: [...analysis.limitations, ...pdfJsLimitations],
    error: analysis.error
  };
}

function mapMetadata(metadata, findings) {
  const categories = new Set((findings || []).map(f => f.indicatorCategory));
  if (!metadata) {
    return {
      pageCount: 0, title: '', author: '', subject: '', keywords: '',
      creator: '', producer: '', creationDate: '', modificationDate: '',
      pdfVersion: '', isLinearized: false, hasJavaScript: false,
      hasEmbeddedFiles: false, hasForms: false, hasSignatures: false,
      permissions: {}
    };
  }
  return {
    pageCount: metadata.pageCount || 0,
    title: metadata.title || '',
    author: metadata.author || '',
    subject: metadata.subject || '',
    keywords: metadata.keywords || '',
    creator: metadata.creator || '',
    producer: metadata.producer || '',
    creationDate: metadata.creationDate || '',
    modificationDate: metadata.modificationDate || '',
    pdfVersion: metadata.pdfVersion || '',
    isLinearized: metadata.isLinearized || false,
    hasJavaScript: categories.has('javascript'),
    hasEmbeddedFiles: categories.has('embedded_file'),
    hasForms: metadata.hasForms || categories.has('form'),
    hasSignatures: metadata.hasSignatures || false,
    isEncrypted: metadata.isEncrypted || false,
    hasObjectStreams: metadata.hasObjectStreams || false,
    permissions: metadata.permissions || {}
  };
}

async function finalizeScan(scanId, scanResult) {
  const validation = validateScanResult(scanResult);
  if (!validation.valid) {
    console.error('Invalid scan result:', validation.missing);
  }

  await setCurrentScan(scanResult);
  await addScanToHistory(scanResult);
  await updateScanInHistory(scanId, scanResult);
  
  const completedBuffer = pdfBuffers.get(scanId);
  pdfBuffers.delete(scanId);
  bufferedPdfBytes = Math.max(0, bufferedPdfBytes - (completedBuffer?.byteLength || 0));
  activeScans.delete(scanId);
  
  sendToSidePanel(createCompleteMessage(scanId, scanResult));
}

async function handleRetryAnalysis(message) {
  const { scanId } = message.payload;
  const scanData = activeScans.get(scanId);
  
  if (scanData) {
    scanData.abortController.abort();
    activeScans.delete(scanId);
  }
  
  const history = await getScanHistory();
  const previousScan = history.find(s => s.scanId === scanId);

  if (!previousScan || !isPdfUrl(previousScan.fileInfo?.url)) {
    return { success: false, error: 'This source cannot be fetched again; the original PDF bytes are not persisted.' };
  }
  try {
    const document = await readPdfUrl(previousScan.fileInfo.url);
    const scan = await registerPdfScan({
      pdfUrl: document.finalUrl,
      pdfBuffer: document.buffer,
      fileName: previousScan.fileInfo.name,
      mimeType: document.contentType,
      tabId: scanData?.tabId,
      deferAutoAnalyze: true
    });
    startAnalysis(scan.scanId);
    return { success: true, newScanId: scan.scanId };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function handleGetScanState(message) {
  let currentScan = await getCurrentScan();
  if (currentScan && [ScanStatus.QUEUED, ScanStatus.ANALYZING].includes(currentScan.status) && !activeScans.has(currentScan.scanId)) {
    currentScan.status = ScanStatus.INCOMPLETE;
    currentScan.limitations = [...(currentScan.limitations || []), 'Service worker restarted; original PDF bytes are not retained for resuming this scan.'];
    currentScan.error = null;
    await setCurrentScan(currentScan);
    await addScanToHistory(currentScan);
  }
  return { scanResult: currentScan };
}

async function handleManualAnalysis(message) {
  const { pdfUrl, tabId } = message.payload;
  
  try {
    const document = await readPdfUrl(pdfUrl);
    const scan = await registerPdfScan({
      pdfUrl: document.finalUrl,
      pdfBuffer: document.buffer,
      fileName: new URL(document.finalUrl).pathname.split('/').pop() || 'document.pdf',
      mimeType: document.contentType,
      tabId
    });
    return { success: true, scanId: scan.scanId };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function handleTabPdf(tabId, pdfUrl) {
  const key = getDocumentKey(tabId, pdfUrl);
  if (documentScans.has(key)) {
    try {
      const scan = await documentScans.get(key);
      if (scan?.scanId) await openPdfViewer(tabId, pdfUrl, scan.fileInfo.name);
    } catch {}
    return;
  }
  const operation = (async () => {
    if (pdfUrl.startsWith('file:') && !(await chrome.extension.isAllowedFileSchemeAccess())) {
      await reportFileAccessBlocked(tabId, pdfUrl);
      return null;
    }
    const document = await readPdfUrl(pdfUrl);
    const activeTab = await chrome.tabs.get(tabId);
    if (activeTab.url !== pdfUrl || !isPdfUrl(activeTab.url)) return null;
    const scan = await registerPdfScan({
      pdfUrl: document.finalUrl,
      pdfBuffer: document.buffer,
      fileName: new URL(document.finalUrl).pathname.split('/').pop() || 'document.pdf',
      mimeType: document.contentType,
      tabId
    });
    const currentTab = await chrome.tabs.get(tabId);
    if (currentTab.url !== pdfUrl || !isPdfUrl(currentTab.url)) return scan;
    await openPdfViewer(tabId, document.finalUrl, scan.fileInfo.name);
    return scan;
  })();
  documentScans.set(key, operation);
  try {
    await operation;
  } catch (error) {
    documentScans.delete(key);
    console.warn('CyberTrace could not inspect this PDF navigation:', error.message);
    chrome.action.setBadgeText({ tabId, text: '!' }).catch(() => {});
  }
}

async function openPdfViewer(tabId, pdfUrl, fileName) {
  const viewerUrl = new URL(chrome.runtime.getURL('src/viewer/viewer.html'));
  viewerUrl.searchParams.set('url', pdfUrl);
  viewerUrl.searchParams.set('name', fileName);
  try {
    await chrome.tabs.update(tabId, { url: viewerUrl.href });
  } catch (error) {
    console.warn('CyberTrace viewer navigation failed:', error.message);
  }
}

async function handleViewerReady(message, sender) {
  const pdfUrl = message.payload?.url;
  const tabId = sender.tab?.id;
  if (!isPdfUrl(pdfUrl) || tabId === undefined) return { success: false, error: 'Unsupported PDF viewer source' };
  for (const { scanResult, tabId: scanTabId } of activeScans.values()) {
    if (scanTabId === tabId && scanResult.fileInfo.url === pdfUrl && scanResult.status !== ScanStatus.FAILED) {
      return { success: true, scanId: scanResult.scanId };
    }
  }
  const current = await getCurrentScan();
  if (current?.tabId === tabId && current?.fileInfo?.url === pdfUrl && [ScanStatus.QUEUED, ScanStatus.ANALYZING, ScanStatus.COMPLETED, ScanStatus.INCOMPLETE].includes(current.status)) {
    return { success: true, scanId: current.scanId };
  }
  return handleManualAnalysis({ payload: { pdfUrl, tabId } });
}

onMessage(async (message, sender) => {
  switch (message.type) {
    case MessageType.PDF_DETECTED:
      return handlePdfDetected(message, sender);
    case MessageType.START_ANALYSIS:
      startAnalysis(message.payload.scanId);
      return { success: true };
    case MessageType.RETRY_ANALYSIS:
      return handleRetryAnalysis(message);
    case MessageType.GET_SCAN_STATE:
      return handleGetScanState(message);
    case MessageType.MANUAL_ANALYSIS:
      return handleManualAnalysis(message);
    case MessageType.VIEWER_READY:
      return handleViewerReady(message, sender);
    default:
      return { success: false, error: 'Unknown message type' };
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    for (const key of documentScans.keys()) if (key.startsWith(`${tabId}:`)) documentScans.delete(key);
  }
  if (changeInfo.status === 'complete' && isPdfUrl(tab.url)) handleTabPdf(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener(tabId => {
  for (const key of documentScans.keys()) if (key.startsWith(`${tabId}:`)) documentScans.delete(key);
});

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(error => {
  console.warn('CyberTrace toolbar panel behavior unavailable:', error.message);
});

chrome.runtime.onInstalled.addListener(() => {
  console.log('CyberTrace extension installed');
});

console.log('CyberTrace background service worker loaded');