import { ScanStatus, MessageType, createMessage, parseMessage } from '../shared/contracts.js';
import { sendToBackground, onMessage } from '../shared/messaging.js';
import { getScanHistory, getCurrentScan, getSettings } from '../shared/storage.js';

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

class SidePanel {
  constructor() {
    this.currentScan = null;
    this.init();
  }

  async init() {
    this.bindEvents();
    await this.loadCurrentScan();
    this.setupMessageListener();
    this.applyTheme();
  }

  bindEvents() {
    document.getElementById('closePanel').addEventListener('click', () => window.close());
    document.getElementById('analyzeBtn').addEventListener('click', () => this.startAnalysis());
    document.getElementById('retryBtn').addEventListener('click', () => this.retryAnalysis());
    document.getElementById('exportReportBtn').addEventListener('click', () => this.exportReport());
    document.getElementById('viewHistoryBtn').addEventListener('click', () => this.openHistory());
  }

  setupMessageListener() {
    onMessage((message) => this.handleMessage(message));
    window.addEventListener('cybertrace:scan-updated', (e) => this.updateFromStorage(e.detail));
    window.addEventListener('cybertrace:history-updated', () => this.updateHistoryButton());
  }

  async loadCurrentScan() {
    const scan = await getCurrentScan();
    if (scan) {
      this.currentScan = scan;
      this.renderScan(scan);
    }
  }

  updateFromStorage(scan) {
    if (scan) {
      this.currentScan = scan;
      this.renderScan(scan);
    }
  }

  handleMessage(message) {
    switch (message.type) {
      case MessageType.SCAN_STATE:
        this.currentScan = message.payload.scanResult;
        this.renderScan(this.currentScan);
        break;
      case MessageType.ANALYSIS_PROGRESS:
        this.updateProgress(message.payload);
        break;
      case MessageType.ANALYSIS_COMPLETE:
        this.currentScan = message.payload.result;
        this.renderScan(this.currentScan);
        break;
      case MessageType.ANALYSIS_FAILED:
        this.handleError(message.payload);
        break;
    }
  }

  renderScan(scan) {
    if (!scan) return;

    this.updateDocumentInfo(scan);
    this.updateScanStatus(scan);
    this.updateMetadata(scan);
    this.updateFindings(scan);
    this.updateRiskAssessment(scan);
    this.updateLimitations(scan);
    this.updateActions(scan);
  }

  updateDocumentInfo(scan) {
    const info = scan.fileInfo;
    document.getElementById('infoFileName').textContent = info.name || '-';
    document.getElementById('infoFileSize').textContent = this.formatBytes(info.size);
    document.getElementById('infoMimeType').textContent = info.mimeType || '-';
    document.getElementById('infoSha256').textContent = info.sha256 ? `${info.sha256.substring(0, 16)}...` : '-';
    document.getElementById('infoSourceUrl').textContent = info.url || 'Local file';
    document.getElementById('infoSourceUrl').title = info.url || 'Local file';
    document.getElementById('infoScanId').textContent = scan.scanId || '-';
    document.getElementById('infoTimestamp').textContent = this.formatDate(scan.timestamp);
    document.getElementById('infoCompletedAt').textContent = scan.completedAt ? this.formatDate(scan.completedAt) : '-';
  }

  updateScanStatus(scan) {
    const badge = document.getElementById('statusBadge');
    badge.textContent = scan.status.charAt(0).toUpperCase() + scan.status.slice(1);
    badge.className = `status-badge ${scan.status}`;

    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    const progressStep = document.getElementById('progressStep');
    const progressContainer = document.getElementById('progressContainer');

    progressFill.style.width = `${scan.progress || 0}%`;
    progressPercent.textContent = `${scan.progress || 0}%`;
    progressStep.textContent = this.getStatusText(scan);

    document.getElementById('pagesAnalyzed').textContent = `${scan.metadata?.pageCount || 0} / ${scan.metadata?.pageCount || 0}`;
    document.getElementById('findingsCount').textContent = scan.findings?.length || 0;
    document.getElementById('riskScore').textContent = scan.riskAssessment?.score !== undefined ? `${scan.riskAssessment.score}/100` : '-';

    const analyzeBtn = document.getElementById('analyzeBtn');
    const retryBtn = document.getElementById('retryBtn');
    const exportBtn = document.getElementById('exportReportBtn');

    switch (scan.status) {
      case ScanStatus.QUEUED:
        analyzeBtn.disabled = false;
        analyzeBtn.style.display = 'inline-flex';
        retryBtn.style.display = 'none';
        exportBtn.disabled = true;
        progressContainer.style.display = 'block';
        break;
      case ScanStatus.ANALYZING:
        analyzeBtn.disabled = true;
        analyzeBtn.style.display = 'none';
        retryBtn.style.display = 'none';
        exportBtn.disabled = true;
        progressContainer.style.display = 'block';
        break;
      case ScanStatus.COMPLETED:
        analyzeBtn.style.display = 'none';
        retryBtn.style.display = 'inline-flex';
        exportBtn.disabled = false;
        progressContainer.style.display = 'none';
        break;
      case ScanStatus.INCOMPLETE:
        analyzeBtn.style.display = 'none';
        retryBtn.style.display = 'inline-flex';
        exportBtn.disabled = false;
        progressContainer.style.display = 'none';
        break;
      case ScanStatus.FAILED:
        analyzeBtn.style.display = 'none';
        retryBtn.style.display = 'inline-flex';
        exportBtn.disabled = true;
        progressContainer.style.display = 'none';
        break;
    }

    document.getElementById('findingsSection').style.display = (scan.findings?.length > 0) ? 'block' : 'none';
    document.getElementById('riskSection').style.display = (scan.status === ScanStatus.COMPLETED || scan.status === ScanStatus.INCOMPLETE) ? 'block' : 'none';
    document.getElementById('limitationsSection').style.display = (scan.limitations?.length > 0) ? 'block' : 'none';
  }

  getStatusText(scan) {
    switch (scan.status) {
      case ScanStatus.QUEUED: return 'Queued';
      case ScanStatus.ANALYZING: return scan.progress > 0 ? `Analyzing... (${scan.progress}%)` : 'Initializing...';
      case ScanStatus.COMPLETED: return 'Analysis complete';
      case ScanStatus.INCOMPLETE: return 'Analysis incomplete';
      case ScanStatus.FAILED: return `Failed: ${scan.error || 'Unknown error'}`;
      default: return 'Unknown';
    }
  }

  updateProgress(payload) {
    const progressFill = document.getElementById('progressFill');
    const progressPercent = document.getElementById('progressPercent');
    const progressStep = document.getElementById('progressStep');

    progressFill.style.width = `${payload.progress}%`;
    progressPercent.textContent = `${payload.progress}%`;
    progressStep.textContent = payload.detail || payload.step || 'Processing...';
  }

  handleError(payload) {
    const badge = document.getElementById('statusBadge');
    badge.textContent = 'Failed';
    badge.className = 'status-badge failed';
    
    document.getElementById('progressStep').textContent = `Error: ${payload.error}`;
    document.getElementById('analyzeBtn').style.display = 'none';
    document.getElementById('retryBtn').style.display = 'inline-flex';
    document.getElementById('exportReportBtn').disabled = true;
  }

  updateMetadata(scan) {
    const meta = scan.metadata || {};
    const fields = {
      metaTitle: meta.title,
      metaAuthor: meta.author,
      metaSubject: meta.subject,
      metaKeywords: meta.keywords,
      metaCreator: meta.creator,
      metaProducer: meta.producer,
      metaCreationDate: meta.creationDate,
      metaModDate: meta.modificationDate,
      metaPdfVersion: meta.pdfVersion,
      metaLinearized: meta.isLinearized ? 'Yes' : 'No',
      metaPageCount: meta.pageCount,
      metaHasJS: meta.hasJavaScript ? 'Yes' : 'No',
      metaEmbeddedFiles: meta.hasEmbeddedFiles ? 'Yes' : 'No',
      metaForms: meta.hasForms ? 'Yes' : 'No',
      metaSignatures: meta.hasSignatures ? 'Yes' : 'No',
      metaEncrypted: meta.isEncrypted ? 'Yes' : 'No',
      metaObjectStreams: meta.hasObjectStreams ? 'Yes' : 'No'
    };

    Object.entries(fields).forEach(([id, value]) => {
      const el = document.getElementById(id);
      if (el) el.textContent = value || 'Not available';
    });
  }

  updateFindings(scan) {
    const container = document.getElementById('findingsList');
    const findings = scan.findings || [];

    if (findings.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
          <p>No findings detected</p>
        </div>
      `;
      return;
    }

    container.innerHTML = findings.map(finding => {
      const evidenceParts = [];
      if (finding.evidenceReference) evidenceParts.push(`Evidence: ${finding.evidenceReference}`);
      if (finding.extractedValue) evidenceParts.push(`Value: ${escapeHtml(String(finding.extractedValue))}`);
      if (finding.detectionMethod) evidenceParts.push(`Method: ${finding.detectionMethod}`);
      if (typeof finding.confidence === 'number') evidenceParts.push(`Confidence: ${(finding.confidence * 100).toFixed(0)}%`);

      return `
        <div class="finding-item">
          <div class="finding-header">
            <span class="finding-type ${finding.severity || 'info'}">${escapeHtml(finding.indicatorCategory || 'finding')}</span>
            <span class="finding-severity">${finding.severity || 'info'}</span>
          </div>
          <div class="finding-title">${escapeHtml(finding.description || 'Untitled finding')}</div>
          <div class="finding-description">${escapeHtml(finding.explanation || finding.description || '')}</div>
          ${evidenceParts.length > 0 ? `<div class="finding-evidence">${evidenceParts.map(escapeHtml).join('<br>')}</div>` : ''}
          ${finding.limitations && finding.limitations.length > 0 ? `<div class="finding-limitations">${finding.limitations.map(l => '⚠ ' + escapeHtml(l)).join('<br>')}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  updateRiskAssessment(scan) {
    const risk = scan.riskAssessment || { score: 0, level: 'none', factors: [] };
    
    document.getElementById('riskScoreValue').textContent = risk.score || 0;
    document.getElementById('riskScoreCircle').style.setProperty('--progress', risk.score || 0);
    
    const levelEl = document.getElementById('riskLevel');
    levelEl.textContent = risk.level || 'none';
    levelEl.className = `risk-level ${risk.level || 'none'}`;

    const factorsContainer = document.getElementById('riskFactors');
    if (risk.factors && risk.factors.length > 0) {
      factorsContainer.innerHTML = risk.factors.map(factor => {
        const label = typeof factor === 'string' ? factor : (factor.explanation || factor.rule || 'Risk factor');
        const contribution = typeof factor === 'object' && typeof factor.contribution === 'number'
          ? ` (+${factor.contribution.toFixed(1)})` : '';
        return `
          <div class="risk-factor">
            <svg class="risk-factor-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
            <span>${escapeHtml(label)}${contribution}</span>
          </div>
        `;
      }).join('');
    } else {
      factorsContainer.innerHTML = '<p class="empty-factors">No risk factors identified</p>';
    }
  }

  updateLimitations(scan) {
    const container = document.getElementById('limitationsList');
    const limitations = scan.limitations || [];

    if (limitations.length === 0) {
      container.innerHTML = '<li class="empty-state">No limitations recorded</li>';
      return;
    }

    container.innerHTML = limitations.map(limitation => `
      <li class="limitation-item">
        <svg class="limitation-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4M12 17h.01"/></svg>
        <span>${limitation}</span>
      </li>
    `).join('');
  }

  updateActions(scan) {
    // Actions are handled in updateScanStatus
  }

  updateHistoryButton() {
    // Could show count of history items
  }

  async startAnalysis() {
    if (!this.currentScan) return;
    await sendToBackground(createMessage(MessageType.START_ANALYSIS, { scanId: this.currentScan.scanId }));
  }

  async retryAnalysis() {
    if (!this.currentScan) return;
    await sendToBackground(createMessage(MessageType.RETRY_ANALYSIS, { scanId: this.currentScan.scanId }));
  }

  async exportReport() {
    if (!this.currentScan) return;
    
    const report = this.generateReport(this.currentScan);
    const blob = new Blob([report], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybertrace-report-${this.currentScan.scanId}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
  }

  generateReport(scan) {
    return JSON.stringify({
      version: '1.0.0',
      generated: new Date().toISOString(),
      scan: scan
    }, null, 2);
  }

  openHistory() {
    // Could open a history view
    console.log('Opening scan history');
  }

  applyTheme() {
    const root = document.documentElement;
    // Theme is handled via CSS custom properties
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  formatDate(isoString) {
    try {
      return new Date(isoString).toLocaleString();
    } catch {
      return isoString;
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.sidePanel = new SidePanel();
});

export { SidePanel };