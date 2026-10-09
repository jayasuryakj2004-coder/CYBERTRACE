import { ScanStatus, MessageType } from '../shared/contracts.js';
import { onMessage } from '../shared/messaging.js';
import {
  clearScanHistory,
  getCurrentScan,
  getScanHistory,
  getSettings,
  setCurrentScan,
  setSettings,
  updateScanInHistory
} from '../shared/storage.js';
import { generateCategorization } from '../categorizer/rules.js';
import { generatePdfReport } from '../report/pdfReport.js';
import { summarizeScanWithGemini, askGeminiAboutScan, embeddedAiAvailable } from '../ai/gemini.js';

const $ = id => document.getElementById(id);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[character]));

function createAiScanSummary(scan) {
  const allFindings = scan.findings || [];
  return {
    scanId: scan.scanId,
    timestamp: scan.timestamp,
    status: scan.status,
    fileInfo: { size: scan.fileInfo?.size, mimeType: scan.fileInfo?.mimeType },
    metadata: {
      pageCount: Number.isInteger(scan.metadata?.pageCount) ? scan.metadata.pageCount : null,
      pdfVersion: typeof scan.metadata?.pdfVersion === 'string' ? scan.metadata.pdfVersion.slice(0, 20) : 'unknown',
      isEncrypted: typeof scan.metadata?.isEncrypted === 'boolean' ? scan.metadata.isEncrypted : null,
      isLinearized: typeof scan.metadata?.isLinearized === 'boolean' ? scan.metadata.isLinearized : null
    },
    findings: allFindings.slice(0, 40).map(finding => ({
      findingId: finding.findingId,
      indicatorCategory: finding.indicatorCategory,
      severity: finding.severity,
      detectionRule: finding.detectionRule,
      confidence: finding.confidence,
      detectionMethod: finding.detectionMethod,
      evidenceReference: String(finding.evidenceReference || '').slice(0, 120),
      objectNumber: finding.objectNumber,
      extractedValue: String(finding.extractedValue || '').slice(0, 120),
      explanation: String(finding.explanation || '').slice(0, 200),
      limitations: (finding.limitations || []).slice(0, 2).map(value => String(value).slice(0, 100))
    })),
    riskAssessment: {
      score: scan.riskAssessment?.score,
      level: scan.riskAssessment?.level,
      factors: (scan.riskAssessment?.factors || []).slice(0, 40).map(factor => typeof factor === 'string' ? factor.slice(0, 300) : ({
        rule: String(factor.rule || '').slice(0, 100),
        indicatorCategory: String(factor.indicatorCategory || '').slice(0, 80),
        severity: String(factor.severity || '').slice(0, 30),
        contribution: factor.contribution,
        explanation: String(factor.explanation || '').slice(0, 200)
      }))
    },
    limitations: [
      ...(scan.limitations || []).slice(0, allFindings.length > 40 ? 39 : 40).map(value => String(value).slice(0, 200)),
      ...(allFindings.length > 40 ? ['AI context limited to the first 40 findings; later findings were not sent for interpretation.'] : [])
    ]
  };
}

class Dashboard {
  constructor() {
    this.scan = null;
    this.aiAnalysis = null;
    this.settings = null;
    this.findingFilter = 'all';
    this.severityFilter = 'all';
    this.init();
  }

  async init() {
    this.bindEvents();
    this.settings = await getSettings();
    this.applySettings();
    await this.loadCurrentScan();
    await this.renderHistory();
    await this.loadAccuracy();
    this.setupMessages();
    try {
      const state = await chrome.runtime.sendMessage({ type: MessageType.GET_SCAN_STATE, payload: {} });
      if (state?.scanResult) this.setScan(state.scanResult);
    } catch {}
    await this.checkBackend();
  }

  bindEvents() {
    document.querySelectorAll('.tab-btn').forEach(button => button.addEventListener('click', () => this.activateTab(button.dataset.tab)));
    $('settingsBtn').addEventListener('click', () => $('settingsModal').classList.remove('hidden'));
    $('closeSettings').addEventListener('click', () => $('settingsModal').classList.add('hidden'));
    $('saveSettings').addEventListener('click', () => this.saveSettings());
    $('analyzeBtn').addEventListener('click', () => this.startAnalysis());
    $('retryScanBtn').addEventListener('click', () => this.retryScan());
    $('runAiAnalysis').addEventListener('click', () => this.runAiAnalysis());
    $('chatSend').addEventListener('click', () => this.askAnalyst());
    $('chatInput').addEventListener('keydown', event => {
      if (event.key === 'Enter') this.askAnalyst();
    });
    $('exportJsonBtn').addEventListener('click', () => this.exportReport('pdf'));
    $('exportHistoryBtn').addEventListener('click', () => this.exportHistory());
    $('clearHistoryBtn').addEventListener('click', () => this.clearHistory());
    $('findingFilter').addEventListener('change', event => {
      this.findingFilter = event.target.value;
      this.renderFindings();
    });
    $('severityFilter').addEventListener('change', event => {
      this.severityFilter = event.target.value;
      this.renderFindings();
    });
    $('historyList').addEventListener('click', event => {
      const button = event.target.closest('[data-open-scan]');
      if (button) this.openHistoryScan(button.dataset.openScan);
    });
    window.addEventListener('cybertrace:scan-updated', event => this.setScan(event.detail));
    window.addEventListener('cybertrace:history-updated', () => this.renderHistory());
  }

  setupMessages() {
    onMessage(message => {
      if (message.type === MessageType.SCAN_STATE || message.type === MessageType.ANALYSIS_COMPLETE) {
        this.setScan(message.payload.scanResult || message.payload.result);
      } else if (message.type === MessageType.ANALYSIS_PROGRESS) {
        if (this.scan && message.payload.scanId === this.scan.scanId) {
          this.scan.progress = Math.max(0, Math.min(100, Number(message.payload.progress) || 0));
          this.scan.status = message.payload.status || ScanStatus.ANALYZING;
          this.renderScan();
        }
      } else if (message.type === MessageType.ANALYSIS_FAILED) {
        $('scanStatusBadge').textContent = 'Failed';
        $('scanStatusBadge').className = 'status-badge failed';
      }
    });
  }

  async loadCurrentScan() {
    const scan = await getCurrentScan();
    if (scan) this.setScan(scan);
    else this.renderEmptyScan();
  }

  setScan(scan) {
    if (!scan) return;
    this.scan = scan;
    this.aiAnalysis = scan.aiAnalysis || null;
    this.renderScan();
  }

  renderEmptyScan() {
    $('docName').textContent = 'No document scanned';
    $('docSize').textContent = '—';
    $('docHash').textContent = '—';
    $('docUrl').textContent = '—';
    $('scanStatusBadge').textContent = 'Waiting';
    $('scanCoverage').textContent = 'No analysis available';
  }

  renderScan() {
    if (!this.scan) return this.renderEmptyScan();
    const scan = this.scan;
    const info = scan.fileInfo || {};
    const metadata = scan.metadata || {};
    const status = scan.status || 'unknown';
    const progress = Math.max(0, Math.min(100, Number(scan.progress) || 0));
    const limitations = scan.limitations || [];

    $('docName').textContent = info.name || 'Unknown document';
    $('docSize').textContent = this.formatBytes(info.size);
    $('docHash').textContent = info.sha256 || 'Unavailable';
    $('docUrl').textContent = info.url || 'Local file';
    $('docUrl').title = info.url || 'Local file';
    $('scanId').textContent = scan.scanId || '—';
    $('scanStarted').textContent = this.formatDate(scan.timestamp);
    $('scanCompleted').textContent = scan.completedAt ? this.formatDate(scan.completedAt) : '—';
    $('scanStatusBadge').textContent = status;
    $('scanStatusBadge').className = `status-badge ${escapeHtml(status)}`;
    $('scanCoverage').textContent = `${limitations.length ? `${limitations.length} limitation(s)` : 'No limitations recorded'} · ${progress}% pipeline progress`;
    $('scanProgressFill').style.width = `${progress}%`;
    $('analyzeBtn').classList.toggle('hidden', status !== ScanStatus.QUEUED);
    $('retryScanBtn').classList.toggle('hidden', ![ScanStatus.COMPLETED, ScanStatus.INCOMPLETE, ScanStatus.FAILED].includes(status));
    $('exportJsonBtn').disabled = ![ScanStatus.COMPLETED, ScanStatus.INCOMPLETE].includes(status);
    $('runAiAnalysis').disabled = ![ScanStatus.COMPLETED, ScanStatus.INCOMPLETE].includes(status);
    $('chatInput').disabled = ![ScanStatus.COMPLETED, ScanStatus.INCOMPLETE].includes(status);
    $('chatSend').disabled = ![ScanStatus.COMPLETED, ScanStatus.INCOMPLETE].includes(status);

    const metadataFields = {
      metaPdfVersion: metadata.pdfVersion,
      metaPageCount: metadata.pageCount,
      metaTitle: metadata.title,
      metaAuthor: metadata.author,
      metaCreator: metadata.creator,
      metaProducer: metadata.producer,
      metaCreationDate: metadata.creationDate,
      metaModDate: metadata.modificationDate,
      metaLinearized: metadata.isLinearized,
      metaEncrypted: metadata.isEncrypted,
      metaObjectStreams: metadata.hasObjectStreams,
      metaForms: metadata.hasForms,
      metaSignatures: metadata.hasSignatures
    };
    Object.entries(metadataFields).forEach(([id, value]) => {
      $(id).textContent = typeof value === 'boolean' ? (value ? 'Yes' : 'No') : (value ?? 'Not available');
    });

    this.renderFindings();
    this.renderRisk();
    this.renderLimitations();
    this.renderNextSteps();
    this.renderAiAnalysis();
  }

  renderFindings() {
    const findings = this.scan?.findings || [];
    const categories = [...new Set(findings.map(item => item.indicatorCategory || 'other'))].sort();
    const categorySelect = $('findingFilter');
    const selectedCategory = this.findingFilter;
    categorySelect.innerHTML = '<option value="all">All Categories</option>' + categories.map(category =>
      `<option value="${escapeHtml(category)}">${escapeHtml(category.replace(/_/g, ' '))}</option>`
    ).join('');
    categorySelect.value = categories.includes(selectedCategory) || selectedCategory === 'all' ? selectedCategory : 'all';
    this.findingFilter = categorySelect.value;
    const filtered = findings.filter(finding =>
      (this.findingFilter === 'all' || finding.indicatorCategory === this.findingFilter) &&
      (this.severityFilter === 'all' || finding.severity === this.severityFilter)
    );
    if (!findings.length) {
      $('findingsList').innerHTML = '<div class="empty-state"><p>No findings detected by configured rules.</p></div>';
      return;
    }
    if (!filtered.length) {
      $('findingsList').innerHTML = '<div class="empty-state"><p>No findings match these filters.</p></div>';
      return;
    }
    const groups = new Map();
    filtered.forEach(finding => {
      const category = finding.indicatorCategory || 'other';
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(finding);
    });
    $('findingsList').innerHTML = [...groups].map(([category, items]) => `
      <section class="finding-group"><h3>${escapeHtml(category.replace(/_/g, ' '))}<span>${items.length}</span></h3>
        ${items.map(finding => this.renderFinding(finding)).join('')}
      </section>`).join('');
  }

  renderFinding(finding) {
    const evidence = [
      ['Evidence reference', finding.evidenceReference],
      ['Object reference', finding.objectNumber === undefined ? '' : `${finding.objectNumber} 0 R`],
      ['Observed value', finding.extractedValue],
      ['Detection method', finding.detectionMethod],
      ['Detection rule', finding.detectionRule],
      ['Confidence', typeof finding.confidence === 'number' ? `${Math.round(finding.confidence * 100)}%` : '']
    ].filter(([, value]) => value !== '' && value !== undefined && value !== null);
    return `<details class="finding-item">
      <summary><span class="finding-severity ${escapeHtml(finding.severity || 'info')}">${escapeHtml(finding.severity || 'info')}</span><span class="finding-title">${escapeHtml(finding.description || finding.findingId || 'Finding')}</span><span class="finding-id">${escapeHtml(finding.findingId || '')}</span></summary>
      <div class="finding-detail"><p><strong>What was detected</strong><br>${escapeHtml(finding.observed || finding.extractedValue || finding.description || 'The configured rule matched a structural feature.')}</p>
      <p><strong>Why it may matter</strong><br>${escapeHtml(finding.explanation || 'This is an indicator only; it does not confirm malicious behavior.')}</p>
      ${evidence.length ? `<dl>${evidence.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`).join('')}</dl>` : '<p>No supporting evidence reference was recorded.</p>'}
      ${(finding.limitations || []).length ? `<p class="warning-text">Limitations: ${(finding.limitations || []).map(escapeHtml).join('; ')}</p>` : ''}</div>
    </details>`;
  }

  renderRisk() {
    const risk = this.scan?.riskAssessment || {};
    const score = Number.isFinite(risk.score) ? Math.max(0, Math.min(100, risk.score)) : 0;
    $('riskScoreValue').textContent = score;
    $('riskScoreCircle').setAttribute('stroke-dashoffset', String(283 * (1 - score / 100)));
    $('riskLevel').textContent = risk.level || 'unknown';
    $('riskLevel').className = `level ${escapeHtml(risk.level || 'unknown')}`;
    $('riskFactors').innerHTML = (risk.factors || []).length ? risk.factors.map(factor => {
      const label = typeof factor === 'string' ? factor : factor.explanation || factor.rule || 'Risk factor';
      const points = typeof factor === 'object' && typeof factor.contribution === 'number' ? ` · +${factor.contribution}` : '';
      return `<div class="risk-factor"><span>${escapeHtml(label)}${escapeHtml(points)}</span></div>`;
    }).join('') : '<p class="empty">No risk factors identified.</p>';
  }

  renderLimitations() {
    const items = this.scan?.limitations || [];
    $('limitationsList').innerHTML = items.length ? items.map(item => `<li>${escapeHtml(item)}</li>`).join('') : '<li>No parser warnings or limitations recorded.</li>';
  }

  renderNextSteps() {
    const findings = this.scan?.findings || [];
    const actions = [];
    if (findings.length) actions.push('Review each finding and its object/evidence reference in the original document.');
    if (findings.some(f => ['javascript', 'launch_action', 'open_action', 'embedded_file'].includes(f.indicatorCategory))) {
      actions.push('If further analysis is warranted, inspect the document in an isolated, non-networked sandbox.');
    }
    if (findings.some(f => ['uri', 'suspicious_uri'].includes(f.indicatorCategory))) {
      actions.push('Verify detected links through approved tooling without opening them directly.');
    }
    if (this.scan?.status === ScanStatus.INCOMPLETE || (this.scan?.limitations || []).length) {
      actions.push('Treat this result as incomplete and use an additional parser or specialist review.');
    }
    if (!actions.length) actions.push('No indicator was detected by the configured checks; this is not a guarantee of safety.');
    $('nextSteps').innerHTML = actions.map(action => `<li>${escapeHtml(action)}</li>`).join('');
  }

  async checkBackend() {
    const status = $('connectionStatus');
    const ready = embeddedAiAvailable();
    status.className = `status-indicator ${ready ? 'online' : 'offline'}`;
    status.lastElementChild.textContent = ready ? 'AI Ready' : 'AI Offline';
  }

  async callAi(path, payload) {
    if (path === 'analyze') {
      return summarizeScanWithGemini(this.scan);
    }
    if (path === 'ask') {
      return askGeminiAboutScan(this.scan, payload.question);
    }
    throw new Error('Unsupported AI action.');
  }

  validateAiAnalysis(data) {
    const ids = new Set((this.scan?.findings || []).map(item => item.findingId));
    if (!data || typeof data.summary !== 'string' || data.summary.length > 500 || !Array.isArray(data.findings_explanation)) return false;
    const keys = Object.keys(data).sort().join(',');
    if (keys !== 'findings_explanation,limitations,possible_scenarios,recommended_actions,summary') return false;
    if (data.findings_explanation.some(item => Object.keys(item).sort().join(',') !== 'explanation,finding_id' || !ids.has(item.finding_id) || typeof item.explanation !== 'string' || item.explanation.length > 300)) return false;
    return ['possible_scenarios', 'recommended_actions', 'limitations'].every(key =>
      Array.isArray(data[key]) && data[key].length <= 10 && data[key].every(item => typeof item === 'string' && item.length <= 200)
    );
  }

  async runAiAnalysis() {
    if (!this.scan) return;
    if (!this.scan.findings || this.scan.findings.length === 0) {
      $('aiError').textContent = 'No readable PDF content or metadata signals were extracted, so AI summarization is unavailable.';
      $('aiError').classList.remove('hidden');
      $('aiStatusText').textContent = 'No AI summary generated';
      return;
    }
    $('runAiAnalysis').disabled = true;
    $('aiStatusText').textContent = 'Preparing minimized evidence summary…';
    $('aiError').classList.add('hidden');
    try {
      const result = await this.callAi('analyze', { scan: createAiScanSummary(this.scan) });
      if (!this.validateAiAnalysis(result)) throw new Error('AI response did not match this scan’s findings. No explanation was displayed.');
      this.aiAnalysis = result;
      this.scan.aiAnalysis = result;
      await setCurrentScan(this.scan);
      await updateScanInHistory(this.scan.scanId, this.scan);
      this.renderAiAnalysis();
      $('aiStatusText').textContent = 'Interpretation generated from supplied scan evidence.';
    } catch (error) {
      this.aiAnalysis = null;
      this.renderAiAnalysis();
      $('aiError').textContent = `${error.message}. Scanner results remain available; retry after checking the optional backend.`;
      $('aiError').classList.remove('hidden');
      $('aiStatusText').textContent = 'AI unavailable';
    } finally {
      $('runAiAnalysis').disabled = false;
    }
  }

  renderAiAnalysis() {
    const data = this.aiAnalysis;
    $('aiResult').classList.toggle('hidden', !data);
    $('aiSummary').textContent = data?.summary || '';
    $('aiFindingsExplanation').innerHTML = (data?.findings_explanation || []).map(item => {
      const finding = (this.scan?.findings || []).find(candidate => candidate.findingId === item.finding_id);
      return `<li><strong>${escapeHtml(finding?.findingId || item.finding_id)}</strong>: ${escapeHtml(item.explanation)}</li>`;
    }).join('');
    $('aiScenarios').innerHTML = (data?.possible_scenarios || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
    $('aiActions').innerHTML = (data?.recommended_actions || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
    $('aiLimitations').innerHTML = (data?.limitations || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
    $('aiStatusText').textContent = data ? 'AI-generated interpretation · scanner evidence remains authoritative' : 'Optional; scanner explanations remain available without AI';
  }

  async askAnalyst() {
    const question = $('chatInput').value.trim();
    if (!question || !this.scan) return;
    $('chatInput').value = '';
    this.addChatMessage('user', question);
    $('chatSend').disabled = true;
    try {
      const result = await this.callAi('ask', { scan: createAiScanSummary(this.scan), question });
      const ids = new Set((this.scan.findings || []).map(item => item.findingId));
      if (Object.keys(result).sort().join(',') !== 'answer,finding_ids' || typeof result.answer !== 'string' || result.answer.length > 1200 || !Array.isArray(result.finding_ids) || result.finding_ids.some(id => !ids.has(id))) {
        throw new Error('AI response referenced unsupported scan data and was discarded');
      }
      this.addChatMessage('assistant', `${result.answer}${result.finding_ids.length ? `\n\nEvidence: ${result.finding_ids.join(', ')}` : ''}`);
    } catch (error) {
      this.addChatMessage('assistant', `AI unavailable: ${error.message}. Refer to the scanner finding details for deterministic evidence.`);
    } finally {
      $('chatSend').disabled = false;
    }
  }

  addChatMessage(role, text) {
    const message = document.createElement('div');
    message.className = `message ${role}`;
    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = role === 'assistant' ? 'AI' : 'You';
    const content = document.createElement('div');
    content.className = 'content';
    const paragraph = document.createElement('p');
    paragraph.textContent = text;
    content.appendChild(paragraph);
    message.append(avatar, content);
    $('chatMessages').appendChild(message);
    message.scrollIntoView({ block: 'nearest' });
  }

  async renderHistory() {
    let history = [];
    try { history = await getScanHistory(); } catch { /* Storage may be unavailable in restricted contexts. */ }
    $('historyList').innerHTML = history.length ? history.map(scan => {
      const score = Number.isFinite(scan.riskAssessment?.score) ? `${scan.riskAssessment.score}/100` : 'not scored';
      const riskLevel = scan.riskAssessment?.level || 'unknown';
      return `
        <article class="history-item"><div><strong>${escapeHtml(scan.fileInfo?.name || 'Unknown document')}</strong>
        <span>${escapeHtml(this.formatDate(scan.timestamp))} · ${escapeHtml(scan.status)} · ${escapeHtml(scan.findings?.length || 0)} finding(s)</span>
        <span>Risk: ${escapeHtml(score)} · ${escapeHtml(riskLevel)}</span>
        <span class="mono">${escapeHtml(scan.fileInfo?.sha256 || '')}</span></div>
        <button class="btn secondary" data-open-scan="${escapeHtml(scan.scanId)}">Open result</button></article>`;
    }).join('') : '<div class="empty-state"><p>No saved scan results.</p></div>';
  }

  async openHistoryScan(scanId) {
    const history = await getScanHistory();
    const scan = history.find(item => item.scanId === scanId);
    if (!scan) return;
    this.setScan(scan);
    await setCurrentScan(scan);
    this.activateTab('overview');
  }

  async clearHistory() {
    if (!window.confirm('Clear saved scan history from this browser? The active scan will not be changed.')) return;
    await clearScanHistory();
    await this.renderHistory();
  }

  async exportHistory() {
    const history = await getScanHistory();
    if (!history.length) return;
    const latest = history[history.length - 1];
    const pdf = await this.buildPdfForScan(latest);
    this.downloadPdf(pdf, `${this.safeFileName(latest.fileInfo?.name || 'cybertrace')}.pdf`);
  }

  async exportReport(format = 'pdf') {
    if (!this.scan) return;
    const pdf = await this.buildPdfForScan(this.scan);
    this.downloadPdf(pdf, `${this.safeFileName(this.scan.fileInfo?.name || 'cybertrace-report')}.pdf`);
  }

  async buildPdfForScan(scan) {
    const findings = (scan.findings || []).map((finding) => ({
      findingId: finding.findingId || `scan-${scan.scanId}`,
      category: finding.indicatorCategory || 'metadata_provenance',
      text: finding.description || finding.observed || finding.explanation || 'Finding observed',
      severity: finding.severity || 'info'
    }));
    const categorization = generateCategorization({
      findings,
      scanStatus: scan.status || 'completed',
      confidence: Number(scan.riskAssessment?.score || 0) / 100,
      possiblyHidden: (scan.limitations || []).filter((reason) => /EOF|hidden|incomplete|partial/i.test(reason))
    });
    const result = await generatePdfReport(categorization, {
      fileName: scan.fileInfo?.name || 'document.pdf',
      sourceType: scan.fileInfo?.url ? (/^https?:/i.test(scan.fileInfo.url) ? 'remote' : 'local') : 'local',
      size: scan.fileInfo?.size || 0,
      sha256: scan.fileInfo?.sha256 || 'unknown',
      mode: this.aiAnalysis ? 'Rules + AI' : 'Rules only'
    });
    return result.pdfBytes;
  }

  downloadPdf(bytes, filename) {
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  download(content, type, filename) {
    const url = URL.createObjectURL(new Blob([content], { type: `${type};charset=utf-8` }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async startAnalysis() {
    if (!this.scan) return;
    await chrome.runtime.sendMessage({ type: MessageType.START_ANALYSIS, payload: { scanId: this.scan.scanId } });
  }

  async retryScan() {
    if (!this.scan) return;
    const result = await chrome.runtime.sendMessage({ type: MessageType.RETRY_ANALYSIS, payload: { scanId: this.scan.scanId } });
    if (!result?.success) window.alert(result?.error || 'Original document bytes are unavailable for retry.');
  }

  async saveSettings() {
    try {
      this.settings = await setSettings({
        ...this.settings,
        autoAnalyze: $('autoAnalyze').checked,
        maxHistoryItems: Math.max(1, Math.min(50, Number($('maxHistory').value) || 50)),
        theme: $('themeSelect').value
      });
      $('settingsModal').classList.add('hidden');
      await this.checkBackend();
    } catch (error) {
      window.alert(error.message || 'Settings could not be saved.');
    }
  }

  applySettings() {
    $('autoAnalyze').checked = this.settings.autoAnalyze;
    $('maxHistory').value = this.settings.maxHistoryItems;
    $('themeSelect').value = this.settings.theme;
  }

  async loadAccuracy() {
    try {
      const response = await fetch(chrome.runtime.getURL('tests/results/evaluation.json'));
      if (!response.ok) throw new Error('Evaluation output unavailable');
      this.renderAccuracy(await response.json());
    } catch {
      $('accuracyContent').innerHTML = '<div class="empty-state"><p>Evaluation results are unavailable. Run the Phase 2 evaluation harness to generate results.</p></div>';
    }
  }

  renderAccuracy(evaluation) {
    const metrics = evaluation.metrics || {};
    const counts = metrics.confusionMatrix || {};
    const observedLabels = (evaluation.samples || []).reduce((result, sample) => {
      result[sample.label] = (result[sample.label] || 0) + 1;
      return result;
    }, {});
    const labels = evaluation.dataset?.labelDistribution || observedLabels;
    const sampleStatuses = (evaluation.samples || []).reduce((result, sample) => {
      result[sample.scanStatus] = (result[sample.scanStatus] || 0) + 1;
      return result;
    }, {});
    const formatMetric = value => typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : 'Not defined';
    const indicatorRows = Object.entries(evaluation.perIndicator || {}).map(([name, item]) => `
      <tr><th>${escapeHtml(name.replace(/_/g, ' '))}</th><td>${item.tp}</td><td>${item.fp}</td><td>${item.fn}</td><td>${formatMetric(item.precision)}</td><td>${formatMetric(item.recall)}</td><td>${formatMetric(item.f1Score)}</td></tr>`).join('');
    $('accuracyContent').innerHTML = `<p class="accuracy-provenance">Dataset: ${escapeHtml(evaluation.dataset?.name || 'CyberTrace labeled fixture dataset')} v${escapeHtml(evaluation.dataset?.version || 'unknown')} · ${escapeHtml(evaluation.dataset?.provenance || 'Provenance not recorded')} · Evaluated: ${escapeHtml(this.formatDate(evaluation.timestamp))} · Threshold: ${escapeHtml(evaluation.threshold)}</p>
      <p class="accuracy-note">These metrics describe the deterministic scanner on this labeled dataset; they do not measure AI explanation quality.</p>
      <div class="metric-grid">${[
        ['Dataset size', `${evaluation.datasetSize ?? metrics.totalSamples ?? 0}`],
        ['Label distribution', `Benign ${labels.benign || 0} · Suspicious ${labels.suspicious || 0} · Unknown ${labels.unknown || 0}`],
        ['Completed / attempted', `${sampleStatuses.completed || 0} / ${(evaluation.samples || []).length}`],
        ['Precision', formatMetric(metrics.precision)], ['Recall', formatMetric(metrics.recall)],
        ['F1', formatMetric(metrics.f1Score)], ['Accuracy', formatMetric(metrics.accuracy)],
        ['False-positive rate', formatMetric(metrics.falsePositiveRate)],
        ['TP / TN / FP / FN', `${counts.tp ?? 0} / ${counts.tn ?? 0} / ${counts.fp ?? 0} / ${counts.fn ?? 0}`],
        ['Incomplete / failed scans', `${metrics.incompleteScans ?? 0} / ${metrics.failedScans ?? 0}`]
      ].map(([label, value]) => `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div>
      <h3>Indicator-level results</h3><div class="table-scroll"><table class="metrics-table"><thead><tr><th>Indicator</th><th>TP</th><th>FP</th><th>FN</th><th>Precision</th><th>Recall</th><th>F1</th></tr></thead><tbody>${indicatorRows || '<tr><td colspan="7">No indicator-level results recorded.</td></tr>'}</tbody></table></div>`;
  }

  activateTab(name) {
    document.querySelectorAll('.tab-btn').forEach(button => button.classList.toggle('active', button.dataset.tab === name));
    document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.toggle('active', panel.id === `tab-${name}`));
    if (name === 'history') this.renderHistory();
  }

  formatBytes(bytes) {
    const size = Number(bytes);
    if (!Number.isFinite(size) || size < 0) return '—';
    if (size === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const index = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
    return `${(size / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
  }

  formatDate(value) {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
  }

  safeFileName(value) {
    return String(value || 'scan').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80);
  }
}

document.addEventListener('DOMContentLoaded', () => { window.cyberTraceDashboard = new Dashboard(); });

export { Dashboard, createAiScanSummary };