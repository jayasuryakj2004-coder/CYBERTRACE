const STATUSES = new Set(['queued', 'analyzing', 'completed', 'incomplete', 'failed']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

function boundedString(value, max, allowEmpty = true) {
  return typeof value === 'string' && value.length <= max && (allowEmpty || value.length > 0);
}

export function validateScanRequest(body, requireQuestion = false) {
  const scan = body?.scan;
  if (!scan || typeof scan !== 'object' || Array.isArray(scan)) return { valid: false, error: 'A scan summary is required' };
  if (!boundedString(scan.scanId, 100, false) || !/^[\w-]+$/.test(scan.scanId)) return { valid: false, error: 'Invalid scan ID' };
  if (!boundedString(scan.timestamp, 40, false) || Number.isNaN(Date.parse(scan.timestamp))) return { valid: false, error: 'Invalid scan timestamp' };
  if (!STATUSES.has(scan.status)) return { valid: false, error: 'Invalid scan status' };

  const fileInfo = scan.fileInfo;
  if (!fileInfo || typeof fileInfo !== 'object' || !Number.isFinite(fileInfo.size) || fileInfo.size < 0 || fileInfo.size > 1_000_000_000) {
    return { valid: false, error: 'Invalid document size' };
  }
  if (fileInfo.mimeType !== undefined && !boundedString(fileInfo.mimeType, 100)) return { valid: false, error: 'Invalid document type' };
  if (!Array.isArray(scan.findings) || scan.findings.length > 40) return { valid: false, error: 'Invalid findings list' };
  for (const finding of scan.findings) {
    if (!finding || !boundedString(finding.findingId, 100, false) || !boundedString(finding.indicatorCategory, 80, false) ||
      !SEVERITIES.has(finding.severity) || !boundedString(finding.detectionRule, 100, false) ||
      !boundedString(finding.detectionMethod, 100) || !boundedString(finding.evidenceReference, 120) ||
      !boundedString(finding.extractedValue, 120) || !boundedString(finding.explanation, 200)) {
      return { valid: false, error: 'Invalid finding data' };
    }
    if (finding.confidence !== undefined && (!Number.isFinite(finding.confidence) || finding.confidence < 0 || finding.confidence > 1)) return { valid: false, error: 'Invalid finding confidence' };
    if (finding.objectNumber !== undefined && (!Number.isInteger(finding.objectNumber) || finding.objectNumber < 0 || finding.objectNumber > 10_000_000)) return { valid: false, error: 'Invalid object reference' };
    if (finding.limitations !== undefined && (!Array.isArray(finding.limitations) || finding.limitations.length > 2 || finding.limitations.some(item => !boundedString(item, 100)))) return { valid: false, error: 'Invalid finding limitations' };
  }

  const risk = scan.riskAssessment;
  if (!risk || typeof risk !== 'object' || !Number.isFinite(risk.score) || risk.score < 0 || risk.score > 100 ||
    !boundedString(risk.level, 20) || !Array.isArray(risk.factors) || risk.factors.length > 40) return { valid: false, error: 'Invalid risk assessment' };
  for (const factor of risk.factors) {
    if (typeof factor === 'string') {
      if (!boundedString(factor, 300)) return { valid: false, error: 'Invalid risk factor' };
    } else if (!factor || typeof factor !== 'object' || !boundedString(factor.rule, 100) ||
      !boundedString(factor.indicatorCategory, 80) || !boundedString(factor.severity, 30) ||
      !Number.isFinite(factor.contribution) || factor.contribution < 0 || factor.contribution > 100 ||
      !boundedString(factor.explanation, 200)) return { valid: false, error: 'Invalid risk factor' };
  }

  const metadata = scan.metadata;
  if (!metadata || typeof metadata !== 'object' ||
    (metadata.pageCount !== null && (!Number.isInteger(metadata.pageCount) || metadata.pageCount < 0 || metadata.pageCount > 1_000_000)) ||
    !boundedString(metadata.pdfVersion, 20) || ['isEncrypted', 'isLinearized'].some(key => metadata[key] !== null && typeof metadata[key] !== 'boolean')) return { valid: false, error: 'Invalid document metadata' };
  if (!Array.isArray(scan.limitations) || scan.limitations.length > 40 || scan.limitations.some(item => !boundedString(item, 200))) return { valid: false, error: 'Invalid analysis limitations' };
  if (requireQuestion && (!boundedString(body.question, 500, false) || !body.question.trim())) return { valid: false, error: 'Question must be 1-500 characters' };
  return { valid: true, scan };
}

export function sanitizeScan(scan) {
  return {
    scanId: scan.scanId,
    timestamp: scan.timestamp,
    status: scan.status,
    metadata: { pageCount: scan.metadata.pageCount, pdfVersion: scan.metadata.pdfVersion, isEncrypted: scan.metadata.isEncrypted, isLinearized: scan.metadata.isLinearized },
    findings: scan.findings.map(finding => ({
      findingId: finding.findingId,
      category: finding.indicatorCategory,
      severity: finding.severity,
      rule: finding.detectionRule,
      confidence: finding.confidence,
      method: finding.detectionMethod,
      evidenceReference: finding.evidenceReference,
      objectNumber: finding.objectNumber,
      excerpt: finding.extractedValue,
      explanation: finding.explanation,
      limitations: finding.limitations || []
    })),
    riskAssessment: { score: scan.riskAssessment.score, level: scan.riskAssessment.level, factors: scan.riskAssessment.factors },
    limitations: scan.limitations
  };
}

export function validateStructuredResponse(response, kind, findingIds) {
  const findings = findingIds.filter(item => item && typeof item === 'object');
  const ids = new Set(findingIds.map(item => typeof item === 'string' ? item : item?.findingId).filter(Boolean));
  const extractUrls = text => [...String(text || '').matchAll(/(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi)]
    .map(match => match[0].replace(/[.,;:!?]+$/, ''));
  const knownUrls = new Set(findings.flatMap(finding => extractUrls(`${finding.excerpt || finding.extractedValue || ''} ${finding.evidenceReference || ''}`)));
  const responseText = JSON.stringify(response);
  const responseUrls = extractUrls(responseText);
  if (responseUrls.some(url => !knownUrls.has(url))) return { valid: false };
  const knownObjects = new Set(findings.map(finding => finding.objectNumber).filter(Number.isInteger));
  const objectMentions = [
    ...responseText.matchAll(/\bobject(?:\s+reference)?\s*#?\s*(\d+)\b/gi),
    ...responseText.matchAll(/\b(\d+)\s+\d+\s+R\b/gi)
  ].map(match => Number(match[1]));
  if (objectMentions.some(number => !knownObjects.has(number))) return { valid: false };
  const strings = (items, maxLength, maxItems) => Array.isArray(items) && items.length <= maxItems && items.every(item => boundedString(item, maxLength));
  const exactKeys = (value, keys) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
  if (!response || typeof response !== 'object' || Array.isArray(response)) return { valid: false };
  if (kind === 'answer') {
    return { valid: exactKeys(response, ['answer', 'finding_ids']) && boundedString(response.answer, 1200, false) && Array.isArray(response.finding_ids) && response.finding_ids.length <= 20 &&
      response.finding_ids.every(id => boundedString(id, 100, false) && ids.has(id)) };
  }
  const explanations = response.findings_explanation;
  const fields = ['summary', 'findings_explanation', 'possible_scenarios', 'recommended_actions', 'limitations'];
  return { valid: exactKeys(response, fields) && boundedString(response.summary, 500, false) && Array.isArray(explanations) && explanations.length <= 50 &&
    explanations.every(item => item && exactKeys(item, ['finding_id', 'explanation']) && ids.has(item.finding_id) && boundedString(item.explanation, 300, false)) &&
    strings(response.possible_scenarios, 200, 10) && strings(response.recommended_actions, 200, 10) && strings(response.limitations, 200, 10) };
}