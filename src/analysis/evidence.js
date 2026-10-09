// Structured evidence schema for CyberTrace findings.
// Every finding must be traceable to actual parser output or a reproducible rule result.

export const Severity = {
  INFO: 'info',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

export const DetectionMethod = {
  PDFJS_API: 'pdfjs_api',
  OBJECT_PARSER: 'object_parser',
  RAW_SCAN: 'raw_scan',
  HASH: 'hash',
  MANUAL: 'manual'
};

export const IndicatorCategory = {
  JAVASCRIPT: 'javascript',
  OPEN_ACTION: 'open_action',
  ADDITIONAL_ACTION: 'additional_action',
  LAUNCH_ACTION: 'launch_action',
  EMBEDDED_FILE: 'embedded_file',
  URI: 'uri',
  SUSPICIOUS_URI: 'suspicious_uri',
  STRUCTURAL_ANOMALY: 'structural_anomaly',
  METADATA_ANOMALY: 'metadata_anomaly',
  ENCODING_ANOMALY: 'encoding_anomaly',
  ENCRYPTION: 'encryption',
  INCREMENTAL_UPDATE: 'incremental_update',
  FORM: 'form',
  SIGNATURE: 'signature',
  TEXT_CONTENT: 'text_content'
};

let findingCounter = 0;

export function createFinding({
  indicatorCategory,
  description,
  severity = Severity.INFO,
  evidenceReference = null,
  objectNumber = null,
  extractedValue = null,
  detectionRule,
  ruleVersion = '1.0.0',
  confidence = 1.0,
  explanation = '',
  limitations = [],
  detectionMethod = DetectionMethod.OBJECT_PARSER,
  observed = true
} = {}) {
  if (!indicatorCategory) throw new Error('Finding requires indicatorCategory');
  if (!detectionRule) throw new Error('Finding requires detectionRule');
  if (confidence < 0 || confidence > 1) throw new Error('Confidence must be in [0,1]');

  findingCounter += 1;
  return {
    findingId: `F-${String(findingCounter).padStart(4, '0')}`,
    indicatorCategory,
    description,
    severity,
    evidenceReference,
    objectNumber,
    extractedValue: boundExcerpt(extractedValue),
    detectionRule,
    ruleVersion,
    confidence,
    explanation,
    limitations,
    detectionMethod,
    observed
  };
}

export function boundExcerpt(value, maxLength = 256) {
  if (value === null || value === undefined) return null;
  const str = String(value);
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + `…[truncated ${str.length - maxLength} chars]`;
}

export function deduplicateFindings(findings) {
  const seen = new Map();
  const result = [];
  for (const f of findings) {
    const key = dedupKey(f);
    if (seen.has(key)) {
      const existing = seen.get(key);
      existing.confidence = Math.max(existing.confidence, f.confidence);
      if (f.evidenceReference && !existing.evidenceReference) {
        existing.evidenceReference = f.evidenceReference;
      }
      continue;
    }
    seen.set(key, f);
    result.push(f);
  }
  return result;
}

function dedupKey(finding) {
  return [
    finding.indicatorCategory,
    finding.detectionRule,
    finding.objectNumber ?? '',
    normalizeExcerpt(finding.extractedValue)
  ].join('|');
}

function normalizeExcerpt(value) {
  if (!value) return '';
  return String(value).replace(/\s+/g, ' ').trim().toLowerCase();
}

export function validateFinding(finding) {
  const required = [
    'findingId', 'indicatorCategory', 'description', 'severity',
    'detectionRule', 'ruleVersion', 'confidence', 'detectionMethod'
  ];
  for (const field of required) {
    if (!(field in finding)) return { valid: false, missing: field };
  }
  if (finding.confidence < 0 || finding.confidence > 1) {
    return { valid: false, reason: 'confidence out of range' };
  }
  return { valid: true };
}

export function findingsByCategory(findings) {
  const map = new Map();
  for (const f of findings) {
    if (!map.has(f.indicatorCategory)) map.set(f.indicatorCategory, []);
    map.get(f.indicatorCategory).push(f);
  }
  return map;
}

export function findingsBySeverity(findings) {
  const order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
  const map = new Map(order.map(s => [s, []]));
  for (const f of findings) {
    if (!map.has(f.severity)) map.set(f.severity, []);
    map.get(f.severity).push(f);
  }
  return map;
}

export function resetFindingCounter() {
  findingCounter = 0;
}