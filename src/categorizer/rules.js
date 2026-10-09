export const CATEGORY_KEYS = [
  'yara_signals',
  'metadata_signals',
  'embedded_indicators',
  'behavioral_signals',
  'network_signals',
  'provenance_signals'
];

export const RATING_LEVELS = ['none', 'info', 'low', 'medium', 'high', 'critical', 'not_assessed'];
export const RATING_RANK = { none: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5, not_assessed: -1 };

const DEFAULT_INTERPRETATION = {
  yara_signals: 'No YARA-style file signatures or executable patterns were matched.',
  metadata_signals: 'No metadata or provenance anomalies were observed in the inspected document.',
  embedded_indicators: 'No embedded objects, archives, or payload containers were detected.',
  behavioral_signals: 'No script, action, or execution behavior was observed on the file.',
  network_signals: 'No URI, URL, or external destination indicators were detected.',
  provenance_signals: 'No provenance or trust-chain anomalies were identified.'
};

function normalizeSeverity(value) {
  return ['none', 'info', 'low', 'medium', 'high', 'critical'].includes(value) ? value : 'info';
}

function sanitizeString(value, fallback = '') {
  return typeof value === 'string' ? value.replace(/[\u0000-\u001F\u007F]+/g, ' ').trim() : fallback;
}

export function ruleEngineFloor(categoryResult) {
  if (!categoryResult || !categoryResult.rating) return 'not_assessed';
  return categoryResult.rating;
}

function pickSeverity(findings) {
  if (!findings.length) return 'none';
  return findings.map(item => normalizeSeverity(item.severity || item.rating || 'info')).sort((a, b) => RATING_RANK[b] - RATING_RANK[a])[0];
}

function inferThreatCategory(finding) {
  const legacyAliases = {
    identity_integrity: 'provenance_signals',
    structural_anomalies: 'metadata_signals',
    active_content: 'behavioral_signals',
    embedded_payloads: 'embedded_indicators',
    links_destinations: 'network_signals',
    social_engineering: 'provenance_signals',
    hidden_deceptive_content: 'yara_signals',
    metadata_provenance: 'provenance_signals',
    signature_behavior: 'yara_signals'
  };

  if (finding?.category && legacyAliases[finding.category]) {
    return legacyAliases[finding.category];
  }

  const context = `${finding?.category || ''} ${finding?.indicatorCategory || ''} ${finding?.detectionRule || ''} ${finding?.description || ''} ${finding?.observed || ''}`.toLowerCase();

  if (/yara|signature|powershell|cmd\.exe|script|javascript|launch|openaction|action/.test(context)) return 'yara_signals';
  if (/metadata|title|author|producer|creationdate|moddate|form|acroform|signature/.test(context)) return 'metadata_signals';
  if (/embedded|attachment|archive|file|filespec|ole|zip|cab/.test(context)) return 'embedded_indicators';
  if (/javascript|launch|openaction|aa|js|script|execute|action/.test(context)) return 'behavioral_signals';
  if (/uri|url|http|https|ftp|domain|ip|mailto|suspicious/.test(context)) return 'network_signals';
  return 'provenance_signals';
}

function createBaseCategory(categoryKey) {
  return {
    rating: 'not_assessed',
    observations: [],
    interpretation: DEFAULT_INTERPRETATION[categoryKey] || 'No evidence was collected for this category.',
    combinationNotes: null
  };
}

export function generateCategorization({ findings = [], scanStatus = 'complete', confidence = 0.5, possiblyHidden = [], overallSummary = '' } = {}) {
  const categories = Object.fromEntries(CATEGORY_KEYS.map(key => [key, createBaseCategory(key)]));
  const grouped = new Map();

  for (const finding of findings) {
    const key = inferThreatCategory(finding);
    if (!CATEGORY_KEYS.includes(key)) continue;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push({
      findingId: finding.findingId || finding.id || `finding_${Math.random().toString(36).slice(2, 10)}`,
      text: sanitizeString(finding.text || finding.description || finding.summary || finding.observed || 'Threat signal observed.'),
      severity: normalizeSeverity(finding.severity || finding.rating || 'info')
    });
  }

  for (const [key, items] of grouped.entries()) {
    const category = categories[key];
    const rating = pickSeverity(items);
    category.rating = rating;
    category.observations = items.map(item => ({ findingId: item.findingId, text: item.text }));
    category.interpretation = `YARA, metadata, and file-context signals in this class suggest ${rating === 'none' ? 'no issue' : 'a ' + rating + ' threat level'}; treatment should remain evidence-based rather than speculative.`;
    if (items.length > 1) {
      category.combinationNotes = items.map(item => item.text).join(' ; ');
    }
  }

  const overallScore = CATEGORY_KEYS.reduce((total, key) => {
    const rating = categories[key].rating;
    return total + (rating === 'critical' ? 5 : rating === 'high' ? 4 : rating === 'medium' ? 3 : rating === 'low' ? 2 : rating === 'info' ? 1 : 0);
  }, 0);

  let overallRating = 'none';
  if (overallScore >= 18) overallRating = 'critical';
  else if (overallScore >= 12) overallRating = 'high';
  else if (overallScore >= 8) overallRating = 'medium';
  else if (overallScore >= 4) overallRating = 'low';
  else if (overallScore > 0) overallRating = 'info';

  if (scanStatus === 'incomplete' || scanStatus === 'failed') {
    overallRating = overallRating === 'none' ? 'info' : overallRating;
  }

  const summary = overallSummary || (
    scanStatus === 'incomplete'
      ? 'The file was only partially read or the document structure is incomplete; the computed threat level is conservative and should be treated as provisional.'
      : 'Threat classification is derived from metadata, YARA-style signals, and observed file indicators rather than the older forensic category schema.'
  );

  const finalConfidence = Number(Math.max(0, Math.min(1, Number(confidence) || 0.5)));

  return {
    scanStatus,
    confidence: finalConfidence,
    categories,
    possiblyHidden: Array.isArray(possiblyHidden) ? possiblyHidden : [],
    overall: {
      rating: overallRating,
      summary,
      isCleanClaim: false
    }
  };
}

export function validateCategorizationResult(result, findings = []) {
  const ids = new Set((findings || []).map(item => item.findingId || item.id));
  const validRatings = new Set(RATING_LEVELS);
  const errors = [];
  if (!result || typeof result !== 'object') return { valid: false, errors: ['Missing result'] };
  if (!Array.isArray(Object.keys(result.categories || {}))) return { valid: false, errors: ['Missing categories'] };
  for (const key of CATEGORY_KEYS) {
    const entry = result.categories[key];
    if (!entry || typeof entry !== 'object') {
      errors.push(`Missing category ${key}`);
      continue;
    }
    if (!validRatings.has(entry.rating)) errors.push(`Invalid rating for ${key}`);
    for (const observation of entry.observations || []) {
      if (observation && observation.findingId && !ids.has(observation.findingId)) {
        errors.push(`Unknown findingId in ${key}: ${observation.findingId}`);
      }
    }
  }
  if (result.scanStatus === 'incomplete' && result.overall.isCleanClaim) errors.push('Incomplete scans must not claim clean.');
  return { valid: errors.length === 0, errors };
}

export function normalizeForReport(result) {
  const normalized = JSON.parse(JSON.stringify(result));
  for (const key of CATEGORY_KEYS) {
    const item = normalized.categories[key];
    if (!item) normalized.categories[key] = createBaseCategory(key);
    item.observations = Array.isArray(item.observations) ? item.observations : [];
    item.interpretation = sanitizeString(item.interpretation || DEFAULT_INTERPRETATION[key]);
    item.combinationNotes = item.combinationNotes ? sanitizeString(item.combinationNotes) : null;
  }
  return normalized;
}
