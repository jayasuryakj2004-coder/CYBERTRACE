// Detection rule definitions with transparent weights.
// Weights are heuristics, NOT calibrated probabilities.
// A score of 80 does NOT mean 80% probability of malware.

import { Severity, IndicatorCategory, DetectionMethod } from './evidence.js';

export const RULE_VERSION = '2.0.0';

export const RiskBand = {
  NONE: 'none',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

export function riskBandForScore(score) {
  if (score <= 0) return RiskBand.NONE;
  if (score <= 20) return RiskBand.LOW;
  if (score <= 40) return RiskBand.MEDIUM;
  if (score <= 60) return RiskBand.HIGH;
  return RiskBand.CRITICAL;
}

export const RULES = {
  JAVASCRIPT_DETECTED: {
    id: 'R-JS-001',
    name: 'javascript_detected',
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    severity: Severity.HIGH,
    weight: 35,
    categoryCap: 45,
    description: 'JavaScript action present in document',
    explanation: 'JavaScript can execute when the document is opened in a compliant viewer. Static inspection only; behavior is not evaluated.'
  },
  OPEN_ACTION: {
    id: 'R-OA-001',
    name: 'open_action',
    indicatorCategory: IndicatorCategory.OPEN_ACTION,
    severity: Severity.MEDIUM,
    weight: 20,
    categoryCap: 25,
    description: 'OpenAction present in catalog',
    explanation: 'The document specifies an action to perform automatically on open. May be benign (e.g., navigation) or used to trigger scripts.'
  },
  ADDITIONAL_ACTION: {
    id: 'R-AA-001',
    name: 'additional_action',
    indicatorCategory: IndicatorCategory.ADDITIONAL_ACTION,
    severity: Severity.MEDIUM,
    weight: 18,
    categoryCap: 20,
    description: 'Additional Actions (/AA) present',
    explanation: 'Additional actions trigger on events such as page open, focus, or save. Context determines whether this is benign.'
  },
  LAUNCH_ACTION: {
    id: 'R-LA-001',
    name: 'launch_action',
    indicatorCategory: IndicatorCategory.LAUNCH_ACTION,
    severity: Severity.CRITICAL,
    weight: 40,
    categoryCap: 60,
    description: 'Launch action (/Launch) present',
    explanation: 'Launch actions can instruct the viewer to start an external application. Modern viewers typically block these, but presence is a strong indicator.'
  },
  EMBEDDED_FILE: {
    id: 'R-EF-001',
    name: 'embedded_file',
    indicatorCategory: IndicatorCategory.EMBEDDED_FILE,
    severity: Severity.LOW,
    weight: 12,
    categoryCap: 15,
    description: 'Embedded file attachment present',
    explanation: 'Embedded files are not extracted or executed. Attachments can carry secondary payloads; presence alone is not proof of maliciousness.'
  },
  URI_EXTERNAL: {
    id: 'R-URI-001',
    name: 'uri_external',
    indicatorCategory: IndicatorCategory.URI,
    severity: Severity.INFO,
    weight: 3,
    categoryCap: 10,
    description: 'External URI link present',
    explanation: 'Links are not followed automatically. External links are common in legitimate documents.'
  },
  SUSPICIOUS_URI: {
    id: 'R-URI-002',
    name: 'suspicious_uri',
    indicatorCategory: IndicatorCategory.SUSPICIOUS_URI,
    severity: Severity.HIGH,
    weight: 22,
    categoryCap: 30,
    description: 'URI matches suspicious pattern',
    explanation: 'URI matches a heuristic pattern (e.g., known-malicious scheme, IP-literal host, or suspicious TLD). This is a heuristic, not a threat-intelligence verdict.'
  },
  ENCRYPTED: {
    id: 'R-EN-001',
    name: 'encrypted_document',
    indicatorCategory: IndicatorCategory.ENCRYPTION,
    severity: Severity.LOW,
    weight: 5,
    categoryCap: 10,
    description: 'Document is encrypted',
    explanation: 'Encryption prevents full structural inspection. Encrypted documents are common (e.g., password-protected) and are not inherently malicious.'
  },
  INCREMENTAL_UPDATE: {
    id: 'R-IU-001',
    name: 'incremental_update',
    indicatorCategory: IndicatorCategory.INCREMENTAL_UPDATE,
    severity: Severity.LOW,
    weight: 4,
    categoryCap: 8,
    description: 'Incremental update detected (multiple revisions)',
    explanation: 'Multiple %%EOF markers indicate incremental saves. Legitimate editors produce these; they can also hide prior content.'
  },
  OBJECT_STREAM: {
    id: 'R-OS-001',
    name: 'object_stream',
    indicatorCategory: IndicatorCategory.STRUCTURAL_ANOMALY,
    severity: Severity.INFO,
    weight: 0,
    categoryCap: 0,
    description: 'Compressed object stream (/ObjStm) present',
    explanation: 'Object streams compress objects. Contents are not fully inspected by the raw scanner; PDF.js API is used where available.'
  },
  MISSING_METADATA: {
    id: 'R-MD-001',
    name: 'missing_metadata',
    indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
    severity: Severity.INFO,
    weight: 0,
    categoryCap: 0,
    description: 'Standard metadata fields absent',
    explanation: 'Missing metadata is not evidence of maliciousness. Many legitimate PDFs omit /Info fields.'
  },
  UNUSUAL_TIMESTAMP: {
    id: 'R-MD-002',
    name: 'unusual_timestamp',
    indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
    severity: Severity.LOW,
    weight: 3,
    categoryCap: 6,
    description: 'Timestamp outside plausible range',
    explanation: 'Creation/modification dates far in the past or future are unusual but not proof of maliciousness.'
  },
  FORM_PRESENT: {
    id: 'R-FM-001',
    name: 'form_present',
    indicatorCategory: IndicatorCategory.FORM,
    severity: Severity.INFO,
    weight: 0,
    categoryCap: 0,
    description: 'AcroForm present',
    explanation: 'Forms are common in legitimate documents. Form fields can host JavaScript, which is flagged separately.'
  },
  HIGH_ENTROPY: {
    id: 'R-EN-002',
    name: 'high_entropy',
    indicatorCategory: IndicatorCategory.ENTROPY_ANOMALY,
    severity: Severity.MEDIUM,
    weight: 18,
    categoryCap: 25,
    description: 'High Shannon byte entropy detected',
    explanation: 'High entropy indicates encrypted, compressed, or packed content that resists static inspection. Such content can hide malicious payloads or deliberately lock the document against analysis. Image-heavy or legitimately compressed PDFs also produce high entropy, so this is an indicator, not proof of maliciousness.'
  },
  FILE_TYPE_MISMATCH: {
    id: 'R-FT-001',
    name: 'file_type_mismatch',
    indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
    severity: Severity.CRITICAL,
    weight: 45,
    categoryCap: 60,
    description: 'Declared file type does not match magic-byte signature',
    explanation: 'The file was presented as a PDF but its magic bytes identify an executable or archive container. Masquerading executable or archive content as a PDF is a common malware delivery technique; viewers that trust the extension may be tricked into processing it.'
  },
  EMBEDDED_BINARY_SIGNATURE: {
    id: 'R-FT-002',
    name: 'embedded_binary_signature',
    indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
    severity: Severity.HIGH,
    weight: 25,
    categoryCap: 35,
    description: 'Executable or archive signature embedded inside document bytes',
    explanation: 'A PE, ZIP, RAR or 7-Zip signature was found inside the document bytes. Polyglot files can hide payloads from parsers that only inspect the outer container.'
  },
  PDF_PREAMBLE: {
    id: 'R-FT-003',
    name: 'pdf_preamble',
    indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
    severity: Severity.INFO,
    weight: 0,
    categoryCap: 0,
    description: 'PDF header preceded by non-PDF preamble bytes',
    explanation: 'The %PDF- header was found after a leading preamble. This is often harmless (BOM or junk prefix) but can also indicate a wrapper or polyglot file.'
  }
};

export function getRule(ruleName) {
  return RULES[ruleName] || null;
}

export function rulesByCategory() {
  const map = new Map();
  for (const rule of Object.values(RULES)) {
    if (!map.has(rule.indicatorCategory)) map.set(rule.indicatorCategory, []);
    map.get(rule.indicatorCategory).push(rule);
  }
  return map;
}

export const DEFAULT_RISK_CONFIG = {
  maxScore: 100,
  categoryCaps: Object.fromEntries(
    Object.values(RULES).map(r => [r.name, r.categoryCap])
  ),
  bands: {
    none: 0,
    low: 20,
    medium: 40,
    high: 60,
    critical: 100
  }
};