// Structural inspection of security-relevant PDF structures.
// Uses PDF-aware object parsing as the primary method.
// Raw keyword scanning is supplementary only and marked as such.

import {
  parsePdfObjects,
  hasKey,
  stripPdfStrings,
  extractStringValue,
  extractUri,
  extractReference,
  countEofMarkers,
  hasObjectStreams,
  isEncrypted,
  isLinearized,
  extractLinkAnnotations,
  extractJavaScriptObjects,
  extractEmbeddedFileObjects,
  extractActionObjects
} from './pdfParser.js';
import {
  createFinding,
  Severity,
  IndicatorCategory,
  DetectionMethod
} from './evidence.js';
import { RULES } from './rules.js';

const SUSPICIOUS_URI_PATTERNS = [
  { pattern: /javascript:/i, name: 'javascript_scheme', severity: Severity.HIGH },
  { pattern: /vbscript:/i, name: 'vbscript_scheme', severity: Severity.HIGH },
  { pattern: /file:/i, name: 'file_scheme', severity: Severity.MEDIUM },
  { pattern: /data:/i, name: 'data_scheme', severity: Severity.MEDIUM },
  { pattern: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i, name: 'ip_literal_host', severity: Severity.MEDIUM },
  { pattern: /\.(?:tk|ml|ga|cf)\b/i, name: 'abuse_tld', severity: Severity.LOW }
];

export function inspectStructure(text) {
  const findings = [];
  const objects = parsePdfObjects(text);
  const structuralInfo = {
    objectCount: objects.length,
    streamCount: (text.match(/\bstream\b/g) || []).length,
    eofCount: countEofMarkers(text),
    hasObjectStreams: hasObjectStreams(text),
    isEncrypted: isEncrypted(text),
    isLinearized: isLinearized(text)
  };

  findings.push(...inspectJavaScript(objects));
  findings.push(...inspectOpenAction(objects));
  findings.push(...inspectAdditionalActions(objects));
  findings.push(...inspectLaunchActions(objects));
  findings.push(...inspectEmbeddedFiles(objects));
  findings.push(...inspectUriLinks(objects));
  findings.push(...inspectStructuralAnomalies(text, structuralInfo));

  return { findings, structuralInfo, objects };
}

function inspectJavaScript(objects) {
  const findings = [];
  const jsObjects = extractJavaScriptObjects(objects);
  for (const js of jsObjects) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.JAVASCRIPT,
      description: 'JavaScript action detected in PDF object',
      severity: Severity.HIGH,
      evidenceReference: `object ${js.objectNumber}`,
      objectNumber: js.objectNumber,
      extractedValue: js.value,
      detectionRule: 'JAVASCRIPT_DETECTED',
      confidence: 0.95,
      explanation: RULES.JAVASCRIPT_DETECTED.explanation,
      limitations: [
        'Static inspection only; script behavior is not evaluated',
        'Scripts inside compressed object streams may not be visible to the raw scanner'
      ],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }
  return findings;
}

function inspectOpenAction(objects) {
  const findings = [];
  for (const obj of objects) {
    if (hasKey(obj.content, 'OpenAction')) {
      const ref = extractReference(obj.content, 'OpenAction');
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.OPEN_ACTION,
        description: 'OpenAction present in catalog',
        severity: Severity.MEDIUM,
        evidenceReference: ref ? `object ${obj.objNum} → object ${ref.objNum}` : `object ${obj.objNum}`,
        objectNumber: obj.objNum,
        extractedValue: ref ? `${ref.objNum} ${ref.gen} R` : 'inline',
        detectionRule: 'OPEN_ACTION',
        confidence: 0.9,
        explanation: RULES.OPEN_ACTION.explanation,
        limitations: ['Target action type is not fully resolved by the raw scanner'],
        detectionMethod: DetectionMethod.OBJECT_PARSER,
        observed: true
      }));
    }
  }
  return findings;
}

function inspectAdditionalActions(objects) {
  const findings = [];
  for (const obj of objects) {
    if (hasKey(obj.content, 'AA')) {
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.ADDITIONAL_ACTION,
        description: 'Additional Actions (/AA) dictionary present',
        severity: Severity.MEDIUM,
        evidenceReference: `object ${obj.objNum}`,
        objectNumber: obj.objNum,
        detectionRule: 'ADDITIONAL_ACTION',
        confidence: 0.85,
        explanation: RULES.ADDITIONAL_ACTION.explanation,
        limitations: ['Event triggers are not enumerated by the raw scanner'],
        detectionMethod: DetectionMethod.OBJECT_PARSER,
        observed: true
      }));
    }
  }
  return findings;
}

function inspectLaunchActions(objects) {
  const findings = [];
  const actions = extractActionObjects(objects);
  for (const action of actions) {
    if (action.actionType === 'Launch') {
      const f = extractStringValue(action.content, 'F');
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.LAUNCH_ACTION,
        description: 'Launch action (/Launch) detected',
        severity: Severity.CRITICAL,
        evidenceReference: `object ${action.objectNumber}`,
        objectNumber: action.objectNumber,
        extractedValue: f,
        detectionRule: 'LAUNCH_ACTION',
        confidence: 0.95,
        explanation: RULES.LAUNCH_ACTION.explanation,
        limitations: ['Modern viewers typically block launch actions; presence is an indicator, not proof of execution'],
        detectionMethod: DetectionMethod.OBJECT_PARSER,
        observed: true
      }));
    }
  }
  return findings;
}

function inspectEmbeddedFiles(objects) {
  const findings = [];
  const embedded = extractEmbeddedFileObjects(objects);
  for (const file of embedded) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.EMBEDDED_FILE,
      description: 'Embedded file attachment referenced',
      severity: Severity.LOW,
      evidenceReference: `object ${file.objectNumber}`,
      objectNumber: file.objectNumber,
      extractedValue: file.name,
      detectionRule: 'EMBEDDED_FILE',
      confidence: 0.85,
      explanation: RULES.EMBEDDED_FILE.explanation,
      limitations: ['Attachment contents are not extracted or inspected in this phase'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }
  return findings;
}

function inspectUriLinks(objects) {
  const findings = [];
  const links = extractLinkAnnotations(objects);
  const seenUris = new Set();
  for (const link of links) {
    if (!link.uri) continue;
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.URI,
      description: 'External URI link annotation present',
      severity: Severity.INFO,
      evidenceReference: `object ${link.objectNumber}`,
      objectNumber: link.objectNumber,
      extractedValue: link.uri,
      detectionRule: 'URI_EXTERNAL',
      confidence: 0.9,
      explanation: RULES.URI_EXTERNAL.explanation,
      limitations: ['Links are not followed automatically'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));

    const suspicious = matchSuspiciousUri(link.uri);
    if (suspicious && !seenUris.has(link.uri)) {
      seenUris.add(link.uri);
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.SUSPICIOUS_URI,
        description: `URI matches suspicious pattern: ${suspicious.name}`,
        severity: suspicious.severity,
        evidenceReference: `object ${link.objectNumber}`,
        objectNumber: link.objectNumber,
        extractedValue: link.uri,
        detectionRule: 'SUSPICIOUS_URI',
        confidence: 0.7,
        explanation: `${RULES.SUSPICIOUS_URI.explanation} Matched pattern: ${suspicious.name}.`,
        limitations: ['Heuristic pattern match; not a threat-intelligence verdict'],
        detectionMethod: DetectionMethod.OBJECT_PARSER,
        observed: true
      }));
    }
  }
  return findings;
}

function matchSuspiciousUri(uri) {
  for (const entry of SUSPICIOUS_URI_PATTERNS) {
    if (entry.pattern.test(uri)) {
      return { name: entry.name, severity: entry.severity };
    }
  }
  return null;
}

function inspectStructuralAnomalies(text, structuralInfo) {
  const findings = [];

  if (structuralInfo.isEncrypted) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.ENCRYPTION,
      description: 'Document is encrypted',
      severity: Severity.LOW,
      evidenceReference: 'document catalog',
      detectionRule: 'ENCRYPTED',
      confidence: 0.95,
      explanation: RULES.ENCRYPTED.explanation,
      limitations: ['Encrypted content cannot be fully inspected; structural scan is limited to unencrypted portions'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  if (structuralInfo.eofCount > 1) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.INCREMENTAL_UPDATE,
      description: `Incremental update detected (${structuralInfo.eofCount} %%EOF markers)`,
      severity: Severity.LOW,
      evidenceReference: 'document body',
      detectionRule: 'INCREMENTAL_UPDATE',
      confidence: 0.9,
      explanation: RULES.INCREMENTAL_UPDATE.explanation,
      limitations: ['Prior revision content is not recovered'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  if (structuralInfo.hasObjectStreams) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.STRUCTURAL_ANOMALY,
      description: 'Compressed object stream (/ObjStm) present',
      severity: Severity.INFO,
      evidenceReference: 'document body',
      detectionRule: 'OBJECT_STREAM',
      confidence: 0.9,
      explanation: RULES.OBJECT_STREAM.explanation,
      limitations: [
        'Objects inside /ObjStm are compressed and not visible to the raw scanner',
        'PDF.js API is used in the browser to inspect compressed objects'
      ],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  if (structuralInfo.isLinearized) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.STRUCTURAL_ANOMALY,
      description: 'Document is linearized (fast web view)',
      severity: Severity.INFO,
      evidenceReference: 'document header',
      detectionRule: 'OBJECT_STREAM',
      confidence: 0.9,
      explanation: 'Linearization optimizes web viewing. Not a security indicator.',
      limitations: [],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  return findings;
}

// Supplementary raw scan: used only to corroborate or flag areas the
// object parser could not reach (e.g., inside streams). Never the sole
// basis for a confirmed structural finding.
export function rawKeywordScan(text) {
  const keywords = ['/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch', '/EmbeddedFiles', '/EF', '/Filespec'];
  const hits = [];
  for (const kw of keywords) {
    const idx = text.indexOf(kw);
    if (idx !== -1) {
      hits.push({ keyword: kw, offset: idx });
    }
  }
  return hits;
}