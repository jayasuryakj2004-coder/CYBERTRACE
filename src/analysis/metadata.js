// Metadata and document integrity extraction.
// Parses the /Info dictionary and document catalog from raw bytes.
// In the browser, PDF.js getMetadata() is used as a cross-check.

import {
  parsePdfObjects,
  findTrailer,
  extractReference,
  extractStringValue,
  hasKey,
  stripPdfStrings,
  getPdfVersion,
  isLinearized,
  hasObjectStreams,
  isEncrypted
} from './pdfParser.js';
import {
  createFinding,
  Severity,
  IndicatorCategory,
  DetectionMethod
} from './evidence.js';
import { RULES } from './rules.js';

export function extractMetadata(text) {
  const objects = parsePdfObjects(text);
  const trailer = findTrailer(text);
  const infoRef = trailer ? extractReference(trailer, 'Info') : null;
  const infoObj = infoRef ? objects.find(o => o.objNum === infoRef.objNum) : null;

  const metadata = {
    pdfVersion: getPdfVersion(text),
    pageCount: countPages(objects),
    title: infoObj ? (extractStringValue(infoObj.content, 'Title') || '') : '',
    author: infoObj ? (extractStringValue(infoObj.content, 'Author') || '') : '',
    subject: infoObj ? (extractStringValue(infoObj.content, 'Subject') || '') : '',
    keywords: infoObj ? (extractStringValue(infoObj.content, 'Keywords') || '') : '',
    creator: infoObj ? (extractStringValue(infoObj.content, 'Creator') || '') : '',
    producer: infoObj ? (extractStringValue(infoObj.content, 'Producer') || '') : '',
    creationDate: infoObj ? (extractStringValue(infoObj.content, 'CreationDate') || '') : '',
    modificationDate: infoObj ? (extractStringValue(infoObj.content, 'ModDate') || '') : '',
    isLinearized: isLinearized(text),
    hasObjectStreams: hasObjectStreams(text),
    isEncrypted: isEncrypted(text),
    hasJavaScript: false,
    hasEmbeddedFiles: false,
    hasForms: false,
    hasSignatures: false,
    infoObjectNumber: infoObj ? infoObj.objNum : null,
    rawInfoPresent: !!infoObj
  };

  metadata.hasForms = objects.some(o => hasKey(o.content, 'AcroForm') || /\/Type\s*\/AcroForm\b/.test(stripPdfStrings(o.content)));
  metadata.hasSignatures = objects.some(o => hasKey(o.content, 'Sig') || /\/Type\s*\/Sig\b/.test(stripPdfStrings(o.content)));

  const metadataFindings = inspectMetadata(metadata, objects);
  return { metadata, metadataFindings };
}

function countPages(objects) {
  let count = 0;
  for (const obj of objects) {
    if (/\/Type\s*\/Pages\b/.test(stripPdfStrings(obj.content))) {
      const countMatch = /\/Count\s+(\d+)/.exec(stripPdfStrings(obj.content));
      if (countMatch) {
        count = Math.max(count, parseInt(countMatch[1], 10));
      }
    }
  }
  return count;
}

function inspectMetadata(metadata, objects) {
  const findings = [];

  const missingFields = [];
  if (!metadata.title) missingFields.push('title');
  if (!metadata.author) missingFields.push('author');
  if (!metadata.subject) missingFields.push('subject');
  if (!metadata.producer) missingFields.push('producer');

  if (missingFields.length > 0) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
      description: `Standard metadata fields absent: ${missingFields.join(', ')}`,
      severity: Severity.INFO,
      evidenceReference: metadata.infoObjectNumber ? `object ${metadata.infoObjectNumber}` : 'no /Info dictionary',
      objectNumber: metadata.infoObjectNumber,
      detectionRule: 'MISSING_METADATA',
      confidence: 0.9,
      explanation: RULES.MISSING_METADATA.explanation,
      limitations: ['Missing metadata is not evidence of maliciousness'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  const timestampFindings = checkTimestamps(metadata);
  findings.push(...timestampFindings);

  if (metadata.hasForms) {
    const formObj = objects.find(o => /\/Type\s*\/AcroForm\b/.test(stripPdfStrings(o.content)));
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.FORM,
      description: 'AcroForm present in document',
      severity: Severity.INFO,
      evidenceReference: formObj ? `object ${formObj.objNum}` : 'document catalog',
      objectNumber: formObj ? formObj.objNum : null,
      detectionRule: 'FORM_PRESENT',
      confidence: 0.9,
      explanation: RULES.FORM_PRESENT.explanation,
      limitations: ['Form fields can host JavaScript, which is flagged separately'],
      detectionMethod: DetectionMethod.OBJECT_PARSER,
      observed: true
    }));
  }

  return findings;
}

function checkTimestamps(metadata) {
  const findings = [];
  const now = Date.now();
  const plausibleMin = new Date('1990-01-01').getTime();
  const plausibleMax = now + 365 * 24 * 60 * 60 * 1000;

  const dates = [
    { label: 'CreationDate', value: metadata.creationDate },
    { label: 'ModDate', value: metadata.modificationDate }
  ];

  for (const date of dates) {
    if (!date.value) continue;
    const parsed = parsePdfDate(date.value);
    if (!parsed) continue;
    if (parsed < plausibleMin || parsed > plausibleMax) {
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
        description: `${date.label} outside plausible range`,
        severity: Severity.LOW,
        evidenceReference: metadata.infoObjectNumber ? `object ${metadata.infoObjectNumber}` : 'unknown',
        objectNumber: metadata.infoObjectNumber,
        extractedValue: date.value,
        detectionRule: 'UNUSUAL_TIMESTAMP',
        confidence: 0.7,
        explanation: RULES.UNUSUAL_TIMESTAMP.explanation,
        limitations: ['Unusual timestamps are not proof of maliciousness'],
        detectionMethod: DetectionMethod.OBJECT_PARSER,
        observed: true
      }));
    }
  }
  return findings;
}

export function parsePdfDate(dateStr) {
  const match = /D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/.exec(dateStr);
  if (!match) {
    const fallback = Date.parse(dateStr);
    return isNaN(fallback) ? null : fallback;
  }
  const [, y, mo, d, h, mi, s] = match;
  return new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}Z`).getTime();
}

// Cross-check metadata using PDF.js API (browser only).
// Returns additional findings from the parsed document.
export async function extractMetadataViaPdfJs(pdfDoc) {
  const findings = [];
  try {
    const meta = await pdfDoc.getMetadata();
    const info = meta?.info || {};
    const xmp = meta?.metadata || null;

    if (info && Object.keys(info).length === 0 && !xmp) {
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
        description: 'No /Info dictionary or XMP metadata present',
        severity: Severity.INFO,
        evidenceReference: 'document catalog',
        detectionRule: 'MISSING_METADATA',
        confidence: 0.9,
        explanation: RULES.MISSING_METADATA.explanation,
        limitations: ['Missing metadata is not evidence of maliciousness'],
        detectionMethod: DetectionMethod.PDFJS_API,
        observed: true
      }));
    }

    const jsActions = await pdfDoc.getJSActions();
    const scripts = Object.values(jsActions || {}).flat().filter(script => typeof script === 'string' && script.length > 0);
    if (scripts.length > 0) {
      findings.push(createFinding({
        indicatorCategory: IndicatorCategory.JAVASCRIPT,
        description: `JavaScript detected via PDF.js (${scripts.length} script(s))`,
        severity: Severity.HIGH,
        evidenceReference: 'document catalog / annotations',
        extractedValue: scripts[0],
        detectionRule: 'JAVASCRIPT_DETECTED',
        confidence: 0.98,
        explanation: RULES.JAVASCRIPT_DETECTED.explanation,
        limitations: ['Static inspection only; script behavior is not evaluated'],
        detectionMethod: DetectionMethod.PDFJS_API,
        observed: true
      }));
    }

    const attachments = await pdfDoc.getAttachments();
    if (attachments && Object.keys(attachments).length > 0) {
      for (const [name, att] of Object.entries(attachments)) {
        findings.push(createFinding({
          indicatorCategory: IndicatorCategory.EMBEDDED_FILE,
          description: `Embedded file attachment: ${name}`,
          severity: Severity.LOW,
          evidenceReference: 'document name tree',
          extractedValue: name,
          detectionRule: 'EMBEDDED_FILE',
          confidence: 0.95,
          explanation: RULES.EMBEDDED_FILE.explanation,
          limitations: ['Attachment contents are not extracted or inspected'],
          detectionMethod: DetectionMethod.PDFJS_API,
          observed: true
        }));
      }
    }
  } catch (error) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.METADATA_ANOMALY,
      description: `PDF.js metadata extraction failed: ${error.message}`,
      severity: Severity.INFO,
      evidenceReference: 'n/a',
      detectionRule: 'MISSING_METADATA',
      confidence: 0.5,
      explanation: 'PDF.js could not extract metadata. Raw scanner results are used instead.',
      limitations: ['Falling back to raw byte scanning'],
      detectionMethod: DetectionMethod.PDFJS_API,
      observed: false
    }));
  }
  return findings;
}