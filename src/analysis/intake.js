// Evidence intake: file-identity verification and entropy measurement.
// Strategy 1 — File-type mismatch: an EXE or archive that is named/served
//   as a PDF is detected from its magic bytes and reported as a critical risk.
// Strategy 2 — Entropy analysis: documents (or streams) with very high
//   Shannon entropy are flagged as suspicious locked/packed/encrypted content.

import {
  detectFileSignature,
  detectEmbeddedSignatures,
  calculateShannonEntropy
} from './pdfParser.js';
import {
  createFinding,
  Severity,
  IndicatorCategory,
  DetectionMethod
} from './evidence.js';
import { RULES } from './rules.js';

export const HIGH_ENTROPY_THRESHOLD = 7.5;
export const EXTREME_ENTROPY_THRESHOLD = 7.8;
export const HIGH_ENTROPY_STREAM_THRESHOLD = 7.5;
const MIN_ENTROPY_SAMPLE_BYTES = 512;
const MIN_STREAM_SAMPLE_BYTES = 64;

export function inspectIntake(buffer, options = {}) {
  const findings = [];
  const signature = detectFileSignature(buffer);
  const documentEntropy = calculateShannonEntropy(buffer);
  const streamEntropy = measureStreamEntropy(buffer, options.text || '');

  const declaredName = typeof options.fileName === 'string' ? options.fileName : '';
  const declaredExtension = extractExtension(declaredName);
  const declaredAsPdf =
    declaredExtension === 'pdf' ||
    /pdf/i.test(String(options.declaredMimeType || '')) ||
    /pdf/i.test(declaredName);

  const info = {
    fileName: declaredName || null,
    declaredExtension: declaredExtension || null,
    declaredMimeType: options.declaredMimeType || null,
    declaredAsPdf,
    detectedFormat: signature.format,
    detectedLabel: signature.label,
    detectedMimeType: signature.mime || null,
    magicHex: signature.magicHex || '',
    isPdf: signature.isPdf,
    isExecutable: signature.isExecutable,
    isArchive: signature.isArchive,
    pdfOffset: typeof signature.pdfOffset === 'number' ? signature.pdfOffset : null,
    blockingFormat: signature.isExecutable || signature.isArchive,
    documentEntropy,
    entropyLevel: classifyEntropy(documentEntropy),
    ...streamEntropy
  };

  findings.push(...inspectFileTypeMismatch(buffer, info, signature));
  findings.push(...inspectEntropy(buffer, info));

  return { info, findings };
}

function inspectFileTypeMismatch(buffer, info, signature) {
  const findings = [];

  // Only identifiable binary containers take the mismatch path. Unrecognized
  // blobs fall through to the orchestrator's %PDF- header validation.
  if (signature.isExecutable || signature.isArchive) {
    const severity = info.declaredAsPdf ? Severity.CRITICAL : Severity.HIGH;
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
      description: info.declaredAsPdf
        ? `File declared as PDF but magic bytes identify ${signature.label}`
        : `Content is not a PDF document (detected ${signature.label})`,
      severity,
      evidenceReference: 'file header (magic-byte validation)',
      extractedValue: `${signature.magicHex} → ${signature.label}`,
      detectionRule: 'FILE_TYPE_MISMATCH',
      confidence: 0.98,
      explanation: info.declaredAsPdf
        ? `${RULES.FILE_TYPE_MISMATCH.explanation} Declared name/extension: ${info.fileName || 'unknown'}.`
        : 'The scanner was invoked on content whose magic bytes are not those of a PDF. Structural PDF inspection cannot apply.',
      limitations: [
        'Magic-byte identification is based on the leading bytes only',
        'Deep structural inspection was skipped because the content is not a PDF'
      ],
      detectionMethod: DetectionMethod.SIGNATURE,
      observed: true
    }));
    return findings;
  }

  if (info.pdfOffset && info.pdfOffset > 0) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
      description: `PDF header found at byte offset +${info.pdfOffset} after a leading preamble`,
      severity: Severity.INFO,
      evidenceReference: 'file header (magic-byte validation)',
      extractedValue: `preamble length ${info.pdfOffset} bytes`,
      detectionRule: 'PDF_PREAMBLE',
      confidence: 0.9,
      explanation: RULES.PDF_PREAMBLE.explanation,
      limitations: ['The preamble content is not identified by this scanner'],
      detectionMethod: DetectionMethod.SIGNATURE,
      observed: true
    }));
  }

  const embedded = detectEmbeddedSignatures(buffer);
  for (const hit of embedded) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.FILE_TYPE_MISMATCH,
      description: `${hit.label} signature embedded at byte offset ${hit.offset}`,
      severity: Severity.HIGH,
      evidenceReference: `byte offset ${hit.offset}`,
      extractedValue: hit.label,
      detectionRule: 'EMBEDDED_BINARY_SIGNATURE',
      confidence: 0.85,
      explanation: `${RULES.EMBEDDED_BINARY_SIGNATURE.explanation} Detected type: ${hit.label} at offset ${hit.offset}.`,
      limitations: [
        'Embedded signatures do not prove the payload is active or reachable',
        'Offset falls inside document bytes; reachability from PDF objects is not resolved'
      ],
      detectionMethod: DetectionMethod.SIGNATURE,
      observed: true
    }));
  }

  return findings;
}

function inspectEntropy(buffer, info) {
  const findings = [];
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (bytes.length < MIN_ENTROPY_SAMPLE_BYTES) return findings;

  if (info.documentEntropy >= EXTREME_ENTROPY_THRESHOLD) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.ENTROPY_ANOMALY,
      description: `Extreme document entropy (${info.documentEntropy.toFixed(2)} bits/byte) — content appears locked, packed, or encrypted`,
      severity: Severity.HIGH,
      evidenceReference: 'whole-document byte histogram',
      extractedValue: `${info.documentEntropy.toFixed(2)} bits/byte`,
      detectionRule: 'HIGH_ENTROPY',
      confidence: Math.min(0.97, 0.75 + (info.documentEntropy - EXTREME_ENTROPY_THRESHOLD)),
      explanation: RULES.HIGH_ENTROPY.explanation,
      limitations: [
        'Entropy is a statistical measure; encrypted or heavily compressed legitimate PDFs score similarly',
        'Static inspection cannot resolve the dense regions'
      ],
      detectionMethod: DetectionMethod.RAW_SCAN,
      observed: true
    }));
  } else if (info.documentEntropy >= HIGH_ENTROPY_THRESHOLD) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.ENTROPY_ANOMALY,
      description: `High document entropy (${info.documentEntropy.toFixed(2)} bits/byte) — suspicious locked or compressed content`,
      severity: Severity.MEDIUM,
      evidenceReference: 'whole-document byte histogram',
      extractedValue: `${info.documentEntropy.toFixed(2)} bits/byte`,
      detectionRule: 'HIGH_ENTROPY',
      confidence: 0.7 + (info.documentEntropy - HIGH_ENTROPY_THRESHOLD),
      explanation: RULES.HIGH_ENTROPY.explanation,
      limitations: [
        'Entropy is a statistical measure; image-heavy or compressed legitimate PDFs score similarly'
      ],
      detectionMethod: DetectionMethod.RAW_SCAN,
      observed: true
    }));
  }

  if (info.streamCount > 0 && info.highEntropyStreams > 0 && info.documentEntropy < HIGH_ENTROPY_THRESHOLD) {
    findings.push(createFinding({
      indicatorCategory: IndicatorCategory.ENTROPY_ANOMALY,
      description: `${info.highEntropyStreams} of ${info.streamCount} content streams exhibit high entropy (max ${info.maxStreamEntropy.toFixed(2)} bits/byte)`,
      severity: Severity.MEDIUM,
      evidenceReference: 'stream byte histograms',
      extractedValue: `max stream entropy ${info.maxStreamEntropy.toFixed(2)} bits/byte`,
      detectionRule: 'HIGH_ENTROPY',
      confidence: 0.7,
      explanation: `${RULES.HIGH_ENTROPY.explanation} Individual streams are denser than the document average, which can indicate selectively packed or encrypted objects.`,
      limitations: [
        'Stream boundaries are located by keyword; streams inside object streams are not reached',
        'Compressed streams are legitimately high-entropy'
      ],
      detectionMethod: DetectionMethod.RAW_SCAN,
      observed: true
    }));
  }

  return findings;
}

function measureStreamEntropy(buffer, text) {
  const results = { streamCount: 0, highEntropyStreams: 0, maxStreamEntropy: 0, averageStreamEntropy: 0 };
  if (!text || !buffer) return results;

  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const entropies = [];
  const streamRegex = /stream\r?\n/g;
  let match;
  while ((match = streamRegex.exec(text)) !== null) {
    const dataStart = streamRegex.lastIndex;
    const endIdx = text.indexOf('endstream', dataStart);
    if (endIdx === -1) break;
    if (endIdx - dataStart < MIN_STREAM_SAMPLE_BYTES) continue;
    const slice = bytes.subarray(dataStart, endIdx);
    const entropy = calculateShannonEntropy(slice);
    entropies.push(entropy);
    results.streamCount += 1;
    if (entropy > results.maxStreamEntropy) results.maxStreamEntropy = entropy;
    if (entropy >= HIGH_ENTROPY_STREAM_THRESHOLD) results.highEntropyStreams += 1;
  }
  results.maxStreamEntropy = Math.round(results.maxStreamEntropy * 100) / 100;
  results.averageStreamEntropy = entropies.length
    ? Math.round((entropies.reduce((sum, value) => sum + value, 0) / entropies.length) * 100) / 100
    : 0;
  return results;
}

function extractExtension(fileName) {
  const clean = String(fileName || '').split('?')[0].split('#')[0];
  const match = /\.([A-Za-z0-9]{1,10})$/.exec(clean);
  return match ? match[1].toLowerCase() : '';
}

export function classifyEntropy(entropy) {
  if (entropy >= EXTREME_ENTROPY_THRESHOLD) return 'extreme';
  if (entropy >= HIGH_ENTROPY_THRESHOLD) return 'high';
  if (entropy >= 6.0) return 'moderate';
  return 'low';
}
