// Analysis orchestrator.
// Coordinates metadata extraction, structural inspection, and risk scoring.
// Works in both Node.js (raw bytes only) and the browser (with PDF.js enhancement).

import { decodeLatin1 } from './pdfParser.js';
import { inspectStructure, rawKeywordScan } from './structural.js';
import { inspectIntake } from './intake.js';
import { extractMetadata, extractMetadataViaPdfJs } from './metadata.js';
import { computeRisk } from './risk.js';
import { deduplicateFindings, validateFinding } from './evidence.js';
import { ScanStatus } from '../shared/contracts.js';

export const AnalysisPhase = {
  METADATA: 'metadata',
  STRUCTURE: 'structure',
  RISK: 'risk',
  COMPLETE: 'complete'
};

export async function analyzePdf(buffer, options = {}) {
  const {
    onProgress = null,
    pdfDoc = null,
    maxSize = 100 * 1024 * 1024,
    signal = null,
    fileName = null,
    declaredMimeType = null
  } = options;

  const result = {
    status: ScanStatus.ANALYZING,
    progress: 0,
    metadata: null,
    structuralInfo: null,
    fileIdentity: null,
    findings: [],
    riskAssessment: null,
    limitations: [],
    error: null
  };

  try {
    if (signal?.aborted) {
      return { ...result, status: ScanStatus.INCOMPLETE, limitations: ['Analysis aborted'] };
    }

    if (!buffer || buffer.byteLength === 0) {
      throw new Error('Empty PDF buffer');
    }

    if (buffer.byteLength > maxSize) {
      throw new Error(`Document exceeds the ${maxSize} byte analysis limit`);
    }

    const text = decodeLatin1(buffer);

    // Intake phase: verify the declared file type against magic bytes and
    // measure byte entropy before any structural inspection.
    emitProgress(onProgress, 5, 'identity', 'Verifying file type and measuring entropy');
    const intake = inspectIntake(buffer, { text, fileName, declaredMimeType });
    result.fileIdentity = intake.info;
    result.findings.push(...intake.findings);
    result.progress = 10;

    // An executable or archive container named/served as a PDF is a critical
    // mismatch: report it and score it without attempting PDF-only parsing.
    if (intake.info.blockingFormat) {
      result.limitations.push(
        `Uploaded bytes are a ${intake.info.detectedLabel}, not a PDF document; structural PDF inspection was skipped`
      );
      emitProgress(onProgress, 90, 'risk', 'Computing risk assessment');
      const uniqueFindings = deduplicateFindings(result.findings);
      const invalid = uniqueFindings.filter(f => !validateFinding(f).valid);
      if (invalid.length > 0) {
        result.limitations.push(`${invalid.length} finding(s) failed validation and were excluded`);
      }
      result.findings = uniqueFindings.filter(f => validateFinding(f).valid);
      result.riskAssessment = computeRisk(result.findings);
      result.progress = 100;
      result.limitations.push(...collectLimitations(result.metadata, { entropy: result.fileIdentity }, result.findings));
      result.status = ScanStatus.COMPLETED;
      return result;
    }

    if (!text.startsWith('%PDF-')) {
      throw new Error('Not a valid PDF: missing %PDF- header');
    }

    emitProgress(onProgress, 10, 'metadata', 'Extracting metadata');
    const { metadata, metadataFindings } = extractMetadata(text);
    result.metadata = metadata;
    result.findings.push(...metadataFindings);
    result.progress = 25;

    if (signal?.aborted) {
      return { ...result, status: ScanStatus.INCOMPLETE, limitations: [...result.limitations, 'Analysis aborted'] };
    }

    emitProgress(onProgress, 40, 'structure', 'Inspecting document structure');
    const { findings: structuralFindings, structuralInfo } = inspectStructure(text);
    result.structuralInfo = { ...structuralInfo, entropy: result.fileIdentity };
    result.findings.push(...structuralFindings);
    result.progress = 60;

    // A structurally complete PDF must contain at least one %%EOF marker.
    // If absent, the document is truncated and the scan cannot be marked complete.
    const truncated = structuralInfo.eofCount === 0;
    if (truncated) {
      result.limitations.push('Document appears truncated: no %%EOF marker found; structural inspection is partial');
    }

    if (pdfDoc) {
      emitProgress(onProgress, 70, 'pdfjs', 'Cross-checking with PDF.js');
      try {
        const pdfJsFindings = await extractMetadataViaPdfJs(pdfDoc);
        result.findings.push(...pdfJsFindings);
      } catch (error) {
        result.limitations.push(`PDF.js cross-check failed: ${error.message}`);
      }
      result.progress = 80;
    }

    const rawHits = rawKeywordScan(text);
    if (rawHits.length > 0) {
      const parserFindings = new Set(result.findings.map(f => f.detectionRule));
      for (const hit of rawHits) {
        const ruleName = keywordToRule(hit.keyword);
        if (ruleName && !parserFindings.has(ruleName)) {
          result.limitations.push(
            `Keyword ${hit.keyword} found at offset ${hit.offset} but not confirmed by object parser (possibly inside a stream or string)`
          );
        }
      }
    }

    if (signal?.aborted) {
      return { ...result, status: ScanStatus.INCOMPLETE, limitations: [...result.limitations, 'Analysis aborted'] };
    }

    emitProgress(onProgress, 90, 'risk', 'Computing risk assessment');
    const uniqueFindings = deduplicateFindings(result.findings);
    const invalid = uniqueFindings.filter(f => !validateFinding(f).valid);
    if (invalid.length > 0) {
      result.limitations.push(`${invalid.length} finding(s) failed validation and were excluded`);
    }
    const validFindings = uniqueFindings.filter(f => validateFinding(f).valid);
    result.findings = validFindings;

    const risk = computeRisk(validFindings);
    result.riskAssessment = risk;
    result.progress = 100;

    result.limitations.push(...collectLimitations(result.metadata, result.structuralInfo, validFindings));

    // Truncated documents are reported as incomplete, never as clean/completed.
    result.status = truncated ? ScanStatus.INCOMPLETE : ScanStatus.COMPLETED;
    return result;

  } catch (error) {
    result.status = ScanStatus.FAILED;
    result.error = error.message;
    result.limitations.push(`Analysis failed: ${error.message}`);
    return result;
  }
}

function emitProgress(onProgress, progress, step, detail) {
  if (onProgress) {
    onProgress({ progress, step, detail });
  }
}

function keywordToRule(keyword) {
  const map = {
    '/JavaScript': 'JAVASCRIPT_DETECTED',
    '/JS': 'JAVASCRIPT_DETECTED',
    '/OpenAction': 'OPEN_ACTION',
    '/AA': 'ADDITIONAL_ACTION',
    '/Launch': 'LAUNCH_ACTION',
    '/EmbeddedFiles': 'EMBEDDED_FILE',
    '/EF': 'EMBEDDED_FILE',
    '/Filespec': 'EMBEDDED_FILE'
  };
  return map[keyword] || null;
}

function collectLimitations(metadata, structuralInfo, findings) {
  const limitations = [];
  const entropy = structuralInfo?.entropy || metadata?.fileIdentity;

  if (metadata?.isEncrypted) {
    limitations.push('Document is encrypted; structural inspection is limited to unencrypted portions');
  }
  if (entropy && entropy.documentEntropy >= 7.5) {
    limitations.push(`High entropy (${Number(entropy.documentEntropy).toFixed(2)} bits/byte); dense regions resist static inspection`);
  }
  if (structuralInfo?.hasObjectStreams) {
    limitations.push('Compressed object streams present; some objects may not be visible to the raw scanner');
  }
  if (metadata?.pageCount > 100) {
    limitations.push('Large document; content stream inspection is limited');
  }
  if (findings.some(f => f.indicatorCategory === 'javascript')) {
    limitations.push('JavaScript detected; static inspection only, behavior is not evaluated');
  }
  if (findings.some(f => f.indicatorCategory === 'embedded_file')) {
    limitations.push('Embedded files present; attachment contents are not extracted');
  }
  if (findings.some(f => f.indicatorCategory === 'suspicious_uri')) {
    limitations.push('Suspicious URI patterns are heuristic matches, not threat-intelligence verdicts');
  }

  return limitations;
}

export function isComplete(status) {
  return status === ScanStatus.COMPLETED;
}

export function isFailed(status) {
  return status === ScanStatus.FAILED;
}

export function isIncomplete(status) {
  return status === ScanStatus.INCOMPLETE;
}