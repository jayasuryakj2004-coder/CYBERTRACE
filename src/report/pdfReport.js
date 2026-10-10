// CYBERTRACE — Digital Forensics Case Report generator.
// Professional print-ready layout: white background, dark navy headings,
// restrained blue accent, bordered tables, severity indicators, numbered
// sections, page numbers, report ID and confidentiality marking.

import { PDFDocument, StandardFonts, rgb } from '../../node_modules/pdf-lib/dist/pdf-lib.esm.min.js';
import { CATEGORY_KEYS } from '../categorizer/rules.js';
import { REPORT_THEME, ratingStyle, severityStyle } from './theme.js';

const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;
const MARGIN = 52;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const CONTENT_TOP = 78;
const CONTENT_BOTTOM = 62;

function defangText(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/https?:\/\//gi, 'hxxps://')
    .replace(/\./g, '[.]')
    .replace(/\s+/g, ' ')
    .slice(0, 500);
}

function sanitizePlainText(value) {
  return String(value ?? '')
    .split('')
    .filter((char) => {
      const code = char.charCodeAt(0);
      return (code >= 32 && code !== 127) || code === 9 || code === 10;
    })
    .join('')
    .replace(/\s+/g, ' ')
    .trim();
}

function hexToRgb(hexColor) {
  const normalized = String(hexColor || '#FFFFFF').replace('#', '');
  const safeHex = normalized.length === 3
    ? normalized.split('').map((char) => char + char).join('')
    : normalized;
  const numeric = Number.parseInt(safeHex, 16);
  if (Number.isNaN(numeric)) return { r: 1, g: 1, b: 1 };
  return {
    r: ((numeric >> 16) & 255) / 255,
    g: ((numeric >> 8) & 255) / 255,
    b: (numeric & 255) / 255
  };
}

function pdfColor(hexColor) {
  const { r, g, b } = hexToRgb(hexColor);
  return rgb(r, g, b);
}

function wrapText(text, maxWidth, font, size) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
      current = candidate;
    } else {
      if (current) lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines.length ? lines : [''];
}

function formatTimestamp(value) {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return sanitizePlainText(value);
  return `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
}

function formatBytes(size) {
  const value = Number(size);
  if (!Number.isFinite(value) || value < 0) return 'Not available';
  if (value === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  return `${(value / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

export async function generatePdfReport(categorization, fileMeta = {}) {
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const reportId = `CT-${Date.now().toString(36).toUpperCase()}`;
  const generatedAt = new Date();

  const pages = [];
  let page = addPage();
  let y = PAGE_HEIGHT - CONTENT_TOP;

  function addPage() {
    const next = pdfDoc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
    next.drawRectangle({ x: 0, y: 0, width: PAGE_WIDTH, height: PAGE_HEIGHT, color: pdfColor(REPORT_THEME.pageBg) });
    pages.push(next);
    return next;
  }

  function ensureSpace(needed) {
    if (y - needed < CONTENT_BOTTOM) {
      page = addPage();
      y = PAGE_HEIGHT - CONTENT_TOP;
    }
  }

  function drawSectionHeading(number, title) {
    ensureSpace(46);
    page.drawText(`${number}. ${title}`, { x: MARGIN, y: y - 12, size: 13, font: bold, color: pdfColor(REPORT_THEME.navy) });
    page.drawLine({ start: { x: MARGIN, y: y - 21 }, end: { x: PAGE_WIDTH - MARGIN, y: y - 21 }, thickness: 1.2, color: pdfColor(REPORT_THEME.accent) });
    y -= 36;
  }

  function drawSubHeading(title) {
    ensureSpace(34);
    page.drawText(title, { x: MARGIN, y: y - 10, size: 10.5, font: bold, color: pdfColor(REPORT_THEME.navy) });
    y -= 22;
  }

  function drawParagraph(text, options = {}) {
    const size = options.size || 9;
    const color = options.color || pdfColor(REPORT_THEME.body);
    const useFont = options.bold ? bold : font;
    const leading = options.leading || size + 4;
    const lines = wrapText(sanitizePlainText(text), CONTENT_WIDTH - (options.indent || 0), useFont, size);
    for (const line of lines) {
      ensureSpace(size + 6);
      page.drawText(line, { x: MARGIN + (options.indent || 0), y: y - size, size, font: useFont, color });
      y -= leading;
    }
    y -= options.gap !== undefined ? options.gap : 4;
  }

  function drawKeyValueTable(rows) {
    const labelWidth = 168;
    const valueWidth = CONTENT_WIDTH - labelWidth;
    for (const [label, value] of rows) {
      const labelLines = wrapText(sanitizePlainText(label), labelWidth - 12, bold, 8.5);
      const valueLines = wrapText(sanitizePlainText(value), valueWidth - 12, font, 8.5);
      const lineCount = Math.max(labelLines.length, valueLines.length);
      const rowHeight = lineCount * 11 + 10;
      ensureSpace(rowHeight);
      page.drawRectangle({
        x: MARGIN, y: y - rowHeight, width: CONTENT_WIDTH, height: rowHeight,
        color: pdfColor(REPORT_THEME.white),
        borderColor: pdfColor(REPORT_THEME.border), borderWidth: 0.75
      });
      labelLines.forEach((line, idx) => {
        page.drawText(line, { x: MARGIN + 8, y: y - 14 - idx * 11, size: 8.5, font: bold, color: pdfColor(REPORT_THEME.navy) });
      });
      valueLines.forEach((line, idx) => {
        page.drawText(line, { x: MARGIN + labelWidth + 8, y: y - 14 - idx * 11, size: 8.5, font, color: pdfColor(REPORT_THEME.body) });
      });
      y -= rowHeight;
    }
    y -= 10;
  }

  function drawTable(columns, rows, options = {}) {
    const widths = columns.map((column) => column.width * CONTENT_WIDTH);
    const headerHeight = 20;

    function drawHeader() {
      page.drawRectangle({
        x: MARGIN, y: y - headerHeight, width: CONTENT_WIDTH, height: headerHeight,
        color: pdfColor(REPORT_THEME.accentLight),
        borderColor: pdfColor(REPORT_THEME.accentBorder), borderWidth: 0.75
      });
      let cursor = MARGIN;
      columns.forEach((column, idx) => {
        page.drawText(column.label.toUpperCase(), {
          x: cursor + 6, y: y - headerHeight + 7, size: 7.5, font: bold,
          color: pdfColor(REPORT_THEME.navy)
        });
        cursor += widths[idx];
      });
      y -= headerHeight;
    }

    ensureSpace(headerHeight + 16);
    drawHeader();

    for (const row of rows) {
      const cellLines = row.map((cell, idx) =>
        wrapText(sanitizePlainText(cell), widths[idx] - 12, font, 8));
      const lineCount = Math.max(...cellLines.map((lines) => lines.length));
      const rowHeight = lineCount * 10.5 + 9;
      if (y - rowHeight < CONTENT_BOTTOM) {
        page = addPage();
        y = PAGE_HEIGHT - CONTENT_TOP;
        drawHeader();
      }
      const stripe = options.stripe !== false;
      page.drawRectangle({
        x: MARGIN, y: y - rowHeight, width: CONTENT_WIDTH, height: rowHeight,
        color: pdfColor(stripe && rows.indexOf(row) % 2 === 1 ? REPORT_THEME.rowAlt : REPORT_THEME.white),
        borderColor: pdfColor(REPORT_THEME.border), borderWidth: 0.5
      });
      let cursor = MARGIN;
      cellLines.forEach((lines, idx) => {
        lines.forEach((line, lineIdx) => {
          page.drawText(line, {
            x: cursor + 6, y: y - 13.5 - lineIdx * 10.5, size: 8, font,
            color: pdfColor(REPORT_THEME.body)
          });
        });
        cursor += widths[idx];
      });
      y -= rowHeight;
    }
    y -= 12;
  }

  function drawSeverityChip(label, severity, x, chipY) {
    const style = severityStyle(severity);
    const text = style.label;
    const chipWidth = Math.max(58, bold.widthOfTextAtSize(text, 7) + 14);
    const chipHeight = 13;
    page.drawRectangle({
      x, y: chipY, width: chipWidth, height: chipHeight,
      color: pdfColor(REPORT_THEME.white),
      borderColor: pdfColor(style.color), borderWidth: 1
    });
    page.drawText(text, { x: x + 7, y: chipY + 3.5, size: 7, font: bold, color: pdfColor(style.color) });
    return chipWidth;
  }

  function drawAlertBox(title, lines, style) {
    const wrapped = [];
    for (const line of lines) {
      wrapped.push(...wrapText(sanitizePlainText(line), CONTENT_WIDTH - 24, font, 8.5));
    }
    const boxHeight = 24 + wrapped.length * 11 + 8;
    ensureSpace(boxHeight);
    page.drawRectangle({
      x: MARGIN, y: y - boxHeight, width: CONTENT_WIDTH, height: boxHeight,
      color: pdfColor(style.bg), borderColor: pdfColor(style.border), borderWidth: 1
    });
    page.drawText(title, { x: MARGIN + 12, y: y - 16, size: 9, font: bold, color: pdfColor(style.text) });
    wrapped.forEach((line, idx) => {
      page.drawText(line, { x: MARGIN + 12, y: y - 30 - idx * 11, size: 8.5, font, color: pdfColor(style.text) });
    });
    y -= boxHeight + 10;
  }

  // ---------------- Cover page ----------------
  page.drawRectangle({ x: 0, y: PAGE_HEIGHT - 190, width: PAGE_WIDTH, height: 190, color: pdfColor(REPORT_THEME.navy) });
  page.drawRectangle({ x: 0, y: PAGE_HEIGHT - 196, width: PAGE_WIDTH, height: 6, color: pdfColor(REPORT_THEME.accent) });
  page.drawText('CYBERTRACE', { x: MARGIN, y: PAGE_HEIGHT - 92, size: 30, font: bold, color: pdfColor(REPORT_THEME.white) });
  page.drawText('DIGITAL FORENSICS CASE REPORT', { x: MARGIN, y: PAGE_HEIGHT - 118, size: 15, font: bold, color: pdfColor(REPORT_THEME.accentBorder) });
  page.drawText('Forensic PDF Analysis · Evidence Documentation', { x: MARGIN, y: PAGE_HEIGHT - 142, size: 10, font, color: pdfColor('#B9C6DA') });
  page.drawText(`Report ID: ${reportId}`, { x: MARGIN, y: PAGE_HEIGHT - 168, size: 10, font: bold, color: pdfColor(REPORT_THEME.white) });

  const overall = categorization.overall || {};
  const chip = ratingStyle(overall.rating || 'not_assessed');
  let coverY = PAGE_HEIGHT - 240;
  page.drawText('EVIDENCE SUMMARY', { x: MARGIN, y: coverY, size: 11, font: bold, color: pdfColor(REPORT_THEME.navy) });
  coverY -= 14;
  const summaryRows = [
    ['Report ID', reportId],
    ['Report generated', formatTimestamp(generatedAt.toISOString())],
    ['Evidence file', fileMeta.fileName || 'Not available'],
    ['Evidence size', formatBytes(fileMeta.size)],
    ['SHA-256', fileMeta.sha256 && fileMeta.sha256 !== 'unknown' ? fileMeta.sha256 : 'Not available'],
    ['Analysis status', sanitizePlainText(categorization.scanStatus || 'Not available')],
    ['Analysis mode', sanitizePlainText(fileMeta.mode || 'Rules only')],
    ['Overall threat rating', chip.label]
  ];
  for (const [label, value] of summaryRows) {
    ensureSpace(26);
    page.drawText(label.toUpperCase(), { x: MARGIN, y: coverY - 8, size: 8, font: bold, color: pdfColor(REPORT_THEME.muted) });
    page.drawText(sanitizePlainText(value), { x: MARGIN + 150, y: coverY - 8, size: 9, font: bold, color: pdfColor(REPORT_THEME.charcoal) });
    page.drawLine({ start: { x: MARGIN, y: coverY - 16 }, end: { x: PAGE_WIDTH - MARGIN, y: coverY - 16 }, thickness: 0.5, color: pdfColor(REPORT_THEME.border) });
    coverY -= 28;
  }
  ensureSpace(40);
  page.drawRectangle({
    x: MARGIN, y: coverY - 34, width: 210, height: 24,
    color: pdfColor(chip.bg)
  });
  page.drawText(`OVERALL: ${chip.label}`, { x: MARGIN + 14, y: coverY - 26, size: 10, font: bold, color: pdfColor(chip.text) });

  ensureSpace(70);
  page.drawText('CONFIDENTIAL — FORENSIC WORK PRODUCT', {
    x: MARGIN, y: 118, size: 9, font: bold, color: pdfColor(REPORT_THEME.accent)
  });
  page.drawText('This report is generated from static, deterministic inspection of the uploaded evidence bytes.', {
    x: MARGIN, y: 102, size: 8, font, color: pdfColor(REPORT_THEME.muted)
  });
  page.drawText('It documents observations and indicators only; it is not a verdict of maliciousness and does', {
    x: MARGIN, y: 90, size: 8, font, color: pdfColor(REPORT_THEME.muted)
  });
  page.drawText('not replace analysis by a qualified examiner. Static inspection does not evaluate executed behavior.', {
    x: MARGIN, y: 78, size: 8, font, color: pdfColor(REPORT_THEME.muted)
  });

  page = addPage();
  y = PAGE_HEIGHT - CONTENT_TOP;

  // ---------------- Section 1: Case and Examiner Information ----------------
  drawSectionHeading(1, 'Case and Examiner Information');
  drawKeyValueTable([
    ['Case name / number', 'Not provided — automated analysis report'],
    ['Investigation title', 'Forensic PDF analysis (automated)'],
    ['Investigator / examiner', 'Not provided'],
    ['Investigator role / title', 'Not applicable'],
    ['Organization / laboratory', 'Not provided'],
    ['Analysis start date/time', formatTimestamp(fileMeta.timestamp)],
    ['Analysis completion date/time', formatTimestamp(fileMeta.completedAt)],
    ['Report generation date/time', formatTimestamp(generatedAt.toISOString())],
    ['Application name', 'CyberTrace'],
    ['Application version', '3.0.0'],
    ['Analysis engine version', 'Rule engine 2.0.0'],
    ['Operating system environment', 'Browser extension runtime (host OS not reliably available)'],
    ['Report ID', reportId],
    ['Analysis ID', sanitizePlainText(fileMeta.scanId || 'Not available')],
    ['Report status', sanitizePlainText(categorization.scanStatus || 'Not available')]
  ]);

  // ---------------- Section 2: Evidence Source Description ----------------
  drawSectionHeading(2, 'Evidence Source Description');
  const identity = fileMeta.fileIdentity || {};
  drawKeyValueTable([
    ['Evidence item number', 'E-001'],
    ['Original file name', fileMeta.fileName || 'Not available'],
    ['Original file extension', identity.declaredExtension ? `.${identity.declaredExtension}` : 'Not available'],
    ['Detected file type', identity.detectedLabel || 'Not available'],
    ['MIME type (declared)', identity.declaredMimeType || 'Not available'],
    ['MIME type (detected)', identity.detectedMimeType || 'Not available'],
    ['File size', formatBytes(fileMeta.size)],
    ['File creation timestamp', 'Not available'],
    ['File modification timestamp', 'Not available'],
    ['Acquisition / upload timestamp', formatTimestamp(fileMeta.timestamp)],
    ['Source reference', fileMeta.sourceType === 'remote' ? defangText(fileMeta.sourceUrl || '') || 'Not available' : 'Local upload'],
    ['Evidence source type', fileMeta.sourceType === 'remote' ? 'Remote document (HTTP(S))' : 'Locally uploaded file'],
    ['Analysis status', sanitizePlainText(categorization.scanStatus || 'Not available')],
    ['MD5 hash', 'Not calculated'],
    ['SHA-256 hash', fileMeta.sha256 && fileMeta.sha256 !== 'unknown' ? fileMeta.sha256 : 'Not available'],
    ['File signature / magic-byte validation', identity.magicHex ? `Magic bytes ${identity.magicHex} -> ${identity.detectedLabel}` : 'Not available'],
    ['Declared extension vs detected type', identity.blockingFormat ? `MISMATCH: presented as PDF, detected as ${identity.detectedLabel}` : 'Consistent with PDF'],
    ['File-type mismatch status', identity.blockingFormat ? 'MISMATCH DETECTED' : 'No mismatch'],
    ['Embedded file count', 'Not extracted in this phase'],
    ['Encryption / password protection', identity.isPdf ? 'Not determined by static scan' : 'Not applicable (content is not a PDF)'],
    ['Write-blocker information', 'Not applicable to uploaded-file analysis'],
    ['Drive make / model / capacity / serial', 'Not applicable to uploaded-file analysis'],
    ['Evidence acquisition notes', 'Evidence bytes were received from the browser upload/fetch pipeline and hashed at intake.'],
    ['Evidence limitations', 'Static inspection only; script behavior, embedded payloads, and compressed streams are not executed or fully resolved.']
  ]);
  if (Number.isFinite(identity.documentEntropy)) {
    drawKeyValueTable([
      ['Shannon entropy (whole document)', `${Number(identity.documentEntropy).toFixed(2)} bits/byte (${sanitizePlainText(identity.entropyLevel || 'low')})`],
      ['Content streams scanned', String(identity.streamCount ?? 0)],
      ['High-entropy streams (>= 7.5 bits/byte)', String(identity.highEntropyStreams ?? 0)],
      ['Maximum stream entropy', identity.streamCount ? `${Number(identity.maxStreamEntropy || 0).toFixed(2)} bits/byte` : 'Not available']
    ]);
  }

  // ---------------- Section 3: Ingest Modules Executed ----------------
  drawSectionHeading(3, 'Ingest Modules Executed');
  const allFindings = CATEGORY_KEYS.flatMap((key) => categorization.categories?.[key]?.observations || []);
  const hasFinding = (predicate) => allFindings.some(predicate);
  const findingsByRule = new Map();
  for (const key of CATEGORY_KEYS) {
    for (const observation of categorization.categories?.[key]?.observations || []) {
      const list = findingsByRule.get(key) || [];
      list.push(observation);
      findingsByRule.set(key, list);
    }
  }
  const moduleRows = [
    ['File Type Identification', 'Identifies the evidence format from content structure', 'Completed', identity.detectedLabel || 'Not available'],
    ['File Signature / Magic-Byte Validation', 'Validates leading bytes against known format signatures', identity.blockingFormat ? 'Completed with Findings' : 'Completed', identity.blockingFormat ? 'Declared PDF, detected non-PDF container' : 'Signature consistent'],
    ['MIME Type Verification', 'Compares declared MIME type with detected format', 'Completed', `${identity.declaredMimeType || 'unknown'} vs ${identity.detectedMimeType || 'unknown'}`],
    ['File Hash Calculation', 'SHA-256 integrity hash over the original evidence bytes', fileMeta.sha256 && fileMeta.sha256 !== 'unknown' ? 'Completed' : 'Failed', fileMeta.sha256 && fileMeta.sha256 !== 'unknown' ? 'SHA-256 recorded in Section 2' : 'Hash unavailable'],
    ['Known-Hash Lookup', 'Comparison against NSRL / known-file databases', 'Not Implemented', 'No hash database is integrated with this scanner'],
    ['Keyword Search', 'Raw keyword scan for security-relevant PDF dictionary keys', 'Completed', 'Supplementary corroboration only'],
    ['Metadata Extraction', 'Parses the Info dictionary, catalog flags, dates, and page count', findingsByRule.get('metadata_signals') ? 'Completed with Findings' : 'Completed', `${findingsByRule.get('metadata_signals')?.length || 0} observation(s)`],
    ['PDF Structural Analysis', 'Object parsing of actions, scripts, annotations, and revisions', identity.blockingFormat ? 'Skipped' : 'Completed', identity.blockingFormat ? 'Content is not a PDF' : `${allFindings.length} observation(s) across all modules`],
    ['Embedded File Detection', 'Detects embedded file attachments and filespec references', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['JavaScript Detection', 'Detects JavaScript and JS action objects', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['Suspicious URL / URI Analysis', 'Link annotation and URI pattern analysis', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['Launch Action Detection', 'Detects actions that target external applications', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['Form and Annotation Analysis', 'AcroForm and annotation inventory', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['Encryption Detection', 'Detects encryption references in the document trailer and catalog', identity.blockingFormat ? 'Skipped' : 'Completed', 'See Section 4 observations'],
    ['Entropy Analysis', 'Shannon byte entropy over document and content streams', 'Completed with Findings', `${Number(identity.documentEntropy || 0).toFixed(2)} bits/byte document; ${identity.highEntropyStreams || 0} high-entropy stream(s)`],
    ['AI-Assisted Findings Explanation', 'Optional model interpretation grounded in scanner evidence', fileMeta.aiAnalysis ? 'Completed' : 'Unavailable', fileMeta.aiAnalysis ? 'See Section 4.4' : 'AI service not used for this export'],
    ['Report Generation', 'Assembles this case report from recorded findings', 'Completed', `Report ID ${reportId}`]
  ];
  drawTable(
    [
      { label: 'Module', width: 0.26 },
      { label: 'Description', width: 0.30 },
      { label: 'Status', width: 0.17 },
      { label: 'Findings / Notes', width: 0.27 }
    ],
    moduleRows
  );

  // ---------------- Section 4: Summary of Key Artifacts and Findings ----------------
  drawSectionHeading(4, 'Summary of Key Artifacts and Findings');

  drawSubHeading('4.1 Executive Summary');
  const findingCount = allFindings.length;
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const key of CATEGORY_KEYS) {
    for (const observation of categorization.categories?.[key]?.observations || []) {
      const level = (observation.severity || 'info').toLowerCase();
      if (level in severityCounts) severityCounts[level] += 1;
    }
  }
  drawParagraph(`Evidence item analyzed: ${fileMeta.fileName || 'Not available'} (${formatBytes(fileMeta.size)}).`, { gap: 2 });
  drawParagraph(`Overall analysis result: ${sanitizePlainText(categorization.scanStatus || 'unknown')} with overall threat rating ${chip.label} at ${Math.round(Number(categorization.confidence || 0) * 100)}% confidence.`, { gap: 2 });
  drawParagraph(`Findings by severity: ${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium, ${severityCounts.low} low, ${severityCounts.info} informational (${findingCount} total observations).`, { gap: 2 });
  drawParagraph(overall.summary || 'No summary was recorded for this analysis.', { gap: 8 });

  if (categorization.scanStatus === 'incomplete' || categorization.scanStatus === 'failed') {
    drawAlertBox(
      'INCOMPLETE SCAN - THIS FILE CANNOT BE CALLED CLEAN',
      [
        'The document was only partially read or the scan failed; the computed threat level is conservative and provisional.',
        ...(Array.isArray(categorization.possiblyHidden) ? categorization.possiblyHidden : [])
      ],
      { bg: REPORT_THEME.alertBg, border: REPORT_THEME.alertBorder, text: REPORT_THEME.alertText }
    );
  }
  if (Array.isArray(categorization.possiblyHidden) && categorization.possiblyHidden.length > 0) {
    drawAlertBox('Possible hidden file content after the last EOF', categorization.possiblyHidden, {
      bg: REPORT_THEME.warnBg, border: REPORT_THEME.warnBorder, text: REPORT_THEME.warnText
    });
  }

  drawSubHeading('4.2 Risk Assessment');
  const riskRows = CATEGORY_KEYS.map((key) => {
    const item = categorization.categories?.[key];
    const observations = item?.observations || [];
    const worst = observations.map((o) => o.severity || 'info')
      .sort((a, b) => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 }[b] - { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[a]))[0];
    return [
      key.replace(/_/g, ' '),
      item?.rating === 'not_assessed' ? 'NOT ASSESSED' : (item?.rating || 'none').toUpperCase(),
      worst ? worst.toUpperCase() : 'NONE',
      String(observations.length),
      sanitizePlainText(item?.interpretation || 'No evidence was collected for this category.')
    ];
  });
  drawTable(
    [
      { label: 'Signal category', width: 0.22 },
      { label: 'Rating', width: 0.10 },
      { label: 'Severity', width: 0.10 },
      { label: 'Count', width: 0.06 },
      { label: 'Assessment basis', width: 0.52 }
    ],
    riskRows
  );

  drawSubHeading('4.3 Key Artifacts and Observations');
  const observationRows = [];
  let observationIndex = 1;
  for (const key of CATEGORY_KEYS) {
    for (const observation of categorization.categories?.[key]?.observations || []) {
      observationRows.push([
        String(observationIndex++),
        key.replace(/_/g, ' '),
        sanitizePlainText(observation.text || 'No observation text recorded'),
        (observation.severity || 'info').toUpperCase(),
        sanitizePlainText(fileMeta.scanId || reportId)
      ]);
    }
  }
  if (observationRows.length) {
    drawTable(
      [
        { label: 'ID', width: 0.05 },
        { label: 'Category', width: 0.22 },
        { label: 'Observed evidence', width: 0.49 },
        { label: 'Severity', width: 0.11 },
        { label: 'Source', width: 0.13 }
      ],
      observationRows
    );
  } else {
    drawParagraph('No artifacts or observations were recorded by the executed modules. Absence of findings is not a guarantee of safety.', { gap: 8 });
  }

  if (fileMeta.limitations && fileMeta.limitations.length) {
    drawSubHeading('4.4 Analysis Limitations');
    for (const limitation of fileMeta.limitations.slice(0, 12)) {
      drawParagraph(`• ${limitation}`, { indent: 10, gap: 2 });
    }
    y -= 4;
  }

  if (fileMeta.aiAnalysis) {
    drawSubHeading('4.5 AI-Assisted Interpretation');
    drawParagraph('The following interpretation is AI-generated, grounded only in the scanner evidence above, and is labeled as interpretation — it does not alter the scanner risk score and is not a verdict.', { color: pdfColor(REPORT_THEME.muted), size: 8.5, gap: 6 });
    if (fileMeta.aiAnalysis.summary) {
      drawParagraph(fileMeta.aiAnalysis.summary, { gap: 6 });
    }
    if (Array.isArray(fileMeta.aiAnalysis.findings_explanation) && fileMeta.aiAnalysis.findings_explanation.length) {
      drawParagraph('Finding explanations:', { bold: true, gap: 2 });
      for (const item of fileMeta.aiAnalysis.findings_explanation) {
        drawParagraph(`• ${sanitizePlainText(item.finding_id || '')}: ${sanitizePlainText(item.explanation || '')}`, { indent: 10, gap: 2 });
      }
      y -= 4;
    }
    if (Array.isArray(fileMeta.aiAnalysis.possible_scenarios) && fileMeta.aiAnalysis.possible_scenarios.length) {
      drawParagraph('Possible scenarios:', { bold: true, gap: 2 });
      for (const scenario of fileMeta.aiAnalysis.possible_scenarios) {
        drawParagraph(`• ${scenario}`, { indent: 10, gap: 2 });
      }
      y -= 4;
    }
    if (Array.isArray(fileMeta.aiAnalysis.recommended_actions) && fileMeta.aiAnalysis.recommended_actions.length) {
      drawParagraph('AI-recommended actions:', { bold: true, gap: 2 });
      for (const action of fileMeta.aiAnalysis.recommended_actions) {
        drawParagraph(`• ${action}`, { indent: 10, gap: 2 });
      }
      y -= 4;
    }
    if (Array.isArray(fileMeta.aiAnalysis.limitations) && fileMeta.aiAnalysis.limitations.length) {
      drawParagraph('AI limitations:', { bold: true, gap: 2 });
      for (const item of fileMeta.aiAnalysis.limitations) {
        drawParagraph(`• ${item}`, { indent: 10, gap: 2 });
      }
      y -= 4;
    }
  }

  // ---------------- Section 5: Conclusion and Recommendations ----------------
  drawSectionHeading(5, 'Conclusion and Recommendations');

  drawSubHeading('5.1 Case Summary');
  const confirmed = observationRows.length ? `${observationRows.length} observation(s) were confirmed by the deterministic scanner modules.` : 'No indicators were confirmed by the deterministic scanner modules.';
  drawParagraph(confirmed, { gap: 2 });
  if (severityCounts.critical || severityCounts.high) {
    drawParagraph(`Confirmed scanner observations include ${severityCounts.critical} critical and ${severityCounts.high} high severity indicator(s). These are structural observations, not proof of executed malicious behavior.`, { gap: 2 });
  }
  if (identity.blockingFormat) {
    drawParagraph(`File-type mismatch: the evidence was presented as a PDF but its magic bytes identify ${identity.detectedLabel}. This is a strong indicator of masqueraded executable or archive content.`, { gap: 2 });
  }
  if (Number.isFinite(identity.documentEntropy) && identity.documentEntropy >= 7.5) {
    drawParagraph(`High entropy (${Number(identity.documentEntropy).toFixed(2)} bits/byte) indicates locked, packed, or encrypted content that resists static inspection.`, { gap: 2 });
  }
  if (fileMeta.aiAnalysis) {
    drawParagraph('AI-generated interpretations, where present in Section 4.5, are labeled and grounded in scanner evidence only.', { gap: 2 });
  }
  drawParagraph('Unresolved questions and limitations: static inspection cannot evaluate script behavior, resolve compressed object streams, or extract embedded payloads. Deleted-file recovery, browser history, communication artifacts, and USB/device history were not examined because the current evidence source does not provide the required artifacts.', { gap: 8 });

  drawSubHeading('5.2 Recommended Actions');
  const recommendations = [];
  if (identity.blockingFormat) {
    recommendations.push('Do not open the file outside an isolated, non-networked sandbox; it is not a PDF despite its name or extension.');
    recommendations.push('Preserve the original bytes and SHA-256 hash; escalate to a qualified examiner for dynamic analysis.');
  }
  if (Number.isFinite(identity.documentEntropy) && identity.documentEntropy >= 7.5) {
    recommendations.push('Treat dense regions as opaque: perform dynamic analysis in a sandbox and verify the document source before any handling.');
  }
  if (hasFinding((o) => /javascript|script/i.test(o.text))) {
    recommendations.push('Review detected scripts or actions in a controlled environment before opening the document in a standard viewer.');
  }
  if (hasFinding((o) => /uri|url|http|ip/i.test(o.text))) {
    recommendations.push('Investigate detected external destinations using approved, isolated analysis methods without opening them directly.');
  }
  if (hasFinding((o) => /launch|executable|archive|embedded/i.test(o.text))) {
    recommendations.push('Review embedded objects, launch targets, and attachments in a controlled environment.');
  }
  if (categorization.scanStatus === 'incomplete' || categorization.scanStatus === 'failed') {
    recommendations.push('The scan was incomplete or failed; repeat the analysis with an additional parser or specialist review before drawing conclusions.');
  }
  recommendations.push('Avoid opening or executing the content until review is complete.');
  recommendations.push('Preserve the original evidence and its calculated SHA-256 hash for chain of custody.');
  if (!recommendations.length) recommendations.push('No indicator was detected by the configured checks; this is not a guarantee of safety.');
  for (const recommendation of recommendations.slice(0, 12)) {
    drawParagraph(`• ${recommendation}`, { indent: 10, gap: 2 });
  }
  y -= 4;

  drawSubHeading('5.3 Chain of Custody and Integrity');
  drawKeyValueTable([
    ['Evidence item ID', 'E-001'],
    ['Evidence source', fileMeta.sourceType === 'remote' ? 'Remote document (HTTP(S))' : 'Locally uploaded file'],
    ['Acquisition timestamp', formatTimestamp(fileMeta.timestamp)],
    ['Initial SHA-256 hash (at intake)', fileMeta.sha256 && fileMeta.sha256 !== 'unknown' ? fileMeta.sha256 : 'Not available'],
    ['Post-analysis SHA-256 hash', 'Not recalculated — the same retained evidence bytes were analyzed'],
    ['Hash comparison result', 'Pre- and post-analysis integrity verification could not be established from the available records; a single SHA-256 was calculated over the original bytes at intake.'],
    ['Evidence handling notes', 'Bytes were received from the browser pipeline, hashed at intake, and analyzed without modification. A hash match verifies byte-level consistency only; it does not prove the file is benign.']
  ]);

  drawSubHeading('5.4 Exported Report Reference');
  drawKeyValueTable([
    ['Report ID', reportId],
    ['Report file name', `${sanitizePlainText(fileMeta.fileName || 'cybertrace-report').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60) || 'cybertrace-report'}_${reportId}.pdf`],
    ['Export timestamp', formatTimestamp(generatedAt.toISOString())],
    ['Report format', 'PDF (A4)'],
    ['Application version', 'CyberTrace 3.0.0 · rule engine 2.0.0'],
    ['Associated analysis ID', sanitizePlainText(fileMeta.scanId || 'Not available')],
    ['Export status', 'Completed']
  ]);

  // ---------------- Header and footer on every page ----------------
  pages.forEach((target, index) => {
    const isCover = index === 0;
    if (!isCover) {
      target.drawText('CYBERTRACE — DIGITAL FORENSICS CASE REPORT', {
        x: MARGIN, y: PAGE_HEIGHT - 40, size: 7.5, font: bold, color: pdfColor(REPORT_THEME.navy)
      });
      target.drawText(`Report ID: ${reportId}`, {
        x: PAGE_WIDTH - MARGIN - 150, y: PAGE_HEIGHT - 40, size: 7.5, font, color: pdfColor(REPORT_THEME.muted)
      });
      target.drawLine({ start: { x: MARGIN, y: PAGE_HEIGHT - 48 }, end: { x: PAGE_WIDTH - MARGIN, y: PAGE_HEIGHT - 48 }, thickness: 0.75, color: pdfColor(REPORT_THEME.accent) });
    }
    target.drawLine({ start: { x: MARGIN, y: 48 }, end: { x: PAGE_WIDTH - MARGIN, y: 48 }, thickness: 0.5, color: pdfColor(REPORT_THEME.border) });
    target.drawText('CONFIDENTIAL — FORENSIC WORK PRODUCT', {
      x: MARGIN, y: 36, size: 7, font: bold, color: pdfColor(REPORT_THEME.muted)
    });
    target.drawText(`Page ${index + 1} of ${pages.length}`, {
      x: PAGE_WIDTH - MARGIN - 90, y: 36, size: 7.5, font, color: pdfColor(REPORT_THEME.muted)
    });
  });

  const pdfBytes = await pdfDoc.save();
  return { pdfBytes, reportId };
}
