import { PDFDocument, StandardFonts, rgb } from '../../node_modules/pdf-lib/dist/pdf-lib.esm.min.js';
import { CATEGORY_KEYS } from '../categorizer/rules.js';
import { REPORT_THEME, ratingStyle } from './theme.js';

function defangText(value) {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/https?:\/\//gi, 'hxxps://')
    .replace(/\./g, '[.]')
    .replace(/\s+/g, ' ')
    .slice(0, 500);
}

function sanitizePlainText(value) {
  return String(value ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function hexToRgb(hexColor) {
  const normalized = String(hexColor || '#FFFFFF').replace('#', '');
  const safeHex = normalized.length === 3
    ? normalized.split('').map((char) => char + char).join('')
    : normalized;
  const numeric = Number.parseInt(safeHex, 16);
  if (Number.isNaN(numeric)) {
    return { r: 1, g: 1, b: 1 };
  }
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

function wrapText(page, text, maxWidth, font, size, leading = 14) {
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
  return lines;
}

export async function generatePdfReport(categorization, fileMeta = {}) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([595, 842]);
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const bold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const margin = 52;
  let y = 790;

  page.drawRectangle({ x: 0, y: 0, width: 595, height: 842, color: rgb(1,1,1) });
  page.drawRectangle({ x: 0, y: 760, width: 595, height: 82, color: rgb(234/255, 88/255, 12/255) });
  page.drawText('CyberTrace - PDF Forensic Report', {
    x: margin,
    y: y,
    size: 22,
    font: bold,
    color: rgb(1,1,1)
  });
  page.drawText(new Date().toISOString().slice(0, 19).replace('T', ' '), {
    x: margin,
    y: y - 20,
    size: 10,
    font,
    color: rgb(1, 1, 1)
  });
  const reportId = `CT-${Date.now().toString(36).toUpperCase()}`;
  page.drawText(`Report ID: ${reportId}`, {
    x: 410,
    y: y - 20,
    size: 9,
    font,
    color: rgb(1, 1, 1)
  });

  y -= 120;
  page.drawRectangle({ x: margin, y: y - 6, width: 490, height: 110, color: rgb(255/255, 247/255, 237/255) });
  page.drawText('Scan Summary', { x: margin, y: y + 80, size: 14, font: bold, color: rgb(234/255, 88/255, 12/255) });
  const infoLines = [
    `File: ${defangText(fileMeta.fileName || 'unknown.pdf')}`,
    `Source: ${fileMeta.sourceType || 'remote'}`,
    `Size: ${fileMeta.size ? `${Math.max(1, Math.round(fileMeta.size / 1024))} KB` : 'unknown'}`,
    `SHA-256: ${defangText(fileMeta.sha256 || 'unknown')}`,
    `Status: ${categorization.scanStatus}`,
    `Mode: ${fileMeta.mode || 'Rules + AI'}`,
    `Confidence: ${(Number(categorization.confidence || 0) * 100).toFixed(0)}%`
  ];
  let lineY = y + 58;
  for (const line of infoLines) {
    page.drawText(line, { x: margin + 10, y: lineY, size: 9, font, color: rgb(31/255, 41/255, 55/255) });
    lineY -= 16;
  }
  const progress = Number(categorization.confidence || 0) * 100;
  page.drawRectangle({ x: margin + 300, y: y + 10, width: 150, height: 12, color: rgb(214/255, 214/255, 214/255) });
  page.drawRectangle({ x: margin + 300, y: y + 10, width: Math.max(0, Math.min(150, progress * 1.5)), height: 12, color: rgb(234/255, 88/255, 12/255) });

  y -= 150;
  const overall = categorization.overall || {};
  page.drawRectangle({ x: margin, y: y - 10, width: 490, height: 100, color: rgb(255/255, 247/255, 237/255) });
  const chip = ratingStyle(overall.rating || 'info');
  page.drawRectangle({ x: margin + 10, y: y + 50, width: 90, height: 24, color: pdfColor(chip.bg) });
  page.drawText(chip.label, { x: margin + 25, y: y + 56, size: 9, font: bold, color: pdfColor(chip.text) });
  const summary = sanitizePlainText(overall.summary || 'Summary unavailable.');
  const summaryLines = wrapText(page, summary, 360, font, 10, 14).slice(0, 3);
  summaryLines.forEach((line, idx) => page.drawText(line, { x: margin + 120, y: y + 60 - idx * 15, size: 10, font, color: rgb(31/255, 41/255, 55/255) }));
  if (categorization.scanStatus === 'incomplete' || categorization.scanStatus === 'failed') {
    page.drawRectangle({ x: margin, y: y - 120, width: 490, height: 24, color: rgb(254/255, 202/255, 202/255) });
    page.drawText('INCOMPLETE SCAN - THIS FILE CANNOT BE CALLED CLEAN', { x: margin + 10, y: y - 108, size: 11, font: bold, color: rgb(153/255, 27/255, 27/255) });
    const hiddenAlerts = Array.isArray(categorization.possiblyHidden) ? categorization.possiblyHidden : [];
    if (hiddenAlerts.length > 0) {
      const hiddenY = y - 148;
      page.drawRectangle({ x: margin, y: hiddenY - 26, width: 490, height: 52, color: rgb(255/255, 247/255, 237/255) });
      page.drawText('Possible hidden file content after the last EOF', { x: margin + 10, y: hiddenY - 10, size: 9, font: bold, color: rgb(153/255, 27/255, 27/255) });
      hiddenAlerts.slice(0, 2).forEach((note, index) => {
        page.drawText(sanitizePlainText(note), { x: margin + 10, y: hiddenY - 26 - index * 14, size: 8, font, color: rgb(31/255, 41/255, 55/255) });
      });
    }
  }

  y -= 200;
  page.drawText('Threat Signal Overview', { x: margin, y: y, size: 14, font: bold, color: rgb(234/255, 88/255, 12/255) });
  const rows = CATEGORY_KEYS.map((key, idx) => {
    const item = categorization.categories[key];
    const label = item?.rating === 'not_assessed' ? 'NOT ASSESSED' : item?.rating?.toUpperCase();
    return [String(idx + 1), key.replace(/_/g, ' '), label, item?.interpretation || 'No evidence'];
  });

  let tableY = y - 20;
  page.drawRectangle({ x: margin, y: tableY - 20, width: 490, height: 18, color: rgb(255/255, 247/255, 237/255) });
  ['#', 'Signal', 'Threat', 'Context'].forEach((header, index) => {
    page.drawText(header, { x: margin + 10 + index * 120, y: tableY - 14, size: 9, font: bold, color: rgb(234/255, 88/255, 12/255) });
  });
  tableY -= 26;
  rows.forEach((row, rowIndex) => {
    page.drawRectangle({ x: margin, y: tableY - 18, width: 490, height: 18, color: rowIndex % 2 === 0 ? rgb(1, 1, 1) : rgb(248/255, 250/255, 252/255) });
    row.forEach((cell, index) => {
      const text = String(cell || '').slice(0, 40);
      page.drawText(text, { x: margin + 10 + index * 120, y: tableY - 14, size: 8.5, font, color: rgb(31/255, 41/255, 55/255) });
    });
    tableY -= 20;
  });

  page.drawText('Evidence Notes', { x: margin, y: Math.max(130, tableY - 36), size: 13, font: bold, color: rgb(234/255, 88/255, 12/255) });
  let evidenceY = Math.max(110, tableY - 58);
  const evidenceEntries = CATEGORY_KEYS.flatMap((key) => (categorization.categories?.[key]?.observations || []).slice(0, 2).map((observation) => ({
    key,
    text: sanitizePlainText(observation.text || '')
  }))).filter((entry) => entry.text);

  for (const entry of evidenceEntries) {
    const brief = `${entry.key.replace(/_/g, ' ')}: ${entry.text}`.slice(0, 180);
    if (evidenceY < 60) break;
    page.drawText(brief, { x: margin + 10, y: evidenceY, size: 8.2, font, color: rgb(31/255, 41/255, 55/255) });
    evidenceY -= 12;
  }

  const pdfBytes = await pdfDoc.save();
  return { pdfBytes, reportId };
}
