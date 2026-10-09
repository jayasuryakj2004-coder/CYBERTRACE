import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractMetadata, extractMetadataViaPdfJs, parsePdfDate } from '../../src/analysis/metadata.js';
import { IndicatorCategory } from '../../src/analysis/evidence.js';

function pdfWith(objects, trailerExtras = '') {
  let pdf = '%PDF-1.4\n';
  for (const obj of objects) {
    pdf += `${obj.num} 0 obj\n${obj.content}\nendobj\n`;
  }
  pdf += 'xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R ' + trailerExtras + ' >>\nstartxref\n0\n%%EOF\n';
  return pdf;
}

test('extractMetadata extracts /Info fields', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Title (My Doc) /Author (Alice) /Subject (Test) /Creator (Word) /Producer (PDF) /CreationDate (D:20240101120000Z) /ModDate (D:20240102120000Z) >>' }
  ], '/Info 2 0 R');
  const { metadata, metadataFindings } = extractMetadata(text);
  assert.equal(metadata.title, 'My Doc');
  assert.equal(metadata.author, 'Alice');
  assert.equal(metadata.subject, 'Test');
  assert.equal(metadata.creator, 'Word');
  assert.equal(metadata.producer, 'PDF');
  assert.equal(metadata.creationDate, 'D:20240101120000Z');
  assert.equal(metadata.modificationDate, 'D:20240102120000Z');
  // No missing-metadata finding when all fields present
  const missingFindings = metadataFindings.filter(f => f.detectionRule === 'MISSING_METADATA');
  assert.equal(missingFindings.length, 0);
});

test('extractMetadata detects missing metadata', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' }
  ]);
  const { metadata, metadataFindings } = extractMetadata(text);
  assert.equal(metadata.title, '');
  const missingFindings = metadataFindings.filter(f => f.detectionRule === 'MISSING_METADATA');
  assert.equal(missingFindings.length, 1);
  assert.equal(missingFindings[0].indicatorCategory, IndicatorCategory.METADATA_ANOMALY);
});

test('extractMetadata detects page count', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /Pages 2 0 R >>' },
    { num: 2, content: '<< /Type /Pages /Kids [3 0 R] /Count 5 >>' }
  ]);
  const { metadata } = extractMetadata(text);
  assert.equal(metadata.pageCount, 5);
});

test('extractMetadata detects PDF version', () => {
  const text = '%PDF-1.7\n' + pdfWith([{ num: 1, content: '<< /Type /Catalog >>' }]);
  const { metadata } = extractMetadata(text);
  assert.equal(metadata.pdfVersion, '1.7');
});

test('extractMetadata detects forms', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /AcroForm 2 0 R >>' },
    { num: 2, content: '<< /Type /AcroForm /Fields [] >>' }
  ]);
  const { metadata } = extractMetadata(text);
  assert.equal(metadata.hasForms, true);
});

test('extractMetadata detects signatures', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Sig >>' }
  ]);
  const { metadata } = extractMetadata(text);
  assert.equal(metadata.hasSignatures, true);
});

test('extractMetadata detects unusual timestamps', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Title (X) /Author (Y) /Subject (Z) /Producer (P) /CreationDate (D:18000101120000Z) >>' }
  ], '/Info 2 0 R');
  const { metadataFindings } = extractMetadata(text);
  const tsFindings = metadataFindings.filter(f => f.detectionRule === 'UNUSUAL_TIMESTAMP');
  assert.equal(tsFindings.length, 1);
});

test('extractMetadataViaPdfJs detects JavaScript returned by getJSActions', async () => {
  const findings = await extractMetadataViaPdfJs({
    getMetadata: async () => ({ info: { Title: 'Test' }, metadata: null }),
    getJSActions: async () => ({ OpenAction: ["app.alert('Hello')"] }),
    getAttachments: async () => null
  });

  const javascript = findings.find(finding => finding.detectionRule === 'JAVASCRIPT_DETECTED');
  assert.ok(javascript);
  assert.equal(javascript.extractedValue, "app.alert('Hello')");
});

test('parsePdfDate parses PDF date format', () => {
  const ts = parsePdfDate('D:20240101120000Z');
  assert.ok(typeof ts === 'number');
  const date = new Date(ts);
  assert.equal(date.getUTCFullYear(), 2024);
  assert.equal(date.getUTCMonth(), 0);
  assert.equal(date.getUTCDate(), 1);
});

test('parsePdfDate falls back to Date.parse', () => {
  const ts = parsePdfDate('2024-01-01T00:00:00Z');
  assert.ok(typeof ts === 'number');
});

test('parsePdfDate returns null for invalid date', () => {
  assert.equal(parsePdfDate('not a date'), null);
});