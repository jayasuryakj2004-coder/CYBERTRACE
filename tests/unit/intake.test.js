import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { inspectIntake, classifyEntropy, HIGH_ENTROPY_THRESHOLD } from '../../src/analysis/intake.js';
import { analyzePdf } from '../../src/analysis/index.js';
import { IndicatorCategory, DetectionMethod } from '../../src/analysis/evidence.js';
import { RULES } from '../../src/analysis/rules.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name) {
  const buffer = readFileSync(join(FIXTURES_DIR, name));
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

function toBuffer(bytes) {
  const view = new Uint8Array(bytes);
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
}

function peBuffer(size = 4096) {
  const pe = Buffer.alloc(size);
  pe[0] = 0x4d; pe[1] = 0x5a; // MZ
  pe[60] = 64;
  pe[64] = 0x50; pe[65] = 0x45; pe[66] = 0x00; pe[67] = 0x00; // PE\0\0
  for (let i = 68; i < size; i++) pe[i] = (i * 73 + 17) & 0xff;
  return pe;
}

test('new rules are registered with categories and caps', () => {
  for (const name of ['HIGH_ENTROPY', 'FILE_TYPE_MISMATCH', 'EMBEDDED_BINARY_SIGNATURE', 'PDF_PREAMBLE']) {
    assert.ok(RULES[name], `${name} rule must exist`);
    assert.ok(RULES[name].indicatorCategory, `${name} must declare an indicator category`);
    assert.ok(Number.isFinite(RULES[name].weight), `${name} must declare a weight`);
  }
  assert.equal(RULES.FILE_TYPE_MISMATCH.severity, 'critical');
  assert.ok(RULES.HIGH_ENTROPY.weight > 0);
});

test('inspectIntake identifies a genuine PDF', () => {
  const buffer = loadFixture('benign-ordinary.pdf');
  const { info, findings } = inspectIntake(buffer, { text: '%PDF-1.4', fileName: 'benign-ordinary.pdf' });
  assert.equal(info.isPdf, true);
  assert.equal(info.blockingFormat, false);
  assert.equal(info.detectedFormat, 'pdf');
  assert.equal(info.declaredAsPdf, true);
  assert.equal(findings.filter(f => f.detectionRule === 'FILE_TYPE_MISMATCH').length, 0);
});

test('inspectIntake flags an EXE named as PDF as critical mismatch', () => {
  const buffer = toBuffer(peBuffer());
  const { info, findings } = inspectIntake(buffer, { text: '', fileName: 'invoice.pdf', declaredMimeType: 'application/pdf' });
  assert.equal(info.isPdf, false);
  assert.equal(info.isExecutable, true);
  assert.equal(info.blockingFormat, true);
  assert.equal(info.declaredAsPdf, true);
  const mismatch = findings.filter(f => f.detectionRule === 'FILE_TYPE_MISMATCH');
  assert.equal(mismatch.length, 1);
  assert.equal(mismatch[0].severity, 'critical');
  assert.equal(mismatch[0].indicatorCategory, IndicatorCategory.FILE_TYPE_MISMATCH);
  assert.equal(mismatch[0].detectionMethod, DetectionMethod.SIGNATURE);
});

test('inspectIntake flags ZIP and RAR archives named as PDF', () => {
  const zip = toBuffer(Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(2048)]));
  const zipInfo = inspectIntake(zip, { text: '', fileName: 'scan.pdf' });
  assert.equal(zipInfo.info.isArchive, true);
  assert.equal(zipInfo.info.blockingFormat, true);
  assert.equal(zipInfo.findings.filter(f => f.detectionRule === 'FILE_TYPE_MISMATCH').length, 1);

  const rar = toBuffer(Buffer.concat([Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]), randomBytes(2048)]));
  const rarInfo = inspectIntake(rar, { text: '', fileName: 'scan.pdf' });
  assert.equal(rarInfo.info.isArchive, true);
  assert.equal(rarInfo.findings.filter(f => f.detectionRule === 'FILE_TYPE_MISMATCH').length, 1);
});

test('inspectIntake reports ELF and Mach-O executables as mismatch', () => {
  const elf = toBuffer(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), randomBytes(2048)]));
  assert.equal(inspectIntake(elf, { text: '', fileName: 'doc.pdf' }).info.isExecutable, true);

  const macho = toBuffer(Buffer.concat([Buffer.from([0xfe, 0xed, 0xfa, 0xce]), randomBytes(2048)]));
  assert.equal(inspectIntake(macho, { text: '', fileName: 'doc.pdf' }).info.isExecutable, true);
});

test('inspectIntake keeps unknown blobs out of the mismatch path', () => {
  const blob = toBuffer(Buffer.from('this is not a pdf at all'));
  const { info, findings } = inspectIntake(blob, { text: 'this is not a pdf at all', fileName: 'doc.pdf' });
  assert.equal(info.detectedFormat, 'unknown');
  assert.equal(info.blockingFormat, false);
  assert.equal(findings.filter(f => f.detectionRule === 'FILE_TYPE_MISMATCH').length, 0);
});

test('inspectIntake detects embedded PE signatures (polyglot)', () => {
  const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n<< /Type /Catalog >>\n'), peBuffer(128), Buffer.from('\n%%EOF\n')]);
  const buffer = toBuffer(pdf);
  const { info, findings } = inspectIntake(buffer, { text: pdf.toString('latin1'), fileName: 'poly.pdf' });
  assert.equal(info.isPdf, true);
  const embedded = findings.filter(f => f.detectionRule === 'EMBEDDED_BINARY_SIGNATURE');
  assert.equal(embedded.length, 1);
  assert.equal(embedded[0].severity, 'high');
});

test('inspectIntake measures Shannon entropy of dense content', () => {
  const dense = Buffer.concat([Buffer.from('%PDF-1.4\n'), randomBytes(65536), Buffer.from('\n%%EOF\n')]);
  const buffer = toBuffer(dense);
  const { info, findings } = inspectIntake(buffer, { text: dense.toString('latin1'), fileName: 'locked.pdf' });
  assert.ok(info.documentEntropy >= HIGH_ENTROPY_THRESHOLD, `entropy ${info.documentEntropy} should exceed threshold`);
  assert.equal(info.entropyLevel, 'extreme');
  const entropyFindings = findings.filter(f => f.detectionRule === 'HIGH_ENTROPY');
  assert.equal(entropyFindings.length, 1);
  assert.ok(['medium', 'high'].includes(entropyFindings[0].severity));
});

test('inspectIntake produces no entropy finding for ordinary text PDFs', () => {
  const buffer = loadFixture('benign-ordinary.pdf');
  const text = String.fromCharCode(...new Uint8Array(buffer));
  const { info, findings } = inspectIntake(buffer, { text, fileName: 'benign-ordinary.pdf' });
  assert.ok(info.documentEntropy < HIGH_ENTROPY_THRESHOLD);
  assert.equal(info.entropyLevel, 'low');
  assert.equal(findings.filter(f => f.detectionRule === 'HIGH_ENTROPY').length, 0);
});

test('classifyEntropy buckets values consistently', () => {
  assert.equal(classifyEntropy(2.0), 'low');
  assert.equal(classifyEntropy(6.2), 'moderate');
  assert.equal(classifyEntropy(7.6), 'high');
  assert.equal(classifyEntropy(7.9), 'extreme');
});

test('analyzePdf completes a non-PDF executable with a critical risk score', async () => {
  const buffer = toBuffer(peBuffer());
  const result = await analyzePdf(buffer, { fileName: 'invoice.pdf', declaredMimeType: 'application/pdf' });
  assert.equal(result.status, 'completed');
  assert.ok(result.riskAssessment.score >= 60, 'score should reach the critical band');
  assert.equal(result.riskAssessment.level, 'critical');
  const mismatch = result.findings.find(f => f.detectionRule === 'FILE_TYPE_MISMATCH');
  assert.ok(mismatch, 'mismatch finding must be present');
  assert.equal(mismatch.severity, 'critical');
  assert.ok(result.fileIdentity.isExecutable);
  assert.ok(result.limitations.some(l => l.includes('not a PDF')));
});

test('analyzePdf completes an archive named as PDF with a critical risk score', async () => {
  const zip = toBuffer(Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(4096)]));
  const result = await analyzePdf(zip, { fileName: 'archive.pdf' });
  assert.equal(result.status, 'completed');
  assert.equal(result.riskAssessment.level, 'critical');
  assert.ok(result.findings.some(f => f.detectionRule === 'FILE_TYPE_MISMATCH'));
});

test('analyzePdf scores extreme-entropy PDFs above clean documents', async () => {
  const dense = Buffer.concat([Buffer.from('%PDF-1.4\n'), randomBytes(65536), Buffer.from('\n%%EOF\n')]);
  const result = await analyzePdf(toBuffer(dense), { fileName: 'locked.pdf' });
  assert.equal(result.status, 'completed');
  assert.ok(result.riskAssessment.score > 0, 'high entropy must contribute to the score');
  assert.ok(result.findings.some(f => f.detectionRule === 'HIGH_ENTROPY'));
  assert.ok(result.limitations.some(l => l.includes('High entropy')));

  const benign = await analyzePdf(loadFixture('benign-ordinary.pdf'));
  assert.equal(benign.riskAssessment.score, 0);
  assert.equal(benign.findings.filter(f => f.detectionRule === 'HIGH_ENTROPY').length, 0);
});

test('analyzePdf still fails on unrecognized non-PDF blobs', async () => {
  const blob = toBuffer(Buffer.from('garbage bytes with no structure'));
  const result = await analyzePdf(blob, { fileName: 'doc.pdf' });
  assert.equal(result.status, 'failed');
  assert.match(result.error, /%PDF-/);
  assert.equal(result.riskAssessment, null);
});

test('file identity is exposed on the analysis result for real fixtures', async () => {
  const result = await analyzePdf(loadFixture('suspicious-javascript.pdf'), { fileName: 'suspicious-javascript.pdf' });
  assert.ok(result.fileIdentity);
  assert.equal(result.fileIdentity.isPdf, true);
  assert.ok(Number.isFinite(result.fileIdentity.documentEntropy));
  assert.ok(Number.isInteger(result.fileIdentity.streamCount));
});
