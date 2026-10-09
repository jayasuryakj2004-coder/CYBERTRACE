import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { analyzePdf } from '../../src/analysis/index.js';
import { computeSHA256 } from '../../src/shared/contracts.js';
import { ScanStatus } from '../../src/shared/contracts.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

function loadFixture(name) {
  const buffer = readFileSync(join(FIXTURES_DIR, name));
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

test('analyzePdf completes on a benign ordinary PDF', async () => {
  const buffer = loadFixture('benign-ordinary.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.COMPLETED);
  assert.equal(result.riskAssessment.score, 0);
  assert.equal(result.riskAssessment.level, 'none');
  assert.ok(result.metadata.pageCount >= 1);
});

test('analyzePdf completes on benign PDF with metadata', async () => {
  const buffer = loadFixture('benign-metadata.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.COMPLETED);
  assert.equal(result.metadata.title, 'Test Document');
  assert.equal(result.metadata.author, 'Test Author');
});

test('analyzePdf detects JavaScript and scores suspicious', async () => {
  const buffer = loadFixture('suspicious-javascript.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.COMPLETED);
  const jsFindings = result.findings.filter(f => f.indicatorCategory === 'javascript');
  assert.ok(jsFindings.length >= 1, 'JavaScript should be detected');
  assert.ok(result.riskAssessment.score >= 50, 'Score should be suspicious');
});

test('analyzePdf detects Launch action', async () => {
  const buffer = loadFixture('suspicious-launch.pdf');
  const result = await analyzePdf(buffer);
  const launchFindings = result.findings.filter(f => f.indicatorCategory === 'launch_action');
  assert.ok(launchFindings.length >= 1, 'Launch action should be detected');
});

test('analyzePdf detects embedded files', async () => {
  const buffer = loadFixture('suspicious-embedded.pdf');
  const result = await analyzePdf(buffer);
  const efFindings = result.findings.filter(f => f.indicatorCategory === 'embedded_file');
  assert.ok(efFindings.length >= 1, 'Embedded file should be detected');
});

test('analyzePdf detects suspicious URI', async () => {
  const buffer = loadFixture('suspicious-uri.pdf');
  const result = await analyzePdf(buffer);
  const susFindings = result.findings.filter(f => f.indicatorCategory === 'suspicious_uri');
  assert.ok(susFindings.length >= 1, 'Suspicious URI should be detected');
});

test('analyzePdf fails on non-PDF (no header)', async () => {
  const buffer = loadFixture('edge-malformed.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.FAILED);
  assert.ok(result.error.includes('%PDF-'));
});

test('analyzePdf marks truncated PDF as incomplete', async () => {
  const buffer = loadFixture('edge-truncated.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.INCOMPLETE);
  assert.ok(result.limitations.some(l => l.includes('truncated')));
});

test('analyzePdf detects encryption', async () => {
  const buffer = loadFixture('edge-encrypted.pdf');
  const result = await analyzePdf(buffer);
  assert.equal(result.status, ScanStatus.COMPLETED);
  const encFindings = result.findings.filter(f => f.indicatorCategory === 'encryption');
  assert.ok(encFindings.length >= 1, 'Encryption should be detected');
});

test('analyzePdf detects incremental update', async () => {
  const buffer = loadFixture('edge-incremental.pdf');
  const result = await analyzePdf(buffer);
  const iuFindings = result.findings.filter(f => f.indicatorCategory === 'incremental_update');
  assert.ok(iuFindings.length >= 1, 'Incremental update should be detected');
});

test('analyzePdf is deterministic', async () => {
  const buffer = loadFixture('suspicious-javascript.pdf');
  const r1 = await analyzePdf(buffer);
  const r2 = await analyzePdf(buffer);
  assert.equal(r1.riskAssessment.score, r2.riskAssessment.score);
  assert.equal(r1.findings.length, r2.findings.length);
});

test('analyzePdf handles empty buffer', async () => {
  const result = await analyzePdf(new ArrayBuffer(0));
  assert.equal(result.status, ScanStatus.FAILED);
});

test('analyzePdf rejects documents above the configured size limit before parsing', async () => {
  const result = await analyzePdf(new Uint8Array([37, 80, 68, 70, 45, 49, 46, 55]).buffer, { maxSize: 4 });
  assert.equal(result.status, ScanStatus.FAILED);
  assert.match(result.error, /analysis limit/);
  assert.equal(result.riskAssessment, null);
});

test('analyzePdf respects abort signal', async () => {
  const buffer = loadFixture('suspicious-javascript.pdf');
  const controller = new AbortController();
  controller.abort();
  const result = await analyzePdf(buffer, { signal: controller.signal });
  assert.equal(result.status, ScanStatus.INCOMPLETE);
});

test('SHA-256 via Web Crypto matches Node crypto (independent implementations)', async () => {
  const buffer = loadFixture('benign-ordinary.pdf');
  const nodeHash = createHash('sha256').update(Buffer.from(buffer)).digest('hex');
  const webCryptoHash = await computeSHA256(buffer);
  assert.equal(webCryptoHash, nodeHash);
  assert.equal(webCryptoHash.length, 64);
});

test('SHA-256 is computed over original bytes (different documents differ)', async () => {
  const buf1 = loadFixture('benign-ordinary.pdf');
  const buf2 = loadFixture('benign-link.pdf');
  const h1 = await computeSHA256(buf1);
  const h2 = await computeSHA256(buf2);
  assert.notEqual(h1, h2);
});

test('SHA-256 matches independent hash for all fixtures', async () => {
  const fixtures = [
    'benign-ordinary.pdf', 'benign-link.pdf', 'benign-form.pdf',
    'benign-metadata.pdf', 'suspicious-javascript.pdf', 'suspicious-launch.pdf'
  ];
  for (const name of fixtures) {
    const buffer = loadFixture(name);
    const nodeHash = createHash('sha256').update(Buffer.from(buffer)).digest('hex');
    const webHash = await computeSHA256(buffer);
    assert.equal(webHash, nodeHash, `SHA-256 mismatch for ${name}`);
  }
});