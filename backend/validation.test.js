import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeScan, validateScanRequest, validateStructuredResponse } from './validation.js';

function validScan(overrides = {}) {
  return {
    scanId: 'scan_123_test', timestamp: '2026-10-09T12:00:00.000Z', status: 'completed',
    fileInfo: { size: 4096, mimeType: 'application/pdf' },
    metadata: { pageCount: 2, pdfVersion: '1.7', isEncrypted: false, isLinearized: false },
    findings: [{ findingId: 'F-0001', indicatorCategory: 'javascript', severity: 'high', detectionRule: 'PDF-JS-001', detectionMethod: 'object parsing', evidenceReference: 'Object 6', extractedValue: 'app.alert()', explanation: 'A JavaScript action was found.', confidence: 0.9, objectNumber: 6, limitations: [] }],
    riskAssessment: { score: 73, level: 'high', factors: [{ rule: 'PDF-JS-001', indicatorCategory: 'javascript', severity: 'high', contribution: 40, explanation: 'JavaScript action' }] },
    limitations: ['Static analysis only'],
    ...overrides
  };
}

test('scan request accepts bounded structured scanner output', () => {
  assert.equal(validateScanRequest({ scan: validScan() }).valid, true);
});

test('scan request rejects invalid score, oversized arrays, and unbounded strings', () => {
  assert.equal(validateScanRequest({ scan: validScan({ riskAssessment: { score: 101, level: 'critical', factors: [] } }) }).valid, false);
  assert.equal(validateScanRequest({ scan: validScan({ findings: Array(41).fill(validScan().findings[0]) }) }).valid, false);
  assert.equal(validateScanRequest({ scan: validScan({ findings: Array(101).fill(validScan().findings[0]) }) }).valid, false);
  assert.equal(validateScanRequest({ scan: validScan({ scanId: 'x'.repeat(101) }) }).valid, false);
});

test('chat request requires a bounded question', () => {
  assert.equal(validateScanRequest({ scan: validScan(), question: 'Why was this flagged?' }, true).valid, true);
  assert.equal(validateScanRequest({ scan: validScan(), question: ' ' }, true).valid, false);
  assert.equal(validateScanRequest({ scan: validScan(), question: 'x'.repeat(501) }, true).valid, false);
});

test('AI payload minimization strips filename, source URL, and hash', () => {
  const scan = validScan({ fileInfo: { size: 5, mimeType: 'application/pdf', name: 'private.pdf', url: 'https://private.test', sha256: 'f'.repeat(64) } });
  const minimized = sanitizeScan(scan);
  assert.equal(minimized.fileInfo, undefined);
  assert.equal(JSON.stringify(minimized).includes('private'), false);
  assert.equal(minimized.findings[0].findingId, 'F-0001');
  assert.equal(minimized.riskAssessment.score, 73);
});

test('structured AI validation rejects nonexistent finding IDs', () => {
  const result = {
    summary: 'Observed one JavaScript action.',
    findings_explanation: [{ finding_id: 'F-9999', explanation: 'Unsupported.' }],
    possible_scenarios: [], recommended_actions: [], limitations: []
  };
  assert.equal(validateStructuredResponse(result, 'analysis', ['F-0001']).valid, false);
  assert.equal(validateStructuredResponse({ answer: 'Evidence is insufficient.', finding_ids: ['F-9999'] }, 'answer', ['F-0001']).valid, false);
});

test('structured AI validation rejects extra fields and URLs absent from evidence', () => {
  const result = {
    summary: 'Observed a structural indicator.', findings_explanation: [],
    possible_scenarios: [], recommended_actions: [], limitations: [], invented_url: 'https://fake.example'
  };
  assert.equal(validateStructuredResponse(result, 'analysis', validScan().findings).valid, false);
  delete result.invented_url;
  result.summary = 'Visit https://fake.example';
  assert.equal(validateStructuredResponse(result, 'analysis', validScan().findings).valid, false);
  result.summary = 'Observed one JavaScript action.';
  assert.equal(validateStructuredResponse(result, 'analysis', validScan().findings).valid, true);
});

test('structured AI validation rejects object references absent from scanner evidence', () => {
  const result = {
    summary: 'Object 99 0 R contains a JavaScript action.', findings_explanation: [],
    possible_scenarios: [], recommended_actions: [], limitations: []
  };
  assert.equal(validateStructuredResponse(result, 'analysis', validScan().findings).valid, false);
  result.summary = 'Object 6 0 R contains the observed JavaScript action.';
  assert.equal(validateStructuredResponse(result, 'analysis', validScan().findings).valid, true);
});