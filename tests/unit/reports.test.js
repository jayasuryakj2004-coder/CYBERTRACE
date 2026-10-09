import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHtmlReport, createJsonReport } from '../../src/shared/reports.js';

function sampleScan(overrides = {}) {
  return {
    scanId: 'scan_test_1', timestamp: '2026-10-09T00:00:00.000Z', completedAt: null,
    status: 'completed', progress: 100,
    fileInfo: { name: 'invoice.pdf', size: 100, mimeType: 'application/pdf', url: 'https://example.test/a.pdf', sha256: 'a'.repeat(64) },
    metadata: { title: 'Quarterly report', pageCount: 2 },
    findings: [{ findingId: 'F-0001', indicatorCategory: 'javascript', severity: 'high', description: 'JavaScript action', evidenceReference: 'Object 6', objectNumber: 6, extractedValue: "app.alert('hi')", detectionRule: 'PDF-JS-001', detectionMethod: 'object scan', explanation: 'A JavaScript action was observed.' }],
    riskAssessment: { score: 72, level: 'high', factors: [{ rule: 'PDF-JS-001', contribution: 32, explanation: 'JavaScript action' }] },
    limitations: ['Static analysis only'],
    ...overrides
  };
}

test('JSON report retains real scan evidence and report provenance', () => {
  const report = JSON.parse(createJsonReport(sampleScan()));
  assert.equal(report.scan.findings[0].findingId, 'F-0001');
  assert.equal(report.scan.riskAssessment.score, 72);
  assert.equal(report.scan.fileInfo.sha256, 'a'.repeat(64));
  assert.equal(report.schemaVersion, '3.1.0');
  assert.equal(report.scanner.ruleEngineVersion, '2.0.0');
});

test('HTML report escapes document data and rejects unsafe source links', () => {
  const html = createHtmlReport(sampleScan({
    fileInfo: { name: '<img src=x onerror=alert(1)>', url: 'javascript:alert(1)', sha256: 'b'.repeat(64) },
    metadata: { title: '<script>alert(1)</script>' }
  }));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('href="javascript:'));
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('HTML report does not make credential-bearing source URLs clickable', () => {
  const html = createHtmlReport(sampleScan({
    fileInfo: { name: 'source.pdf', url: 'https://user:password@example.test/file.pdf', sha256: 'c'.repeat(64) }
  }));
  assert.ok(!html.includes('href="https://user:password'));
});

test('AI report interpretation is labeled and escaped', () => {
  const html = createHtmlReport(sampleScan(), { summary: '<b>interpretation</b>', recommended_actions: ['Review object 6'] });
  assert.match(html, /AI interpretation/);
  assert.match(html, /&lt;b&gt;interpretation&lt;\/b&gt;/);
});