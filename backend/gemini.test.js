import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.GEMINI_API_KEY = 'unit-test-key-only';
const { analyzeWithGemini } = await import('./gemini.js');

function scanSummary() {
  return {
    scanId: 'scan_test_1', timestamp: '2026-10-09T12:00:00.000Z', status: 'completed',
    fileInfo: { name: 'private.pdf', size: 100, mimeType: 'application/pdf', url: 'https://private.example/file.pdf', sha256: 'a'.repeat(64) },
    metadata: { pageCount: 1, pdfVersion: '1.7', isEncrypted: false, isLinearized: false, title: 'Private title' },
    findings: [{ findingId: 'F-0001', indicatorCategory: 'javascript', severity: 'high', detectionRule: 'PDF-JS-001', detectionMethod: 'object parser', evidenceReference: 'Object 6', objectNumber: 6, extractedValue: 'app.alert()', explanation: 'JavaScript action detected.', limitations: [] }],
    riskAssessment: { score: 75, level: 'high', factors: [{ rule: 'PDF-JS-001', indicatorCategory: 'javascript', severity: 'high', contribution: 40, explanation: 'Observed script action.' }] },
    limitations: []
  };
}

function analysisResponse(overrides = {}) {
  return {
    summary: 'The scanner observed one JavaScript action.',
    findings_explanation: [{ finding_id: 'F-0001', explanation: 'A PDF JavaScript action was observed.' }],
    possible_scenarios: ['It could run if a viewer executes the action.'],
    recommended_actions: ['Review object 6 in an isolated environment.'],
    limitations: ['Static analysis does not establish execution.'],
    ...overrides
  };
}

function geminiResponse(value) {
  return { candidates: [{ content: { parts: [{ text: JSON.stringify(value) }] } }] };
}

test('Gemini REST request uses structured JSON, server key header, and minimized evidence', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let requestOptions;
  globalThis.fetch = async (url, options) => {
    requestUrl = String(url);
    requestOptions = options;
    return { ok: true, json: async () => geminiResponse(analysisResponse()) };
  };
  try {
    const result = await analyzeWithGemini(scanSummary());
    assert.equal(result.findings_explanation[0].finding_id, 'F-0001');
    assert.ok(requestUrl.startsWith('https://generativelanguage.googleapis.com/v1beta/models/'));
    assert.equal(requestUrl.includes('unit-test-key-only'), false);
    assert.equal(requestOptions.headers['x-goog-api-key'], 'unit-test-key-only');
    const body = JSON.parse(requestOptions.body);
    assert.equal(body.generationConfig.responseFormat.text.mimeType, 'APPLICATION_JSON');
    assert.equal(body.generationConfig.responseFormat.text.schema.type, 'OBJECT');
    const prompt = body.contents[0].parts[0].text;
    assert.equal(prompt.includes('private.pdf'), false);
    assert.equal(prompt.includes('private.example'), false);
    assert.equal(prompt.includes('Private title'), false);
    assert.match(prompt, /app\.alert\(\)/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Gemini timeout failures are reduced to a safe service error', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('upstream timeout with private details'); };
  try {
    await assert.rejects(analyzeWithGemini(scanSummary()), { message: 'AI_UPSTREAM_UNAVAILABLE' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Gemini quota errors do not expose upstream response details', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 429, text: async () => 'private upstream detail' });
  try {
    await assert.rejects(analyzeWithGemini(scanSummary()), { message: 'AI_QUOTA' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Gemini malformed JSON and unknown finding IDs are rejected', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ candidates: [{ content: { parts: [{ text: '{' }] } }] }) });
  try {
    await assert.rejects(analyzeWithGemini(scanSummary()), { message: 'AI_INVALID_RESPONSE' });
    globalThis.fetch = async () => ({ ok: true, json: async () => geminiResponse(analysisResponse({
      findings_explanation: [{ finding_id: 'F-9999', explanation: 'invented' }]
    })) });
    await assert.rejects(analyzeWithGemini(scanSummary()), { message: 'AI_INVALID_RESPONSE' });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('missing Gemini key returns configuration error without sending a request', async () => {
  const originalFetch = globalThis.fetch;
  process.env.GEMINI_API_KEY = '';
  const { analyzeWithGemini: analyzeWithoutKey } = await import('./gemini.js?missing-key-test');
  globalThis.fetch = async () => { throw new Error('fetch must not run without a key'); };
  try {
    await assert.rejects(analyzeWithoutKey(scanSummary()), { message: 'AI_NOT_CONFIGURED' });
  } finally {
    globalThis.fetch = originalFetch;
    process.env.GEMINI_API_KEY = 'unit-test-key-only';
  }
});