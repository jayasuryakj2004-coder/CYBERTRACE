import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeRisk, explainScore } from '../../src/analysis/risk.js';
import { createFinding, resetFindingCounter, Severity, IndicatorCategory, DetectionMethod } from '../../src/analysis/evidence.js';
import { riskBandForScore, RULES } from '../../src/analysis/rules.js';

function makeFinding(ruleName, overrides = {}) {
  const rule = RULES[ruleName];
  return createFinding({
    indicatorCategory: rule.indicatorCategory,
    description: rule.description,
    severity: rule.severity,
    detectionRule: ruleName,
    confidence: 1.0,
    ...overrides
  });
}

test('computeRisk returns score 0 for no findings', () => {
  const result = computeRisk([]);
  assert.equal(result.score, 0);
  assert.equal(result.level, 'none');
  assert.equal(result.findingCount, 0);
});

test('computeRisk is deterministic', () => {
  resetFindingCounter();
  const findings = [makeFinding('JAVASCRIPT_DETECTED'), makeFinding('OPEN_ACTION')];
  const r1 = computeRisk(findings);
  const r2 = computeRisk(findings);
  assert.equal(r1.score, r2.score);
  assert.deepEqual(r1.contributions, r2.contributions);
});

test('computeRisk applies severity multiplier', () => {
  resetFindingCounter();
  // JavaScript: weight 35, HIGH severity (1.25), confidence 1.0 => 43.75
  const result = computeRisk([makeFinding('JAVASCRIPT_DETECTED')]);
  assert.equal(result.score, 43.75);
});

test('computeRisk applies confidence factor', () => {
  resetFindingCounter();
  // JavaScript: weight 35, HIGH (1.25), confidence 0.5 => 21.875, rounded to 21.88
  const result = computeRisk([makeFinding('JAVASCRIPT_DETECTED', { confidence: 0.5 })]);
  assert.equal(result.score, 21.88);
});

test('computeRisk respects category caps', () => {
  resetFindingCounter();
  // Two JavaScript findings: each 43.75, but categoryCap is 45.
  // First contributes 43.75, second contributes min(43.75, 45-43.75=1.25) = 1.25.
  // Total = 45.
  const f1 = makeFinding('JAVASCRIPT_DETECTED', { objectNumber: 1, extractedValue: 'a' });
  const f2 = makeFinding('JAVASCRIPT_DETECTED', { objectNumber: 2, extractedValue: 'b' });
  const result = computeRisk([f1, f2]);
  assert.equal(result.score, 45);
  assert.equal(result.contributions.find(c => c.findingId === f1.findingId).capped, false);
  assert.equal(result.contributions.find(c => c.findingId === f2.findingId).capped, true);
});

test('computeRisk caps at maxScore', () => {
  resetFindingCounter();
  const findings = [
    makeFinding('LAUNCH_ACTION'),
    makeFinding('JAVASCRIPT_DETECTED'),
    makeFinding('OPEN_ACTION'),
    makeFinding('SUSPICIOUS_URI'),
    makeFinding('ADDITIONAL_ACTION'),
    makeFinding('EMBEDDED_FILE')
  ];
  const result = computeRisk(findings, { maxScore: 100 });
  assert.ok(result.score <= 100);
});

test('computeRisk constrains configured score bounds to 0-100', () => {
  resetFindingCounter();
  const findings = [makeFinding('LAUNCH_ACTION'), makeFinding('JAVASCRIPT_DETECTED')];
  const aboveRange = computeRisk(findings, { maxScore: 500 });
  const belowRange = computeRisk(findings, { maxScore: -1 });
  assert.equal(aboveRange.maxScore, 100);
  assert.ok(aboveRange.score <= 100);
  assert.equal(belowRange.maxScore, 0);
  assert.equal(belowRange.score, 0);
});

test('computeRisk deduplicates overlapping findings', () => {
  resetFindingCounter();
  const base = {
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JS',
    severity: Severity.HIGH,
    detectionRule: 'JAVASCRIPT_DETECTED',
    objectNumber: 5,
    extractedValue: 'alert(1)'
  };
  const f1 = createFinding({ ...base });
  const f2 = createFinding({ ...base });
  const result = computeRisk([f1, f2]);
  assert.equal(result.findingCount, 1);
});

test('computeRisk ignores unknown rules', () => {
  resetFindingCounter();
  const f = createFinding({
    indicatorCategory: 'javascript',
    description: 'JS',
    detectionRule: 'NONEXISTENT_RULE'
  });
  const result = computeRisk([f]);
  assert.equal(result.score, 0);
  assert.equal(result.findingCount, 0);
});

test('risk bands are correct', () => {
  assert.equal(riskBandForScore(0), 'none');
  assert.equal(riskBandForScore(0.01), 'low');
  assert.equal(riskBandForScore(20), 'low');
  assert.equal(riskBandForScore(20.01), 'medium');
  assert.equal(riskBandForScore(40), 'medium');
  assert.equal(riskBandForScore(40.01), 'high');
  assert.equal(riskBandForScore(60), 'high');
  assert.equal(riskBandForScore(60.01), 'critical');
  assert.equal(riskBandForScore(100), 'critical');
});

test('computeRisk produces correct level for JavaScript + OpenAction', () => {
  resetFindingCounter();
  // JS: 43.75, OpenAction: 20*1.0*1.0=20 => 63.75 => high
  const result = computeRisk([makeFinding('JAVASCRIPT_DETECTED'), makeFinding('OPEN_ACTION')]);
  assert.equal(result.score, 63.75);
  assert.equal(result.level, 'critical');
});

test('computeRisk produces high for Launch action', () => {
  resetFindingCounter();
  // Launch: 40*1.5*1.0=60 => high.
  const result = computeRisk([makeFinding('LAUNCH_ACTION')]);
  assert.equal(result.score, 60);
  assert.equal(result.level, 'high');
});

test('explainScore produces readable output', () => {
  resetFindingCounter();
  const result = computeRisk([makeFinding('JAVASCRIPT_DETECTED')]);
  const explanation = explainScore(result);
  assert.ok(explanation.includes('Risk score'));
  assert.ok(explanation.includes('javascript_detected'));
});

test('risk result includes disclaimer', () => {
  resetFindingCounter();
  const result = computeRisk([makeFinding('JAVASCRIPT_DETECTED')]);
  assert.ok(result.disclaimer.includes('not a calibrated probability'));
});