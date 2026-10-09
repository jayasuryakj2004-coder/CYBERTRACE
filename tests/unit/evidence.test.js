import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createFinding,
  boundExcerpt,
  deduplicateFindings,
  validateFinding,
  findingsByCategory,
  findingsBySeverity,
  resetFindingCounter,
  Severity,
  IndicatorCategory,
  DetectionMethod
} from '../../src/analysis/evidence.js';

test('createFinding creates a valid finding with all required fields', () => {
  resetFindingCounter();
  const f = createFinding({
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JavaScript detected',
    severity: Severity.HIGH,
    detectionRule: 'JAVASCRIPT_DETECTED',
    evidenceReference: 'object 5',
    objectNumber: 5,
    extractedValue: 'app.alert(1)',
    confidence: 0.95,
    explanation: 'JS can execute',
    detectionMethod: DetectionMethod.OBJECT_PARSER
  });
  assert.ok(f.findingId.startsWith('F-'));
  assert.equal(f.indicatorCategory, 'javascript');
  assert.equal(f.severity, 'high');
  assert.equal(f.detectionRule, 'JAVASCRIPT_DETECTED');
  assert.equal(f.confidence, 0.95);
  assert.equal(f.observed, true);
  assert.equal(f.detectionMethod, 'object_parser');
});

test('createFinding throws without indicatorCategory', () => {
  assert.throws(() => createFinding({ detectionRule: 'X' }), /indicatorCategory/);
});

test('createFinding throws without detectionRule', () => {
  assert.throws(() => createFinding({ indicatorCategory: 'javascript' }), /detectionRule/);
});

test('createFinding throws with confidence out of range', () => {
  assert.throws(() => createFinding({
    indicatorCategory: 'javascript',
    detectionRule: 'X',
    confidence: 1.5
  }), /Confidence/);
  assert.throws(() => createFinding({
    indicatorCategory: 'javascript',
    detectionRule: 'X',
    confidence: -0.1
  }), /Confidence/);
});

test('boundExcerpt truncates long values', () => {
  const long = 'a'.repeat(300);
  const result = boundExcerpt(long, 100);
  assert.ok(result.length < 300);
  assert.ok(result.includes('truncated'));
});

test('boundExcerpt returns null for null', () => {
  assert.equal(boundExcerpt(null), null);
});

test('deduplicateFindings removes exact duplicates', () => {
  resetFindingCounter();
  const base = {
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JS',
    severity: Severity.HIGH,
    detectionRule: 'JAVASCRIPT_DETECTED',
    objectNumber: 5,
    extractedValue: 'alert(1)',
    confidence: 0.9
  };
  const f1 = createFinding({ ...base });
  const f2 = createFinding({ ...base });
  const deduped = deduplicateFindings([f1, f2]);
  assert.equal(deduped.length, 1);
});

test('deduplicateFindings keeps distinct findings', () => {
  resetFindingCounter();
  const f1 = createFinding({
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JS',
    detectionRule: 'JAVASCRIPT_DETECTED',
    objectNumber: 5,
    extractedValue: 'alert(1)'
  });
  const f2 = createFinding({
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JS',
    detectionRule: 'JAVASCRIPT_DETECTED',
    objectNumber: 6,
    extractedValue: 'alert(2)'
  });
  const deduped = deduplicateFindings([f1, f2]);
  assert.equal(deduped.length, 2);
});

test('deduplicateFindings merges confidence to max', () => {
  resetFindingCounter();
  const base = {
    indicatorCategory: IndicatorCategory.JAVASCRIPT,
    description: 'JS',
    detectionRule: 'JAVASCRIPT_DETECTED',
    objectNumber: 5,
    extractedValue: 'alert(1)'
  };
  const f1 = createFinding({ ...base, confidence: 0.5 });
  const f2 = createFinding({ ...base, confidence: 0.9 });
  const deduped = deduplicateFindings([f1, f2]);
  assert.equal(deduped.length, 1);
  assert.equal(deduped[0].confidence, 0.9);
});

test('validateFinding accepts a valid finding', () => {
  resetFindingCounter();
  const f = createFinding({
    indicatorCategory: 'javascript',
    description: 'JS',
    detectionRule: 'JAVASCRIPT_DETECTED'
  });
  assert.equal(validateFinding(f).valid, true);
});

test('validateFinding rejects a finding missing required fields', () => {
  const result = validateFinding({ indicatorCategory: 'javascript' });
  assert.equal(result.valid, false);
  assert.ok(result.missing);
});

test('findingsByCategory groups findings', () => {
  resetFindingCounter();
  const f1 = createFinding({ indicatorCategory: 'javascript', description: 'a', detectionRule: 'R1' });
  const f2 = createFinding({ indicatorCategory: 'javascript', description: 'b', detectionRule: 'R2' });
  const f3 = createFinding({ indicatorCategory: 'uri', description: 'c', detectionRule: 'R3' });
  const map = findingsByCategory([f1, f2, f3]);
  assert.equal(map.get('javascript').length, 2);
  assert.equal(map.get('uri').length, 1);
});

test('findingsBySeverity orders by severity', () => {
  resetFindingCounter();
  const f1 = createFinding({ indicatorCategory: 'javascript', description: 'a', severity: Severity.INFO, detectionRule: 'R1' });
  const f2 = createFinding({ indicatorCategory: 'javascript', description: 'b', severity: Severity.CRITICAL, detectionRule: 'R2' });
  const map = findingsBySeverity([f1, f2]);
  assert.equal(map.get(Severity.CRITICAL).length, 1);
  assert.equal(map.get(Severity.INFO).length, 1);
});