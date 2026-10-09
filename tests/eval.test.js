import test from 'node:test';
import assert from 'node:assert/strict';
import { generateCategorization, ruleEngineFloor, CATEGORY_KEYS } from '../src/categorizer/rules.js';

const findings = [
  { findingId: 'F2-1', category: 'active_content', text: 'JavaScript executed and OpenAction triggered', severity: 'high' },
  { findingId: 'F6-1', category: 'structural_anomalies', text: 'bad startxref and multiple %%EOF', severity: 'medium' }
];

test('rule engine produces all categories', () => {
  const result = generateCategorization({ findings, scanStatus: 'complete', confidence: 0.9 });
  assert.deepEqual(Object.keys(result.categories).sort(), CATEGORY_KEYS.slice().sort());
  assert.equal(result.categories.behavioral_signals.rating, 'high');
  assert.equal(result.categories.metadata_signals.rating, 'medium');
  assert.equal(result.overall.isCleanClaim, false);
});

test('rule engine enforces floor and not_assessed', () => {
  const result = generateCategorization({ findings: [], scanStatus: 'complete', confidence: 0.7 });
  assert.equal(result.categories.provenance_signals.rating, 'not_assessed');
  assert.ok(result.confidence > 0);
  assert.equal(ruleEngineFloor(result.categories.behavioral_signals), 'not_assessed');
});
