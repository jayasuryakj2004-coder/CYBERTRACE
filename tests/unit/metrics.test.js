import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  confusionMatrix,
  precision,
  recall,
  f1Score,
  accuracy,
  falsePositiveRate,
  falseNegativeRate,
  computeMetrics,
  perIndicatorPerformance,
  generateSummary
} from '../../src/evaluation/metrics.js';

function makeSample({ sampleId, label, riskScore, scanStatus = 'completed', knownIndicators = [], detectedFindings = [] }) {
  return {
    sampleId,
    label,
    riskScore,
    scanStatus,
    knownIndicators,
    detectedFindings
  };
}

test('confusionMatrix counts TP/TN/FP/FN correctly', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'suspicious', riskScore: 60 }),
    makeSample({ sampleId: 's3', label: 'benign', riskScore: 10 }),
    makeSample({ sampleId: 's4', label: 'benign', riskScore: 20 }),
    makeSample({ sampleId: 's5', label: 'benign', riskScore: 70 }),  // FP
    makeSample({ sampleId: 's6', label: 'suspicious', riskScore: 30 }) // FN
  ];
  const cm = confusionMatrix(samples, { threshold: 50 });
  assert.equal(cm.tp, 2);
  assert.equal(cm.tn, 2);
  assert.equal(cm.fp, 1);
  assert.equal(cm.fn, 1);
});

test('confusionMatrix excludes failed scans', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'benign', riskScore: 10, scanStatus: 'failed', error: 'boom' })
  ];
  const cm = confusionMatrix(samples, { threshold: 50 });
  assert.equal(cm.tp, 1);
  assert.equal(cm.failed, 1);
  assert.equal(cm.errors.length, 1);
});

test('confusionMatrix excludes incomplete scans', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'benign', riskScore: 10, scanStatus: 'incomplete' })
  ];
  const cm = confusionMatrix(samples, { threshold: 50 });
  assert.equal(cm.tn, 0);
  assert.equal(cm.incomplete, 1);
});

test('confusionMatrix excludes unknown labels', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'unknown', riskScore: 10 })
  ];
  const cm = confusionMatrix(samples, { threshold: 50 });
  assert.equal(cm.unknown, 1);
});

test('precision returns null for zero denominator', () => {
  assert.equal(precision(0, 0), null);
});

test('precision computes correctly', () => {
  assert.equal(precision(3, 1), 0.75);
});

test('recall returns null for zero denominator', () => {
  assert.equal(recall(0, 0), null);
});

test('recall computes correctly', () => {
  assert.equal(recall(3, 1), 0.75);
});

test('f1Score returns null for null inputs', () => {
  assert.equal(f1Score(null, 0.5), null);
  assert.equal(f1Score(0.5, null), null);
});

test('f1Score returns null for zero denominator', () => {
  assert.equal(f1Score(0, 0), null);
});

test('f1Score computes correctly', () => {
  const p = 0.5, r = 0.5;
  assert.equal(f1Score(p, r), 0.5);
});

test('accuracy returns null for zero denominator', () => {
  assert.equal(accuracy(0, 0, 0, 0), null);
});

test('accuracy computes correctly', () => {
  assert.equal(accuracy(3, 3, 1, 1), 0.75);
});

test('falsePositiveRate returns null for zero denominator', () => {
  assert.equal(falsePositiveRate(0, 0), null);
});

test('falsePositiveRate computes correctly', () => {
  assert.equal(falsePositiveRate(1, 3), 0.25);
});

test('falseNegativeRate computes correctly', () => {
  assert.equal(falseNegativeRate(1, 3), 0.25);
});

test('computeMetrics returns undefined flags for zero denominators', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'benign', riskScore: 10 })
  ];
  const m = computeMetrics(samples, { threshold: 50 });
  // Only TN, no TP/FP/FN => precision undefined, recall undefined
  assert.equal(m.confusionMatrix.tn, 1);
  assert.equal(m.undefinedMetrics.precision, true);
  assert.equal(m.undefinedMetrics.recall, true);
  assert.equal(m.undefinedMetrics.f1Score, true);
  assert.equal(m.undefinedMetrics.accuracy, false); // accuracy is defined (1/1)
});

test('computeMetrics computes correct metrics on known case', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'suspicious', riskScore: 60 }),
    makeSample({ sampleId: 's3', label: 'benign', riskScore: 10 }),
    makeSample({ sampleId: 's4', label: 'benign', riskScore: 20 })
  ];
  const m = computeMetrics(samples, { threshold: 50 });
  assert.equal(m.confusionMatrix.tp, 2);
  assert.equal(m.confusionMatrix.tn, 2);
  assert.equal(m.confusionMatrix.fp, 0);
  assert.equal(m.confusionMatrix.fn, 0);
  assert.equal(m.precision, 1.0);
  assert.equal(m.recall, 1.0);
  assert.equal(m.f1Score, 1.0);
  assert.equal(m.accuracy, 1.0);
  assert.equal(m.falsePositiveRate, 0.0);
});

test('computeMetrics does not classify failures as correct', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'benign', riskScore: 0, scanStatus: 'failed', error: 'parse error' })
  ];
  const m = computeMetrics(samples, { threshold: 50 });
  assert.equal(m.confusionMatrix.tn, 0);
  assert.equal(m.failedScans, 1);
  assert.equal(m.evaluatedSamples, 0);
});

test('perIndicatorPerformance computes per-indicator stats', () => {
  const samples = [
    makeSample({
      sampleId: 's1', label: 'suspicious', riskScore: 80,
      knownIndicators: ['javascript'],
      detectedFindings: [{ indicatorCategory: 'javascript' }]
    }),
    makeSample({
      sampleId: 's2', label: 'suspicious', riskScore: 80,
      knownIndicators: ['javascript'],
      detectedFindings: []  // missed
    })
  ];
  const perf = perIndicatorPerformance(samples);
  assert.equal(perf.javascript.tp, 1);
  assert.equal(perf.javascript.fn, 1);
  assert.equal(perf.javascript.recall, 0.5);
});

test('perIndicatorPerformance counts false positives', () => {
  const samples = [
    makeSample({
      sampleId: 's1', label: 'benign', riskScore: 10,
      knownIndicators: [],
      detectedFindings: [{ indicatorCategory: 'javascript' }]  // FP
    })
  ];
  const perf = perIndicatorPerformance(samples);
  assert.equal(perf.javascript.fp, 1);
  assert.equal(perf.javascript.precision, 0.0);
});

test('generateSummary produces non-empty string with metrics', () => {
  const samples = [
    makeSample({ sampleId: 's1', label: 'suspicious', riskScore: 80 }),
    makeSample({ sampleId: 's2', label: 'benign', riskScore: 10 })
  ];
  const m = computeMetrics(samples, { threshold: 50 });
  const summary = generateSummary(m, {});
  assert.ok(summary.includes('CyberTrace Evaluation Summary'));
  assert.ok(summary.includes('Precision'));
  assert.ok(summary.includes('Recall'));
});