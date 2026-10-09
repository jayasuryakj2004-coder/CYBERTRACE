// Evaluation metrics for the CyberTrace scanner.
// Handles zero denominators as undefined (null), never silently
// classifies scan failures as correct results.

export function confusionMatrix(samples, options = {}) {
  const { threshold = 50, labelField = 'label', scoreField = 'riskScore' } = options;

  let tp = 0, tn = 0, fp = 0, fn = 0;
  let failed = 0, incomplete = 0, unknown = 0;
  const errors = [];

  for (const sample of samples) {
    const label = sample[labelField];
    const status = sample.scanStatus;
    const score = sample[scoreField];

    if (status === 'failed') {
      failed++;
      errors.push({ sampleId: sample.sampleId, reason: sample.error || 'scan failed' });
      continue;
    }
    if (status === 'incomplete') {
      incomplete++;
      continue;
    }
    if (label === 'unknown') {
      unknown++;
      continue;
    }
    if (label !== 'benign' && label !== 'suspicious') {
      unknown++;
      continue;
    }
    if (typeof score !== 'number') {
      unknown++;
      continue;
    }

    const predicted = score >= threshold ? 'suspicious' : 'benign';
    const actual = label;

    if (predicted === 'suspicious' && actual === 'suspicious') tp++;
    else if (predicted === 'benign' && actual === 'benign') tn++;
    else if (predicted === 'suspicious' && actual === 'benign') fp++;
    else if (predicted === 'benign' && actual === 'suspicious') fn++;
  }

  return { tp, tn, fp, fn, failed, incomplete, unknown, errors };
}

export function precision(tp, fp) {
  const denom = tp + fp;
  return denom === 0 ? null : tp / denom;
}

export function recall(tp, fn) {
  const denom = tp + fn;
  return denom === 0 ? null : tp / denom;
}

export function f1Score(prec, rec) {
  if (prec === null || rec === null) return null;
  const denom = prec + rec;
  return denom === 0 ? null : (2 * prec * rec) / denom;
}

export function accuracy(tp, tn, fp, fn) {
  const denom = tp + tn + fp + fn;
  return denom === 0 ? null : (tp + tn) / denom;
}

export function falsePositiveRate(fp, tn) {
  const denom = fp + tn;
  return denom === 0 ? null : fp / denom;
}

export function falseNegativeRate(fn, tp) {
  const denom = fn + tp;
  return denom === 0 ? null : fn / denom;
}

export function computeMetrics(samples, options = {}) {
  const cm = confusionMatrix(samples, options);
  const prec = precision(cm.tp, cm.fp);
  const rec = recall(cm.tp, cm.fn);
  const f1 = f1Score(prec, rec);
  const acc = accuracy(cm.tp, cm.tn, cm.fp, cm.fn);
  const fpr = falsePositiveRate(cm.fp, cm.tn);
  const fnr = falseNegativeRate(cm.fn, cm.tp);

  const evaluated = cm.tp + cm.tn + cm.fp + cm.fn;
  const total = samples.length;

  return {
    threshold: options.threshold ?? 50,
    confusionMatrix: { tp: cm.tp, tn: cm.tn, fp: cm.fp, fn: cm.fn },
    precision: round4(prec),
    recall: round4(rec),
    f1Score: round4(f1),
    accuracy: round4(acc),
    falsePositiveRate: round4(fpr),
    falseNegativeRate: round4(fnr),
    evaluatedSamples: evaluated,
    totalSamples: total,
    failedScans: cm.failed,
    incompleteScans: cm.incomplete,
    unknownLabels: cm.unknown,
    failedAnalysisRate: total === 0 ? null : cm.failed / total,
    incompleteAnalysisRate: total === 0 ? null : cm.incomplete / total,
    errors: cm.errors,
    undefinedMetrics: {
      precision: prec === null,
      recall: rec === null,
      f1Score: f1 === null,
      accuracy: acc === null,
      falsePositiveRate: fpr === null,
      falseNegativeRate: fnr === null
    }
  };
}

export function perIndicatorPerformance(samples, options = {}) {
  const indicatorMap = new Map();

  for (const sample of samples) {
    if (sample.scanStatus !== 'completed') continue;
    const findings = sample.detectedFindings || [];
    const detectedIndicators = new Set(findings.map(f => f.indicatorCategory));

    for (const indicator of sample.knownIndicators || []) {
      if (!indicatorMap.has(indicator)) {
        indicatorMap.set(indicator, { tp: 0, fp: 0, fn: 0, tn: 0 });
      }
      const counts = indicatorMap.get(indicator);
      if (detectedIndicators.has(indicator)) {
        counts.tp++;
      } else {
        counts.fn++;
      }
    }

    for (const detected of detectedIndicators) {
      if (!indicatorMap.has(detected)) {
        indicatorMap.set(detected, { tp: 0, fp: 0, fn: 0, tn: 0 });
      }
      const counts = indicatorMap.get(detected);
      const known = (sample.knownIndicators || []).includes(detected);
      if (!known) {
        counts.fp++;
      }
    }
  }

  const result = {};
  for (const [indicator, counts] of indicatorMap) {
    const prec = precision(counts.tp, counts.fp);
    const rec = recall(counts.tp, counts.fn);
    result[indicator] = {
      ...counts,
      precision: round4(prec),
      recall: round4(rec),
      f1Score: round4(f1Score(prec, rec))
    };
  }
  return result;
}

export function generateSummary(metrics, perIndicator) {
  const lines = [
    '=== CyberTrace Evaluation Summary ===',
    `Threshold: ${metrics.threshold}`,
    `Evaluated samples: ${metrics.evaluatedSamples} / ${metrics.totalSamples}`,
    `Failed scans: ${metrics.failedScans} (${pct(metrics.failedAnalysisRate)})`,
    `Incomplete scans: ${metrics.incompleteScans} (${pct(metrics.incompleteAnalysisRate)})`,
    `Unknown labels: ${metrics.unknownLabels}`,
    '',
    'Confusion Matrix:',
    `  TP=${metrics.confusionMatrix.tp} TN=${metrics.confusionMatrix.tn} FP=${metrics.confusionMatrix.fp} FN=${metrics.confusionMatrix.fn}`,
    '',
    'Metrics:',
    `  Precision: ${fmt(metrics.precision)}`,
    `  Recall: ${fmt(metrics.recall)}`,
    `  F1 Score: ${fmt(metrics.f1Score)}`,
    `  Accuracy: ${fmt(metrics.accuracy)}`,
    `  False Positive Rate: ${fmt(metrics.falsePositiveRate)}`,
    `  False Negative Rate: ${fmt(metrics.falseNegativeRate)}`,
    ''
  ];

  if (perIndicator && Object.keys(perIndicator).length > 0) {
    lines.push('Per-Indicator Performance:');
    for (const [indicator, perf] of Object.entries(perIndicator)) {
      lines.push(
        `  ${indicator}: TP=${perf.tp} FP=${perf.fp} FN=${perf.fn} ` +
        `P=${fmt(perf.precision)} R=${fmt(perf.recall)} F1=${fmt(perf.f1Score)}`
      );
    }
  }

  if (metrics.errors && metrics.errors.length > 0) {
    lines.push('', 'Failed scan errors:');
    for (const err of metrics.errors) {
      lines.push(`  ${err.sampleId}: ${err.reason}`);
    }
  }

  return lines.join('\n');
}

function round4(value) {
  return value === null ? null : Math.round(value * 10000) / 10000;
}

function fmt(value) {
  return value === null ? 'undefined' : value.toFixed(4);
}

function pct(value) {
  return value === null ? 'undefined' : `${(value * 100).toFixed(1)}%`;
}