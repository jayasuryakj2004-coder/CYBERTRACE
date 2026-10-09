// Deterministic rule-based risk engine.
// Score is a transparent weighted sum, NOT a calibrated probability.

import { Severity, deduplicateFindings } from './evidence.js';
import { RULES, riskBandForScore, RULE_VERSION } from './rules.js';

const SEVERITY_MULTIPLIER = {
  [Severity.INFO]: 0.5,
  [Severity.LOW]: 0.75,
  [Severity.MEDIUM]: 1.0,
  [Severity.HIGH]: 1.25,
  [Severity.CRITICAL]: 1.5
};

export function computeRisk(findings, config = {}) {
  const requestedMaxScore = Number.isFinite(config.maxScore) ? config.maxScore : 100;
  const maxScore = Math.min(100, Math.max(0, requestedMaxScore));
  const categoryCaps = config.categoryCaps ?? defaultCategoryCaps();

  const unique = deduplicateFindings(findings);

  const contributions = [];
  const categoryTotals = new Map();
  let contributingCount = 0;

  for (const finding of unique) {
    const rule = RULES[finding.detectionRule];
    if (!rule) continue;

    contributingCount++;

    const baseWeight = rule.weight;
    const severityMultiplier = SEVERITY_MULTIPLIER[finding.severity] ?? 1.0;
    const confidenceFactor = clamp(finding.confidence, 0, 1);

    let contribution = baseWeight * severityMultiplier * confidenceFactor;
    contribution = round2(contribution);

    const cap = categoryCaps[rule.name] ?? Infinity;
    const currentCategoryTotal = categoryTotals.get(rule.name) ?? 0;
    const allowed = Math.max(0, cap - currentCategoryTotal);
    const applied = Math.min(contribution, allowed);

    if (applied > 0) {
      categoryTotals.set(rule.name, round2(currentCategoryTotal + applied));
      contributions.push({
        findingId: finding.findingId,
        rule: rule.name,
        ruleId: rule.id,
        indicatorCategory: finding.indicatorCategory,
        severity: finding.severity,
        baseWeight,
        severityMultiplier,
        confidenceFactor,
        contribution: applied,
        capped: applied < contribution,
        categoryCap: cap,
        explanation: rule.explanation
      });
    }
  }

  const rawScore = contributions.reduce((sum, c) => sum + c.contribution, 0);
  const score = Math.min(maxScore, round2(rawScore));
  const level = riskBandForScore(score);

  const factors = contributions
    .sort((a, b) => b.contribution - a.contribution)
    .map(c => ({
      rule: c.rule,
      indicatorCategory: c.indicatorCategory,
      severity: c.severity,
      contribution: c.contribution,
      explanation: c.explanation
    }));

  const categoryBreakdown = Object.fromEntries(
    [...categoryTotals.entries()].map(([k, v]) => [k, v])
  );

  return {
    score,
    level,
    maxScore,
    factors,
    categoryBreakdown,
    contributions,
    findingCount: contributingCount,
    ruleVersion: RULE_VERSION,
    disclaimer: 'Score is a heuristic weighted sum of observed indicators. It is not a calibrated probability of maliciousness.'
  };
}

function defaultCategoryCaps() {
  const caps = {};
  for (const rule of Object.values(RULES)) {
    caps[rule.name] = rule.categoryCap;
  }
  return caps;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function round2(value) {
  return Math.round(value * 100) / 100;
}

export function scoreIsComplete(scanStatus) {
  return scanStatus === 'completed';
}

export function explainScore(riskResult) {
  const lines = [
    `Risk score: ${riskResult.score}/${riskResult.maxScore} (${riskResult.level})`,
    `Based on ${riskResult.findingCount} unique finding(s) across ${Object.keys(riskResult.categoryBreakdown).length} indicator category(ies).`,
    riskResult.disclaimer
  ];
  for (const factor of riskResult.factors) {
    lines.push(`  + ${factor.contribution.toFixed(2)} from ${factor.rule} [${factor.severity}] — ${factor.explanation}`);
  }
  return lines.join('\n');
}

export { RULE_VERSION };