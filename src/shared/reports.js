import { createReport } from './contracts.js';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function safeHttpUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url.href : '';
  } catch {
    return '';
  }
}

export function createJsonReport(scan, aiAnalysis = null) {
  return JSON.stringify(createReport(scan, aiAnalysis), null, 2);
}

export function createHtmlReport(scan, aiAnalysis = null) {
  const report = createReport(scan, aiAnalysis);
  const metadataRows = Object.entries(scan.metadata || {}).map(([key, value]) =>
    `<tr><th>${escapeHtml(key)}</th><td>${escapeHtml(typeof value === 'object' ? JSON.stringify(value) : value)}</td></tr>`
  ).join('');
  const findings = (scan.findings || []).map(finding => `
    <article class="finding">
      <h3>${escapeHtml(finding.description || finding.findingId || 'Finding')}</h3>
      <p><strong>${escapeHtml(finding.indicatorCategory || 'unknown')}</strong> · ${escapeHtml(finding.severity || 'unknown')} · ${escapeHtml(finding.findingId || 'no ID')}</p>
      <p>${escapeHtml(finding.explanation || '')}</p>
      <dl>
        <dt>Evidence reference</dt><dd>${escapeHtml(finding.evidenceReference || 'Not recorded')}</dd>
        <dt>Object</dt><dd>${escapeHtml(finding.objectNumber ?? 'Not recorded')}</dd>
        <dt>Observed value</dt><dd>${escapeHtml(finding.extractedValue || 'Not recorded')}</dd>
        <dt>Detection method</dt><dd>${escapeHtml(finding.detectionMethod || 'Not recorded')}</dd>
      </dl>
    </article>`).join('') || '<p>No findings recorded.</p>';
  const limitations = (scan.limitations || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const factors = (scan.riskAssessment?.factors || []).map(factor => {
    const label = typeof factor === 'string' ? factor : factor.explanation || factor.rule || 'Risk factor';
    const contribution = typeof factor === 'object' ? factor.contribution : null;
    return `<li>${escapeHtml(label)}${typeof contribution === 'number' ? ` (+${escapeHtml(contribution)})` : ''}</li>`;
  }).join('');
  const sourceUrl = safeHttpUrl(scan.fileInfo?.url);
  const source = sourceUrl
    ? `<a rel="noreferrer" href="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</a>`
    : escapeHtml(scan.fileInfo?.url || 'Local file');
  const aiSection = aiAnalysis ? `
    <section><h2>AI interpretation</h2>
      <p class="notice">AI-generated interpretation, not a verdict. Scanner observations remain authoritative.</p>
      <p>${escapeHtml(aiAnalysis.summary)}</p>
      <ul>${(aiAnalysis.recommended_actions || []).map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
    </section>` : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CyberTrace report · ${escapeHtml(scan.fileInfo?.name || scan.scanId)}</title>
<style>body{font:15px/1.55 system-ui,sans-serif;max-width:980px;margin:32px auto;padding:0 20px;color:#17212b}h1,h2{color:#123b43}h1{border-bottom:3px solid #168477;padding-bottom:12px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid #d7e0e4;vertical-align:top;word-break:break-word}th{width:30%;color:#3e5964}.finding{border:1px solid #d7e0e4;padding:14px;margin:12px 0}.finding dl{display:grid;grid-template-columns:150px 1fr;gap:4px 12px}.finding dt{font-weight:600}.finding dd{margin:0;word-break:break-word}.notice{padding:10px;background:#eff7f4;border-left:3px solid #168477}.mono{font-family:ui-monospace,monospace;word-break:break-all}</style></head><body>
<h1>CyberTrace forensic report</h1><p>Interpretation aid only. This report is not digitally signed and does not represent a complete legal chain of custody.</p>
<section><h2>Scan</h2><table>
<tr><th>Report schema</th><td>${escapeHtml(report.schemaVersion)}</td></tr><tr><th>Scan ID</th><td class="mono">${escapeHtml(scan.scanId)}</td></tr>
<tr><th>Generated</th><td>${escapeHtml(report.generatedAt)}</td></tr><tr><th>Started</th><td>${escapeHtml(scan.timestamp)}</td></tr><tr><th>Completed</th><td>${escapeHtml(scan.completedAt || 'Not completed')}</td></tr>
<tr><th>Status</th><td>${escapeHtml(scan.status)}</td></tr><tr><th>Document</th><td>${escapeHtml(scan.fileInfo?.name || 'Unknown')}</td></tr>
<tr><th>Source</th><td>${source}</td></tr><tr><th>Original-byte SHA-256</th><td class="mono">${escapeHtml(scan.fileInfo?.sha256 || 'Unavailable')}</td></tr>
<tr><th>Risk score</th><td>${escapeHtml(scan.riskAssessment?.score ?? 'Unknown')}/100 (${escapeHtml(scan.riskAssessment?.level || 'unknown')})</td></tr>
<tr><th>Analysis limitations</th><td>${(scan.limitations || []).length ? (scan.limitations || []).map(escapeHtml).join('<br>') : 'None recorded'}</td></tr>
</table></section><section><h2>Metadata</h2><table>${metadataRows}</table></section>
<section><h2>Risk contributions</h2><ul>${factors || '<li>None recorded</li>'}</ul></section>
<section><h2>Findings and evidence</h2>${findings}</section>${aiSection}
<footer><p>CyberTrace ${escapeHtml(report.scanner.version)} · Rule engine ${escapeHtml(report.scanner.ruleEngineVersion)}</p></footer></body></html>`;
}

export { safeHttpUrl };