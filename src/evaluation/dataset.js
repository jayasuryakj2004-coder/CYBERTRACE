// Labeled evaluation dataset definition.
// Each record has an independent reference label and known indicator labels.
// knownIndicators lists ALL indicators genuinely present in the sample,
// determined from fixture construction (NOT from scanner output).
// File-level labels are distinct from indicator labels.
// A PDF containing JavaScript is NOT automatically malicious.
// The scanner's prediction is NEVER used as ground truth.

export const DatasetSample = {
  sampleId: '',
  fileName: '',
  label: 'unknown',
  knownIndicators: [],
  provenance: '',
  notes: ''
};

export const EVALUATION_DATASET_VERSION = '1.0.0';

export const EVALUATION_DATASET = [
  {
    sampleId: 'benign-001',
    fileName: 'benign-ordinary.pdf',
    label: 'benign',
    knownIndicators: ['metadata_anomaly'],
    provenance: 'synthetic',
    notes: 'Ordinary PDF with catalog, pages, and text. No /Info dictionary (missing metadata is not malicious).'
  },
  {
    sampleId: 'benign-002',
    fileName: 'benign-link.pdf',
    label: 'benign',
    knownIndicators: ['metadata_anomaly', 'uri'],
    provenance: 'synthetic',
    notes: 'PDF with a legitimate external HTTPS link. Links are common and benign.'
  },
  {
    sampleId: 'benign-003',
    fileName: 'benign-form.pdf',
    label: 'benign',
    knownIndicators: ['metadata_anomaly', 'form'],
    provenance: 'synthetic',
    notes: 'PDF with an AcroForm. Forms are common in legitimate documents.'
  },
  {
    sampleId: 'benign-004',
    fileName: 'benign-metadata.pdf',
    label: 'benign',
    knownIndicators: [],
    provenance: 'synthetic',
    notes: 'PDF with full /Info metadata (title, author, subject, creator, producer, dates). No indicators.'
  },
  {
    sampleId: 'suspicious-001',
    fileName: 'suspicious-javascript.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'javascript', 'open_action'],
    provenance: 'synthetic',
    notes: 'PDF with a /JavaScript action auto-triggered via /OpenAction. JavaScript is a strong indicator but not proof of malware.'
  },
  {
    sampleId: 'suspicious-002',
    fileName: 'suspicious-openaction.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'open_action', 'javascript'],
    provenance: 'synthetic',
    notes: 'PDF with /OpenAction triggering a JavaScript action on open.'
  },
  {
    sampleId: 'suspicious-003',
    fileName: 'suspicious-embedded.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'embedded_file', 'javascript', 'open_action'],
    provenance: 'synthetic',
    notes: 'PDF with an embedded file attachment (/EmbeddedFiles, /Filespec) and auto-executing JavaScript via /OpenAction.'
  },
  {
    sampleId: 'suspicious-004',
    fileName: 'suspicious-launch.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'launch_action', 'open_action'],
    provenance: 'synthetic',
    notes: 'PDF with a /Launch action auto-triggered via /OpenAction. Strong indicator; modern viewers block execution.'
  },
  {
    sampleId: 'suspicious-005',
    fileName: 'suspicious-uri.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'uri', 'suspicious_uri', 'javascript', 'open_action'],
    provenance: 'synthetic',
    notes: 'PDF with multiple URIs using IP-literal hosts (heuristic suspicious pattern) and auto-executing JavaScript.'
  },
  {
    sampleId: 'suspicious-006',
    fileName: 'suspicious-additional-action.pdf',
    label: 'suspicious',
    knownIndicators: ['metadata_anomaly', 'additional_action', 'javascript'],
    provenance: 'synthetic',
    notes: 'PDF with /AA additional actions containing JavaScript.'
  },
  {
    sampleId: 'edge-001',
    fileName: 'edge-malformed.pdf',
    label: 'unknown',
    knownIndicators: [],
    provenance: 'synthetic',
    notes: 'Malformed PDF (missing %PDF- header). Expected to fail parsing; must NOT be scored as benign.'
  },
  {
    sampleId: 'edge-002',
    fileName: 'edge-truncated.pdf',
    label: 'unknown',
    knownIndicators: [],
    provenance: 'synthetic',
    notes: 'Truncated PDF (no %%EOF marker). Expected to be incomplete; must NOT be scored as benign.'
  },
  {
    sampleId: 'edge-003',
    fileName: 'edge-encrypted.pdf',
    label: 'unknown',
    knownIndicators: ['metadata_anomaly', 'encryption'],
    provenance: 'synthetic',
    notes: 'Encrypted PDF (/Encrypt in trailer). Structural inspection is limited; label is unknown.'
  },
  {
    sampleId: 'edge-004',
    fileName: 'edge-no-metadata.pdf',
    label: 'benign',
    knownIndicators: ['metadata_anomaly'],
    provenance: 'synthetic',
    notes: 'Valid PDF with no /Info dictionary. Missing metadata is not malicious.'
  },
  {
    sampleId: 'edge-005',
    fileName: 'edge-incremental.pdf',
    label: 'benign',
    knownIndicators: ['metadata_anomaly', 'incremental_update', 'uri'],
    provenance: 'synthetic',
    notes: 'PDF with incremental update (two %%EOF markers) and a link annotation in the second revision. Common from editors; benign.'
  }
];

export function getSample(sampleId) {
  return EVALUATION_DATASET.find(s => s.sampleId === sampleId) || null;
}

export function getSamplesByLabel(label) {
  return EVALUATION_DATASET.filter(s => s.label === label);
}

export function datasetStats() {
  const stats = { total: EVALUATION_DATASET.length, benign: 0, suspicious: 0, unknown: 0 };
  for (const sample of EVALUATION_DATASET) {
    if (sample.label === 'benign') stats.benign++;
    else if (sample.label === 'suspicious') stats.suspicious++;
    else stats.unknown++;
  }
  return stats;
}

export function toCsv(samples) {
  const header = 'sampleId,fileName,label,knownIndicators,provenance,notes';
  const rows = samples.map(s => [
    s.sampleId,
    s.fileName,
    s.label,
    `"${(s.knownIndicators || []).join(';')}"`,
    s.provenance,
    `"${(s.notes || '').replace(/"/g, '""')}"`
  ].join(','));
  return [header, ...rows].join('\n');
}