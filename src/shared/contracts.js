export const ScanStatus = {
  QUEUED: 'queued',
  ANALYZING: 'analyzing',
  COMPLETED: 'completed',
  INCOMPLETE: 'incomplete',
  FAILED: 'failed'
};

export const MessageType = {
  PDF_DETECTED: 'pdf_detected',
  START_ANALYSIS: 'start_analysis',
  ANALYSIS_PROGRESS: 'analysis_progress',
  ANALYSIS_COMPLETE: 'analysis_complete',
  ANALYSIS_FAILED: 'analysis_failed',
  GET_SCAN_STATE: 'get_scan_state',
  SCAN_STATE: 'scan_state',
  RETRY_ANALYSIS: 'retry_analysis',
  OPEN_SIDE_PANEL: 'open_side_panel',
  VIEWER_READY: 'viewer_ready',
  MANUAL_ANALYSIS: 'manual_analysis',
  REQUEST_AI_ANALYSIS: 'request_ai_analysis',
  AI_ANALYSIS_RESULT: 'ai_analysis_result',
  AI_ANALYSIS_ERROR: 'ai_analysis_error',
  GET_HISTORY: 'get_history',
  HISTORY_RESULT: 'history_result',
  CLEAR_HISTORY: 'clear_history',
  EXPORT_REPORT: 'export_report',
  REPORT_RESULT: 'report_result',
  GET_ACCURACY_METRICS: 'get_accuracy_metrics',
  ACCURACY_METRICS_RESULT: 'accuracy_metrics_result',
  AI_CHAT_MESSAGE: 'ai_chat_message',
  AI_CHAT_RESPONSE: 'ai_chat_response'
};

export function createScanResult(overrides = {}) {
  const scanId = overrides.scanId || generateScanId();
  const now = new Date().toISOString();
  
  return {
    scanId,
    timestamp: overrides.timestamp || now,
    completedAt: overrides.completedAt || null,
    fileInfo: overrides.fileInfo || {
      name: 'unknown.pdf',
      size: 0,
      mimeType: 'application/pdf',
      url: '',
      sha256: ''
    },
    status: overrides.status || ScanStatus.QUEUED,
    progress: overrides.progress || 0,
    findings: overrides.findings || [],
    metadata: overrides.metadata || {
      pageCount: 0,
      title: '',
      author: '',
      subject: '',
      keywords: '',
      creator: '',
      producer: '',
      creationDate: '',
      modificationDate: '',
      pdfVersion: '',
      isLinearized: false,
      hasJavaScript: false,
      hasEmbeddedFiles: false,
      hasForms: false,
      hasSignatures: false,
      permissions: {}
    },
    riskAssessment: overrides.riskAssessment || {
      score: 0,
      level: 'unknown',
      factors: []
    },
    limitations: overrides.limitations || [],
    error: overrides.error || null
  };
}

export function generateScanId() {
  return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

export function validateScanResult(result) {
  const required = ['scanId', 'timestamp', 'fileInfo', 'status', 'findings', 'metadata', 'riskAssessment', 'limitations'];
  for (const field of required) {
    if (!(field in result)) {
      return { valid: false, missing: field };
    }
  }
  return { valid: true };
}

export async function computeSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function createMessage(type, payload = {}) {
  return {
    type,
    payload,
    timestamp: new Date().toISOString(),
    id: `${type}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`
  };
}

export function parseMessage(message) {
  if (!message || typeof message !== 'object') return null;
  if (!message.type || !MessageType[message.type.toUpperCase()]) return null;
  return message;
}

export const AIResponseSchema = {
  summary: { type: 'string', maxLength: 500 },
  findings_explanation: {
    type: 'array',
    maxItems: 50,
    items: {
      type: 'object',
      properties: {
        finding_id: { type: 'string' },
        explanation: { type: 'string', maxLength: 300 }
      },
      required: ['finding_id', 'explanation']
    }
  },
  possible_scenarios: {
    type: 'array',
    maxItems: 10,
    items: { type: 'string', maxLength: 200 }
  },
  recommended_actions: {
    type: 'array',
    maxItems: 10,
    items: { type: 'string', maxLength: 200 }
  },
  limitations: {
    type: 'array',
    maxItems: 10,
    items: { type: 'string', maxLength: 200 }
  }
};

export const ReportSchemaVersion = '3.1.0';

export function createReport(scan, aiAnalysis = null) {
  return {
    schemaVersion: ReportSchemaVersion,
    generatedAt: new Date().toISOString(),
    analysisCoverage: {
      status: scan.status,
      pipelineProgress: scan.progress ?? 0,
      limitations: scan.limitations || []
    },
    scan: {
      scanId: scan.scanId,
      timestamp: scan.timestamp,
      completedAt: scan.completedAt,
      status: scan.status,
      progress: scan.progress ?? 0,
      fileInfo: scan.fileInfo,
      metadata: scan.metadata,
      findings: scan.findings,
      riskAssessment: scan.riskAssessment,
      limitations: scan.limitations,
      error: scan.error
    },
    aiAnalysis: aiAnalysis ? {
      ...aiAnalysis,
      disclaimer: 'AI-generated interpretation. Not a substitute for expert forensic analysis. Grounded in scanner evidence only.'
    } : null,
    scanner: {
      name: 'CyberTrace',
      version: '3.0.0',
      ruleEngineVersion: '2.0.0'
    }
  };
}

export function createHistoryEntry(scan) {
  return {
    scanId: scan.scanId,
    timestamp: scan.timestamp,
    completedAt: scan.completedAt,
    fileName: scan.fileInfo.name,
    fileSize: scan.fileInfo.size,
    sha256: scan.fileInfo.sha256,
    url: scan.fileInfo.url,
    status: scan.status,
    riskScore: scan.riskAssessment?.score ?? 0,
    riskLevel: scan.riskAssessment?.level ?? 'unknown',
    findingCount: scan.findings?.length ?? 0,
    hasAIAnalysis: !!scan.aiAnalysis
  };
}