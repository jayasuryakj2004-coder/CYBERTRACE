// Professional forensic report palette.
// White background, dark navy headings, restrained blue accent.

export const REPORT_THEME = {
  navy: '#16233F',
  charcoal: '#2B3442',
  body: '#333F50',
  muted: '#5A6577',
  accent: '#2456A6',
  accentLight: '#E8EEF7',
  accentBorder: '#9FB6D9',
  border: '#C7D0DC',
  rowAlt: '#F4F7FB',
  white: '#FFFFFF',
  pageBg: '#FFFFFF',
  critical: '#8B1A1A',
  high: '#B34A12',
  medium: '#8F6400',
  low: '#2456A6',
  info: '#5A6577',
  none: '#2B3442',
  criticalBg: '#8B1A1A',
  criticalText: '#FFFFFF',
  highBg: '#B34A12',
  highText: '#FFFFFF',
  mediumBg: '#D9A00A',
  mediumText: '#2B3442',
  lowBg: '#DCE7F5',
  lowText: '#16233F',
  infoBg: '#EEF1F5',
  infoText: '#2B3442',
  noneBg: '#FFFFFF',
  noneText: '#2B3442',
  notAssessedBg: '#EEF1F5',
  notAssessedText: '#5A6577',
  notAssessedBorder: '#9CA3AF',
  alertBg: '#FBEAEA',
  alertBorder: '#D9A0A0',
  alertText: '#8B1A1A',
  warnBg: '#FFF7E6',
  warnBorder: '#E3C878',
  warnText: '#7A5800'
};

export function ratingStyle(rating) {
  const normalized = (rating || '').toLowerCase();
  switch (normalized) {
    case 'critical': return { bg: REPORT_THEME.criticalBg, text: REPORT_THEME.criticalText, label: 'CRITICAL', color: REPORT_THEME.critical };
    case 'high': return { bg: REPORT_THEME.highBg, text: REPORT_THEME.highText, label: 'HIGH', color: REPORT_THEME.high };
    case 'medium': return { bg: REPORT_THEME.mediumBg, text: REPORT_THEME.mediumText, label: 'MEDIUM', color: REPORT_THEME.medium };
    case 'low': return { bg: REPORT_THEME.lowBg, text: REPORT_THEME.lowText, label: 'LOW', color: REPORT_THEME.low };
    case 'info': return { bg: REPORT_THEME.infoBg, text: REPORT_THEME.infoText, label: 'INFO', color: REPORT_THEME.info };
    case 'none': return { bg: REPORT_THEME.noneBg, text: REPORT_THEME.noneText, label: 'NONE', color: REPORT_THEME.none };
    case 'not_assessed': return { bg: REPORT_THEME.notAssessedBg, text: REPORT_THEME.notAssessedText, label: 'NOT ASSESSED', color: REPORT_THEME.notAssessedText };
    default: return { bg: REPORT_THEME.noneBg, text: REPORT_THEME.noneText, label: 'NONE', color: REPORT_THEME.none };
  }
}

export function severityStyle(severity) {
  const normalized = (severity || '').toLowerCase();
  switch (normalized) {
    case 'critical': return { color: REPORT_THEME.critical, label: 'CRITICAL' };
    case 'high': return { color: REPORT_THEME.high, label: 'HIGH' };
    case 'medium': return { color: REPORT_THEME.medium, label: 'MEDIUM' };
    case 'low': return { color: REPORT_THEME.low, label: 'LOW' };
    case 'info': return { color: REPORT_THEME.info, label: 'INFO' };
    default: return { color: REPORT_THEME.info, label: 'INFO' };
  }
}
