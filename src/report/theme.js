export const REPORT_THEME = {
  primary: '#EA580C',
  accent: '#F97316',
  tint: '#FFF7ED',
  borderTint: '#FED7AA',
  text: '#1F2937',
  muted: '#6B7280',
  white: '#FFFFFF',
  criticalBg: '#9A3412',
  criticalText: '#FFFFFF',
  highBg: '#EA580C',
  highText: '#FFFFFF',
  mediumBg: '#FB923C',
  mediumText: '#1F2937',
  lowBg: '#FDBA74',
  lowText: '#1F2937',
  infoBg: '#FFEDD5',
  infoText: '#1F2937',
  noneBg: '#FFFFFF',
  noneText: '#1F2937',
  notAssessedBg: '#F3F4F6',
  notAssessedText: '#6B7280',
  notAssessedBorder: '#9CA3AF'
};

export function ratingStyle(rating) {
  const normalized = (rating || '').toLowerCase();
  switch (normalized) {
    case 'critical': return { bg: REPORT_THEME.criticalBg, text: REPORT_THEME.criticalText, label: 'CRITICAL' };
    case 'high': return { bg: REPORT_THEME.highBg, text: REPORT_THEME.highText, label: 'HIGH' };
    case 'medium': return { bg: REPORT_THEME.mediumBg, text: REPORT_THEME.mediumText, label: 'MEDIUM' };
    case 'low': return { bg: REPORT_THEME.lowBg, text: REPORT_THEME.lowText, label: 'LOW' };
    case 'info': return { bg: REPORT_THEME.infoBg, text: REPORT_THEME.infoText, label: 'INFO' };
    case 'none': return { bg: REPORT_THEME.noneBg, text: REPORT_THEME.noneText, label: 'NONE' };
    case 'not_assessed': return { bg: REPORT_THEME.notAssessedBg, text: REPORT_THEME.notAssessedText, label: 'NOT ASSESSED' };
    default: return { bg: REPORT_THEME.noneBg, text: REPORT_THEME.noneText, label: 'NONE' };
  }
}
