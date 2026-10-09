import { CATEGORY_KEYS } from './rules.js';

export const categorySchema = {
  type: 'object',
  required: ['scanStatus', 'confidence', 'categories', 'possiblyHidden', 'overall'],
  additionalProperties: false,
  properties: {
    scanStatus: { type: 'string', enum: ['complete', 'incomplete', 'failed'] },
    confidence: { type: 'number', minimum: 0, maximum: 1 },
    categories: {
      type: 'object',
      required: CATEGORY_KEYS,
      additionalProperties: false,
      properties: Object.fromEntries(CATEGORY_KEYS.map((key) => [key, {
        type: 'object',
        required: ['rating', 'observations', 'interpretation', 'combinationNotes'],
        additionalProperties: false,
        properties: {
          rating: {
            type: 'string',
            enum: ['none', 'info', 'low', 'medium', 'high', 'critical', 'not_assessed']
          },
          observations: {
            type: 'array',
            items: {
              type: 'object',
              required: ['findingId', 'text'],
              additionalProperties: false,
              properties: {
                findingId: { type: 'string' },
                text: { type: 'string' }
              }
            }
          },
          interpretation: { type: 'string' },
          combinationNotes: { type: ['string', 'null'] }
        }
      }]))
    },
    possiblyHidden: { type: 'array', items: { type: 'string' } },
    overall: {
      type: 'object',
      required: ['rating', 'summary', 'isCleanClaim'],
      additionalProperties: false,
      properties: {
        rating: { type: 'string', enum: ['none', 'info', 'low', 'medium', 'high', 'critical', 'not_assessed'] },
        summary: { type: 'string' },
        isCleanClaim: { type: 'boolean' }
      }
    }
  }
};

export function validateSchema(result) {
  if (!result || typeof result !== 'object') return false;
  if (!result.categories || typeof result.categories !== 'object') return false;
  if (Object.keys(result.categories).sort().join(',') !== CATEGORY_KEYS.slice().sort().join(',')) return false;
  if (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 1) return false;
  for (const key of CATEGORY_KEYS) {
    const entry = result.categories[key];
    if (!entry || !['none','info','low','medium','high','critical','not_assessed'].includes(entry.rating)) return false;
    if (!Array.isArray(entry.observations)) return false;
  }
  return result.scanStatus === 'complete' || result.scanStatus === 'incomplete' || result.scanStatus === 'failed';
}
