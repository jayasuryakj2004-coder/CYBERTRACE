import dotenv from 'dotenv';
import { timingSafeEqual } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { analyzeWithGemini, answerWithGemini, configuredModel } from './gemini.js';
import { validateScanRequest } from './validation.js';

const backendDir = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: resolve(backendDir, '.env') });

const app = express();
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3001);
const API_TOKEN = process.env.CYBERTRACE_API_TOKEN || '';
const configuredOrigins = (process.env.CORS_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean);
const loopbackHost = ['127.0.0.1', 'localhost', '::1'].includes(HOST);

if (!loopbackHost && API_TOKEN.length < 32) {
  throw new Error('CYBERTRACE_API_TOKEN must be at least 32 characters when binding outside loopback');
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, false);
    const extensionOrigin = loopbackHost && /^chrome-extension:\/\/[a-p]{32}$/.test(origin);
    const localhostOrigin = process.env.NODE_ENV !== 'production' && /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/.test(origin);
    callback(null, extensionOrigin || localhostOrigin || configuredOrigins.includes(origin));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false,
  maxAge: 600
}));
app.use(express.json({ limit: '96kb', strict: true }));

const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 12,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Request limit reached; wait before retrying.' }
});

function hasValidToken(header) {
  if (API_TOKEN.length < 32 || typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const supplied = Buffer.from(header.slice(7));
  const expected = Buffer.from(API_TOKEN);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

function requireAuthentication(req, res, next) {
  if (!API_TOKEN) return res.status(503).json({ error: 'AI backend authentication is not configured.' });
  if (!hasValidToken(req.get('authorization'))) return res.status(401).json({ error: 'Backend access token required.' });
  next();
}

function eligibleScan(scan, res) {
  if (!['completed', 'incomplete'].includes(scan.status)) {
    res.status(409).json({ error: 'Wait for forensic analysis to complete before requesting AI interpretation.' });
    return false;
  }
  return true;
}

function healthPayload() {
  return { status: 'ok', aiConfigured: Boolean(process.env.GEMINI_API_KEY), model: configuredModel };
}

app.get('/health', (_req, res) => {
  res.json(healthPayload());
});

app.get('/api/health', (_req, res) => {
  res.json(healthPayload());
});

app.post('/scan', apiLimiter, requireAuthentication, async (req, res) => {
  const validation = validateScanRequest(req.body);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  if (!eligibleScan(validation.scan, res)) return;
  try {
    res.json(await analyzeWithGemini(validation.scan));
  } catch (error) {
    const code = error.message;
    console.warn('CyberTrace AI request unavailable:', code);
    if (code === 'AI_NOT_CONFIGURED') return res.status(503).json({ error: 'Gemini is not configured on this backend.' });
    if (code === 'AI_QUOTA') return res.status(429).json({ error: 'Gemini quota is unavailable; retry later.' });
    return res.status(502).json({ error: 'AI response unavailable or invalid; scanner results are unchanged.' });
  }
});

app.post('/categorize', apiLimiter, requireAuthentication, async (req, res) => {
  const validation = validateScanRequest(req.body);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  if (!eligibleScan(validation.scan, res)) return;
  try {
    res.json(await analyzeWithGemini(validation.scan));
  } catch (error) {
    const code = error.message;
    console.warn('CyberTrace AI request unavailable:', code);
    if (code === 'AI_NOT_CONFIGURED') return res.status(503).json({ error: 'Gemini is not configured on this backend.' });
    if (code === 'AI_QUOTA') return res.status(429).json({ error: 'Gemini quota is unavailable; retry later.' });
    return res.status(502).json({ error: 'AI response unavailable or invalid; scanner results are unchanged.' });
  }
});

app.post('/api/analyze', apiLimiter, requireAuthentication, async (req, res) => {
  const validation = validateScanRequest(req.body);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  if (!eligibleScan(validation.scan, res)) return;
  try {
    res.json(await analyzeWithGemini(validation.scan));
  } catch (error) {
    const code = error.message;
    console.warn('CyberTrace AI request unavailable:', code);
    if (code === 'AI_NOT_CONFIGURED') return res.status(503).json({ error: 'Gemini is not configured on this backend.' });
    if (code === 'AI_QUOTA') return res.status(429).json({ error: 'Gemini quota is unavailable; retry later.' });
    return res.status(502).json({ error: 'AI response unavailable or invalid; scanner results are unchanged.' });
  }
});

app.post('/api/ask', apiLimiter, requireAuthentication, async (req, res) => {
  const validation = validateScanRequest(req.body, true);
  if (!validation.valid) return res.status(400).json({ error: validation.error });
  if (!eligibleScan(validation.scan, res)) return;
  try {
    res.json(await answerWithGemini(validation.scan, req.body.question.trim()));
  } catch (error) {
    const code = error.message;
    console.warn('CyberTrace AI question unavailable:', code);
    if (code === 'AI_NOT_CONFIGURED') return res.status(503).json({ error: 'Gemini is not configured on this backend.' });
    if (code === 'AI_QUOTA') return res.status(429).json({ error: 'Gemini quota is unavailable; retry later.' });
    return res.status(502).json({ error: 'AI response unavailable or invalid; scanner results are unchanged.' });
  }
});

app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body exceeds the 96 KB limit.' });
  if (error instanceof SyntaxError) return res.status(400).json({ error: 'Request body must be valid JSON.' });
  console.error('CyberTrace backend request failed.');
  return res.status(500).json({ error: 'Internal server error.' });
});

export { app };

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`CyberTrace backend listening on http://${HOST}:${PORT}`);
    console.log(`Gemini model: ${configuredModel}; API key configured: ${Boolean(process.env.GEMINI_API_KEY)}`);
    if (API_TOKEN.length < 32) console.warn('AI routes disabled until CYBERTRACE_API_TOKEN is set to at least 32 characters.');
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 35_000;
  server.keepAliveTimeout = 5_000;
}