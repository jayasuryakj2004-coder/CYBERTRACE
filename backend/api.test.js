import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';

process.env.CYBERTRACE_API_TOKEN = 'test-only-backend-token-1234567890';
process.env.GEMINI_API_KEY = '';
const { app } = await import('./api.js');
let server;
let baseUrl;

before(async () => {
  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (server) await new Promise(resolve => server.close(resolve));
});

test('health reports backend availability without revealing credentials', async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.status, 'ok');
  assert.equal(body.aiConfigured, false);
  assert.equal(JSON.stringify(body).includes('test-only-backend-token'), false);
});

test('analysis endpoint requires backend authentication', async () => {
  const response = await fetch(`${baseUrl}/api/analyze`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: 'Backend access token required.' });
});

test('authenticated oversized requests are rejected at the parser boundary', async () => {
  const response = await fetch(`${baseUrl}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test-only-backend-token-1234567890' },
    body: JSON.stringify({ padding: 'x'.repeat(100_000) })
  });
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { error: 'Request body exceeds the 96 KB limit.' });
});