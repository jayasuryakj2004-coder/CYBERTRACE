import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sendToSidePanel } from '../../src/shared/messaging.js';

test('background service worker module links and registers with Chrome APIs', async () => {
  const registered = [];
  const storage = { cybertrace_settings: { autoAnalyze: false } };
  globalThis.chrome = {
    storage: {
      local: {
        get: async key => ({ [key]: storage[key] }),
        set: async values => Object.assign(storage, values),
        remove: async key => { delete storage[key]; }
      },
      onChanged: { addListener: () => {} }
    },
    runtime: {
      onMessage: { addListener: listener => registered.push(['message', listener]) },
      onInstalled: { addListener: listener => registered.push(['installed', listener]) },
      sendMessage: async () => ({}),
      getURL: path => `chrome-extension://test/${path}`
    },
    tabs: {
      onUpdated: { addListener: listener => registered.push(['updated', listener]) },
      onRemoved: { addListener: listener => registered.push(['removed', listener]) },
      update: async () => {},
      get: async () => ({ url: 'https://example.test/file.pdf' }),
      sendMessage: async () => ({})
    },
    sidePanel: {
      setPanelBehavior: async () => {},
      open: async () => {}
    }
  };

  try {
    await import(`../../src/background.js?load-test=${Date.now()}`);
    assert.deepEqual(registered.map(([event]) => event).sort(), ['installed', 'message', 'removed', 'updated']);

    const messageListener = registered.find(([event]) => event === 'message')[1];
    const pdfUrl = 'https://example.test/document.pdf';
    const pdfBuffer = new TextEncoder().encode('%PDF-1.7\n%%EOF').buffer;
    const response = await new Promise(resolve => {
      const keepChannelOpen = messageListener({
        type: 'pdf_detected',
        payload: { pdfUrl, pdfBuffer, fileName: 'document.pdf', mimeType: 'application/pdf' }
      }, { tab: { id: 7 }, url: pdfUrl }, resolve);
      assert.equal(keepChannelOpen, true);
    });

    assert.equal(response.success, true);
    assert.equal(storage.cybertrace_current_scan.fileInfo.url, pdfUrl);
    assert.equal(storage.cybertrace_current_scan.status, 'queued');
  } finally {
    delete globalThis.chrome;
  }
});

test('extension CSP permits requests to local PDF files', () => {
  const manifest = JSON.parse(readFileSync(new URL('../../manifest.json', import.meta.url), 'utf8'));
  const connectDirective = manifest.content_security_policy.extension_pages
    .split(';')
    .find(directive => directive.trim().startsWith('connect-src '));

  assert.ok(connectDirective?.includes('file:'), 'connect-src should allow file URLs');
});

test('side panel notifications tolerate a closed panel', async () => {
  const originalChrome = globalThis.chrome;
  globalThis.chrome = {
    runtime: {
      sendMessage: async () => {
        throw new Error('Could not establish connection. Receiving end does not exist.');
      }
    }
  };

  try {
    await assert.doesNotReject(sendToSidePanel({ type: 'analysis_progress', payload: {} }));
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});