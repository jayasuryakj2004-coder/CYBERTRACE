(function() {
  'use strict';
  const MAX_PDF_BYTES = 100 * 1024 * 1024;

  async function readPdfBytes(response) {
    const contentLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB limit');
    if (!response.body?.getReader) {
      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB limit');
      return buffer;
    }
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_PDF_BYTES) {
          await reader.cancel();
          throw new Error('PDF exceeds the 100 MiB limit');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes.buffer;
  }

  const isPdfUrl = (url) => {
    try {
      const parsed = new URL(url);
      return parsed.pathname.toLowerCase().endsWith('.pdf') || 
             parsed.searchParams.has('format') && parsed.searchParams.get('format') === 'pdf';
    } catch {
      return false;
    }
  };

  const isPdfResponse = (response) => {
    const contentType = response.headers.get('content-type') || '';
    return contentType.includes('application/pdf');
  };

  let pdfDetected = false;

  async function detectAndReportPdf() {
    if (pdfDetected) return;
    
    if (isPdfUrl(window.location.href)) {
      pdfDetected = true;
      if (!await reportPdf(window.location.href)) pdfDetected = false;
      return;
    }

    if (document.contentType === 'application/pdf') {
      pdfDetected = true;
      if (!await reportPdf(window.location.href)) pdfDetected = false;
      return;
    }

    const embed = document.querySelector('embed[type="application/pdf"], object[type="application/pdf"]');
    if (embed && embed.src) {
      pdfDetected = true;
      if (!await reportPdf(embed.src)) pdfDetected = false;
      return;
    }

    const iframe = document.querySelector('iframe[src$=".pdf"]');
    if (iframe) {
      pdfDetected = true;
      if (!await reportPdf(iframe.src)) pdfDetected = false;
      return;
    }
  }

  // Only report the URL; the service worker fetches the bytes itself.
  // (ArrayBuffers cannot cross chrome.runtime.sendMessage - they arrive as {}.)
  async function reportPdf(pdfUrl) {
    const fileName = decodeURIComponent(pdfUrl.split('?')[0].split('/').pop() || 'document.pdf');
    return new Promise(resolve => chrome.runtime.sendMessage({
      type: 'pdf_detected',
      payload: { pdfUrl, fileName, mimeType: 'application/pdf' }
    }, (response) => {
      if (chrome.runtime.lastError) {
        console.warn('CyberTrace: Could not send PDF to background', chrome.runtime.lastError.message);
        resolve(false);
      } else {
        resolve(Boolean(response?.success));
      }
    }));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', detectAndReportPdf);
  } else {
    detectAndReportPdf();
  }

  window.addEventListener('beforeunload', () => {
    pdfDetected = false;
  });

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'viewer_ready') {
      detectAndReportPdf();
    }
    return true;
  });
})();