import * as pdfjsLib from '../assets/pdfjs/pdf.mjs';

const MAX_PDF_BYTES = 100 * 1024 * 1024;

async function readBoundedPdf(response) {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB viewer limit');
  if (!response.body?.getReader) {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB viewer limit');
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
        throw new Error('PDF exceeds the 100 MiB viewer limit');
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

pdfjsLib.GlobalWorkerOptions.workerSrc = chrome.runtime.getURL('src/assets/pdfjs/pdf.worker.mjs');
pdfjsLib.GlobalWorkerOptions.cMapUrl = chrome.runtime.getURL('src/assets/pdfjs/cmaps/');
pdfjsLib.GlobalWorkerOptions.cMapPacked = true;

const STORAGE_KEY = 'cybertrace_viewer_state';

class PDFViewer {
  constructor() {
    this.pdfDoc = null;
    this.currentPage = 1;
    this.totalPages = 0;
    this.scale = 1.0;
    this.autoScale = 'auto';
    this.container = document.getElementById('canvasContainer');
    this.canvas = document.getElementById('pdfCanvas');
    this.ctx = this.canvas.getContext('2d');
    this.thumbnailList = document.getElementById('thumbnailList');
    this.loadingOverlay = document.getElementById('loadingOverlay');
    this.loadingText = document.getElementById('loadingText');
    this.loadingProgress = document.getElementById('loadingProgress');
    this.progressFill = document.getElementById('progressFill');
    this.errorOverlay = document.getElementById('errorOverlay');
    this.errorTitle = document.getElementById('errorTitle');
    this.errorMessage = document.getElementById('errorMessage');
    this.pdfCanvasWrapper = document.getElementById('pdfCanvasWrapper');
    this.sidebar = document.getElementById('thumbnailSidebar');
    this.renderStatus = document.getElementById('renderStatus');
    this.fileSizeEl = document.getElementById('fileSize');
    this.pageDimensionsEl = document.getElementById('pageDimensions');
    this.docNameEl = document.getElementById('docName');
    this.docSourceEl = document.getElementById('docSource');
    this.pageNumberInput = document.getElementById('pageNumber');
    this.pageCountEl = document.getElementById('pageCount');
    this.zoomSelect = document.getElementById('zoomSelect');
    this.thumbnails = new Map();
    this.renderQueue = [];
    this.isRendering = false;
    this.pdfData = null;
    this.pdfUrl = null;
    this.fileName = null;
    this.fileSize = 0;
    this.init();
  }

  async init() {
    this.bindEvents();
    this.restoreState();
    await this.loadPDF();
  }

  bindEvents() {
    document.getElementById('prevPage').addEventListener('click', () => this.prevPage());
    document.getElementById('nextPage').addEventListener('click', () => this.nextPage());
    this.pageNumberInput.addEventListener('change', (e) => this.goToPage(parseInt(e.target.value, 10)));
    this.pageNumberInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.goToPage(parseInt(e.target.value, 10));
    });
    document.getElementById('zoomOut').addEventListener('click', () => this.zoomOut());
    document.getElementById('zoomIn').addEventListener('click', () => this.zoomIn());
    this.zoomSelect.addEventListener('change', (e) => this.setZoom(e.target.value));
    document.getElementById('toggleSidebar').addEventListener('click', () => this.toggleSidebar());
    document.getElementById('openSidePanel').addEventListener('click', () => this.openSidePanel());
    document.getElementById('retryBtn').addEventListener('click', () => this.retryLoad());
    document.getElementById('manualAnalysisBtn').addEventListener('click', () => this.requestManualAnalysis());
    window.addEventListener('resize', () => this.handleResize());
    window.addEventListener('keydown', (e) => this.handleKeydown(e));
    window.addEventListener('message', (e) => this.handleMessage(e));
  }

  handleMessage(event) {
    if (event.origin !== window.location.origin) return;
    if (event.data?.type === 'cybertrace:pdf_data') {
      this.loadPDFFromData(event.data.payload);
    }
  }

  async loadPDF() {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const pdfUrl = urlParams.get('url');
      const pdfData = urlParams.get('data');
      this.fileName = urlParams.get('name') || 'document.pdf';
      this.fileSize = parseInt(urlParams.get('size') || '0', 10);

      if (pdfData) {
        if (pdfData.length > Math.ceil(MAX_PDF_BYTES * 4 / 3)) throw new Error('PDF exceeds the 100 MiB viewer limit');
        const buffer = this.base64ToArrayBuffer(pdfData);
        await this.loadPDFFromBuffer(buffer);
      } else if (pdfUrl) {
        this.pdfUrl = pdfUrl;
        await this.loadPDFFromUrl(pdfUrl);
      } else {
        throw new Error('No PDF source provided');
      }
    } catch (error) {
      this.showError('Failed to Load Document', error.message);
    }
  }

  async loadPDFFromUrl(url) {
    this.showLoading('Fetching document...');
    try {
      const response = await fetch(url, { credentials: 'same-origin', signal: AbortSignal.timeout(20000) });
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      const buffer = await readBoundedPdf(response);
      await this.loadPDFFromBuffer(buffer);
    } catch (error) {
      throw new Error(`Failed to fetch PDF: ${error.message}`);
    }
  }

  async loadPDFFromData(payload) {
    if (payload.buffer) {
      await this.loadPDFFromBuffer(payload.buffer);
    }
  }

  async loadPDFFromBuffer(buffer) {
    if (buffer.byteLength > MAX_PDF_BYTES) throw new Error('PDF exceeds the 100 MiB viewer limit');
    this.pdfData = buffer;
    this.fileSize = buffer.byteLength;
    this.showLoading('Parsing PDF...');
    try {
      this.pdfDoc = await pdfjsLib.getDocument({ data: buffer, disableAutoFetch: true }).promise;
      this.totalPages = this.pdfDoc.numPages;
      this.updateUI();
      await this.renderThumbnails();
      await this.renderPage(this.currentPage);
      this.hideLoading();
      this.saveState();
      this.notifyViewerReady();
    } catch (error) {
      if (error.name === 'InvalidPDFException') {
        throw new Error('Invalid or corrupted PDF file');
      } else if (error.name === 'MissingPDFException') {
        throw new Error('PDF data is missing');
      } else if (error.message.includes('password')) {
        throw new Error('Password-protected PDFs are not supported');
      }
      throw error;
    }
  }

  async renderThumbnails() {
    this.thumbnailList.innerHTML = '';
    this.thumbnails.clear();
    const maxThumbnails = Math.min(this.totalPages, 50);
    for (let i = 1; i <= maxThumbnails; i++) {
      const item = this.createThumbnailItem(i);
      this.thumbnailList.appendChild(item);
    }
    if (this.totalPages > 50) {
      const moreItem = document.createElement('div');
      moreItem.className = 'thumbnail-item more';
      moreItem.innerHTML = `<div class="thumbnail-label">+ ${this.totalPages - 50} more pages</div>`;
      this.thumbnailList.appendChild(moreItem);
    }
  }

  createThumbnailItem(pageNum) {
    const item = document.createElement('div');
    item.className = 'thumbnail-item';
    item.dataset.page = pageNum;
    item.setAttribute('role', 'listitem');
    item.setAttribute('aria-label', `Page ${pageNum}`);
    if (pageNum === this.currentPage) item.classList.add('active');
    const canvas = document.createElement('canvas');
    canvas.className = 'thumbnail-canvas';
    item.appendChild(canvas);
    const label = document.createElement('div');
    label.className = 'thumbnail-label';
    label.textContent = `Page ${pageNum}`;
    item.appendChild(label);
    item.addEventListener('click', () => this.goToPage(pageNum));
    this.thumbnails.set(pageNum, { canvas, item });
    this.queueThumbnailRender(pageNum, canvas);
    return item;
  }

  queueThumbnailRender(pageNum, canvas) {
    this.renderQueue.push({ pageNum, canvas, isThumbnail: true });
    this.processRenderQueue();
  }

  async processRenderQueue() {
    if (this.isRendering || this.renderQueue.length === 0) return;
    this.isRendering = true;
    while (this.renderQueue.length > 0) {
      const task = this.renderQueue.shift();
      await this.renderTask(task);
    }
    this.isRendering = false;
  }

  async renderTask(task) {
    if (!this.pdfDoc) return;
    try {
      const page = await this.pdfDoc.getPage(task.pageNum);
      const viewport = page.getViewport({ scale: 0.15 });
      task.canvas.width = viewport.width;
      task.canvas.height = viewport.height;
      const renderContext = {
        canvasContext: task.canvas.getContext('2d'),
        viewport: viewport,
        enableWebGL: false
      };
      await page.render(renderContext).promise;
    } catch (error) {
      console.warn(`Failed to render thumbnail for page ${task.pageNum}`, error);
    }
  }

  async renderPage(pageNum) {
    if (!this.pdfDoc || pageNum < 1 || pageNum > this.totalPages) return;
    this.showLoading(`Rendering page ${pageNum}...`, true);
    this.updateRenderStatus(`Rendering page ${pageNum} of ${this.totalPages}`);
    try {
      const page = await this.pdfDoc.getPage(pageNum);
      const viewport = this.getViewport(page);
      const outputScale = window.devicePixelRatio || 1;
      this.canvas.width = Math.floor(viewport.width * outputScale);
      this.canvas.height = Math.floor(viewport.height * outputScale);
      this.canvas.style.width = `${viewport.width}px`;
      this.canvas.style.height = `${viewport.height}px`;
      const renderContext = {
        canvasContext: this.ctx,
        viewport: viewport,
        transform: [outputScale, 0, 0, outputScale, 0, 0],
        enableWebGL: false
      };
      this.ctx.save();
      this.ctx.fillStyle = '#ffffff';
      this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
      this.ctx.restore();
      await page.render(renderContext).promise;
      this.currentPage = pageNum;
      this.updateUI();
      this.updateActiveThumbnail();
      this.updateFooterInfo(page);
      this.saveState();
      this.hideLoading();
      this.updateRenderStatus('Ready');
    } catch (error) {
      this.showError('Render Error', `Failed to render page ${pageNum}: ${error.message}`);
    }
  }

  getViewport(page) {
    const containerWidth = this.container.clientWidth - 64;
    const containerHeight = this.container.clientHeight - 64;
    let viewport;
    if (this.autoScale === 'auto' || this.autoScale === 'page-fit') {
      viewport = page.getViewport({ scale: 1.0 });
      const scaleX = containerWidth / viewport.width;
      const scaleY = containerHeight / viewport.height;
      const scale = Math.min(scaleX, scaleY, 2.0);
      this.scale = Math.max(scale, 0.25);
      viewport = page.getViewport({ scale: this.scale });
    } else if (this.autoScale === 'page-width') {
      viewport = page.getViewport({ scale: 1.0 });
      this.scale = containerWidth / viewport.width;
      this.scale = Math.max(Math.min(this.scale, 3.0), 0.25);
      viewport = page.getViewport({ scale: this.scale });
    } else {
      this.scale = parseFloat(this.autoScale) || 1.0;
      viewport = page.getViewport({ scale: this.scale });
    }
    return viewport;
  }

  updateUI() {
    this.pageNumberInput.value = this.currentPage;
    this.pageNumberInput.max = this.totalPages;
    this.pageCountEl.textContent = this.totalPages;
    this.docNameEl.textContent = this.fileName;
    this.docSourceEl.textContent = this.pdfUrl ? new URL(this.pdfUrl).origin : 'Local file';
    this.fileSizeEl.textContent = this.formatBytes(this.fileSize);
    document.getElementById('prevPage').disabled = this.currentPage <= 1;
    document.getElementById('nextPage').disabled = this.currentPage >= this.totalPages;
    if (this.autoScale !== 'auto' && this.autoScale !== 'page-fit' && this.autoScale !== 'page-width') {
      this.zoomSelect.value = this.autoScale;
    } else {
      this.zoomSelect.value = this.autoScale;
    }
  }

  updateActiveThumbnail() {
    this.thumbnails.forEach(({ item }, pageNum) => {
      item.classList.toggle('active', pageNum === this.currentPage);
    });
    const activeItem = this.thumbnails.get(this.currentPage)?.item;
    if (activeItem) {
      activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }

  updateFooterInfo(page) {
    const viewport = page.getViewport({ scale: 1.0 });
    this.pageDimensionsEl.textContent = `${Math.round(viewport.width)} × ${Math.round(viewport.height)} pts`;
  }

  updateRenderStatus(text) {
    this.renderStatus.textContent = text;
  }

  prevPage() {
    if (this.currentPage > 1) this.renderPage(this.currentPage - 1);
  }

  nextPage() {
    if (this.currentPage < this.totalPages) this.renderPage(this.currentPage + 1);
  }

  goToPage(pageNum) {
    const clamped = Math.max(1, Math.min(pageNum, this.totalPages));
    if (clamped !== this.currentPage) {
      this.renderPage(clamped);
    }
    this.pageNumberInput.value = this.currentPage;
  }

  zoomIn() {
    const values = ['0.5', '0.75', '1', '1.25', '1.5', '2', '3', '4'];
    const currentIdx = values.indexOf(this.zoomSelect.value);
    if (currentIdx < values.length - 1) {
      this.setZoom(values[currentIdx + 1]);
    }
  }

  zoomOut() {
    const values = ['0.5', '0.75', '1', '1.25', '1.5', '2', '3', '4'];
    const currentIdx = values.indexOf(this.zoomSelect.value);
    if (currentIdx > 0) {
      this.setZoom(values[currentIdx - 1]);
    }
  }

  setZoom(value) {
    this.autoScale = value;
    this.zoomSelect.value = value;
    this.renderPage(this.currentPage);
    this.saveState();
  }

  toggleSidebar() {
    this.sidebar.classList.toggle('collapsed');
    this.handleResize();
  }

  handleResize() {
    if (this.pdfDoc) {
      this.renderPage(this.currentPage);
    }
  }

  handleKeydown(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
    switch (e.key) {
      case 'ArrowLeft':
      case 'ArrowUp':
        e.preventDefault();
        this.prevPage();
        break;
      case 'ArrowRight':
      case 'ArrowDown':
      case ' ':
        e.preventDefault();
        this.nextPage();
        break;
      case 'Home':
        e.preventDefault();
        this.goToPage(1);
        break;
      case 'End':
        e.preventDefault();
        this.goToPage(this.totalPages);
        break;
      case '+':
      case '=':
        e.preventDefault();
        this.zoomIn();
        break;
      case '-':
        e.preventDefault();
        this.zoomOut();
        break;
      case '0':
        e.preventDefault();
        this.setZoom('auto');
        break;
    }
  }

  showLoading(text, showProgress = false) {
    this.loadingText.textContent = text;
    this.loadingProgress.style.display = showProgress ? 'block' : 'none';
    this.loadingOverlay.style.display = 'flex';
    this.pdfCanvasWrapper.style.display = 'none';
    this.errorOverlay.style.display = 'none';
  }

  hideLoading() {
    this.loadingOverlay.style.display = 'none';
    this.pdfCanvasWrapper.style.display = 'flex';
    this.errorOverlay.style.display = 'none';
  }

  showError(title, message) {
    this.loadingOverlay.style.display = 'none';
    this.pdfCanvasWrapper.style.display = 'none';
    this.errorTitle.textContent = title;
    this.errorMessage.textContent = message;
    this.errorOverlay.style.display = 'flex';
    this.updateRenderStatus('Error');
  }

  retryLoad() {
    this.hideLoading();
    this.loadPDF();
  }

  requestManualAnalysis() {
    chrome.runtime.sendMessage({
      type: 'manual_analysis',
      payload: { pdfUrl: this.pdfUrl, tabId: null }
    });
  }

  openSidePanel() {
    chrome.sidePanel.open({ windowId: chrome.windows.WINDOW_ID_CURRENT }).catch(error => {
      console.warn('CyberTrace side panel could not be opened:', error.message);
    });
  }

  notifyViewerReady() {
    chrome.runtime.sendMessage({ type: 'viewer_ready', payload: { url: this.pdfUrl } });
  }

  saveState() {
    const state = {
      currentPage: this.currentPage,
      scale: this.scale,
      autoScale: this.autoScale,
      fileName: this.fileName,
      fileSize: this.fileSize,
      pdfUrl: this.pdfUrl
    };
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {}
  }

  restoreState() {
    try {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) {
        const state = JSON.parse(stored);
        this.currentPage = state.currentPage || 1;
        this.scale = state.scale || 1.0;
        this.autoScale = state.autoScale || 'auto';
      }
    } catch {}
  }

  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.viewer = new PDFViewer();
});

export { PDFViewer };