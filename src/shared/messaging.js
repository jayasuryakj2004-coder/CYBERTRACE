import { MessageType, createMessage, parseMessage } from './contracts.js';

const listeners = new Map();
const pendingRequests = new Map();
let requestId = 0;

export function sendMessage(target, message) {
  return new Promise((resolve, reject) => {
    const id = `${++requestId}_${Date.now()}`;
    const timeout = setTimeout(() => {
      pendingRequests.delete(id);
      reject(new Error(`Message timeout: ${message.type}`));
    }, 10000);

    pendingRequests.set(id, { resolve, reject, timeout });
    
    try {
      target.postMessage(message, '*');
    } catch (error) {
      clearTimeout(timeout);
      pendingRequests.delete(id);
      reject(error);
    }
  });
}

export function sendToBackground(message) {
  return chrome.runtime.sendMessage(message);
}

export function sendToSidePanel(message) {
  return chrome.runtime.sendMessage(message).catch(() => undefined);
}

export function sendToContentScript(tabId, message) {
  return chrome.tabs.sendMessage(tabId, message);
}

export function broadcastToViewers(message) {
  return chrome.runtime.sendMessage(message);
}

export function onMessage(listener) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const parsed = parseMessage(message);
    if (!parsed) {
      return false;
    }
    
    const result = listener(parsed, sender);
    if (result instanceof Promise) {
      result.then(sendResponse).catch(err => sendResponse({ error: err.message }));
      return true;
    }
    sendResponse(result);
    return true;
  });
}

export function onMessageExternal(listener) {
  chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
    const parsed = parseMessage(message);
    if (!parsed) return false;
    const result = listener(parsed, sender);
    if (result instanceof Promise) {
      result.then(sendResponse).catch(err => sendResponse({ error: err.message }));
      return true;
    }
    sendResponse(result);
    return true;
  });
}

export function setupPortListener(portName, handler) {
  chrome.runtime.onConnect.addListener(port => {
    if (port.name === portName) {
      port.onMessage.addListener(msg => {
        const parsed = parseMessage(msg);
        if (parsed) handler(parsed, port);
      });
    }
  });
}

export function connectToBackground(portName) {
  const port = chrome.runtime.connect({ name: portName });
  return {
    port,
    postMessage: (message) => port.postMessage(message),
    onMessage: (handler) => port.onMessage.addListener(msg => {
      const parsed = parseMessage(msg);
      if (parsed) handler(parsed);
    }),
    onDisconnect: (handler) => port.onDisconnect.addListener(handler)
  };
}

export function createScanMessage(type, scanId, data = {}) {
  return createMessage(type, { scanId, ...data });
}

export function createProgressMessage(scanId, progress, status, details = {}) {
  return createMessage(MessageType.ANALYSIS_PROGRESS, { scanId, progress, status, ...details });
}

export function createCompleteMessage(scanId, result) {
  return createMessage(MessageType.ANALYSIS_COMPLETE, { scanId, result });
}

export function createErrorMessage(scanId, error, details = {}) {
  return createMessage(MessageType.ANALYSIS_FAILED, { scanId, error: error.message || error, ...details });
}