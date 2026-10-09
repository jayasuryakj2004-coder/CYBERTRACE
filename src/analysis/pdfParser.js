// Low-level PDF byte parsing utilities.
// Targeted, safe scanner: finds object boundaries and dictionary keys.
// This is NOT a general-purpose PDF interpreter. It does not execute,
// resolve all references, or evaluate stream contents.

export function decodeLatin1(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (typeof TextDecoder !== 'undefined') {
    try {
      return new TextDecoder('latin1').decode(bytes);
    } catch (_) {
      // fall through to manual decode
    }
  }
  let str = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    str += String.fromCharCode.apply(null, chunk);
  }
  return str;
}

export function parsePdfObjects(text) {
  const objects = [];
  const regex = /(\d+)\s+(\d+)\s+obj\b/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const objNum = parseInt(match[1], 10);
    const gen = parseInt(match[2], 10);
    const contentStart = regex.lastIndex;
    const end = findObjectEnd(text, contentStart);
    const content = text.slice(contentStart, end);
    objects.push({ objNum, gen, start: match.index, end, content });
  }
  return objects;
}

function findObjectEnd(text, contentStart) {
  const endObjIdx = text.indexOf('endobj', contentStart);
  if (endObjIdx === -1) return text.length;

  const streamIdx = text.indexOf('stream', contentStart);
  if (streamIdx !== -1 && streamIdx < endObjIdx) {
    const endStreamIdx = text.indexOf('endstream', streamIdx + 6);
    if (endStreamIdx !== -1) {
      const endObjAfterStream = text.indexOf('endobj', endStreamIdx + 9);
      if (endObjAfterStream !== -1) return endObjAfterStream + 6;
    }
  }
  return endObjIdx + 6;
}

export function stripPdfStrings(content) {
  return content
    .replace(/\((?:[^()\\]|\\.)*\)/g, ' ')
    .replace(/<[0-9A-Fa-f\s]*>/g, ' ');
}

export function hasKey(content, key) {
  const cleaned = stripPdfStrings(content);
  const regex = new RegExp(`\\/${key}(?![A-Za-z0-9])`);
  return regex.test(cleaned);
}

export function extractStringValue(content, key) {
  // Locate /key followed by an optional whitespace and a literal string.
  const keyRegex = new RegExp(`\\/${key}\\s*\\(`);
  const match = keyRegex.exec(content);
  if (match) {
    const openIdx = match.index + match[0].length - 1;
    const value = parsePdfString(content, openIdx);
    if (value !== null) return value;
  }
  // Fall back to a hex string <...>.
  const hexRegex = new RegExp(`\\/${key}\\s*<([0-9A-Fa-f\\s]*)>`);
  const hexMatch = hexRegex.exec(content);
  if (hexMatch) return hexToString(hexMatch[1]);
  return null;
}

// Parse a PDF literal string starting at the opening parenthesis.
// Handles balanced parentheses and backslash escapes.
export function parsePdfString(content, openIdx) {
  if (content[openIdx] !== '(') return null;
  let depth = 1;
  let i = openIdx + 1;
  let result = '';
  while (i < content.length && depth > 0) {
    const ch = content[i];
    if (ch === '\\') {
      const next = content[i + 1];
      if (next === 'n') result += '\n';
      else if (next === 'r') result += '\r';
      else if (next === 't') result += '\t';
      else if (next === 'b') result += '\b';
      else if (next === 'f') result += '\f';
      else if (next === '(') result += '(';
      else if (next === ')') result += ')';
      else if (next === '\\') result += '\\';
      else if (next === '\n') { /* line continuation */ }
      else result += next;
      i += 2;
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) break;
    }
    result += ch;
    i++;
  }
  return result;
}

export function extractReference(content, key) {
  const regex = new RegExp(`\\/${key}\\s+(\\d+)\\s+(\\d+)\\s+R`);
  const match = regex.exec(content);
  if (match) return { objNum: parseInt(match[1], 10), gen: parseInt(match[2], 10) };
  return null;
}

export function extractUri(content) {
  const match = /\/URI\s*\(/.exec(content);
  if (!match) return null;
  const openIdx = match.index + match[0].length - 1;
  return parsePdfString(content, openIdx);
}

export function hexToString(hex) {
  const cleaned = hex.replace(/\s+/g, '');
  let str = '';
  for (let i = 0; i + 1 < cleaned.length; i += 2) {
    str += String.fromCharCode(parseInt(cleaned.substr(i, 2), 16));
  }
  return str;
}

export function findTrailer(text) {
  const trailerIdx = text.lastIndexOf('trailer');
  if (trailerIdx === -1) return null;
  const start = trailerIdx + 7;
  const end = text.indexOf('startxref', start);
  return text.slice(start, end === -1 ? text.length : end);
}

export function countEofMarkers(text) {
  const matches = text.match(/%%EOF/g);
  return matches ? matches.length : 0;
}

export function getPdfVersion(text) {
  const match = /%PDF-(\d+\.\d+)/.exec(text);
  return match ? match[1] : null;
}

export function isLinearized(text) {
  return /\/Linearized\b/.test(text);
}

export function hasObjectStreams(text) {
  return /\/ObjStm\b/.test(stripPdfStrings(text));
}

export function isEncrypted(text) {
  return /\/Encrypt\b/.test(stripPdfStrings(text));
}

export function countStreams(text) {
  const matches = text.match(/\bstream\b/g);
  return matches ? matches.length : 0;
}

export function extractTextContent(text) {
  const textOps = [];
  const regex = /\((?:[^()\\]|\\.)*\)\s*Tj/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    textOps.push(match[0]);
  }
  return textOps;
}

export function extractLinkAnnotations(objects) {
  const links = [];
  for (const obj of objects) {
    if (hasKey(obj.content, 'Subtype') && /\/Subtype\s*\/Link\b/.test(stripPdfStrings(obj.content))) {
      const uri = extractUri(obj.content);
      links.push({
        objectNumber: obj.objNum,
        uri,
        content: obj.content
      });
    }
  }
  return links;
}

export function extractJavaScriptObjects(objects) {
  const jsObjects = [];
  for (const obj of objects) {
    const hasJS = hasKey(obj.content, 'JavaScript') || hasKey(obj.content, 'JS');
    const hasS = hasKey(obj.content, 'S') && /\/S\s*\/JavaScript\b/.test(stripPdfStrings(obj.content));
    if (hasJS || hasS) {
      const jsValue = extractStringValue(obj.content, 'JS') || extractStringValue(obj.content, 'JavaScript');
      jsObjects.push({
        objectNumber: obj.objNum,
        value: jsValue,
        content: obj.content
      });
    }
  }
  return jsObjects;
}

export function extractEmbeddedFileObjects(objects) {
  const embedded = [];
  for (const obj of objects) {
    if (hasKey(obj.content, 'Filespec') || hasKey(obj.content, 'EF') || hasKey(obj.content, 'EmbeddedFile')) {
      const name = extractStringValue(obj.content, 'F') || extractStringValue(obj.content, 'UF');
      embedded.push({
        objectNumber: obj.objNum,
        name,
        content: obj.content
      });
    }
  }
  return embedded;
}

export function extractActionObjects(objects) {
  const actions = [];
  for (const obj of objects) {
    const cleaned = stripPdfStrings(obj.content);
    const sMatch = /\/S\s*\/(\w+)/.exec(cleaned);
    if (sMatch) {
      const actionType = sMatch[1];
      if (['Launch', 'URI', 'GoTo', 'GoToR', 'Named', 'JavaScript', 'SubmitForm', 'ImportData'].includes(actionType)) {
        actions.push({
          objectNumber: obj.objNum,
          actionType,
          content: obj.content
        });
      }
    }
  }
  return actions;
}