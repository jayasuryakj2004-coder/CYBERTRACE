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

/**
 * Calculates Shannon byte entropy for a buffer or Uint8Array.
 * Returns a value between 0.0 and 8.0 bits per byte.
 */
export function calculateShannonEntropy(buffer) {
  if (!buffer) return 0;
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (bytes.length === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }

  let entropy = 0;
  const total = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / total;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Inspects initial bytes (magic bytes) to identify file type and signature mismatches.
 */
export function detectFileSignature(buffer) {
  if (!buffer || buffer.byteLength === 0) {
    return { format: 'empty', label: 'Empty File', isPdf: false, isExecutable: false, isArchive: false, magicHex: '' };
  }

  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const len = bytes.length;
  const magicHex = Array.from(bytes.subarray(0, Math.min(8, len)))
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');

  // 1. Standard PDF magic header: %PDF- (0x25 0x50 0x44 0x46 0x2D)
  if (len >= 5 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2D) {
    return {
      format: 'pdf',
      label: 'PDF Document (ISO 32000-1)',
      mime: 'application/pdf',
      isPdf: true,
      isExecutable: false,
      isArchive: false,
      magicHex
    };
  }

  // Check if %PDF- appears within the first 1024 bytes (with small preamble or BOM)
  const preambleLimit = Math.min(1024, len);
  let pdfOffset = -1;
  for (let i = 0; i <= preambleLimit - 5; i++) {
    if (bytes[i] === 0x25 && bytes[i + 1] === 0x50 && bytes[i + 2] === 0x44 && bytes[i + 3] === 0x46 && bytes[i + 4] === 0x2D) {
      pdfOffset = i;
      break;
    }
  }

  // 2. Windows Portable Executable (PE / MZ): 0x4D 0x5A ("MZ")
  if (len >= 2 && bytes[0] === 0x4D && bytes[1] === 0x5A) {
    return {
      format: 'pe_executable',
      label: 'Windows Executable / DLL (PE/MZ)',
      mime: 'application/vnd.microsoft.portable-executable',
      isPdf: false,
      isExecutable: true,
      isArchive: false,
      magicHex,
      pdfOffset
    };
  }

  // 3. Linux/Unix ELF Executable: 0x7F 0x45 0x4C 0x46 ("\x7FELF")
  if (len >= 4 && bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) {
    return {
      format: 'elf_executable',
      label: 'Linux/Unix ELF Binary Executable',
      mime: 'application/x-executable',
      isPdf: false,
      isExecutable: true,
      isArchive: false,
      magicHex,
      pdfOffset
    };
  }

  // 4. Mach-O Executables & Universal Binaries
  if (len >= 4) {
    const isMacho = (
      (bytes[0] === 0xFE && bytes[1] === 0xED && bytes[2] === 0xFA && (bytes[3] === 0xCE || bytes[3] === 0xCF)) ||
      (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE) ||
      (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE) ||
      (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE)
    );
    if (isMacho) {
      return {
        format: 'macho_executable',
        label: 'Mach-O Binary / Java Bytecode Executable',
        mime: 'application/x-mach-binary',
        isPdf: false,
        isExecutable: true,
        isArchive: false,
        magicHex,
        pdfOffset
      };
    }
  }

  // 5. ZIP Archive / Android Package (APK) / JAR: 0x50 0x4B 0x03 0x04 or 0x50 0x4B 0x05 0x06
  if (len >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && (
    (bytes[2] === 0x03 && bytes[3] === 0x04) ||
    (bytes[2] === 0x05 && bytes[3] === 0x06) ||
    (bytes[2] === 0x07 && bytes[3] === 0x08)
  )) {
    return {
      format: 'zip_apk_archive',
      label: 'ZIP Archive / Android APK Package / JAR Container',
      mime: 'application/zip',
      isPdf: false,
      isExecutable: false,
      isArchive: true,
      magicHex,
      pdfOffset
    };
  }

  // 6. RAR Archive: 0x52 0x61 0x72 0x21 0x1A 0x07 ("Rar!\x1A\x07")
  if (len >= 6 && bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21 && bytes[4] === 0x1A && bytes[5] === 0x07) {
    return {
      format: 'rar_archive',
      label: 'RAR Compressed Archive Container',
      mime: 'application/vnd.rar',
      isPdf: false,
      isExecutable: false,
      isArchive: true,
      magicHex,
      pdfOffset
    };
  }

  // 7. 7-Zip Archive: 0x37 0x7A 0xBC 0xAF 0x27 0x1C ("7z\xBC\xAF\x27\x1C")
  if (len >= 6 && bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF && bytes[4] === 0x27 && bytes[5] === 0x1C) {
    return {
      format: '7z_archive',
      label: '7-Zip Compressed Archive Container',
      mime: 'application/x-7z-compressed',
      isPdf: false,
      isExecutable: false,
      isArchive: true,
      magicHex,
      pdfOffset
    };
  }

  // 8. GZIP Compressed Archive: 0x1F 0x8B
  if (len >= 2 && bytes[0] === 0x1F && bytes[1] === 0x8B) {
    return {
      format: 'gzip_archive',
      label: 'GZIP Compressed Archive',
      mime: 'application/gzip',
      isPdf: false,
      isExecutable: false,
      isArchive: true,
      magicHex,
      pdfOffset
    };
  }

  // 9. If %PDF- was found with preamble
  if (pdfOffset > 0) {
    return {
      format: 'pdf_with_preamble',
      label: `PDF Document (with leading preamble offset +${pdfOffset})`,
      mime: 'application/pdf',
      isPdf: true,
      isExecutable: false,
      isArchive: false,
      magicHex,
      pdfOffset
    };
  }

  // 10. Unknown / non-PDF format
  return {
    format: 'unknown',
    label: 'Unknown Non-PDF Binary / Plaintext',
    mime: 'application/octet-stream',
    isPdf: false,
    isExecutable: false,
    isArchive: false,
    magicHex
  };
}

/**
 * Scans a PDF buffer for polyglot or embedded executable/archive headers.
 */
export function detectEmbeddedSignatures(buffer) {
  if (!buffer || buffer.byteLength < 32) return [];
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const hits = [];

  // Look for embedded PE executable ("MZ" with PE pointer)
  for (let i = 1; i <= bytes.length - 64; i++) {
    if (bytes[i] === 0x4D && bytes[i + 1] === 0x5A) { // "MZ"
      const peOffset = i + 60 < bytes.length ? bytes[i + 60] | (bytes[i + 61] << 8) : 0;
      if (peOffset > 0 && i + peOffset + 4 <= bytes.length) {
        if (bytes[i + peOffset] === 0x50 && bytes[i + peOffset + 1] === 0x45 && bytes[i + peOffset + 2] === 0x00 && bytes[i + peOffset + 3] === 0x00) {
          hits.push({ type: 'pe_executable', offset: i, label: 'Embedded Windows PE Executable' });
        }
      }
    }
  }

  // Look for embedded ZIP / APK (PK\x03\x04)
  for (let i = 1; i <= bytes.length - 30; i++) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) {
      hits.push({ type: 'zip_archive', offset: i, label: 'Embedded ZIP/APK Container' });
      break; // report at most one
    }
  }

  // Look for embedded 7-Zip (7z\xBC\xAF\x27\x1C)
  for (let i = 1; i <= bytes.length - 6; i++) {
    if (bytes[i] === 0x37 && bytes[i + 1] === 0x7A && bytes[i + 2] === 0xBC && bytes[i + 3] === 0xAF && bytes[i + 4] === 0x27 && bytes[i + 5] === 0x1C) {
      hits.push({ type: '7z_archive', offset: i, label: 'Embedded 7-Zip Container' });
      break;
    }
  }

  return hits;
}