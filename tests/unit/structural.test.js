import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parsePdfObjects,
  hasKey,
  stripPdfStrings,
  extractStringValue,
  extractUri,
  extractReference,
  countEofMarkers,
  hasObjectStreams,
  isEncrypted,
  isLinearized,
  getPdfVersion,
  extractLinkAnnotations,
  extractJavaScriptObjects,
  extractEmbeddedFileObjects,
  extractActionObjects
} from '../../src/analysis/pdfParser.js';
import { inspectStructure, rawKeywordScan } from '../../src/analysis/structural.js';
import { IndicatorCategory } from '../../src/analysis/evidence.js';

function pdfWith(objects, trailerExtras = '') {
  let pdf = '%PDF-1.4\n';
  for (const obj of objects) {
    pdf += `${obj.num} 0 obj\n${obj.content}\nendobj\n`;
  }
  pdf += 'xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R ' + trailerExtras + ' >>\nstartxref\n0\n%%EOF\n';
  return pdf;
}

test('parsePdfObjects finds objects with correct numbers', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Pages >>' }
  ]);
  const objects = parsePdfObjects(text);
  assert.equal(objects.length, 2);
  assert.equal(objects[0].objNum, 1);
  assert.equal(objects[1].objNum, 2);
});

test('hasKey detects a key in a dictionary', () => {
  assert.equal(hasKey('<< /Type /Catalog /Pages 2 0 R >>', 'Type'), true);
  assert.equal(hasKey('<< /Type /Catalog >>', 'OpenAction'), false);
});

test('hasKey ignores keys inside string literals', () => {
  // /JavaScript inside a string should NOT be detected as a key
  const text = '<< /Contents (This mentions /JavaScript in text) >>';
  assert.equal(hasKey(text, 'JavaScript'), false);
});

test('hasKey detects key even with string content present', () => {
  const text = '<< /S /JavaScript /JS (app.alert("/JavaScript")) >>';
  assert.equal(hasKey(text, 'JavaScript'), true);
  assert.equal(hasKey(text, 'JS'), true);
});

test('stripPdfStrings removes string literals', () => {
  const cleaned = stripPdfStrings('<< /Title (Hello /World) >>');
  assert.ok(!cleaned.includes('Hello'));
  assert.ok(cleaned.includes('/Title'));
});

test('extractStringValue extracts literal string', () => {
  const value = extractStringValue('<< /Title (My Document) >>', 'Title');
  assert.equal(value, 'My Document');
});

test('extractStringValue extracts hex string', () => {
  // "Hi" in hex is 4869
  const value = extractStringValue('<< /Title <4869> >>', 'Title');
  assert.equal(value, 'Hi');
});

test('extractUri extracts URI from annotation', () => {
  const uri = extractUri('<< /A << /S /URI /URI (https://example.com) >> >>');
  assert.equal(uri, 'https://example.com');
});

test('extractReference extracts object reference', () => {
  const ref = extractReference('<< /OpenAction 5 0 R >>', 'OpenAction');
  assert.equal(ref.objNum, 5);
  assert.equal(ref.gen, 0);
});

test('countEofMarkers counts %%EOF occurrences', () => {
  assert.equal(countEofMarkers('%%EOF\n%%EOF\n'), 2);
  assert.equal(countEofMarkers('no eof here'), 0);
});

test('hasObjectStreams detects /ObjStm', () => {
  assert.equal(hasObjectStreams('<< /Type /ObjStm >>'), true);
  assert.equal(hasObjectStreams('<< /Type /Catalog >>'), false);
});

test('isEncrypted detects /Encrypt', () => {
  assert.equal(isEncrypted('<< /Encrypt 5 0 R >>'), true);
  assert.equal(isEncrypted('<< /Type /Catalog >>'), false);
});

test('isLinearized detects /Linearized', () => {
  assert.equal(isLinearized('<< /Linearized 1 >>'), true);
});

test('getPdfVersion extracts version', () => {
  assert.equal(getPdfVersion('%PDF-1.7\n'), '1.7');
  assert.equal(getPdfVersion('no header'), null);
});

test('extractLinkAnnotations finds URI links', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://example.com) >> >>' }
  ]);
  const links = extractLinkAnnotations(parsePdfObjects(text));
  assert.equal(links.length, 1);
  assert.equal(links[0].uri, 'https://example.com');
});

test('extractJavaScriptObjects finds JavaScript actions', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /S /JavaScript /JS (app.alert(1)) >>' }
  ]);
  const js = extractJavaScriptObjects(parsePdfObjects(text));
  assert.equal(js.length, 1);
  assert.equal(js[0].value, 'app.alert(1)');
});

test('extractEmbeddedFileObjects finds filespecs', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Filespec /F (file.exe) >>' }
  ]);
  const embedded = extractEmbeddedFileObjects(parsePdfObjects(text));
  assert.equal(embedded.length, 1);
  assert.equal(embedded[0].name, 'file.exe');
});

test('extractActionObjects finds Launch actions', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /S /Launch /F (cmd.exe) >>' }
  ]);
  const actions = extractActionObjects(parsePdfObjects(text));
  assert.equal(actions.length, 1);
  assert.equal(actions[0].actionType, 'Launch');
});

test('inspectStructure detects JavaScript', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /OpenAction 2 0 R >>' },
    { num: 2, content: '<< /S /JavaScript /JS (app.alert(1)) >>' }
  ]);
  const { findings } = inspectStructure(text);
  const jsFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.JAVASCRIPT);
  assert.equal(jsFindings.length, 1);
});

test('inspectStructure detects OpenAction', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /OpenAction 2 0 R >>' },
    { num: 2, content: '<< /S /GoTo >>' }
  ]);
  const { findings } = inspectStructure(text);
  const oaFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.OPEN_ACTION);
  assert.equal(oaFindings.length, 1);
});

test('inspectStructure detects Launch action', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /OpenAction 2 0 R >>' },
    { num: 2, content: '<< /S /Launch /F (cmd.exe) >>' }
  ]);
  const { findings } = inspectStructure(text);
  const launchFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.LAUNCH_ACTION);
  assert.equal(launchFindings.length, 1);
});

test('inspectStructure detects embedded files', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Filespec /F (payload.exe) /EF << /F 3 0 R >> >>' }
  ]);
  const { findings } = inspectStructure(text);
  const efFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.EMBEDDED_FILE);
  assert.equal(efFindings.length, 1);
});

test('inspectStructure detects suspicious URI (IP literal)', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://192.168.1.1/x) >> >>' }
  ]);
  const { findings } = inspectStructure(text);
  const susFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.SUSPICIOUS_URI);
  assert.equal(susFindings.length, 1);
});

test('inspectStructure does not flag legitimate HTTPS URI as suspicious', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://www.example.com) >> >>' }
  ]);
  const { findings } = inspectStructure(text);
  const susFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.SUSPICIOUS_URI);
  assert.equal(susFindings.length, 0);
  const uriFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.URI);
  assert.equal(uriFindings.length, 1);
});

test('inspectStructure detects encryption', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' }
  ], '/Encrypt 2 0 R');
  const { findings } = inspectStructure(text);
  const encFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.ENCRYPTION);
  assert.equal(encFindings.length, 1);
});

test('inspectStructure detects incremental update', () => {
  const text = pdfWith([{ num: 1, content: '<< /Type /Catalog >>' }]) + '%%EOF\n';
  const { findings } = inspectStructure(text);
  const iuFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.INCREMENTAL_UPDATE);
  assert.equal(iuFindings.length, 1);
});

test('inspectStructure detects additional actions', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /AA << /O << /S /JavaScript >> >> >>' }
  ]);
  const { findings } = inspectStructure(text);
  const aaFindings = findings.filter(f => f.indicatorCategory === IndicatorCategory.ADDITIONAL_ACTION);
  assert.equal(aaFindings.length, 1);
});

test('inspectStructure on benign PDF produces no security findings', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog /Pages 2 0 R >>' },
    { num: 2, content: '<< /Type /Pages /Kids [3 0 R] /Count 1 >>' },
    { num: 3, content: '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>' }
  ]);
  const { findings } = inspectStructure(text);
  const securityCategories = [
    IndicatorCategory.JAVASCRIPT, IndicatorCategory.LAUNCH_ACTION,
    IndicatorCategory.OPEN_ACTION, IndicatorCategory.EMBEDDED_FILE,
    IndicatorCategory.SUSPICIOUS_URI
  ];
  const securityFindings = findings.filter(f => securityCategories.includes(f.indicatorCategory));
  assert.equal(securityFindings.length, 0);
});

test('rawKeywordScan finds keywords', () => {
  const text = '<< /JavaScript /JS (x) >> /OpenAction /Launch';
  const hits = rawKeywordScan(text);
  const keywords = hits.map(h => h.keyword);
  assert.ok(keywords.includes('/JavaScript'));
  assert.ok(keywords.includes('/OpenAction'));
  assert.ok(keywords.includes('/Launch'));
});

test('object parser handles stream objects', () => {
  const text = pdfWith([
    { num: 1, content: '<< /Type /Catalog >>' },
    { num: 2, content: '<< /Length 5 >>\nstream\nhello\nendstream' }
  ]);
  const objects = parsePdfObjects(text);
  assert.equal(objects.length, 2);
  // The stream content should not be parsed as a separate object
  assert.equal(objects[1].objNum, 2);
});