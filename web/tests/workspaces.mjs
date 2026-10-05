import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { RouteLifetime } from '../src/state.ts';
import { ApiError } from '../src/api.ts';

// Tiny DOM/xterm test doubles exercise the actual event handlers; no browser
// acceptance, SSH/SFTP server, or new test framework is claimed by these checks.
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const xterm = moduleURL(`export class Terminal { constructor(){this.writes=[];} loadAddon(){} open(element){element.terminal=this;} reset(){this.writes=[];} resize(){} dispose(){} write(bytes,done){this.writes.push(Uint8Array.from(bytes));done?.();} }`);
const fit = moduleURL(`export class FitAddon { fit(){} }`);
const socket = moduleURL(`export class TargetSocket { constructor(api,life){this.api=api;this.active=false;this.connectionId='bound-connection';life.own(()=>this.close());} close(){this.active=false;} send(){return true;} async connect(target,capability,control){this.active=true;control({type:'session_ready'});control({type:'opened',channel_id:1});control({type:'ready',channel_id:1});} }`);
let source = ts.transpileModule(await readFile(new URL('../src/workspaces.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
source = source.replace("from '@xterm/xterm'", `from '${xterm}'`).replace("from '@xterm/addon-fit'", `from '${fit}'`).replace("from './terminal'", `from '${socket}'`);
for (const name of ['api', 'state', 'protocol', 'replay']) source = source.replace(`from './${name}'`, `from '${new URL(`../src/${name}.ts`, import.meta.url).href}'`);
const { mountReplay, mountFiles } = await import(moduleURL(source));
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; this.attributes = {}; this._text = ''; this._value = ''; this.files = []; this.disabled = false; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get value() { return this._value; }
  set value(value) { this._value = value; if (this.type === 'file' && value === '') this.files = []; }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this.children = []; this.append(...children); if (this.tagName === 'select') this._value = children[0]?.value ?? ''; }
  setAttribute(name, value) { this.attributes[name] = value; }
  focus() { this.focused = true; }
  scrollIntoView() { this.scrolled = true; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
  click() { if (!this.disabled) this.onclick?.(); }
}
function dom(t) {
  const previous = { document: globalThis.document, Option: globalThis.Option };
  globalThis.document = { createElement: tag => new Element(tag) };
  globalThis.Option = class extends Element { constructor(text, value) { super('option'); this.textContent = text; this.value = value; } };
  t.after(() => Object.assign(globalThis, previous)); return new Element('section');
}
function all(root) { return [root, ...root.children.flatMap(all)]; }
function find(root, test) { return all(root).find(test); }
const flush = async () => { for (let index = 0; index < 20; index++) await new Promise(resolve => setImmediate(resolve)); };
function recordingBody() {
  const events = [{ type: 'meta', seq: 0, elapsed_us: 0, format_version: 1, term: 'xterm-256color', cols: 80, rows: 24 }, { type: 'output', seq: 1, elapsed_us: 0, stream: 'stdout', data_base64: Buffer.from('REPLAY_中文').toString('base64') }, { type: 'end', seq: 2, elapsed_us: 0, reason: 'closed' }];
  return new Response(events.map(value => JSON.stringify(value)).join('\n') + '\n', { headers: { 'Content-Type': 'application/x-ndjson' } });
}

test('one click on actual replay selection starts reading and renders Chinese bytes', async t => {
  const root = dom(t), life = new RouteLifetime(), calls = [], errors = [];
  const api = { recordings: async () => ({ items: [{ id: 'record-1', state: 'complete', format_version: 1 }], next_cursor: null }), recording: async id => { calls.push(['metadata', id]); return { id, state: 'complete', format_version: 1 }; }, recordingContent: async id => { calls.push(['content', id]); return recordingBody(); } };
  mountReplay(root, api, life, () => {}, error => errors.push(error)); await flush();
  const choose = find(root, value => value.tagName === 'button' && value.textContent === '选择回放'); choose.click(); await flush();
  assert.deepEqual(calls, [['metadata', 'record-1'], ['content', 'record-1']]); assert.equal(errors.length, 0);
  const term = find(root, value => value.terminal)?.terminal;
  assert.equal(Buffer.concat(term.writes).toString('utf8'), 'REPLAY_中文'); assert.match(root.textContent, /state=complete/); life.dispose();
});

test('unsupported recording format has a visible reason instead of a dead action', async t => {
  const root = dom(t), life = new RouteLifetime(); let contentCalls = 0;
  mountReplay(root, { recordings: async () => ({ items: [{ id: 'future', state: 'complete', format_version: 2 }], next_cursor: null }), recordingContent: async () => { contentCalls++; } }, life, () => {}, () => {}); await flush();
  const choose = find(root, value => value.tagName === 'button' && value.textContent === '选择回放'); assert.equal(choose.disabled, true); assert.match(root.textContent, /不支持录制格式 2/); choose.click(); assert.equal(contentCalls, 0); life.dispose();
});

test('upload card suggests directory/filename, preserves edits, and sends the original File once', async t => {
  const root = dom(t), life = new RouteLifetime(), uploads = [], errors = [];
  const target = { asset: { id: 'asset', name: 'Target A' }, account: { id: 'account', username: 'operator', capabilities: ['sftp'] } };
  const api = { files: async () => ({ items: [] }), upload: async (connection, path, file) => { uploads.push({ connection, path, file }); return { bytes: file.size }; } };
  mountFiles(root, api, life, () => target, () => {}, error => errors.push(error), { features: { copy_jobs: false } });
  const fileInput = find(root, value => value.id === 'upload-file'), destination = find(root, value => value.id === 'upload-destination'), upload = find(root, value => value.id === 'upload-submit');
  assert.equal(upload.disabled, true); assert.match(root.textContent, /请先点击“建立 SFTP 连接”/);
  find(root, value => value.tagName === 'button' && value.textContent === '建立 SFTP 连接').click(); await flush();
  const file = new File([new Uint8Array([255, 0, 1])], '中文.txt'); fileInput.files = [file]; fileInput.onchange();
  assert.equal(destination.value, './中文.txt'); assert.equal(upload.disabled, false);
  destination.value = '/tmp/custom.bin'; destination.oninput(); const directory = find(root, value => value.id === 'file-path'); directory.value = '/other'; directory.onchange(); assert.equal(destination.value, '/tmp/custom.bin'); fileInput.files = [file]; fileInput.onchange(); assert.equal(destination.value, '/tmp/custom.bin');
  upload.click(); await flush(); assert.equal(uploads.length, 1); assert.equal(uploads[0].connection, 'bound-connection'); assert.equal(uploads[0].path, '/tmp/custom.bin'); assert.equal(uploads[0].file, file); assert.equal(errors.length, 0); assert.match(root.textContent, /服务端确认写入 3 字节/); life.dispose();
});

test('upload unknown result stays explicit and is never automatically retried', async t => {
  const root = dom(t), life = new RouteLifetime(), errors = []; let uploads = 0;
  mountFiles(root, { files: async () => ({ items: [] }), upload: async () => { uploads++; throw new ApiError('RESULT_UNKNOWN', 'interrupted'); } }, life, () => ({ asset: { id: 'a', name: 'A' }, account: { id: 'b', username: 'u', capabilities: ['sftp'] } }), () => {}, error => errors.push(error), { features: {} });
  find(root, value => value.tagName === 'button' && value.textContent === '建立 SFTP 连接').click(); await flush(); const file = find(root, value => value.id === 'upload-file'); file.files = [new File(['abc'], 'a.txt')]; file.onchange(); find(root, value => value.id === 'upload-submit').click(); await flush(); assert.equal(uploads, 1); assert.equal(errors[0].code, 'RESULT_UNKNOWN'); assert.match(root.textContent, /上传结果未知/); life.dispose();
});
