import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { ApiError } from '../src/api.ts';
import { RouteLifetime } from '../src/state.ts';

// Actual main.ts handlers, tiny DOM only: no browser/layout, network or new dependency.
const moduleURL = source => `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`;
const workbenches = moduleURL('export function mountSession(){return()=>{}} export function mountTerminalSession(){return()=>{}} export function mountReplay(){}');
let source = ts.transpileModule(await readFile(new URL('../src/main.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } }).outputText;
source = source.replace(/^import ['"].*\.css['"];\s*$/gm, '');
for (const name of ['api', 'state']) source = source.replace(`from './${name}'`, `from '${new URL(`../src/${name}.ts`, import.meta.url).href}'`);
for (const name of ['guac', 'workspaces', 'terminal']) source = source.replace(`from './${name}'`, `from '${workbenches}'`);
assert.match(source, /void initialize\(\);\s*$/);
source = source.replace(/void initialize\(\);\s*$/, 'export { editDialog, mountUsers, mountAdminAssets, mountAssets, mountConsole, mountGrants, mountActivity, confirmSshHostKey, confirmRdpCertificate, prepareSshConnection, getTarget, renderAssets, renderAccounts, renderRoute, showError, clearError, clearMemory, api }; export function fixtureRoute(value) { route = value; } export function fixtureAccess(identity, targets, discovery) { me = identity; assets = targets; info = discovery; } export function fixtureGroups(groups) { assetGroups = groups; }');
let moduleCount = 0;
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {}; this.listeners = {}; this._text = ''; this._value = ''; this.hidden = false; this.disabled = false; this.required = false; this.className = ''; this.classList = { add: name => { this.className += ` ${name}`; } }; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this._text = String(value); this.replaceChildren(); }
  get value() { return this._value; }
  set value(value) { this._value = this.tagName === 'select' && !this.children.some(child => child.value === value) ? '' : String(value); }
  get parentElement() { return this.parent ?? null; }
  get isConnected() { return this === document.body || !!this.parent?.isConnected; }
  get lastChild() { return this.children.at(-1); }
  get options() { return this.children.filter(child => child.tagName === 'option'); }
  append(...children) { for (let child of children) { if (typeof child !== 'object') { const text = new Element('#text'); text.textContent = child; child = text; } child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { for (const child of this.children) child.parent = null; this.children = []; this.append(...children); if (this.tagName === 'select') this._value = children[0]?.value ?? ''; }
  closest(tag) { let value = this; while (value && value.tagName !== tag) value = value.parent; return value ?? null; }
  after(child) { child.parent = this.parent; this.parent.children.splice(this.parent.children.indexOf(this) + 1, 0, child); }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(name, handler) { (this.listeners[name] ??= []).push(handler); }
  dispatch(name) { const event = { target: this, preventDefault() {} }; for (const handler of this.listeners[name] ?? []) handler(event); this[`on${name}`]?.(event); }
  dispatchEvent(event) { this.dispatch(event.type); return true; }
  querySelectorAll(selector) { return all(this).slice(1).filter(value => selector.split(',').some(part => { const match = /^(?:([a-z][a-z0-9-]*))?(?:\[(name|type)=['"]?([^'"\]]+)['"]?\])?$/.exec(part.trim()); return match && (!match[1] || value.tagName === match[1]) && (!match[2] || value[match[2]] === match[3]); })); }
  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
  focus() { document.activeElement = this; }
  scrollIntoView() {}
  showModal() { this.open = true; }
  close() { if (this.open) { this.open = false; this.dispatch('close'); } }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
  click() { if (!this.disabled) this.onclick?.(); }
}
class Input extends Element { constructor() { super('input'); } }
const all = root => [root, ...root.children.flatMap(all)];
const field = (dialog, name) => all(dialog).find(value => value.name === name);
const button = (root, text) => all(root).find(value => value.tagName === 'button' && value.textContent === text);
const submit = dialog => dialog.querySelector('form').onsubmit({ preventDefault() {} });
const flush = async () => { for (let index = 0; index < 10; index++) await new Promise(resolve => setImmediate(resolve)); };
const asset = { id: 'asset /1', name: 'Test server', host: 'target.test', port: 2222, protocol: 'ssh', ssh_host_key: 'ssh-ed25519 AAAA', security: null, rdp_certificate_sha256: null, tags: ['demo', 'linux'], group_id: null, enabled: true, revision: 1 };
const page = { items: [], next_cursor: null };
const accountPath = `/api/v1/admin/assets/${encodeURIComponent(asset.id)}/accounts`;
const assetPath = `/api/v1/admin/assets/${encodeURIComponent(asset.id)}`;
const freshAsset = { ...asset, revision: 7 };
const account = { id: '11111111-1111-4111-8111-111111111111', asset_id: asset.id, label: 'Primary', username: 'root', domain: null, enabled: true, revision: 11, credential_kind: 'password', credential_revision: 3 };
const secondAccount = { ...account, id: '22222222-2222-4222-8222-222222222222', label: 'Deploy', username: 'deploy', enabled: false, revision: 17, credential_kind: 'private_key' };
const targetAccountPath = value => `/api/v1/admin/accounts/${encodeURIComponent(value.id)}`;
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const managedUser = { id: 'user /2', username: 'Delete <user>', role: 'operator', enabled: true, revision: 8 };
const userRow = (view, user = managedUser) => all(view).find(value => value.tagName === 'tr' && all(value).some(child => child.tagName === 'span' && child.textContent === user.id));
async function fixture(t, mutation = async () => asset, { edit = false, read, open = true, routeId, access, groups, grants = false, users = false, connections = false, audit = false } = {}) {
  const names = ['document', 'window', 'location', 'Option', 'HTMLInputElement'];
  const previous = new Map(names.map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const body = new Element('body'), ids = new Map();
  globalThis.document = { body, activeElement: null, querySelector: selector => body.querySelector(selector), createElement: tag => tag === 'input' ? new Input() : new Element(tag), getElementById: id => { if (!ids.has(id)) { const element = new Element(['asset', 'account'].includes(id) ? 'select' : 'div'); element.id = id; body.append(element); ids.set(id, element); } return ids.get(id); } };
  globalThis.window = { addEventListener() {} };
  globalThis.location = { origin: 'https://test.invalid', hash: users ? '#/users' : '#/admin-assets' };
  globalThis.HTMLInputElement = Input;
  globalThis.Option = class extends Element { constructor(text, value) { super('option'); this.textContent = text; this.value = value; } };
  const life = new RouteLifetime(); let main;
  t.after(() => { life.dispose(); main?.clearMemory(); for (const [name, descriptor] of previous) { if (descriptor) Object.defineProperty(globalThis, name, descriptor); else delete globalThis[name]; } });
  main = await import(moduleURL(`${source}\n// fixture ${++moduleCount}`));
  const calls = [], reads = [];
  const defaults = path => {
    const url = new URL(path, location.origin);
    if (users && url.pathname === '/api/v1/admin/users') return { items: [structuredClone(managedUser), identity().user], next_cursor: null };
    if (edit && url.pathname === '/api/v1/admin/assets') return { items: [{ ...asset }], next_cursor: null };
    if (edit && url.pathname === assetPath) return structuredClone(freshAsset);
    if (edit && url.pathname === accountPath) return { items: [structuredClone(url.searchParams.has('cursor') ? secondAccount : account)], next_cursor: url.searchParams.has('cursor') ? null : 'account-page-2' };
    return page;
  };
  main.api.json = async (path, options = {}) => {
    if (!options.method || options.method === 'GET') { reads.push({ path, signal: options.signal }); return read ? read(path, options, defaults) : defaults(path); }
    calls.push({ path, method: options.method, revision: options.revision, body: structuredClone(options.body), signal: options.signal });
    return mutation(path, options);
  };
  if (routeId) main.fixtureRoute({ name: 'admin-assets', id: routeId });
  if (users) { main.fixtureRoute({ name: 'users' }); main.fixtureAccess(identity(), [], null); main.mountUsers(life); }
  else if (access) { main.fixtureAccess(...access); if (groups) main.fixtureGroups(groups); main.renderAssets(); main.mountAssets(); }
  else if (grants) main.mountGrants(life);
  else if (connections) main.mountActivity('connections', life);
  else if (audit) main.mountActivity('audit', life);
  else main.mountAdminAssets(life);
  await flush();
  if (open) { button(ids.get('route-view'), users ? '删除' : edit ? '编辑资产与账号' : '新建资产').click(); await flush(); }
  const dialog = body.querySelector('dialog'); if (open) assert(dialog?.open);
  return { ...main, life, dialog, calls, reads, body, view: ids.get('route-view') };
}
function fill(dialog, type = 'password') {
  for (const [name, value] of Object.entries({ name: asset.name, host: asset.host, port: '2222', tags: ' demo, linux, ', ssh_host_key: 'ssh-ed25519 AAAA', label: 'Primary', username: 'root' })) field(dialog, name).value = value;
  field(dialog, 'credential_type').value = type; field(dialog, 'credential_type').dispatch('change');
  if (type === 'password') field(dialog, 'password').value = 'test-secret';
  else { field(dialog, 'key_pem').value = '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n'; field(dialog, 'passphrase').value = 'key-secret'; }
}

test('SSH asset creation needs no manual host public key and keeps target credentials separate', async t => {
  const { dialog, calls } = await fixture(t, (path, options) => path === '/api/v1/admin/assets' ? { ...asset, ...options.body } : account);
  fill(dialog); field(dialog, 'ssh_host_key').value = '';
  assert.equal(field(dialog, 'ssh_host_key').required, false);
  submit(dialog); await flush();
  assert.equal(calls.length, 2); assert.equal(calls[0].body.ssh_host_key, null);
  assert.equal(calls[0].body.password, undefined); assert.equal(calls[1].body.credential.password, 'test-secret');
  assert.equal(dialog.open, false);
});

const hostKeyScan = { asset_id: asset.id, host: asset.host, port: asset.port, revision: freshAsset.revision, approved_fingerprint: null, keys: [
  { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:first', public_key: 'ssh-ed25519 AAAA' },
  { algorithm: 'ecdsa-sha2-nistp256', fingerprint: 'SHA256:second', public_key: 'ecdsa-sha2-nistp256 BBBB' },
] };

test('host key discovery requires an explicit confirmation and cancelling never saves trust', async t => {
  const main = await fixture(t, () => hostKeyScan, { open: false });
  const result = main.confirmSshHostKey(freshAsset, main.life); await flush();
  const dialog = main.body.querySelector('dialog'); assert(dialog.open); assert.match(dialog.textContent, /首次信任确认/);
  assert.equal(main.calls.length, 1); assert.equal(main.calls[0].method, 'POST'); assert.equal(main.calls[0].revision, freshAsset.revision);
  assert.equal(main.calls[0].path, assetPath + '/ssh-host-key/scan'); assert.equal(main.calls[0].body, undefined);
  assert.match(field(dialog, 'host_key').options[0].textContent, /SHA256:first/);
  button(dialog, '取消').click(); assert.equal(await result, false); assert.equal(main.calls.length, 1);
});

test('confirmation saves only the selected scanned key using the scanned revision, once', async t => {
  const main = await fixture(t, path => path.endsWith('/scan') ? hostKeyScan : freshAsset, { open: false });
  const result = main.confirmSshHostKey(freshAsset, main.life); await flush();
  const dialog = main.body.querySelector('dialog'); field(dialog, 'host_key').value = '1';
  submit(dialog); submit(dialog); await flush(); assert.equal(await result, true);
  assert.equal(main.calls.length, 2); assert.equal(main.calls[1].method, 'PATCH'); assert.equal(main.calls[1].revision, hostKeyScan.revision);
  assert.deepEqual(main.calls[1].body, { ssh_host_key: hostKeyScan.keys[1].public_key });
});

test('changed host keys show the previous fingerprint and approval conflicts cannot replay', async t => {
  for (const code of ['REVISION_CONFLICT', 'RESULT_UNKNOWN']) await t.test(code, async t => {
    const main = await fixture(t, path => { if (path.endsWith('/scan')) return { ...hostKeyScan, approved_fingerprint: 'SHA256:previous' }; throw new ApiError(code, 'Reread', 'key-approval'); }, { open: false });
    const result = main.confirmSshHostKey(freshAsset, main.life); await flush();
    const dialog = main.body.querySelector('dialog'); assert.match(dialog.textContent, /主机密钥已变化/); assert.match(dialog.textContent, /SHA256:previous/);
    submit(dialog); await flush(); assert.equal(button(dialog, '确认').disabled, true);
    submit(dialog); await flush(); assert.equal(main.calls.length, 2);
    button(dialog, '取消').click(); assert.equal(await result, false);
  });
});

test('first SSH administrator connection confirms missing trust; approved and other protocols skip scanning', async t => {
  const main = await fixture(t, path => path.endsWith('/scan') ? hostKeyScan : freshAsset, { open: false, read: () => ({ ...freshAsset, ssh_host_key: null }) });
  main.fixtureAccess(identity(), [], null);
  const selected = { asset: accessible, account: accessible.accounts[0] };
  selected.asset = { ...selected.asset, id: asset.id };
  const result = main.prepareSshConnection(selected, main.life); await flush();
  const dialog = main.body.querySelector('dialog'); assert(dialog.open); button(dialog, '取消').click(); assert.equal(await result, false);
  main.api.adminAsset = async () => freshAsset;
  assert.equal(await main.prepareSshConnection(selected, main.life), true);
  assert.equal(await main.prepareSshConnection({ ...selected, asset: { ...selected.asset, protocol: 'vnc' } }, main.life), true);
  assert.equal(main.calls.length, 1);
});

test('route disposal during discovery or confirmation cannot approve a detached host key', async t => {
  for (const phase of ['scan', 'confirm']) await t.test(phase, async t => {
    const pending = deferred(); const main = await fixture(t, () => phase === 'scan' ? pending.promise : hostKeyScan, { open: false });
    const result = main.confirmSshHostKey(freshAsset, main.life); await flush();
    const dialog = main.body.querySelector('dialog'); main.life.dispose();
    if (phase === 'scan') pending.resolve(hostKeyScan);
    else submit(dialog);
    assert.equal(await result, false); assert.equal(main.calls.length, 1); assert.equal(main.body.querySelector('dialog'), null);
  });
});

test('credential mode defaults to password; only active fields validate and switching clears inactive secrets', async t => {
  const { dialog } = await fixture(t), type = field(dialog, 'credential_type');
  const active = (name, expected, required) => { const input = field(dialog, name); assert.equal(input.parentElement.hidden, !expected); assert.equal(input.disabled, !expected); assert.equal(input.required, required); };
  assert.equal(type.value, 'password'); active('password', true, true); active('key_pem', false, false); active('passphrase', false, false);
  field(dialog, 'password').value = 'discard-password'; type.value = 'private_key'; type.dispatch('change');
  active('password', false, false); active('key_pem', true, true); active('passphrase', true, false); assert.equal(field(dialog, 'password').value, '');
  field(dialog, 'key_pem').value = 'discard-key'; field(dialog, 'passphrase').value = 'discard-passphrase'; type.value = 'password'; type.dispatch('change');
  active('password', true, true); active('key_pem', false, false); active('passphrase', false, false);
  assert.equal(field(dialog, 'key_pem').value, ''); assert.equal(field(dialog, 'passphrase').value, '');
  assert(dialog.className.includes('asset-create-dialog')); assert.equal(all(dialog).filter(value => value.tagName === 'fieldset').length, 2);
});

test('one asset/username/credential modal submits asset without secrets, then account, then detail', async t => {
  for (const type of ['password', 'private_key']) await t.test(type, async t => {
    const created = deferred(), saved = deferred();
    const { dialog, calls } = await fixture(t, path => path === '/api/v1/admin/assets' ? created.promise : saved.promise);
    fill(dialog, type); submit(dialog); await flush();
    assert.deepEqual(calls.map(call => call.path), ['/api/v1/admin/assets']);
    assert.deepEqual(calls[0].body, { name: asset.name, host: asset.host, port: asset.port, tags: asset.tags, group_id: null, protocol: 'ssh', ssh_host_key: asset.ssh_host_key });
    for (const name of ['password', 'key_pem', 'passphrase']) assert.equal(field(dialog, name).value, '');
    assert.equal(button(dialog, '确认').disabled, true); assert.equal(location.hash, '#/admin-assets');
    submit(dialog); assert.equal(calls.length, 1); created.resolve(asset); await flush();
    assert.deepEqual(calls.map(call => call.path), ['/api/v1/admin/assets', accountPath]);
    assert.equal(dialog.querySelector('fieldset').disabled, true);
    assert.deepEqual(calls[1].body, { label: 'Primary', username: 'root', domain: null, credential: type === 'password' ? { type, password: 'test-secret' } : { type, key_pem: '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n', passphrase: 'key-secret' } });
    assert.equal(location.hash, '#/admin-assets'); saved.resolve({ id: 'account' }); await flush();
    // A successful create closes the form and stays on the list; it does not open the editor for the new asset.
    assert.equal(location.hash, '#/admin-assets'); assert.equal(dialog.open, false); assert.equal(dialog.parentElement, null);
    assert.match(document.getElementById('status').textContent, /资产与首个目标账号已创建/);
  });
});

test('known account failure retries the same created asset without another asset POST', async t => {
  let attempts = 0;
  const { dialog, calls } = await fixture(t, path => { if (path === '/api/v1/admin/assets') return asset; if (++attempts === 1) throw new ApiError('INVALID_ARGUMENT', 'Bad credential', 'r', 400); return { id: 'account' }; });
  fill(dialog); submit(dialog); await flush();
  assert.equal(dialog.open, true); assert.match(dialog.textContent, /账号创建失败/); assert.equal(button(dialog, '确认').disabled, false);
  assert.equal(dialog.querySelector('fieldset').disabled, true); assert.equal(field(dialog, 'password').value, '');
  field(dialog, 'username').value = 'other'; field(dialog, 'password').value = 'replacement-secret'; submit(dialog); await flush();
  assert.deepEqual(calls.map(call => call.path), ['/api/v1/admin/assets', accountPath, accountPath]);
  assert.deepEqual(calls[2].body, { label: 'Primary', username: 'other', domain: null, credential: { type: 'password', password: 'replacement-secret' } });
  assert.equal(location.hash, '#/admin-assets'); assert.equal(dialog.open, false);
});

test('RESULT_UNKNOWN at either mutation prevents a second submit', async t => {
  for (const stage of ['asset', 'account']) await t.test(stage, async t => {
    const { dialog, calls } = await fixture(t, path => { if (stage === 'account' && path === '/api/v1/admin/assets') return asset; throw new ApiError('RESULT_UNKNOWN', 'Interrupted'); });
    fill(dialog); submit(dialog); await flush(); const count = calls.length;
    assert.equal(count, stage === 'asset' ? 1 : 2); assert.equal(button(dialog, '确认').disabled, true); assert.equal(dialog.open, true); assert.match(dialog.textContent, /结果未知/);
    if (stage === 'account') assert(dialog.textContent.includes(asset.id));
    field(dialog, 'password').value = 'must-not-retry'; submit(dialog); await flush(); assert.equal(calls.length, count); assert.equal(location.hash, '#/admin-assets');
    button(dialog, '取消').click(); assert.equal(field(dialog, 'password').value, '');
  });
});

test('route disposal closes the modal and clears passwords, PEM and passphrase without submitting', async t => {
  const { dialog, calls, life } = await fixture(t);
  fill(dialog, 'private_key'); field(dialog, 'password').value = 'inactive-secret'; life.dispose();
  assert.equal(life.signal.aborted, true); assert.equal(dialog.open, false); assert.equal(dialog.parentElement, null);
  for (const name of ['password', 'key_pem', 'passphrase']) assert.equal(field(dialog, name).value, '');
  assert.equal(calls.length, 0);
});

test('route disposal while asset creation is pending does not continue with account creation', async t => {
  const created = deferred(), { dialog, calls, life } = await fixture(t, () => created.promise);
  fill(dialog, 'private_key'); submit(dialog); await flush(); life.dispose(); created.resolve(asset); await flush();
  assert.equal(dialog.open, false); assert.equal(dialog.parentElement, null);
  for (const name of ['password', 'key_pem', 'passphrase']) assert.equal(field(dialog, name).value, '');
  assert.equal(calls.length, 1); assert.equal(calls[0].signal.aborted, true); assert.equal(location.hash, '#/admin-assets');
});

test('asset modal CSS hides inactive fields and supplies two columns with a narrow-screen fallback', async () => {
  const css = await readFile(new URL('../src/style.css', import.meta.url), 'utf8');
  assert.match(css, /\[hidden\]\s*\{\s*display:\s*none\s*!important/);
  assert.match(css, /dialog\.asset-create-dialog fieldset\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)/);
  assert.match(css, /@media\s*\(max-width:\s*\d+px\)\s*\{\s*dialog\.asset-create-dialog fieldset\s*\{\s*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
});

const choose = (dialog, name, value) => { const input = field(dialog, name); input.value = value; input.dispatch('change'); };
function changedEdit(dialog) {
  field(dialog, 'name').value = 'Renamed server'; field(dialog, 'asset_enabled').checked = false;
  field(dialog, 'username').value = 'renamed-root'; field(dialog, 'account_enabled').checked = false;
  choose(dialog, 'credential_type', 'password'); field(dialog, 'password').value = 'replacement-secret';
}
const updatedAsset = { ...freshAsset, name: 'Renamed server', enabled: false, revision: 8 };
const updatedAccount = { ...account, username: 'renamed-root', enabled: false, revision: 12 };
const editReply = path => path === assetPath ? structuredClone(updatedAsset) : path.endsWith('/credential') ? { ...updatedAccount, revision: 13, credential_revision: 4 } : structuredClone(updatedAccount);

test('one combined edit entry reads fresh asset and all account pages; unchanged keep saves no mutation', async t => {
  const { view, dialog, reads, calls } = await fixture(t, undefined, { edit: true });
  const row = all(view).find(value => value.tagName === 'tr' && value.textContent.includes(asset.name)); assert(row);
  assert.deepEqual(all(row).filter(value => value.tagName === 'button').map(value => value.textContent), ['编辑资产与账号', '重新核验主机指纹', '删除']);
  assert(!all(row).some(value => value.tagName === 'a' && value.textContent === '主机密钥'));
  assert(!all(view).some(value => value.tagName === 'a' && value.textContent === '账号与主机密钥'));
  assert(!button(row, '编辑')); assert(!button(row, '替换凭据'));
  assert(reads.some(value => value.path === assetPath));
  const pages = reads.filter(value => new URL(value.path, location.origin).pathname === accountPath);
  assert.equal(pages.length, 2); assert.equal(new URL(pages[1].path, location.origin).searchParams.get('cursor'), 'account-page-2');
  assert.equal(field(dialog, 'account_id').value, account.id);
  assert.deepEqual(field(dialog, 'account_id').options.map(value => value.value), [account.id, secondAccount.id, 'new']);
  for (const name of ['name', 'host', 'port', 'tags', 'asset_enabled', 'account_id', 'username', 'account_enabled', 'credential_type', 'password', 'key_pem', 'passphrase']) assert(field(dialog, name), name);
  assert.equal(field(dialog, 'credential_type').value, 'keep');
  for (const name of ['password', 'key_pem', 'passphrase']) { assert.equal(field(dialog, name).value, ''); assert.equal(field(dialog, name).parentElement.hidden, true); }
  submit(dialog); await flush(); assert.deepEqual(calls, []); assert.equal(dialog.open, false);
});

test('changing selected account switches metadata, resets keep and clears secrets; new requires credentials', async t => {
  const { dialog } = await fixture(t, undefined, { edit: true });
  choose(dialog, 'credential_type', 'private_key'); field(dialog, 'key_pem').value = 'discard-key'; field(dialog, 'passphrase').value = 'discard-passphrase';
  field(dialog, 'password').value = 'inactive-secret'; choose(dialog, 'account_id', secondAccount.id);
  assert.equal(field(dialog, 'username').value, secondAccount.username); assert.equal(field(dialog, 'account_enabled').checked, false);
  assert.equal(field(dialog, 'credential_type').value, 'keep');
  for (const name of ['password', 'key_pem', 'passphrase']) assert.equal(field(dialog, name).value, '');
  choose(dialog, 'credential_type', 'password'); field(dialog, 'password').value = 'discard-password'; choose(dialog, 'account_id', 'new');
  assert.equal(field(dialog, 'username').value, ''); assert.notEqual(field(dialog, 'credential_type').value, 'keep');
  assert.equal(field(dialog, 'password').value, ''); assert.equal(field(dialog, 'account_enabled').disabled, true);
  assert.equal(field(dialog, 'account_enabled').parentElement.hidden, true);
  assert.equal(field(dialog, field(dialog, 'credential_type').value === 'password' ? 'password' : 'key_pem').required, true);
  choose(dialog, 'account_id', account.id); assert.equal(field(dialog, 'username').value, account.username); assert.equal(field(dialog, 'account_enabled').checked, true);
});

test('changed asset and account PATCH use current revisions; credential PUT uses account PATCH result', async t => {
  const { dialog, calls } = await fixture(t, editReply, { edit: true }); changedEdit(dialog); submit(dialog); await flush();
  assert.deepEqual(calls.map(value => [value.path, value.method, value.revision]), [
    [assetPath, 'PATCH', freshAsset.revision], [targetAccountPath(account), 'PATCH', account.revision], [targetAccountPath(account) + '/credential', 'PUT', updatedAccount.revision],
  ]);
  assert.equal(calls[0].body.name, updatedAsset.name); assert.equal(calls[0].body.enabled, false);
  assert(Object.keys(calls[0].body).every(name => ['name', 'host', 'port', 'tags', 'group_id', 'enabled', 'ssh_host_key'].includes(name)));
  assert.deepEqual(calls[1].body, { username: updatedAccount.username, enabled: false });
  assert.deepEqual(calls[2].body, { type: 'password', password: 'replacement-secret' }); assert.equal(dialog.open, false);
});

test('label-only account edit sends no unchanged authentication fields or credential mutation', async t => {
  const { dialog, calls } = await fixture(t, (path, options) => ({ ...account, ...options.body, revision: account.revision + 1 }), { edit: true });
  field(dialog, 'label').value = 'Renamed label'; submit(dialog); await flush();
  assert.equal(calls.length, 1); assert.equal(calls[0].path, targetAccountPath(account)); assert.equal(calls[0].method, 'PATCH'); assert.equal(calls[0].revision, account.revision);
  assert.deepEqual(calls[0].body, { label: 'Renamed label' }); assert.equal(dialog.open, false);
});

test('credential-only save updates selected paginated account without asset/account PATCH', async t => {
  const { dialog, calls } = await fixture(t, () => ({ ...secondAccount, revision: 18, credential_revision: 4 }), { edit: true });
  choose(dialog, 'account_id', secondAccount.id); choose(dialog, 'credential_type', 'private_key');
  field(dialog, 'key_pem').value = '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n'; field(dialog, 'passphrase').value = 'key-secret';
  submit(dialog); await flush();
  assert.deepEqual(calls.map(value => [value.path, value.method, value.revision]), [[targetAccountPath(secondAccount) + '/credential', 'PUT', secondAccount.revision]]);
  assert.deepEqual(calls[0].body, { type: 'private_key', key_pem: '-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n', passphrase: 'key-secret' });
});

test('known later-stage failure retries only unacknowledged account/credential stages', async t => {
  for (const stage of ['account', 'credential']) await t.test(stage, async t => {
    let attempts = 0; const failurePath = targetAccountPath(account) + (stage === 'credential' ? '/credential' : '');
    const { dialog, calls } = await fixture(t, path => { if (path === failurePath && ++attempts === 1) throw new ApiError('INVALID_ARGUMENT', 'Invalid replacement', 'r', 400); return editReply(path); }, { edit: true });
    changedEdit(dialog); submit(dialog); await flush(); assert.equal(dialog.open, true); assert.equal(button(dialog, '确认').disabled, false);
    assert.equal(field(dialog, 'password').value, ''); field(dialog, 'password').value = 'retry-secret'; submit(dialog); await flush();
    assert.deepEqual(calls.map(value => [value.path, value.method, value.revision]), [
      [assetPath, 'PATCH', 7], [targetAccountPath(account), 'PATCH', 11],
      stage === 'credential' ? [targetAccountPath(account) + '/credential', 'PUT', 12] : [targetAccountPath(account), 'PATCH', 11],
      [targetAccountPath(account) + '/credential', 'PUT', 12],
    ]);
    assert.deepEqual(calls[3].body, { type: 'password', password: 'retry-secret' }); assert.equal(dialog.open, false);
  });
});

test('new account in combined editor creates once with selected password or private-key credential', async t => {
  for (const type of ['password', 'private_key']) await t.test(type, async t => {
    const { dialog, calls } = await fixture(t, () => ({ ...account, id: '33333333-3333-4333-8333-333333333333', username: 'new-user', revision: 1 }), { edit: true });
    choose(dialog, 'account_id', 'new'); field(dialog, 'username').value = 'new-user'; field(dialog, 'label').value = 'New user'; choose(dialog, 'credential_type', type);
    if (type === 'password') field(dialog, 'password').value = 'new-secret'; else { field(dialog, 'key_pem').value = 'new-key'; field(dialog, 'passphrase').value = ''; }
    submit(dialog); submit(dialog); await flush();
    assert.deepEqual(calls.map(value => [value.path, value.method]), [[accountPath, 'POST']]);
    assert.deepEqual(calls[0].body, { label: 'New user', username: 'new-user', domain: null, credential: type === 'password' ? { type, password: 'new-secret' } : { type, key_pem: 'new-key', passphrase: null } }); assert.equal(dialog.open, false);
  });
});

test('unknown or revision conflict at any edit mutation blocks replay and requires reread', async t => {
  for (const code of ['RESULT_UNKNOWN', 'REVISION_CONFLICT']) for (const stage of ['asset', 'account', 'credential']) await t.test(`${code} ${stage}`, async t => {
    const failurePath = stage === 'asset' ? assetPath : targetAccountPath(account) + (stage === 'credential' ? '/credential' : '');
    const { dialog, calls } = await fixture(t, path => { if (path === failurePath) throw new ApiError(code, 'Must reread', 'r', code === 'REVISION_CONFLICT' ? 412 : 0); return editReply(path); }, { edit: true });
    changedEdit(dialog); submit(dialog); await flush(); const count = calls.length;
    assert.equal(count, ['asset', 'account', 'credential'].indexOf(stage) + 1); assert.equal(dialog.open, true); assert.equal(button(dialog, '确认').disabled, true);
    assert.match(dialog.textContent, code === 'RESULT_UNKNOWN' ? /结果未知/ : /修订冲突/);
    field(dialog, 'password').value = 'must-not-replay'; submit(dialog); await flush(); assert.equal(calls.length, count);
    button(dialog, '取消').click(); assert.equal(field(dialog, 'password').value, '');
  });
});

test('edit disposal while a known stage is pending prevents every later mutation', async t => {
  for (const stage of ['asset', 'account']) await t.test(stage, async t => {
    const pending = deferred(), failurePath = stage === 'asset' ? assetPath : targetAccountPath(account);
    const { dialog, calls, life } = await fixture(t, path => path === failurePath ? pending.promise : editReply(path), { edit: true });
    changedEdit(dialog); submit(dialog); await flush();
    assert.equal(field(dialog, 'account_id').disabled, true); assert.equal(field(dialog, 'credential_type').disabled, true);
    const count = calls.length; life.dispose(); pending.resolve(editReply(failurePath)); await flush();
    assert.equal(calls.length, count); assert.equal(count, stage === 'asset' ? 1 : 2); assert.equal(calls.at(-1).signal.aborted, true);
    assert.equal(dialog.open, false); assert.equal(dialog.parentElement, null);
    for (const name of ['password', 'key_pem', 'passphrase']) assert.equal(field(dialog, name).value, '');
  });
});

const identity = (role = 'admin', enabled = true) => ({ user: { id: 'u', username: 'user', role, enabled, revision: 1 }, login_session_id: 'l', policy_revision: 1, csrf_token: 'csrf' });
const discovery = { features: { web_ssh: true, web_rdp: false, web_vnc: true } };
const accessible = { id: 'available', name: 'Available target', protocol: 'ssh', tags: ['linux'], accounts: [{ id: 'ssh-account', label: 'Deploy', username: 'deploy', domain: null, credential_kind: 'password' }] };

test('connection revocation keeps login, while HTTP 401 and identity revocation clear it', async t => {
  const main = await fixture(t, undefined, { open: false, access: [identity(), [accessible], discovery] });
  main.fixtureRoute({ name: 'console', id: accessible.id, sub: accessible.accounts[0].id });
  const target = main.getTarget();
  main.showError(new ApiError('LOGIN_SESSION_REVOKED', 'Connection cancelled'), target);
  assert.deepEqual(main.getTarget(), target);
  assert.match(document.getElementById('error').textContent, /LOGIN_SESSION_REVOKED/);
  main.showError(new ApiError('UNAUTHORIZED', 'Login expired', 'r', 401), target);
  assert.equal(main.getTarget(), null);
  main.fixtureAccess(identity(), [accessible], discovery); main.renderAssets();
  main.showError(new ApiError('LOGIN_SESSION_REVOKED', 'Login revoked'));
  assert.equal(main.getTarget(), null);
});

test('one console action is protocol-gated, with empty targets kept visible', async t => {
 const empty = { id: 'empty', name: 'Empty target', protocol: 'ssh', accounts: [] };
 const main = await fixture(t, undefined, { open: false, access: [identity(), [empty, accessible], discovery] });
 assert.match(main.view.textContent, /2 个目标/);
 assert.equal(main.getTarget(), null);
 const windows=[];const origOpen=globalThis.window.open;globalThis.window.open=url=>{windows.push(String(url));return null;};
 try{button(main.view, '连接').click();assert.equal(windows.length,1);assert.match(windows[0],/#\/console\/[^/]+\/ssh-account/);}
 finally{globalThis.window.open=origOpen;}
 main.view.replaceChildren(); main.fixtureAccess(identity(), [accessible], {features:{web_ssh:false}}); main.mountAssets(); assert(!button(main.view,'连接'));
});

test('Grant create/edit has no permission inputs or column and sends only exact access metadata', async t => {
  const grant = { id: 'grant', user_id: 'u', asset_id: 'a', account_id: 'c', enabled: true, expires_at: null, revision: 6, capabilities: ['shell', 'exec', 'sftp'], username: 'alice', asset_name: 'db', account_label: 'root' };
  const lists = { '/admin/users': { id: 'u', username: 'alice', role: 'operator', enabled: true }, '/admin/assets': { id: 'a', name: 'db', host: 'h', port: 22, protocol: 'ssh', enabled: true }, '/admin/assets/a/accounts': { id: 'c', label: 'root', username: 'root', enabled: true } };
  const main = await fixture(t, async () => grant, { open: false, grants: true, read: async path => ({ items: [Object.entries(lists).find(([key]) => path.split('?')[0].endsWith(key))?.[1] ?? grant], next_cursor: null }) });
  assert.match(main.view.textContent, /删除 Grant 不会移除管理员的隐式访问/);
  for (const name of ['alice', 'db', 'root']) assert.match(main.view.textContent, new RegExp(name));
  assert(!all(main.view).some(value => value.tagName === 'th' && value.textContent === '能力'));
  button(main.view, '新建授权').click(); await flush(); let dialog = main.body.querySelector('dialog'); assert(!field(dialog, 'capabilities'));
  for (const [name, value] of Object.entries({ user_id: 'u', asset_id: 'a', account_id: 'c' })) assert.equal(field(dialog, name).value, value);
  submit(dialog); await flush(); assert.deepEqual(main.calls[0].body, { user_id: 'u', asset_id: 'a', account_id: 'c', expires_at: null });
  button(main.view, '编辑').click(); dialog = main.body.querySelector('dialog'); assert(!field(dialog, 'capabilities'));
  field(dialog, 'enabled').checked = false; submit(dialog); await flush();
  assert.deepEqual(main.calls[1].body, { enabled: false, expires_at: null }); assert.equal(main.calls[1].revision, 6);
});

test('user delete confirmation names identity/revision and consequences; cancelling restores focus without a request', async t => {
  const main = await fixture(t, undefined, { users: true, open: false }), remove = button(userRow(main.view), '删除');
  remove.focus(); remove.click(); const dialog = main.body.querySelector('dialog');
  assert.equal(remove.className, 'danger-text'); assert.equal(dialog.attributes['aria-labelledby'], dialog.querySelector('h2').id);
  assert.equal(all(dialog).find(value => value.attributes.role === 'alert')?.tagName, 'p');
  assert.equal(document.activeElement, button(dialog, '确认')); assert(button(dialog, '确认').className.includes('danger'));
  for (const value of [managedUser.username, managedUser.id, String(managedUser.revision), '无法登录', '票据', '运行连接', '审计', '历史连接', '录制', '主机密钥', '旧授权', '用户名可供新账号复用', '不继承旧授权、会话或历史归属', '无法恢复']) assert(dialog.textContent.includes(value), value);
  assert.equal(main.calls.length, 0); button(dialog, '取消').click();
  assert.equal(main.calls.length, 0); assert.equal(main.reads.length, 1); assert.equal(dialog.parentElement, null); assert.equal(document.activeElement, remove);
});

test('current login user delete action is disabled with an explanation', async t => {
  const main = await fixture(t, undefined, { users: true, open: false }), remove = button(userRow(main.view, identity().user), '删除');
  assert.equal(remove.disabled, true); assert.equal(remove.title, '不能删除当前登录用户');
  remove.click(); remove.onclick(); await flush(); assert.equal(main.calls.length, 0); assert.equal(main.body.querySelector('dialog'), null);
});

test('user deletion submits once while pending and only removes the row after the post-204 list read', async t => {
  const saved = deferred(), refreshed = deferred(); let reads = 0;
  const main = await fixture(t, () => saved.promise, { users: true, read: (path, options, defaults) => ++reads === 1 ? defaults(path) : refreshed.promise });
  const { dialog } = main, remove = button(userRow(main.view), '删除'); submit(dialog); submit(dialog); await flush();
  assert.equal(main.calls.length, 1); assert.deepEqual(main.calls[0], { path: `/api/v1/admin/users/${encodeURIComponent(managedUser.id)}`, method: 'DELETE', revision: managedUser.revision, body: undefined, signal: main.life.signal });
  assert.equal(button(dialog, '确认').disabled, true); assert.equal(button(dialog, '取消').disabled, true); assert(userRow(main.view)); assert.equal(main.reads.length, 1);
  saved.resolve(undefined); await flush(); assert.equal(main.reads.length, 2); assert.equal(remove.disabled, true); assert(userRow(main.view)); assert.equal(dialog.open, true);
  submit(dialog); assert.equal(main.calls.length, 1); refreshed.resolve({ items: [identity().user], next_cursor: null }); await flush();
  assert(!userRow(main.view)); assert(userRow(main.view, identity().user)); assert.equal(dialog.open, false); assert.equal(main.calls.length, 1);
  assert.match(document.getElementById('status').textContent, /用户删除已确认/);
});

test('user delete 403/404/412/unknown errors retain the row; unknown and conflicts cannot resubmit', async t => {
  for (const [code, status] of [['PERMISSION_DENIED', 403], ['RESOURCE_NOT_FOUND', 404], ['REVISION_CONFLICT', 412], ['RESULT_UNKNOWN', 0]]) await t.test(code, async t => {
    const main = await fixture(t, () => { throw new ApiError(code, 'Delete rejected', 'user-delete-request', status); }, { users: true });
    submit(main.dialog); await flush(); assert.equal(main.calls.length, 1); assert.equal(main.reads.length, 1); assert(userRow(main.view));
    assert.equal(main.dialog.open, true);
    const blocked = ['RESULT_UNKNOWN', 'REVISION_CONFLICT'].includes(code), remove = button(userRow(main.view), '删除'); assert.equal(remove.disabled, blocked);
    const error = document.getElementById('error'); assert.equal(error.hidden, false); assert(error.textContent.includes(code)); assert(error.textContent.includes('user-delete-request'));
    assert.equal(button(main.dialog, '确认').disabled, blocked); assert.equal(button(main.dialog, '取消').disabled, false);
    if (blocked) { submit(main.dialog); await flush(); assert.equal(main.calls.length, 1); assert.match(main.dialog.textContent, code === 'RESULT_UNKNOWN' ? /结果未知/ : /修订冲突/); button(main.dialog, '取消').click(); remove.click(); remove.onclick(); await flush(); assert.equal(main.calls.length, 1); assert.equal(main.body.querySelector('dialog'), null); }
  });
});

test('disposing a user route prevents detached confirmation and late post-delete list reads', async t => {
  await t.test('unsubmitted actual route', async t => {
    const main = await fixture(t, undefined, { users: true, open: false }); main.renderRoute(); await flush();
    const remove = button(userRow(main.view), '删除'); remove.click(); const dialog = main.body.querySelector('dialog');
    location.hash = '#/assets'; main.renderRoute(); assert.equal(dialog.open, false); assert.equal(dialog.parentElement, null);
    submit(dialog); remove.click(); await flush(); assert.equal(main.calls.length, 0);
  });
  await t.test('pending DELETE', async t => {
    const saved = deferred(), main = await fixture(t, () => saved.promise, { users: true }); submit(main.dialog); await flush();
    const reads = main.reads.length; main.life.dispose(); saved.resolve(undefined); await flush();
    assert.equal(main.calls.length, 1); assert.equal(main.calls[0].signal.aborted, true); assert.equal(main.reads.length, reads);
    assert.equal(main.dialog.open, false); assert.equal(main.dialog.parentElement, null);
  });
});

test('acknowledged user deletion with a failed list refresh keeps the GET error and disables old-row replay', async t => {
  let reads = 0;
  const main = await fixture(t, () => undefined, { users: true, read: (path, options, defaults) => { if (++reads === 1) return defaults(path); throw new ApiError('NETWORK_OR_TIMEOUT', '读取失败或超时。', 'user-list-request'); } });
  submit(main.dialog); await flush(); const row = userRow(main.view), remove = button(row, '删除'), error = document.getElementById('error');
  assert(row); assert.equal(main.calls.length, 1); assert.equal(main.reads.length, 2); assert.equal(main.dialog.open, false);
  assert.equal(error.hidden, false); assert.match(error.textContent, /用户删除已确认，但列表刷新失败/); assert(error.textContent.includes('NETWORK_OR_TIMEOUT')); assert(error.textContent.includes('user-list-request'));
  assert.match(document.getElementById('status').textContent, /用户删除已确认；若列表未更新，请点击刷新/);
  for (const action of all(row).filter(value => value.tagName === 'button')) assert.equal(action.disabled, true);
  remove.click(); remove.onclick(); submit(main.dialog); await flush(); assert.equal(main.calls.length, 1); assert.equal(main.reads.length, 2);
});


test('RDP password and VNC none/password creation send protocol-specific exact account bodies',async t=>{
 for(const [protocol,type] of [['rdp','password'],['vnc','none'],['vnc','password']])await t.test(protocol+' '+type,async t=>{
 const {dialog,calls}=await fixture(t,(path,options)=>path==='/api/v1/admin/assets'?{...asset,...options.body}:{...account,...options.body,credential_kind:type});
 fill(dialog);choose(dialog,'protocol',protocol);field(dialog,'label').value='Desktop';
 if(protocol==='rdp'){field(dialog,'username').value='alice';field(dialog,'domain').value='CORP';assert.equal(field(dialog,'rdp_certificate_sha256').required,false);assert.equal(field(dialog,'security'),undefined,'security is detected, not chosen');assert.equal(field(dialog,'port').value,'3389');}
 else {assert.equal(field(dialog,'username').disabled,true);assert.equal(field(dialog,'domain').disabled,true);assert.equal(field(dialog,'port').value,'5900');}
 assert(!field(dialog,'credential_type').options.some(x=>x.value==='private_key'));choose(dialog,'credential_type',type);if(type==='password')field(dialog,'password').value='testpw';submit(dialog);await flush();
 assert.equal(calls.length,2);assert.equal(calls[0].body.protocol,protocol);assert.equal(calls[0].body.ssh_host_key,undefined);
 if(protocol==='rdp'){assert.equal(calls[0].body.security,undefined);assert.equal(calls[0].body.rdp_certificate_sha256,null,'an RDP asset waits for first-connect confirmation');}else{assert.equal(calls[0].body.security,undefined);assert.equal(calls[0].body.rdp_certificate_sha256,undefined);}
 assert.deepEqual(calls[1].body,{label:'Desktop',username:protocol==='vnc'?null:'alice',domain:protocol==='rdp'?'CORP':null,credential:type==='none'?{type:'none'}:{type:'password',password:'testpw'}});assert.equal(dialog.open,false);
 });
});

test('account display name is optional and creation derives protocol-specific defaults',async t=>{
 for(const [protocol,type,label] of [['ssh','password','root'],['rdp','password','CORP\\alice'],['vnc','none','无认证'],['vnc','password','密码认证']])await t.test(protocol+' '+type,async t=>{
  const {dialog,calls}=await fixture(t,(path,options)=>path==='/api/v1/admin/assets'?{...asset,...options.body}:{...account,...options.body,credential_kind:type});
  fill(dialog);choose(dialog,'protocol',protocol);field(dialog,'label').value='';
  assert.equal(field(dialog,'label').required,false);assert(!dialog.textContent.includes('首个账号'));assert(!dialog.textContent.includes('账号标签'));
  if(protocol==='rdp'){field(dialog,'username').value='alice';field(dialog,'domain').value='CORP';field(dialog,'rdp_certificate_sha256').value='a'.repeat(64);}
  choose(dialog,'credential_type',type);if(type==='password')field(dialog,'password').value='testpw';
  submit(dialog);await flush();assert.equal(calls.length,2);assert.equal(calls[1].body.label,label);assert.equal(dialog.open,false);
 });
});

test('automatic account names track login edits and keep existing VNC credential kind',async t=>{
 for(const [protocol,kind,label,username,domain] of [['ssh','password','root','root',null],['rdp','password','CORP\\alice','alice','CORP'],['vnc','none','无认证',null,null],['vnc','password','密码认证',null,null]])await t.test(protocol+' '+kind,async t=>{
  const current={...account,label,username,domain,credential_kind:kind};
  const {dialog,calls}=await fixture(t,(path,options)=>({...current,...options.body,revision:12}),{edit:true,read:(path,options,defaults)=>{
   const url=new URL(path,location.origin);if(url.pathname===accountPath)return{items:[current],next_cursor:null};
   const row=defaults(path);return url.pathname===assetPath?{...row,protocol,...(protocol==='rdp'?{security:'nla',rdp_certificate_sha256:'a'.repeat(64)}:{})}:row;
  }});
  assert.equal(field(dialog,'label').value,'');assert.equal(field(dialog,'credential_type').value,'keep');
  if(protocol==='ssh')field(dialog,'username').value='deploy';else if(protocol==='rdp')field(dialog,'domain').value='NEW';
  submit(dialog);await flush();assert.equal(dialog.open,false);
  if(protocol==='vnc')assert.equal(calls.length,0);
  else {assert.equal(calls.length,1);assert.deepEqual(calls[0].body,protocol==='ssh'?{label:'deploy',username:'deploy'}:{label:'NEW\\alice',domain:'NEW'});}
 });
});

test('clearing a custom display name restores automatic naming without changing credentials',async t=>{
 const {dialog,calls}=await fixture(t,(path,options)=>({...account,...options.body,revision:12}),{edit:true});
 assert.equal(field(dialog,'label').value,'Primary');field(dialog,'label').value='';submit(dialog);await flush();
 assert.equal(calls.length,1);assert.deepEqual(calls[0].body,{label:'root'});assert.equal(dialog.open,false);
});

test('overlong automatic RDP names fail before asset creation and can use a short custom name',async t=>{
 const {dialog,calls}=await fixture(t,(path,options)=>path==='/api/v1/admin/assets'?{...asset,...options.body}:{...account,...options.body});
 fill(dialog);choose(dialog,'protocol','rdp');field(dialog,'label').value='';field(dialog,'domain').value='a'.repeat(128);field(dialog,'rdp_certificate_sha256').value='a'.repeat(64);
 submit(dialog);await flush();assert.equal(calls.length,0);assert.match(dialog.textContent,/自动名称过长/);
 field(dialog,'label').value='短名称';field(dialog,'password').value='replacement-secret';submit(dialog);await flush();assert.equal(calls.length,2);assert.equal(calls[1].body.label,'短名称');assert.equal(dialog.open,false);
});

const productionGroup={id:'33333333-3333-4333-8333-333333333333',name:'生产',revision:4,parent_id:null,sort_order:0};
const groupRead=(groups,extra)=> (path,options,defaults)=>{
 const url=new URL(path,location.origin);if(url.pathname==='/api/v1/admin/asset-groups')return{items:structuredClone(groups),next_cursor:null};
 return extra?extra(url,defaults(path)):defaults(path);
};
test('admin asset groups nest sorted children and keep assets in their own section',async t=>{
 const db={...productionGroup,id:'db',name:'数据库 <b>主库</b>',parent_id:productionGroup.id,sort_order:1};
 const gateway={...productionGroup,id:'gateway',name:'网关',parent_id:productionGroup.id,sort_order:0};
 const replica={...productionGroup,id:'replica',name:'只读库',parent_id:db.id};
 const orphan={...productionGroup,id:'orphan',name:'孤立分组',parent_id:'missing',sort_order:2};
 const groups=[replica,db,orphan,productionGroup,gateway];
 const rows=[{...asset,id:'root-asset',name:'生产主机',group_id:productionGroup.id},{...asset,id:'db-asset',name:'数据库主机',group_id:db.id},{...asset,id:'loose-asset',name:'未分组主机'}];
 const main=await fixture(t,undefined,{open:false,read:groupRead(groups,(url,fallback)=>url.pathname==='/api/v1/admin/assets'?{items:rows,next_cursor:null}:fallback)});
 const sections=all(main.view).filter(value=>value.className==='asset-group');
 assert.deepEqual(sections.map(value=>value.dataset.groupId),['',productionGroup.id,gateway.id,db.id,replica.id,orphan.id]);
 const section=id=>sections.find(value=>value.dataset.groupId===id),root=section(productionGroup.id);
 assert.equal(section(db.id).parentElement,root);assert.equal(section(gateway.id).parentElement,root);
 assert.equal(section(replica.id).parentElement,section(db.id));assert.equal(section(orphan.id).parentElement,root.parentElement);
 assert(sections.every(value=>value.open));assert.equal(section(db.id).children[0].textContent,db.name);
 assert.equal(section(db.id).querySelector('b'),null,'group names remain text, not HTML');
 assert.deepEqual(root.children.filter(value=>value.className==='table-scroll').flatMap(value=>all(value).filter(child=>child.tagName==='tr').slice(1).map(value=>value.textContent.includes('生产主机'))),[true]);
 assert(section(db.id).children.some(value=>value.className==='table-scroll'&&value.textContent.includes('数据库主机')));
 assert.equal(all(main.view).filter(value=>value.tagName==='tr'&&value.textContent.includes('数据库主机')).length,1);
 const filter=all(main.view).find(value=>value.tagName==='select'&&value.attributes['aria-label']==='筛选资产分组');
 assert.deepEqual(filter.options.map(value=>value.textContent),['全部分组','未分组','生产','　网关','　数据库 <b>主库</b>','　　只读库','孤立分组']);
});
test('empty parent groups show their children rather than a misleading empty asset message',async t=>{
 const db={...productionGroup,id:'db',name:'数据库',parent_id:productionGroup.id};
 const main=await fixture(t,undefined,{open:false,read:groupRead([db,productionGroup])});
 const root=all(main.view).find(value=>value.dataset.groupId===productionGroup.id);
 const child=all(main.view).find(value=>value.dataset.groupId===db.id);
 assert.equal(child.parentElement,root);assert.equal(root.children.some(value=>value.className==='hint'),false);
 assert.equal(child.children.find(value=>value.className==='hint')?.textContent,'暂无资产');
});

test('asset create/edit choose a persisted group without mutating accounts or credentials',async t=>{
 await t.test('create loads all group pages',async t=>{
  const second={...productionGroup,id:'44444444-4444-4444-8444-444444444444',name:'测试'};
  const {dialog,calls}=await fixture(t,(path,options)=>path==='/api/v1/admin/assets'?{...asset,...options.body}:{...account,...options.body},{read:(path,options,defaults)=>{
   const url=new URL(path,location.origin);return url.pathname==='/api/v1/admin/asset-groups'?{items:[url.searchParams.has('cursor')?second:productionGroup],next_cursor:url.searchParams.has('cursor')?null:'groups-next'}:defaults(path);
  }});
  const groupOptions=field(dialog,'group_id').options.map(item=>item.value);assert.equal(groupOptions[0],'');assert.deepEqual(groupOptions.slice(1).sort(),[productionGroup.id,second.id].sort());fill(dialog);choose(dialog,'group_id',productionGroup.id);submit(dialog);await flush();
  assert.equal(calls[0].body.group_id,productionGroup.id);assert.equal(dialog.open,false);
 });
 await t.test('move existing asset',async t=>{
  const {dialog,calls}=await fixture(t,(path,options)=>({...freshAsset,...options.body,revision:8}),{edit:true,read:groupRead([productionGroup])});
  choose(dialog,'group_id',productionGroup.id);submit(dialog);await flush();assert.equal(calls.length,1);assert.equal(calls[0].path,assetPath);assert.equal(calls[0].revision,freshAsset.revision);assert.equal(calls[0].body.group_id,productionGroup.id);assert.equal(dialog.open,false);
 });
});
test('group rename and deletion carry revisions and retain assets',async t=>{
 const groups=[{...productionGroup}];
 const main=await fixture(t,(path,options)=>{if(options.method==='DELETE'){groups.length=0;return;}Object.assign(groups[0],options.body,{revision:5});return structuredClone(groups[0]);},{edit:true,open:false,read:groupRead(groups)});
 button(main.view,'管理分组').click();await flush();let dialog=main.body.querySelector('dialog');field(dialog,'name').value='生产新区';submit(dialog);await flush();
 assert.equal(main.calls.length,1);assert.deepEqual(main.calls[0],{path:'/api/v1/admin/asset-groups/'+productionGroup.id,method:'PATCH',revision:4,body:{name:'生产新区',parent_id:null,sort_order:0},signal:main.life.signal});assert.equal(dialog.open,false);
 button(main.view,'管理分组').click();await flush();dialog=main.body.querySelector('dialog');button(dialog,'删除分组').click();await flush();
 const confirmation=all(main.body).filter(item=>item.tagName==='dialog').at(-1);assert.match(confirmation.textContent,/移回.*未分组/);submit(confirmation);await flush();
 assert.equal(main.calls.length,2);assert.equal(main.calls[1].method,'DELETE');assert.equal(main.calls[1].revision,5);assert.equal(main.calls[1].body,undefined);assert.equal(main.calls[1].path,'/api/v1/admin/asset-groups/'+productionGroup.id);assert(main.view.textContent.includes(asset.name));assert.equal(dialog.open,false);
});
test('unknown group creation outcome blocks replay',async t=>{
 const main=await fixture(t,async()=>{throw new ApiError('RESULT_UNKNOWN','unknown');},{open:false});button(main.view,'新建分组').click();await flush();
 const dialog=main.body.querySelector('dialog');field(dialog,'name').value='测试';submit(dialog);await flush();assert.equal(main.calls.length,1);assert.equal(button(dialog,'确认').disabled,true);submit(dialog);await flush();assert.equal(main.calls.length,1);
});
test('confirmed group creation closes its form even when the following read fails',async t=>{
 let saved=false;const main=await fixture(t,async()=>{saved=true;return productionGroup;},{open:false,read:(path,options,defaults)=>{
  if(saved&&path.includes('/admin/asset-groups'))throw new ApiError('NETWORK_OR_TIMEOUT','read failed');return defaults(path);
 }});
 button(main.view,'新建分组').click();await flush();const dialog=main.body.querySelector('dialog');field(dialog,'name').value='生产';submit(dialog);await flush();
 assert.equal(main.calls.length,1);assert.equal(dialog.open,false);assert.equal(dialog.parentElement,null);assert.equal(document.getElementById('error').hidden,false);
});
test('available assets group/filter only the authorized asset snapshot',async t=>{
 const grouped={...accessible,group_id:productionGroup.id,group_name:productionGroup.name};const ungrouped={...accessible,id:'ungrouped',name:'未分组服务器',group_id:null,group_name:null};
 const main=await fixture(t,undefined,{access:[identity('operator'),[grouped,ungrouped],discovery],open:false});
 const treeItems=all(main.view).filter(item=>item.tagName==='button'&&item.className.includes('tree-item'));assert.equal(treeItems.length,3);
 treeItems.find(item=>item.textContent.includes(productionGroup.name)).click();assert(main.view.textContent.includes(grouped.name));assert(!main.view.textContent.includes(ungrouped.name));
 treeItems.find(item=>item.textContent.includes('未分组')).click();assert(!main.view.textContent.includes(grouped.name));assert(main.view.textContent.includes(ungrouped.name));assert(!main.reads.some(row=>row.path.includes('asset-groups')));
});

test('console window auto-applies route asset and account to the hidden selectors',async t=>{
 const main=await fixture(t,undefined,{access:[identity('operator'),[accessible],discovery],open:false});
 main.view.replaceChildren();main.renderAssets();main.fixtureRoute({name:'console',id:accessible.id,sub:accessible.accounts[0].id});
 await main.mountConsole(main.life,accessible.id,accessible.accounts[0].id);
 assert.equal(main.getTarget().asset.id,accessible.id);assert.equal(main.getTarget().account.id,accessible.accounts[0].id);
});

test('console selects a later asset and its second account, rejecting a missing account',async t=>{
 const other={...accessible,id:'other',accounts:[{...accessible.accounts[0],id:'first'},{...accessible.accounts[0],id:'second'}]};
 const main=await fixture(t,undefined,{access:[identity('operator'),[accessible,other],discovery],open:false});main.view.replaceChildren();main.renderAssets();
 main.mountConsole(main.life,other.id,'second');assert.equal(main.getTarget().asset.id,other.id);assert.equal(main.getTarget().account.id,'second');
 main.mountConsole(main.life,other.id,'missing');assert.match(document.getElementById('status').textContent,/未授权/);
});
test('console can load a target outside the first list page and ignores a disposed route',async t=>{
 const target={...accessible,id:'later',group_id:null,group_name:null};
 const main=await fixture(t,undefined,{access:[identity('operator'),[accessible],discovery],open:false,read:(path,options,defaults)=>path==='/api/v1/assets/later'?target:defaults(path)});
 main.view.replaceChildren();main.renderAssets();main.mountConsole(main.life,target.id,target.accounts[0].id);await flush();assert.equal(main.getTarget().asset.id,target.id);
 const pending=deferred();main.api.asset=()=>pending.promise;main.mountConsole(main.life,'pending','pending');main.life.dispose();pending.resolve({...target,id:'pending'});await flush();assert.equal(main.getTarget().asset.id,target.id);
});

test('console keeps opened sessions alive when switching tabs, and stops at the per-user connection cap',async t=>{
  const four={...accessible,id:'multi',group_id:null,group_name:null,accounts:['one','two','three','four'].map(name=>({...accessible.accounts[0],id:`acc-${name}`,label:`acct-${name}`}))};
  const main=await fixture(t,undefined,{access:[identity('operator'),[four],discovery],open:false});
  main.view.replaceChildren();main.renderAssets();main.mountConsole(main.life,four.id,'acc-one');
  const rail=label=>all(main.view).find(value=>value.tagName==='button'&&value.className.includes('console-target')&&value.textContent.includes(label));
  const tabs=()=>all(main.view).filter(value=>/^console-tab( active)?$/.test(value.className));
  const panes=()=>all(main.view).filter(value=>value.className==='console-pane');
  // One pane per opened session; switching hides the previous pane instead of detaching it.
  assert.equal(tabs().length,1);assert.equal(panes().length,1);const first=panes()[0];assert.equal(first.hidden,false);
  rail('acct-two').click();rail('acct-three').click();
  assert.equal(tabs().length,3);assert.equal(panes().length,3);
  assert.equal(panes().filter(value=>value.hidden).length,2,'only the focused session is visible');
  assert(panes().includes(first),'the first session pane survives a tab switch');
  assert.equal(main.getTarget().account.id,'acc-three');
  // One user may hold at most three concurrent connections; refuse the fourth locally.
  rail('acct-four').click();assert.equal(tabs().length,3);
  assert.match(document.getElementById('status').textContent,/并发上限/);
  // Selecting an already open target only refocuses it.
  rail('acct-one').click();assert.equal(tabs().length,3);assert.equal(main.getTarget().account.id,'acc-one');assert.equal(first.hidden,false);
  all(main.view).filter(value=>value.className==='console-tab-close')[0].click();
  assert.equal(tabs().length,2);assert(!panes().includes(first));
  rail('acct-four').click();assert.equal(tabs().length,3);assert.equal(panes().length,3);
});

test('console repaints the rail when the asset list arrives after the popup opened',async t=>{
  const other={...accessible,id:'other',name:'Second target',group_id:null,group_name:null,accounts:[{...accessible.accounts[0],id:'other-account'}]};
  const main=await fixture(t,undefined,{access:[identity('operator'),[accessible],discovery],open:false});
  main.view.replaceChildren();main.renderAssets();main.fixtureRoute({name:'console',id:accessible.id,sub:accessible.accounts[0].id});
  await main.mountConsole(main.life,accessible.id,accessible.accounts[0].id);
  const targets=()=>all(main.view).filter(value=>value.tagName==='button'&&value.className.includes('console-target'));
  const panes=()=>all(main.view).filter(value=>value.className==='console-pane');
  // The popup can mount before /api/v1/assets has been read; the rail must not be stuck on one target.
  assert.deepEqual(targets().map(value=>value.textContent.includes(other.name)),[false]);
  const first=panes()[0];
  main.fixtureAccess(identity('operator'),[accessible,other],discovery);main.renderAssets();
  assert.deepEqual(targets().map(value=>value.textContent.includes(other.name)),[false,true]);
  // Opening it adds a session in place: no route change, so the live session survives.
  targets().find(value=>value.textContent.includes(other.name)).click();
  assert.equal(main.getTarget().account.id,'other-account');
  assert.equal(panes().length,2);assert(panes().includes(first),'the existing session is not rebuilt');
});

test('nested groups render as an indented tree and a parent selection lists its subtree',async t=>{
  const g=(id,name,parent,sort)=>({id,name,revision:1,parent_id:parent,sort_order:sort});
  const forest=[g('root','\u751f\u4ea7',null,0),g('db','\u6570\u636e\u5e93','root',1),g('web','\u7f51\u5173','root',0),g('orphan','\u5b64\u7acb','missing',0)];
  const inForest=id=>({...accessible,id:'a-'+id,name:'asset-'+id,group_id:id,group_name:forest.find(x=>x.id===id).name,accounts:[{...accessible.accounts[0],id:'acc-'+id}]});
  const main=await fixture(t,undefined,{access:[identity('operator'),[inForest('root'),inForest('db'),inForest('web')],discovery],groups:forest,open:false});
  const elements=()=>all(main.view).filter(v=>v.tagName==='button'&&v.className.includes('tree-item'));
  const items=()=>elements().map(v=>({name:v.children[0].textContent,cls:v.className}));
  const listed=items();
  // sort_order first, then nesting: root, its children by sort_order, and an orphan whose parent is unknown.
  assert.deepEqual(listed.map(v=>v.name),['\u5168\u90e8\u8d44\u4ea7','\u751f\u4ea7','\u7f51\u5173','\u6570\u636e\u5e93']);
  assert(!listed.some(v=>v.name==='\u5b64\u7acb'),'a group with no assets is not listed');
  assert.equal(listed.find(v=>v.name==='\u7f51\u5173').cls.includes('tree-depth-1'),true);
  assert.equal(listed.find(v=>v.name==='\u751f\u4ea7').cls.includes('tree-depth-1'),false);
  assert.equal(listed.find(v=>v.name==='\u6570\u636e\u5e93').cls.includes('tree-depth-1'),true);
  // Selecting the parent lists the whole subtree, not just its own assets.
  elements().find(v=>v.children[0].textContent==='\u751f\u4ea7').onclick();
  const shown=main.view.textContent;
  assert(shown.includes('asset-db')&&shown.includes('asset-web')&&shown.includes('asset-root'));
  assert.match(main.view.textContent,/3 个目标/);
});

test('asset deletion names the resource and its consequences, submits once with the revision, then refreshes',async t=>{
  const main=await fixture(t,()=>undefined,{edit:true,open:false});
  const row=all(main.view).find(value=>value.tagName==='tr'&&value.textContent.includes(asset.name));assert(row);
  const remove=button(row,'删除');assert.equal(remove.className,'danger-text');
  remove.click();await flush();
  const dialog=main.body.querySelector('dialog');assert(dialog.open);assert.equal(button(dialog,'确认').className,'primary danger');
  // The confirmation must name the resource and every consequence, not just say "are you sure".
  for(const value of [asset.name,asset.id,String(asset.revision),'目标账号','授权','票据','会话','审计','录制','主机指纹','不可恢复'])
    assert(dialog.textContent.includes(value),value);
  assert.equal(main.calls.length,0,'confirming must not pre-issue a request');
  submit(dialog);assert.equal(button(dialog,'确认').disabled,true);
  submit(dialog);await flush();
  assert.equal(main.calls.length,1,'no replay while the delete is pending');
  assert.deepEqual(main.calls[0],{path:assetPath,method:'DELETE',revision:asset.revision,body:undefined,signal:main.life.signal});
  assert.equal(dialog.open,false);assert.equal(dialog.parentElement,null);
  assert.match(document.getElementById('status').textContent,/资产删除已确认/);
});
test('a rejected asset deletion keeps the row, disables replay on unknown/conflict, and never retries blindly',async t=>{
  for(const [code,status] of [['REVISION_CONFLICT',412],['RESULT_UNKNOWN',0],['PERMISSION_DENIED',403]])await t.test(code,async t=>{
    const main=await fixture(t,()=>{throw new ApiError(code,'delete rejected','asset-delete-request',status);},{edit:true,open:false});
    const row=all(main.view).find(value=>value.tagName==='tr'&&value.textContent.includes(asset.name));assert(row);
    const remove=button(row,'删除');remove.click();await flush();
    const dialog=main.body.querySelector('dialog');submit(dialog);await flush();
    assert.equal(main.calls.length,1);
    const blocked=['REVISION_CONFLICT','RESULT_UNKNOWN'].includes(code);
    assert.equal(remove.disabled,blocked,'only unknown/conflict may block a replay');
    const error=document.getElementById('error');assert.equal(error.hidden,false);assert(error.textContent.includes(code));
    assert.equal(button(dialog,'确认').disabled,blocked);assert.equal(button(dialog,'取消').disabled,false);
    if(blocked){submit(dialog);await flush();assert.equal(main.calls.length,1,'a blocked deletion must not be replayed');}
  });
});

const rdpAsset = { ...freshAsset, protocol: 'rdp', port: 3389, ssh_host_key: null, security: 'nla', rdp_certificate_sha256: null };
const rdpScan = { asset_id: rdpAsset.id, host: rdpAsset.host, port: 3389, revision: rdpAsset.revision, approved_sha256: null, approved_security: 'nla', sha256: 'b'.repeat(64), selected_protocol: 'tls', security: 'tls' };
test('RDP first-connect confirmation scans the saved asset and saves the pin with the detected security mode, once', async t => {
  const main = await fixture(t, path => path.endsWith('/scan') ? rdpScan : { ...rdpAsset, rdp_certificate_sha256: rdpScan.sha256, security: 'tls' }, { open: false });
  const result = main.confirmRdpCertificate(rdpAsset, main.life); await flush();
  const dialog = main.body.querySelector('dialog'); assert(dialog.open);
  assert.equal(main.calls[0].path, assetPath + '/rdp-certificate/scan'); assert.equal(main.calls[0].method, 'POST'); assert.equal(main.calls[0].revision, rdpAsset.revision); assert.equal(main.calls[0].body, undefined);
  assert.match(dialog.textContent, /首次信任确认/); assert.match(dialog.textContent, new RegExp(rdpScan.sha256)); assert.match(dialog.textContent, /安全模式：TLS/);
  submit(dialog); submit(dialog); await flush(); assert.equal(await result, true);
  assert.equal(main.calls.length, 2); assert.equal(main.calls[1].method, 'PATCH'); assert.equal(main.calls[1].revision, rdpScan.revision);
  assert.deepEqual(main.calls[1].body, { rdp_certificate_sha256: rdpScan.sha256, security: 'tls' });
});
test('RDP re-verification warns when the certificate changed, and cancelling saves nothing', async t => {
  const main = await fixture(t, () => ({ ...rdpScan, approved_sha256: 'c'.repeat(64), security: 'nla', selected_protocol: 'nla' }), { open: false });
  const result = main.confirmRdpCertificate({ ...rdpAsset, rdp_certificate_sha256: 'c'.repeat(64) }, main.life); await flush();
  const dialog = main.body.querySelector('dialog'); assert.match(dialog.textContent, /证书已变化/); assert.match(dialog.textContent, /安全模式：NLA/);
  button(dialog, '取消').click(); assert.equal(await result, false); assert.equal(main.calls.length, 1);
});

test('connection rows name the user, asset and account, and details expand under the clicked row', async t => {
  const base = { ticket_id: 't', user_id: 'u1', login_session_id: 's', target_protocol: 'ssh', display: { width: 1280, height: 720, dpi: 96 }, protocol_version: 2, state: 'closed', created_at: '2026-01-01T00:00:00Z', started_at: null, ended_at: null, failure: null, bytes_in: 2048, bytes_out: 10, recording_id: null };
  const first = { ...base, id: 'conn-1', asset_id: 'a1', account_id: 'c1', user_snapshot: 'alice', asset_snapshot: 'db-prod', account_label: 'Primary', target_username: 'root' };
  const second = { ...base, id: 'conn-2', asset_id: 'a2', account_id: 'c2', user_snapshot: 'bob', asset_snapshot: 'web-01', account_label: null, target_username: null };
  const main = await fixture(t, async () => null, { open: false, connections: true, read: async () => ({ items: [first, second], next_cursor: null }) });
  const rows = () => all(main.view).filter(value => value.tagName === 'tr');
  for (const text of ['alice', 'db-prod', 'Primary · root', 'web-01', 'c2']) assert.match(main.view.textContent, new RegExp(text));
  const toggles = all(main.view).filter(value => value.tagName === 'button' && value.textContent === '详情');
  toggles[0].click();
  let list = rows(); const opened = list.findIndex(row => row.className.includes('row-detail'));
  assert.equal(list[opened - 1].children.some(cell => cell.textContent.includes('db-prod')), true, 'details must follow the clicked row');
  assert.match(list[opened].textContent, /2\.0 KiB/); assert.match(list[opened].textContent, /1280×720/);
  assert.equal(toggles[0].attributes['aria-expanded'], 'true'); assert.equal(main.reads.filter(read => read.path.includes('conn-1')).length, 0);
  toggles[0].click(); assert.equal(rows().some(row => row.className.includes('row-detail')), false); assert.equal(toggles[0].attributes['aria-expanded'], 'false');
});

test('audit rows name the actor, action and object, and the payload opens under the clicked row', async t => {
  const event = { id: 'e1', occurred_at: '2026-01-01T00:00:00Z', actor_id: 'u1', actor_username: 'alice', login_session_id: 's1', action: 'asset.updated', resource_type: 'asset', resource_id: 'a1', resource_name: 'db-prod', request_id: 'r1', sanitized_payload: { port: 2222 } };
  const failure = { id: 'e2', occurred_at: '2026-01-01T00:01:00Z', actor_id: null, actor_username: null, login_session_id: null, action: 'user.login_failure', resource_type: 'user', resource_id: null, resource_name: null, request_id: 'r2', sanitized_payload: { reason_code: 'UNAUTHENTICATED' } };
  const main = await fixture(t, async () => null, { open: false, audit: true, read: async () => ({ items: [event, failure], next_cursor: null }) });
  for (const text of ['alice', '修改资产', 'db-prod', '登录失败', '系统 / 未登录']) assert.match(main.view.textContent, new RegExp(text));
  assert.doesNotMatch(all(main.view).filter(value => value.tagName === 'tr' && !value.className.includes('row-detail')).map(row => row.textContent).join(''), /r1|UNAUTHENTICATED/);
  const toggles = all(main.view).filter(value => value.tagName === 'button' && value.textContent === '详情');
  toggles[0].click();
  const rows = all(main.view).filter(value => value.tagName === 'tr'), opened = rows.findIndex(row => row.className.includes('row-detail'));
  assert.match(rows[opened - 1].textContent, /db-prod/); assert.match(rows[opened].textContent, /port2222/); assert.match(rows[opened].textContent, /r1/);
  toggles[0].click(); assert.equal(all(main.view).some(row => row.className.includes('row-detail')), false);
  const actionFilter = all(main.view).find(value => value.name === 'action'); assert(actionFilter.options.some(option => option.textContent === '登录失败' && option.value === 'user.login_failure'));
});
