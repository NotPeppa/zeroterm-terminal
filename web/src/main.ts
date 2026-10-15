import './style.css';
import { ApiClient, ApiError, groupTree, type Me, type Info, type Asset, type AdminAsset, type AssetGroup, type AdminAccount, type Credential, type Account, type Role, type Page, type Query, type TargetProtocol } from './api';
import { allowedInNavigation, allowedRoute, discoveryWarning, parseRoute, RouteLifetime, routes, stateMessage, type Route, type RouteName, type SessionState } from './state';
import { mountSession, type Target } from './guac';
import { mountTerminalSession } from './terminal';
import { mountReplay } from './workspaces';

const api = new ApiClient();
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const view = element('route-view'), status = element('status'), errorBox = element('error');
let me: Me | null = null, info: Info | null = null, assets: Asset[] = [], assetGroups: AssetGroup[] = [], cursor: string | null = null;
let auth = new RouteLifetime(), routeLife = new RouteLifetime(), route: Route = { name: 'assets' };
/** The server-configured minimum, for labels only; the server enforces it. */
const passwordLabel = (label: string) => `${label}（至少 ${info?.password_min_length ?? 12} 字节）`;
let authBusy = false, targetUpdate: () => void = () => {}, statusMirror: HTMLElement | null = null;
/** Targets with a live console session in this page; empty outside the popup console. */
let consoleTargets = new Set<string>();
const assetSelect = element<HTMLSelectElement>('asset') ?? document.createElement('select'), accountSelect = element<HTMLSelectElement>('account') ?? document.createElement('select');
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => { const result = document.createElement(tag); result.textContent = text; if (className) result.className = className; return result; };
// The popup console hides the workspace statusbar, so the console footer mirrors the same live text.
function statusText(text: string) { status.textContent = text; if (statusMirror) statusMirror.textContent = text; }
const targetKey = (target: Target) => `${target.asset.id}\u0000${target.account.id}`;
/** An error belongs to the console while its session is still open there, not only while it is focused. */
function liveTarget(target: Target): boolean {
  if (consoleTargets.size) return consoleTargets.has(targetKey(target));
  const selected = getTarget();
  return selected?.asset.id === target.asset.id && selected.account.id === target.account.id;
}
function showError(error: unknown, target?: Target) {
  if (error instanceof ApiError && (error.status === 401 || !target && ['LOGIN_SESSION_REVOKED', 'USER_DISABLED'].includes(error.code))) clearMemory();
  else if (target && (!me?.user.enabled || routeLife.signal.aborted || route.name !== 'console' || !liveTarget(target))) return;
  errorBox.hidden = false; errorBox.textContent = stateMessage(error) + (error instanceof ApiError ? ' · ' + error.code + ' · request_id: ' + (error.requestId || '不可用') : '');
}
function clearError() { errorBox.hidden = true; errorBox.textContent = ''; }
errorBox.onclick = clearError;
export function button(text: string, action: () => void, parent?: HTMLElement, className = '') { const result = node('button', text, className); result.type = 'button'; result.onclick = action; parent?.append(result); return result; }

// Static, trusted Lucide-style icon paths (no user data is ever inserted here).
const icons: Record<RouteName | 'collapse', string> = {
  assets: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><path d="M6 6h.01M6 18h.01"/>',
  console: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="2" y1="21" x2="22" y2="21"/>',
  connections: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  recordings: '<circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/>',
  audit: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><path d="M16 13H8M16 17H8"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
  'admin-assets': '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/>',
  grants: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  profile: '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
  collapse: '<polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/>',
};
const svg = (paths: string) => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;

// Display helpers: every server string goes through textContent.
const tones: Record<string, string> = { active: 'green', streaming: 'green', complete: 'green', approved: 'green', completed: 'green', connecting: 'blue', pending: 'blue', preparing: 'blue', queued: 'blue', running: 'blue', candidate: 'orange', closing: 'orange', partial: 'orange', failed: 'red', corrupt: 'red', revoked: 'red', interrupted: 'red', missing: 'red', admin: 'purple', operator: 'blue', auditor: 'orange', ssh: 'blue', rdp: 'purple', vnc: 'green' };
function tag(text: string, tone = tones[text] ?? '') { return node('span', text, `tag ${tone}`); }
function tags(values: string[] = []) { const span = node('span'); for (const value of values) span.append(tag(value)); if (!values.length) span.textContent = '—'; return span; }
function enabledTag(enabled: boolean) { return node('span', enabled ? '启用' : '停用', `tag dot ${enabled ? 'green' : ''}`); }
function mono(text: unknown) { const span = node('span', String(text ?? '—'), 'mono ellipsis'); span.title = String(text ?? ''); return span; }
function stacked(main: string, sub: unknown) { const span = node('span', main); span.append(mono(sub)); (span.lastChild as HTMLElement).className = 'sub mono'; return span; }
function when(value: unknown) { if (typeof value !== 'string' || !value) return '—'; const date = new Date(value); return Number.isFinite(date.valueOf()) ? date.toLocaleString('zh-CN', { hour12: false }) : value; }
function details(summary: string, value: unknown) { const box = node('details'); box.append(node('summary', summary), node('pre', JSON.stringify(value, null, 2))); return box; }
function bar(parent: HTMLElement) { const root = node('div', '', 'bar'), left = node('div', '', 'left'), right = node('div', '', 'right'); root.append(left, right); parent.append(root); return { left, right }; }
/**
 * The group forest backing the given assets, nested by parent_id and indented for a tree.
 * Falls back to a flat list of names derived from the assets when the server sends no groups.
 */
function groupForest(list: Asset[]): { id: string; name: string; depth: number }[] {
  const referenced = new Map<string, string>();
  for (const asset of list) if (asset.group_id) referenced.set(asset.group_id, asset.group_name ?? '未命名分组');
  const known = assetGroups.filter(group => referenced.has(group.id));
  if (!known.length) return [...referenced].sort((a, b) => a[1].localeCompare(b[1], undefined, { numeric: true })).map(([id, name]) => ({ id, name, depth: 0 }));
  return groupTree(known).map(entry => ({ id: entry.group.id, name: entry.group.name, depth: entry.depth }));
}
const sessionStates: Record<SessionState, [string, string]> = { idle: ['未连接', ''], connecting: ['连接中', 'blue'], ready: ['已连接', 'green'], closed: ['已断开', 'orange'] };

function link(text: string, hash: string) { const result = node('a', text); result.href = hash; return result; }
function getTarget(): Target | null { if (!me?.user.enabled || me.user.role === 'auditor') return null; const asset = assets.find(value => value.id === assetSelect.value), account = asset?.accounts.find(value => value.id === accountSelect.value); return asset && account ? { asset, account } : null; }
function renderAccounts() {
  const previous = accountSelect.value;
  accountSelect.replaceChildren(...(assets.find(value => value.id === assetSelect.value)?.accounts ?? []).map(account => new Option(account.label, account.id)));
  if ([...accountSelect.options].some(option => option.value === previous)) accountSelect.value = previous;
  targetUpdate();
}
function renderAssets() { const previous = assetSelect.value; assetSelect.replaceChildren(...assets.map(asset => new Option(asset.name, asset.id))); if ([...assetSelect.options].some(option => option.value === previous)) assetSelect.value = previous; renderAccounts(); }
async function loadAssets(append = false, signal = auth.signal) {
  const result = await api.assets(append && cursor ? { cursor } : {}, signal); if (signal.aborted) return;
  assets = append ? [...assets, ...result.items.filter(item => !assets.some(old => old.id === item.id))] : result.items; cursor = result.next_cursor;
  if (!append) assetGroups = result.groups ?? [];
  renderAssets();
  if (route.name === 'assets') renderRoute();
  // The console has no statusbar; its footer shows session state, not a list-read message.
  if (route.name !== 'console') statusText(assets.length ? '可用目标已读取。' : '没有可用目标。');
}
function renderNavigation() {
  const navigation = element('navigation'); navigation.replaceChildren();
  if (!me) return;
  let group = '';
  for (const item of routes.filter(item => allowedInNavigation(item.name, me!.user.role, info))) {
    if (item.group !== group) { group = item.group; navigation.append(node('div', group, 'nav-group')); }
    const anchor = node('a'); anchor.href = `#/${item.name}`; anchor.title = item.label; anchor.innerHTML = svg(icons[item.name]); anchor.append(node('span', item.label));
    if (route.name === item.name) anchor.setAttribute('aria-current', 'page'); navigation.append(anchor);
  }
}
function setWorkspace(identity: Me) {
  me = identity; element('login-panel').hidden = true; element('workspace').hidden = false;
  element('sidebar-user').textContent = identity.user.username; element('menu-name').textContent = identity.user.username;
  const role = element('menu-role'); role.textContent = identity.user.role; role.className = `tag ${tones[identity.user.role] ?? ''}`;
  if (!location.hash) location.hash = identity.user.role === 'auditor' ? '#/connections' : '#/assets';
  renderAssets(); renderRoute();
}
function clearMemory() {
  auth.dispose(); auth = new RouteLifetime(); routeLife.dispose(); routeLife = new RouteLifetime(); api.clearAuth();
  me = null; assets = []; cursor = null; targetUpdate = () => {}; statusMirror = null; consoleTargets.clear(); view.replaceChildren(); assetSelect.replaceChildren(); accountSelect.replaceChildren(); element<HTMLInputElement>('password').value = '';
  element('workspace').hidden = true; element('login-panel').hidden = false; element('identity').textContent = ''; element('navigation').replaceChildren(); element('username').focus();
  document.body.classList?.remove?.('console', 'replay'); document.title = 'ZeroTerm · 堡垒机';
}
async function authAction(work: () => Promise<void>) {
  if (authBusy) return; authBusy = true; clearError(); element<HTMLButtonElement>('login').disabled = element<HTMLButtonElement>('logout').disabled = element<HTMLButtonElement>('refresh').disabled = true;
  try { await work(); } catch (error) { showError(error); } finally { authBusy = false; element<HTMLButtonElement>('login').disabled = element<HTMLButtonElement>('logout').disabled = false; element<HTMLButtonElement>('refresh').disabled = false; }
}
/** Follows next_cursor to the end; a malformed page or a repeated cursor is a server fault. */
async function allPages<T>(load: (cursor?: string) => Promise<Page<T>>, what: string): Promise<T[]> {
  const items: T[] = [], seen = new Set<string>(); let cursor: string | undefined;
  do {
    const page = await load(cursor);
    if (!Array.isArray(page.items) || !(page.next_cursor === null || typeof page.next_cursor === 'string')) throw new ApiError('INVALID_RESPONSE', `${what}响应不完整。`);
    items.push(...page.items); cursor = page.next_cursor ?? undefined;
    if (cursor) { if (seen.has(cursor)) throw new ApiError('INVALID_RESPONSE', `${what}分页游标重复。`); seen.add(cursor); }
  } while (cursor);
  return items;
}
async function routeAction(life: RouteLifetime, work: () => Promise<unknown>, result = '操作已由服务端确认。'): Promise<boolean> {
  clearError();
  try { await work(); if (!life.signal.aborted) statusText(result); return !life.signal.aborted; }
  catch (error) { if (!life.signal.aborted || error instanceof ApiError && error.code === 'RESULT_UNKNOWN') showError(error); return false; }
}

type Field = { name: string; label: string; section?: string; value?: string; type?: 'password' | 'number' | 'datetime-local' | 'checkbox' | 'textarea'; options?: string[]; optionLabels?: Record<string, string>; required?: boolean; min?: number; max?: number; half?: boolean };
function editDialog(title: string, fields: Field[], submit: (values: Record<string, string>) => Promise<unknown>, life: RouteLifetime = routeLife, danger = false, result = '操作已由服务端确认。') {
  const opener = document.activeElement as HTMLElement | null;
  const dialog = node('dialog'), form = node('form'), heading = node('h2', title), issue = node('p', '', 'error'); heading.id = 'dialog-heading'; dialog.setAttribute('aria-labelledby', heading.id);
  if (!fields.length) { dialog.classList.add('confirm-dialog'); if (danger) dialog.classList.add('danger-dialog'); }
  const controls = new Map<string, HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(); form.append(heading);
  let section: HTMLFieldSetElement | undefined;
  for (const field of fields) {
    if (field.section && section?.dataset.section !== field.section) { section = node('fieldset'); section.dataset.section = field.section; section.append(node('legend', field.section)); form.append(section); }
    const label = node('label', field.label);
    let input: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
    if (field.options) { input = node('select'); input.replaceChildren(...field.options.map(value => new Option(field.optionLabels?.[value] ?? value, value))); }
    else if (field.type === 'textarea') input = node('textarea');
    else { input = node('input'); input.type = field.type ?? 'text'; if (field.type === 'password') input.autocomplete = 'new-password'; if (field.min !== undefined) input.min = String(field.min); if (field.max !== undefined) input.max = String(field.max); }
    input.name = field.name; input.value = field.value ?? ''; input.required = field.required !== false && field.type !== 'checkbox';
    if (input instanceof HTMLInputElement && field.type === 'checkbox') input.checked = field.value === 'true';
    controls.set(field.name, input); label.append(input); if (field.half) label.classList.add('half'); (field.section ? section! : form).append(label);
  }
  const credentialType = controls.get('credential_type');
  if (credentialType) {
    const syncCredentialFields = () => {
      for (const name of ['password', 'key_pem', 'passphrase']) {
        const input = controls.get(name); if (!input) continue;
        const active = credentialType.value === (name === 'password' ? 'password' : 'private_key');
        input.parentElement!.hidden = !active; input.disabled = !active; input.required = active && name !== 'passphrase';
        if (!active) input.value = '';
      }
    };
    credentialType.addEventListener('change', syncCredentialFields); syncCredentialFields();
  }
  if (!fields.length) form.append(node('p', '确认后提交一次，不会自动重试。', 'muted'));
  issue.setAttribute('role', 'alert'); form.append(issue);
  const actions = node('div', '', 'toolbar'), cancel = button('取消', () => dialog.close(), actions), save = node('button', '确认', danger ? 'primary danger' : 'primary'); save.type = 'submit'; actions.append(save); form.append(actions); dialog.append(form); document.body.append(dialog);
  let pending = false, uncertain = false;
  dialog.addEventListener('cancel', event => { if (pending) event.preventDefault(); });
  const clearSecrets = () => { for (const input of controls.values()) if (input instanceof HTMLInputElement && input.type === 'password' || input.name === 'key_pem') input.value = ''; };
  dialog.addEventListener('close', () => { clearSecrets(); dialog.remove(); if (opener?.isConnected) opener.focus(); });
  life.own(() => { clearSecrets(); dialog.close(); dialog.remove(); });
  form.onsubmit = event => {
    event.preventDefault(); if (pending || uncertain || life.signal.aborted) return;
    const values: Record<string, string> = {}; for (const [name, input] of controls) values[name] = input instanceof HTMLInputElement && input.type === 'checkbox' ? String(input.checked) : input.value;
    clearSecrets(); pending = true; save.disabled = cancel.disabled = true; issue.textContent = '正在提交；不会自动重试。';
    const disabled = new Map([...controls.values()].map(input => [input, input.disabled]));
    for (const input of controls.values()) input.disabled = true;
    void submit(values).then(() => { if (!life.signal.aborted) { statusText(result); dialog.close(); } }).catch(error => { uncertain = error instanceof ApiError && ['RESULT_UNKNOWN', 'REVISION_CONFLICT'].includes(error.code); if (!life.signal.aborted) { issue.textContent = uncertain ? `${stateMessage(error)} ${error instanceof Error ? error.message : ''}` : stateMessage(error); showError(error); } }).finally(() => { for (const key of Object.keys(values)) values[key] = ''; for (const [input, state] of disabled) input.disabled = state; pending = false; save.disabled = uncertain; cancel.disabled = false; });
  };
  dialog.showModal(); (controls.values().next().value ?? save).focus();
  return dialog;
}
function confirmDialog(title: string, action: () => Promise<unknown>, life = routeLife, danger = true, result?: string) { return editDialog(title, [], action, life, danger, result); }
const textField = (name: string, label: string, value = '', required = true): Field => ({ name, label, value, required });
const enabledField = (enabled: boolean): Field => ({ name: 'enabled', label: '启用', type: 'checkbox', value: String(enabled) });
const credentialFields: Field[] = [{ name: 'credential_type', label: '认证方式', options: ['password', 'private_key'], optionLabels: { keep: '保持现有凭据', password: '密码', private_key: 'SSH 私钥', none: '无凭据（仅 VNC）' }, value: 'password' }, { name: 'password', label: '目标密码', type: 'password', required: false }, { name: 'key_pem', label: 'OpenSSH 格式 Ed25519 私钥', type: 'textarea', required: false }, { name: 'passphrase', label: '私钥口令（可选）', type: 'password', required: false }];
function credential(values: Record<string, string>): Credential { if (values.credential_type === 'none') return { type: 'none' }; if (values.credential_type === 'private_key') { if (!values.key_pem) throw new Error('需要 OpenSSH 格式 Ed25519 私钥。'); return { type: 'private_key', key_pem: values.key_pem, passphrase: values.passphrase || null }; } if (!values.password) throw new Error('需要目标密码。'); return { type: 'password', password: values.password }; }
function clearCredential(value: Credential) { if (value.type === 'password') value.password = ''; else if (value.type === 'private_key') { value.key_pem = ''; value.passphrase = null; } }
function expiry(value: string) { if (!value) return null; const date = new Date(value); if (!Number.isFinite(date.valueOf()) || date.valueOf() <= Date.now()) throw new Error('到期时间必须在未来。'); return date.toISOString(); }

type Column<T> = { label: string; value: (item: T) => string | Node };
function table<T>(parent: HTMLElement, items: T[], columns: Column<T>[], actions?: (item: T, container: HTMLElement) => void) {
  const scroll = node('div', '', 'table-scroll'), table = node('table'), head = node('thead'), header = node('tr'); for (const column of columns) header.append(node('th', column.label)); if (actions) header.append(node('th', '操作')); head.append(header); table.append(head);
  const body = node('tbody');
  for (const item of items) { const row = node('tr'); for (const column of columns) { const cell = node('td'); cell.append(column.value(item)); row.append(cell); } if (actions) { const cell = node('td', '', 'actions'), toolbar = node('div', '', 'toolbar'); actions(item, toolbar); cell.append(toolbar); row.append(cell); } body.append(row); }
  if (!items.length) { const row = node('tr'), cell = node('td', '暂无数据', 'empty'); cell.colSpan = columns.length + (actions ? 1 : 0); row.append(cell); body.append(row); }
  table.append(body); scroll.append(table); parent.append(scroll);
}
function paged<T>(parent: HTMLElement, life: RouteLifetime, load: (query: Query) => Promise<Page<T>>, render: (items: T[], output: HTMLElement) => void, initial: Query = {}, controls = bar(parent)) {
  const output = node('div'), pager = node('div', '', 'pager'), state = node('span', '正在读取…'); controls.left.append(state); parent.append(output, pager);
  let busy = false, next: string | null = null, items: T[] = [], filters = initial, serial = 0;
  const reload = button('刷新', () => { void read(false); }, controls.right), more = button('加载更多', () => { void read(true); }, pager); more.hidden = true;
  async function read(append: boolean) {
    if (busy || life.signal.aborted) return; const request = ++serial; busy = true; reload.disabled = more.disabled = true; state.textContent = '正在读取服务端数据…';
    try { const page = await load({ ...filters, ...(append && next ? { cursor: next } : {}) }); if (life.signal.aborted || request !== serial) return; if (!Array.isArray(page?.items) || !(page.next_cursor === null || typeof page.next_cursor === 'string')) throw new ApiError('INVALID_RESPONSE', '分页响应不完整。'); items = append ? [...items, ...page.items] : page.items; next = page.next_cursor; output.replaceChildren(); state.textContent = `共 ${items.length} 条${next ? '，还有更多' : ''}`; render(items, output); more.hidden = !next; }
    catch (error) { if (!life.signal.aborted) { state.textContent = stateMessage(error); showError(error); } }
    finally { if (request === serial) { busy = false; reload.disabled = more.disabled = false; } }
  }
  void read(false); return { reload: () => read(false), filter: (query: Query) => { filters = query; next = null; items = []; serial++; busy = false; return read(false); } };
}

function groupedTables<T>(parent: HTMLElement, rows: T[], groupOf: (row: T) => { id: string | null; name: string | null }, render: (rows: T[], parent: HTMLElement) => void, groups: AssetGroup[] = []) {
  const buckets = new Map<string, { name: string; rows: T[] }>([['', { name: '未分组', rows: [] }], ...groups.map(group => [group.id, { name: group.name, rows: [] as T[] }] as const)]);
  for (const row of rows) { const group = groupOf(row), id = group.id ?? ''; if (!buckets.has(id)) buckets.set(id, { name: group.name ?? '未分组', rows: [] }); buckets.get(id)!.rows.push(row); }
  const withRows = [...buckets.values()].filter(group => group.rows.length);
  const flat = withRows.length <= 1 && !groups.length;
  const forest = groupTree(groups), known = new Set(groups.map(group => group.id)), ancestors: HTMLDetailsElement[] = [], sections: HTMLDetailsElement[] = [];
  const ordered = [{ id: '', depth: 0 }, ...forest.map(({ group, depth }) => ({ id: group.id, depth })), ...[...buckets.keys()].filter(id => id && !known.has(id)).map(id => ({ id, depth: 0 }))];
  for (const { id, depth } of ordered) {
    const group = buckets.get(id)!;
    if (!group.rows.length && !groups.length && rows.length) continue;
    if (!id && !group.rows.length && groups.length) continue;
    const section = node('details', '', 'asset-group'); section.open = true; section.dataset.groupId = id;
    if (!flat) section.append(node('summary', group.name));
    if (group.rows.length) render(group.rows, section);
    (depth ? ancestors[depth - 1] : parent).append(section);
    ancestors[depth] = section; ancestors.length = depth + 1; sections.push(section);
  }
  for (const section of sections) {
    if (section.children.length === (flat ? 0 : 1)) section.append(node('p', '暂无资产', 'hint'));
  }
}
function mountAssets() {
  view.append(node('p', me?.user.role === 'admin' ? '管理员默认访问所有启用资产账号，无需单独授权；主机密钥仍需核验。' : '普通用户通过有效的精确资产账号授权访问，允许浏览器远程会话。', 'hint'));
  const root = node('div', '', 'assets-layout');
  const tree = node('aside', '', 'assets-tree');
  const main = node('div', '', 'assets-main');
  root.append(tree, main);
  view.append(root);

  const controls = bar(main), search = node('input', '', 'search'); search.type = 'search'; search.placeholder = '搜索资产、标签或账号'; search.setAttribute('aria-label', '搜索可用资产'); controls.right.append(search);
  button('刷新', () => { void authAction(() => loadAssets(false)); }, controls.right);
  const count = node('span'); controls.left.append(count);
  const output = node('div'); main.append(output);

  const rows = assets.flatMap<{ asset: Asset; account: Account | null }>(asset => asset.accounts.length ? asset.accounts.map(account => ({ asset, account })) : [{ asset, account: null }]);
  let selectedGroup = '*';
  const query = () => search.value.trim().toLowerCase();
  const matchRow = ({ asset, account }: { asset: Asset; account: Account | null }) => !query() || [asset.name, asset.group_name ?? '', account?.label ?? '', ...(asset.tags ?? [])].some(value => value.toLowerCase().includes(query()));

  /** Each group plus every id nested under it, so selecting a parent lists the whole subtree. */
  const scopes = () => {
    const forest = groupForest(assets), parentOf = new Map(assetGroups.map(group => [group.id, group.parent_id])), under = new Map<string, Set<string>>();
    for (const entry of forest) {
      let cursor: string | null | undefined = entry.id;
      for (let guard = 0; cursor && guard < 64; guard++) {
        if (!under.has(cursor)) under.set(cursor, new Set());
        under.get(cursor)!.add(entry.id);
        cursor = parentOf.get(cursor);
      }
    }
    return { forest, under };
  };

  const buildTree = () => {
    tree.replaceChildren();
    const makeItem = (id: string, name: string, num: number, depth = 0) => {
      const item = node('button', '', depth ? `tree-item tree-depth-${Math.min(depth, 5)}` : 'tree-item');
      item.type = 'button';
      if (selectedGroup === id) item.classList.add('active');
      item.append(node('span', name, 'tree-name'), node('span', String(num), 'tree-count'));
      item.onclick = () => { selectedGroup = id; buildTree(); render(); };
      tree.append(item);
    };
    const { forest, under } = scopes();
    makeItem('*', '全部资产', rows.filter(matchRow).length);
    for (const entry of forest) {
      const scope = under.get(entry.id) ?? new Set([entry.id]);
      const num = rows.filter(row => matchRow(row) && scope.has(row.asset.group_id ?? '')).length;
      if (num) makeItem(entry.id, entry.name, num, entry.depth);
    }
    const loose = rows.filter(row => matchRow(row) && !row.asset.group_id).length;
    if (loose) makeItem('', '未分组', loose);
  };

  const render = () => {
    const scope = selectedGroup === '*' ? null : selectedGroup === '' ? new Set(['']) : (scopes().under.get(selectedGroup) ?? new Set([selectedGroup]));
    const visible = rows.filter(r => (scope === null || scope.has(r.asset.group_id ?? '')) && matchRow(r));
    count.textContent = `${visible.length} 个目标${query() ? '（已过滤）' : ''}`; output.replaceChildren();
    table(output, visible, [
      { label: '资产', value: item => stacked(item.asset.name, item.asset.id) },
      { label: '协议', value: item => tag(item.asset.protocol) },
      { label: '标签', value: item => tags(item.asset.tags) },
      { label: '目标账号', value: item => item.account?.label ?? '暂无可用账号' },
    ], ({ asset, account }, toolbar) => {
      if (!account) { if (me?.user.role === 'admin') toolbar.append(link('管理资产', '#/admin-assets')); return; }
      if (!me?.user.enabled) return;
      if (allowedRoute('console', me.user.role, info) && info?.features?.[('web_' + asset.protocol) as 'web_ssh' | 'web_rdp' | 'web_vnc'] === true) button('连接', () => {
        // Only noopener: any width/height here turns the tab into a popup window. More room comes from the console's own 全屏.
        const opened = window.open(`#/console/${encodeURIComponent(asset.id)}/${encodeURIComponent(account.id)}`, '_blank', 'noopener');
        if (!opened) statusText('浏览器拦截了新标签页；请允许本站打开新窗口后重试。');
      }, toolbar, 'link');
    });
  };
  search.oninput = () => { buildTree(); render(); };
  buildTree(); render();
  if (cursor) button('更多目标', () => { void authAction(() => loadAssets(true)); }, main, 'block');
}
function mountUsers(life: RouteLifetime) {
  const controls = bar(view); let refresh: () => Promise<void>;
  button('新建用户', () => editDialog('新建用户', [textField('username', '用户名'), { name: 'password', label: passwordLabel('初始密码'), type: 'password' }, { name: 'role', label: '角色', options: ['operator', 'auditor', 'admin'] }], async values => { await api.createUser({ username: values.username, password: values.password, role: values.role as Role }, life.signal); await refresh(); }, life, false), controls.right, 'primary');
  refresh = paged(view, life, query => api.users(query, life.signal), (items, output) => table(output, items, [
    { label: '用户名', value: item => stacked(item.username, item.id) },
    { label: '角色', value: item => tag(item.role) },
    { label: '状态', value: item => enabledTag(item.enabled) },
    { label: '修订', value: item => String(item.revision) },
  ], (item, toolbar) => {
    button('编辑', () => editDialog(`编辑用户 ${item.username}`, [{ name: 'role', label: '角色', options: ['operator', 'auditor', 'admin'], value: item.role }, enabledField(item.enabled)], async values => { await api.updateUser(item.id, item.revision, { role: values.role as Role, enabled: values.enabled === 'true' }, life.signal); await refresh(); }, life), toolbar, 'link');
    button('重置密码', () => editDialog('重置密码：该用户现有登录会话将撤销', [{ name: 'password', label: passwordLabel('新密码'), type: 'password' }], async values => { await api.resetPassword(item.id, item.revision, values.password, life.signal); await refresh(); }, life, true), toolbar, 'danger-text');
    const remove = button('删除', () => {
      if (remove.disabled || life.signal.aborted) return;
      confirmDialog(`删除用户 ${item.username} · ID ${item.id} · 修订 ${item.revision}？该账号将无法登录，现有登录会话、票据与运行连接将撤销；审计、历史连接、录制、批准的主机密钥及旧授权保留。用户名可供新账号复用，但新账号使用新 ID 与密码，不继承旧授权、会话或历史归属。删除后无法恢复。`, async () => {
        if (remove.disabled || life.signal.aborted) return;
        try { await api.deleteUser(item.id, item.revision, life.signal); }
        catch (error) { if (error instanceof ApiError && ['RESULT_UNKNOWN', 'REVISION_CONFLICT'].includes(error.code)) remove.disabled = true; throw error; }
        if (life.signal.aborted) return;
        for (const action of toolbar.querySelectorAll('button')) action.disabled = true;
        clearError(); await refresh();
        if (!life.signal.aborted && !errorBox.hidden) errorBox.textContent = `用户删除已确认，但列表刷新失败。${errorBox.textContent}`;
      }, life, true, '用户删除已确认；若列表未更新，请点击刷新。');
    }, toolbar, 'danger-text');
    if (item.id === me?.user.id) { remove.disabled = true; remove.title = '不能删除当前登录用户'; }
  }), {}, controls).reload;
}

type ConsoleSession = { key: string; target: Target; life: RouteLifetime; pane: HTMLElement; tab: HTMLElement; open: HTMLButtonElement; status: HTMLElement; dot: HTMLElement; update: () => void };
/** The server refuses a fourth concurrent connection for one user: production.limits.connections_per_user is capped at 3. */
const MAX_CONSOLE_SESSIONS = 3;
/** Popup session window: many concurrent terminals behind one tab strip, with the workspace chrome removed. */
function mountConsole(life: RouteLifetime, assetId: string, accountId: string) {
  const wrap = node('div', '', 'console-wrap'), side = node('aside', '', 'console-side'), rail = node('div', '', 'console-rail');
  const main = node('div', '', 'console-main'), bar = node('header', '', 'console-bar'), tabbar = node('div', '', 'console-tabs'), host = node('div', '', 'console-host'), foot = node('footer', '', 'console-status');
  wrap.append(side, main); main.append(bar, tabbar, host, foot); view.append(wrap);
  tabbar.setAttribute('role', 'tablist'); tabbar.setAttribute('aria-label', '已打开的会话');

  const consoleIcons = { back: '<path d="M19 12H5"/><polyline points="12 19 5 12 12 5"/>', collapse: '<polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/>' };
  const backIcon = node('span', '', 'console-back-icon'); backIcon.innerHTML = svg(consoleIcons.back);
  const back = node('a', '', 'console-back'); back.href = '#/assets'; back.title = '返回工作台'; back.setAttribute('aria-label', '返回工作台'); back.append(backIcon, node('span', '工作台', 'console-back-text'));
  const protocolTag = node('span', '—', 'tag'), title = node('h1', '控制台', 'console-title'), accountName = node('span', '', 'console-account');
  const identity = node('div', '', 'console-identity'); identity.append(protocolTag, title, accountName);
  const badge = node('span', sessionStates.idle[0], `console-state ${sessionStates.idle[1]}`); badge.setAttribute('role', 'status');
  const actions = node('div', '', 'console-bar-actions');
  const userMenu = node('details', '', 'console-user'), userSummary = node('summary'), userDrop = node('div', '', 'menu');
  const userHead = node('div', '', 'menu-head'), userText = node('div');
  const guard = (work: () => Promise<void>) => (event: Event) => { const self = event.currentTarget as HTMLButtonElement; self.disabled = true; void work().finally(() => { self.disabled = false; }); };
  bar.append(back, identity, badge, actions);
  actions.append(userMenu);
  userSummary.append(node('span', '', 'avatar'), node('span', me!.user.username));
  userText.append(node('strong', me!.user.username), tag(me!.user.role, tones[me!.user.role] ?? ''));
  userHead.append(node('span', '', 'avatar lg'), userText);
  const refreshItem = node('button', '主动刷新登录', 'menu-item'); refreshItem.type = 'button'; refreshItem.onclick = guard(() => refreshLogin());
  const logoutItem = node('button', '注销', 'menu-item danger-item'); logoutItem.type = 'button'; logoutItem.onclick = guard(() => logout());
  userDrop.append(userHead, refreshItem, logoutItem); userMenu.append(userSummary, userDrop);
  button('全屏', () => { void (document.fullscreenElement ? document.exitFullscreen() : wrap.requestFullscreen()).catch(showError); }, actions);

  const sideHead = node('div', '', 'console-side-head'), collapse = node('button', '', 'console-collapse');
  collapse.type = 'button'; collapse.title = '折叠目标列表'; collapse.setAttribute('aria-label', '折叠目标列表'); collapse.setAttribute('aria-expanded', 'true'); collapse.innerHTML = svg(consoleIcons.collapse);
  const count = node('span', '0', 'console-side-count'); sideHead.append(collapse, node('span', '目标', 'console-side-title'), count);
  const searchBox = node('div', '', 'console-side-search');
  const search = node('input', '', 'console-search'); search.type = 'search'; search.placeholder = '搜索资产、账号或标签'; search.setAttribute('aria-label', '搜索目标');
  searchBox.append(search); side.append(sideHead, searchBox, rail);
  collapse.onclick = () => {
    const collapsed = wrap.classList.toggle('collapsed');
    collapse.title = collapsed ? '展开目标列表' : '折叠目标列表';
    collapse.setAttribute('aria-label', collapse.title);
    collapse.setAttribute('aria-expanded', String(!collapsed));
  };

  const mark = node('span', '', 'console-status-mark'), footerSlot = node('span', '', 'console-status-text'), hints = node('details', '', 'console-hint');
  hints.append(node('summary', '快捷键与限制')); foot.append(mark, footerSlot, hints);
  const sessions: ConsoleSession[] = []; let focused: ConsoleSession | null = null;
  const owned = new Set<HTMLElement>();
  const enabled = (target: Target) => info?.features?.[('web_' + target.asset.protocol) as 'web_ssh' | 'web_rdp' | 'web_vnc'] === true;

  const renderList = () => {
    const query = search.value.trim().toLowerCase();
    const groups = new Map<string, { id: string; name: string; rows: { asset: Asset; account: Account }[] }>();
    for (const asset of assets) for (const account of asset.accounts) {
      if (query && ![asset.name, asset.group_name ?? '', account.label, ...(asset.tags ?? [])].some(value => value.toLowerCase().includes(query))) continue;
      const key = asset.group_id ?? '';
      if (!groups.has(key)) groups.set(key, { id: key, name: '', rows: [] });
      groups.get(key)!.rows.push({ asset, account });
    }
    rail.replaceChildren();
    let shown = 0;
    const appendTargets = (bucket: { name: string; rows: { asset: Asset; account: Account }[] }, section: HTMLElement) => {
      for (const { asset, account } of bucket.rows) {
        const key = `${asset.id}\u0000${account.id}`, open = sessions.some(session => session.key === key);
        const item = node('button', '', 'console-target'); item.type = 'button';
        if (open) item.classList.add('open');
        if (focused?.key === key) item.classList.add('active');
        item.title = open ? '已打开，点此切换到该会话' : '在该标签页内打开一个会话';
        const text = node('span', '', 'console-target-text');
        text.append(node('span', asset.name, 'console-target-name'), node('span', account.label + (asset.tags?.length ? ' · ' + asset.tags.join(' · ') : ''), 'console-target-account'));
        item.append(tag(asset.protocol), text); section.append(item); shown++;
        item.onclick = () => openSession(asset.id, account.id);
      }
    };
    if (!groups.size) rail.append(node('p', '没有匹配的目标', 'hint console-empty'));
    for (const entry of groupForest(assets)) {
      const bucket = groups.get(entry.id);
      if (!bucket?.rows.length) continue;
      const section = node('section', '', 'console-group'), sectionHead = node('div', '', entry.depth ? `console-group-title console-group-depth-${Math.min(entry.depth, 5)}` : 'console-group-title');
      sectionHead.append(node('span', entry.name), node('span', String(bucket.rows.length), 'console-group-count'));
      section.append(sectionHead);
      appendTargets(bucket, section);
      rail.append(section);
    }
    // Assets outside the group forest (no group, or a group the server did not report) still need a home.
    const forest = new Set(groupForest(assets).map(entry => entry.id));
    const loose = [...groups.values()].filter(bucket => !bucket.id || !forest.has(bucket.id));
    if (loose.length) {
      const section = node('section', '', 'console-group'), sectionHead = node('div', '', 'console-group-title');
      sectionHead.append(node('span', '未分组'));
      section.append(sectionHead);
      for (const bucket of loose) appendTargets(bucket, section);
      rail.append(section);
    }
    const total = assets.reduce((sum, asset) => sum + asset.accounts.length, 0);
    count.textContent = query ? `${shown} / ${total}` : String(total);
  };
  search.oninput = renderList;

  const identify = (target: Target) => {
    protocolTag.textContent = target.asset.protocol; protocolTag.className = `tag ${tones[target.asset.protocol] ?? ''}`;
    title.textContent = target.asset.name; accountName.textContent = target.account.label;
    document.title = `${target.asset.name} · ${target.account.label} · ZeroTerm`;
  };
  // Focusing only reveals a pane; it never tears a session down, so terminals stay live across switches.
  function focusSession(session: ConsoleSession) {
    focused = session;
    for (const other of sessions) {
      const active = other === session;
      other.pane.hidden = !active;
      other.tab.className = active ? 'console-tab active' : 'console-tab';
      other.open.setAttribute('aria-selected', String(active));
    }
    footerSlot.replaceChildren(session.status); statusMirror = session.status; owned.add(session.status);
    hints.replaceChildren(node('summary', '快捷键与限制'));
    const hint = session.pane.querySelector('.hint'); if (hint) hints.append(hint);
    assetSelect.value = session.target.asset.id; renderAccounts(); accountSelect.value = session.target.account.id; renderAccounts();
    identify(session.target);
    renderList();
  }
  function closeSession(key: string) {
    const index = sessions.findIndex(session => session.key === key);
    if (index < 0) return;
    const [session] = sessions.splice(index, 1);
    session.life.dispose(); session.tab.remove(); session.pane.remove(); consoleTargets.delete(key);
    if (focused === session) {
      focused = null;
      if (sessions.length) focusSession(sessions[Math.min(index, sessions.length - 1)]);
      else { title.textContent = '没有打开的会话'; statusText('所有会话已关闭。'); location.hash = '#/assets'; }
    } else renderList();
  }
  function addSession(target: Target) {
    const key = targetKey(target);
    if (!enabled(target)) { statusText('该协议未启用远程会话。'); return false; }
    const sessionLife = new RouteLifetime(); life.own(() => sessionLife.dispose());
    const pane = node('div', '', 'console-pane'), statusLine = node('span', '', 'console-status-text'), dot = node('span', '', 'console-tab-dot');
    const tab = node('div', '', 'console-tab'), open = node('button', '', 'console-tab-open');
    open.type = 'button'; open.setAttribute('role', 'tab'); open.title = `${target.asset.name} · ${target.account.label}`;
    open.append(tag(target.asset.protocol), node('span', target.asset.name, 'console-tab-name'), node('span', target.account.label, 'console-tab-account'), dot);
    const close = node('button', '×', 'console-tab-close'); close.type = 'button'; close.title = '关闭该会话'; close.setAttribute('aria-label', `关闭会话 ${target.asset.name} · ${target.account.label}`);
    tab.append(open, close); host.append(pane); tabbar.append(tab);
    const session: ConsoleSession = { key, target, life: sessionLife, pane, tab, open, status: statusLine, dot, update: () => {} };
    sessions.push(session); consoleTargets.add(key);
    open.onclick = () => focusSession(session);
    close.onclick = () => closeSession(key);
    session.update = (target.asset.protocol === 'ssh' ? mountTerminalSession : mountSession)(pane, api, sessionLife, () => target,
      text => { status.textContent = text; statusLine.textContent = text; }, showError, enabled, value => prepareSshConnection(value, sessionLife),
      value => { dot.className = `console-tab-dot ${sessionStates[value][1]}`; if (focused === session) { badge.textContent = sessionStates[value][0]; badge.className = `console-state ${sessionStates[value][1]}`; } });
    focusSession(session);
    // Auto-connect once per opened session; reconnect stays an explicit toolbar action.
    const connect = pane.querySelector<HTMLButtonElement>('[data-session="connect"]');
    if (connect && !connect.disabled) connect.click();
    return true;
  }
  function openSession(nextAssetId: string, nextAccountId: string) {
    const key = `${nextAssetId}\u0000${nextAccountId}`, existing = sessions.find(session => session.key === key);
    if (existing) { focusSession(existing); return; }
    if (sessions.length >= MAX_CONSOLE_SESSIONS) { statusText(`已达服务端并发上限：每个用户最多 ${MAX_CONSOLE_SESSIONS} 条连接。请先关闭一个会话再打开。`); return; }
    const asset = assets.find(value => value.id === nextAssetId), account = asset?.accounts.find(value => value.id === nextAccountId);
    if (!asset || !account) { statusText('目标不存在或未授权。'); return; }
    addSession({ asset, account });
  }

  // The popup arrives before the asset list does, and a later refresh must repaint the rail without touching live sessions.
  life.own(() => { for (const session of [...sessions]) session.life.dispose(); sessions.length = 0; focused = null; consoleTargets.clear(); if (statusMirror && owned.has(statusMirror)) statusMirror = null; });
  targetUpdate = () => { renderList(); focused?.update(); };

  const requested = () => {
    const asset = assets.find(value => value.id === assetId), account = asset?.accounts.find(value => value.id === accountId);
    if (!asset || !account) { title.textContent = '目标不可用'; statusText('目标不存在或未授权。'); return; }
    assetSelect.value = assetId; renderAccounts(); accountSelect.value = accountId; renderAccounts(); renderList();
    identify({ asset, account });
    addSession({ asset, account });
  };
  if (assets.some(asset => asset.id === assetId)) requested();
  else {
    title.textContent = '正在读取目标…'; statusText('正在读取目标资产…'); renderList();
    void api.asset(assetId, life.signal).then(asset => { if (life.signal.aborted) return; assets = [...assets.filter(value => value.id !== asset.id), asset]; renderAssets(); requested(); }).catch(error => { if (!life.signal.aborted) { title.textContent = '目标不可用'; statusText('目标不存在或未授权。'); showError(error); } });
  }
}

async function confirmSshHostKey(asset: AdminAsset, life: RouteLifetime): Promise<boolean> {
  statusText('正在获取 SSH 主机指纹…');
  const scan = await api.scanSshHostKey(asset.id, asset.revision, life.signal);
  if (life.signal.aborted) return false;
  if (scan.asset_id !== asset.id || scan.host !== asset.host || scan.port !== asset.port || scan.revision !== asset.revision || !Array.isArray(scan.keys) || !scan.keys.length) throw new ApiError('INVALID_RESPONSE', '主机指纹响应不完整，请重新读取资产。');
  return new Promise(resolve => {
    let approved = false;
    const dialog = editDialog(`确认 SSH 主机身份：${asset.name}`, [{ name: 'host_key', label: '目标主机指纹', options: scan.keys.map((_, index) => String(index)), optionLabels: Object.fromEntries(scan.keys.map((key, index) => [String(index), `${key.algorithm} · ${key.fingerprint}`])), value: '0' }], async values => {
      const key = scan.keys[Number(values.host_key)];
      if (!key) throw new Error('请选择要确认的主机指纹。');
      await api.updateAsset(asset.id, scan.revision, { ssh_host_key: key.public_key }, life.signal);
      approved = true;
    }, life, false, '主机指纹已确认并保存。');
    const heading = dialog.querySelector('h2')!;
    dialog.classList.add('host-key-dialog');
    heading.after(node('p', `目标：${scan.host}:${scan.port}。请核对主机指纹；确认后自动保存公钥，后续连接将严格校验。`, 'hint'));
    if (scan.approved_fingerprint) {
      const changed = !scan.keys.some(key => key.fingerprint === scan.approved_fingerprint);
      heading.after(node('p', `${changed ? '主机密钥已变化，请核实更换原因后再确认。' : '已有确认记录。'} 原指纹：${scan.approved_fingerprint}`, changed ? 'error' : 'hint'));
    } else heading.after(node('p', '这是首次信任确认。可通过服务器控制台或管理员提供的指纹核对。', 'hint'));
    dialog.addEventListener('close', () => resolve(approved && !life.signal.aborted), { once: true });
  });
}
/** Admins confirm an unconfirmed SSH host key or RDP certificate on first connect. */
async function prepareSshConnection(target: Target, life: RouteLifetime): Promise<boolean> {
  if (target.asset.protocol === 'vnc' || me?.user.role !== 'admin') return true;
  const asset = await api.adminAsset(target.asset.id, life.signal);
  if (life.signal.aborted) return false;
  if (asset.protocol === 'rdp') return asset.rdp_certificate_sha256 ? true : confirmRdpCertificate(asset, life);
  return asset.ssh_host_key ? true : confirmSshHostKey(asset, life);
}
async function confirmRdpCertificate(asset: AdminAsset, life: RouteLifetime): Promise<boolean> {
  statusText('正在获取 RDP 证书指纹…');
  const scan = await api.scanRdpCertificate(asset.id, asset.revision, life.signal);
  if (life.signal.aborted) return false;
  if (scan.asset_id !== asset.id || scan.host !== asset.host || scan.port !== asset.port || scan.revision !== asset.revision || !/^[a-f0-9]{64}$/.test(scan.sha256) || !['nla', 'tls'].includes(scan.security)) throw new ApiError('INVALID_RESPONSE', '证书指纹响应不完整，请重新读取资产。');
  const mode = scan.security === 'nla' ? 'NLA' : 'TLS';
  return new Promise(resolve => {
    let approved = false;
    const dialog = editDialog(`确认 RDP 主机身份：${asset.name}`, [], async () => {
      await api.updateAsset(asset.id, scan.revision, { rdp_certificate_sha256: scan.sha256, security: scan.security }, life.signal);
      approved = true;
    }, life, false, '证书指纹已确认并保存。');
    const heading = dialog.querySelector('h2')!;
    dialog.classList.add('host-key-dialog');
    heading.after(node('p', `安全模式：${mode}（服务器选择${mode === 'NLA' ? '，Windows 默认' : '，服务器不支持 NLA'}）。确认后自动保存，后续连接将严格校验。`, 'hint'));
    heading.after(node('p', scan.sha256, 'mono'));
    heading.after(node('p', `目标：${scan.host}:${scan.port}。证书指纹（leaf DER SHA-256）：`, 'hint'));
    if (scan.approved_sha256) {
      const changed = scan.approved_sha256 !== scan.sha256;
      heading.after(node('p', `${changed ? '证书已变化，请核实更换原因（例如 Windows 自签名证书到期续期）后再确认。' : '已有确认记录。'} 原指纹：${scan.approved_sha256}`, changed ? 'error' : 'hint'));
    } else heading.after(node('p', '这是首次信任确认。可在目标机器上查询证书指纹核对。', 'hint'));
    dialog.addEventListener('close', () => resolve(approved && !life.signal.aborted), { once: true });
  });
}
function mountAdminAssets(life: RouteLifetime) {
  const controls = bar(view); let refresh: () => Promise<void>;
  let groups: AssetGroup[] = [];
  async function loadGroups() {
    const loaded = await allPages(cursor => api.assetGroups({ limit: 200, cursor }, life.signal), '分组列表'); if (life.signal.aborted) return;
    groups = [...new Map(loaded.map(group => [group.id, group])).values()];
  }
  const groupField = (asset?: AdminAsset): Field => ({ name: 'group_id', label: '资产分组', options: ['', ...groupTree(groups).map(entry => entry.group.id)], optionLabels: { '': '未分组', ...Object.fromEntries(groupTree(groups).map(entry => [entry.group.id, `${'　'.repeat(entry.depth)}${entry.group.name}`])) }, value: asset?.group_id ?? '', required: false });
  const refreshAfterGroupWrite = async () => { try { await refresh(); } catch (error) { if (!life.signal.aborted) showError(error); } };
  /** Parent choices are indented; a group may not be nested under itself or its own descendants. */
  const parentOptions = (excludeId?: string) => {
    const hidden = new Set<string>(); let cursor = excludeId ?? null;
    for (let guard = 0; cursor && guard < 64; guard++) { hidden.add(cursor); cursor = groups.find(group => group.id === cursor)?.parent_id ?? null; }
    return groupTree(groups).filter(entry => !hidden.has(entry.group.id));
  };
  const parentField = (value: string | null, excludeId?: string): Field => {
    const choices = parentOptions(excludeId);
    return { name: 'parent_id', label: '上级分组', options: ['', ...choices.map(entry => entry.group.id)], optionLabels: { '': '（顶层分组）', ...Object.fromEntries(choices.map(entry => [entry.group.id, `${'　'.repeat(entry.depth)}${entry.group.name}`])) }, value: value ?? '', required: false };
  };
  const sortField = (value: number): Field => ({ name: 'sort_order', label: '同级排序（小在前）', type: 'number', value: String(value), required: false, min: -100000, max: 100000 });
  const readOrder = (value: string) => { const order = Number(value); return Number.isFinite(order) ? Math.max(-100000, Math.min(100000, Math.trunc(order))) : 0; };
  const newGroup = () => editDialog('新建分组', [textField('name', '分组名称'), parentField(null), sortField(0)], async values => {
    await api.createAssetGroup({ name: values.name.trim(), parent_id: values.parent_id || null, sort_order: readOrder(values.sort_order) }, life.signal);
    await refreshAfterGroupWrite();
  }, life, false, '分组已创建。');
  button('新建分组', newGroup, controls.right);
  button('管理分组', () => { void routeAction(life, async () => {
    await loadGroups(); if (life.signal.aborted) return; if (!groups.length) { newGroup(); return; }
    const snapshot = new Map(groups.map(group => [group.id, group]));
    const dialog = editDialog('管理分组', [
      { name: 'group_id', label: '资产分组', options: [...snapshot.keys()], optionLabels: Object.fromEntries(groupTree(groups).map(entry => [entry.group.id, `${'　'.repeat(entry.depth)}${entry.group.name}`])), value: groups[0].id },
      textField('name', '分组名称', groups[0].name), parentField(groups[0].parent_id, groups[0].id), sortField(groups[0].sort_order),
    ], async values => {
      const group = snapshot.get(values.group_id)!;
      await api.patchAssetGroup(group.id, group.revision, { name: values.name.trim(), parent_id: values.parent_id || null, sort_order: readOrder(values.sort_order) }, life.signal);
      await refreshAfterGroupWrite();
    }, life, false, '分组已更新。');
    const picker = dialog.querySelector<HTMLSelectElement>('[name="group_id"]')!;
    picker.onchange = () => {
      const group = snapshot.get(picker.value)!;
      dialog.querySelector<HTMLInputElement>('[name="name"]')!.value = group.name;
      const parent = dialog.querySelector<HTMLSelectElement>('[name="parent_id"]')!;
      const choices = parentOptions(group.id);
      parent.replaceChildren(new Option('（顶层分组）', ''), ...choices.map(entry => new Option(`${'　'.repeat(entry.depth)}${entry.group.name}`, entry.group.id)));
      parent.value = choices.some(entry => entry.group.id === group.parent_id) ? group.parent_id! : '';
      dialog.querySelector<HTMLInputElement>('[name="sort_order"]')!.value = String(group.sort_order);
    };
    button('删除分组', () => {
      const group = snapshot.get(picker.value)!;
      const childCount = groups.filter(value => value.parent_id === group.id).length;
      const confirm = editDialog(`删除分组：${group.name}`, [], async () => { await api.deleteAssetGroup(group.id, group.revision, life.signal); dialog.close(); await refreshAfterGroupWrite(); }, life, true);
      confirm.querySelector('h2')!.after(node('p', `组内资产将移回“未分组”，资产、账号和授权均保留。${childCount ? `其下 ${childCount} 个子分组将上移到本组的位置。` : ''}`, 'hint'));
    }, dialog.querySelector<HTMLElement>('.toolbar') ?? dialog.querySelector('form')!, 'danger-text');
  }, '分组信息已读取。'); }, controls.right);
  const assetFields = (asset?: AdminAsset): Field[] => [
    textField('name', '资产名称', asset?.name), textField('host', '目标地址（IP 或域名）', asset?.host),
    groupField(asset),
    ...(!asset ? [{ name: 'protocol', label: '目标协议（创建后不可变）', options: ['ssh', 'rdp', 'vnc'], value: 'ssh' }] : []),
    { name: 'port', label: '目标端口', type: 'number', value: String(asset?.port ?? 22), min: 1, max: 65535 },
    { name: 'ssh_host_key', label: '手动导入主机公钥（可选；留空后首次连接确认指纹）', type: 'textarea', value: asset?.ssh_host_key ?? '', required: false },
    textField('rdp_certificate_sha256', '手动导入 RDP 证书指纹（可选；留空后首次连接确认）', asset?.rdp_certificate_sha256 ?? '', false),
    textField('tags', '标签（逗号分隔）', asset?.tags.join(', '), false),
  ];
  const assetBody = (values: Record<string, string>, protocol: TargetProtocol) => {
    const body = { name: values.name, host: values.host, port: Number(values.port), group_id: values.group_id || null, tags: values.tags.split(',').map(value => value.trim()).filter(Boolean) };
    if (protocol === 'ssh') { const key = values.ssh_host_key.trim(); if (key && !/^(?:ssh-|ecdsa-)[^\s]+ [A-Za-z0-9+/]+={0,2}(?: [^\r\n]+)?$/.test(key)) throw new Error('手动导入时请填写 OpenSSH 主机公钥。也可留空，在首次连接时确认指纹。'); return { ...body, ssh_host_key: key || null }; }
    if (protocol === 'rdp') { const pin = values.rdp_certificate_sha256.trim(); if (pin && !/^[a-f0-9]{64}$/.test(pin)) throw new Error('手动导入时请填写 leaf DER 证书的 64 位小写 SHA-256。也可留空，在首次连接时确认。'); return { ...body, rdp_certificate_sha256: pin || null }; }
    return body;
  };
  const defaultAccountLabel = (protocol: TargetProtocol, username: string | null, domain: string | null, kind: Account['credential_kind']) =>
    protocol === 'vnc' ? kind === 'none' ? '无认证' : '密码认证' : `${protocol === 'rdp' && domain ? domain.trim() + '\\' : ''}${username?.trim() ?? ''}`;
  const customAccountLabel = (account: AdminAccount | undefined, protocol: TargetProtocol) => account && account.label !== defaultAccountLabel(protocol, account.username, account.domain, account.credential_kind) ? account.label : '';
  const accountBody = (values: Record<string, string>, protocol: TargetProtocol, account?: AdminAccount) => {
    if (protocol !== 'vnc' && !values.username.trim()) throw new Error('SSH/RDP 需要用户名。');
    const kind = values.credential_type === 'keep' ? account!.credential_kind : values.credential_type as Account['credential_kind'];
    const label = values.label.trim() || defaultAccountLabel(protocol, values.username, values.domain, kind);
    if ([...label].length > 128) throw new Error('账号显示名称最多 128 个字符；自动名称过长时请填写自定义名称。');
    return { label, username: protocol === 'vnc' ? null : values.username, domain: protocol === 'rdp' ? values.domain || null : null };
  };
  function protocolDialog(dialog: HTMLDialogElement, fixed?: TargetProtocol) {
    const get = (name: string) => dialog.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>( '[name="' + name + '"]')!;
    const type = get('credential_type') as HTMLSelectElement, picker = dialog.querySelector<HTMLSelectElement>('[name="protocol"]');
    const sync = () => {
      const protocol = fixed ?? picker!.value as TargetProtocol;
      const modes = [...(type.value === 'keep' ? ['keep'] : []), 'password', ...(protocol === 'ssh' ? ['private_key'] : protocol === 'vnc' ? ['none'] : [])];
      const selected = modes.includes(type.value) ? type.value : 'password';
      type.replaceChildren(...modes.map(value => new Option(credentialFields[0].optionLabels![value], value))); type.value = selected; type.dispatchEvent(new Event('change'));
      for (const [name, active] of [['ssh_host_key', protocol === 'ssh'], ['rdp_certificate_sha256', protocol === 'rdp'], ['username', protocol !== 'vnc'], ['domain', protocol === 'rdp']] as const) {
        const control = get(name); control.parentElement!.hidden = !active; control.disabled = !active; control.required = active && !['domain', 'ssh_host_key', 'rdp_certificate_sha256'].includes(name); if (!active) control.value = '';
      }
    };
    picker?.addEventListener('change', () => { get('port').value = ({ ssh: '22', rdp: '3389', vnc: '5900' } as Record<string,string>)[picker.value]; sync(); }); sync();
  }
  async function editAsset(item: AdminAsset) {
    let asset = await api.adminAsset(item.id, life.signal);
    await loadGroups(); if (life.signal.aborted) return;
    const accounts = new Map((await allPages(cursor => api.accounts(asset.id, { cursor }, life.signal), '账号列表')).map(account => [account.id, account] as const)); if (life.signal.aborted) return;
    const selected = accounts.values().next().value;
    const dialog = editDialog('编辑资产与账号', [
      ...[...assetFields(asset), { ...enabledField(asset.enabled), name: 'asset_enabled', label: '启用资产' }].map(field => ({ ...field, section: '资产信息' })),
      ...[
        { name: 'account_id', label: '目标账号', options: [...accounts.keys(), 'new'], optionLabels: { ...Object.fromEntries([...accounts.values()].map(account => [account.id, `${account.label}${account.enabled ? '' : '（已停用）'}`])), new: '＋ 新增账号' }, value: selected?.id ?? 'new' },
        textField('label', '显示名称（可选，留空自动命名）', customAccountLabel(selected, asset.protocol), false), textField('username', 'SSH/RDP 用户名', selected?.username ?? '', false), textField('domain', 'RDP 域（可选）', selected?.domain ?? '', false),
        { ...enabledField(selected?.enabled ?? true), name: 'account_enabled', label: '启用账号' },
        ...credentialFields.map(field => field.name === 'credential_type' ? { ...field, options: selected ? ['keep', 'password', 'private_key'] : field.options, value: selected ? 'keep' : 'password' } : field),
      ].map(field => ({ ...field, section: '账号与凭据' })),
    ], async values => {
      let account = accounts.get(values.account_id);
      const secret = values.credential_type === 'keep' ? undefined : credential(values);
      if (!account && (values.account_id !== 'new' || !secret)) { if (secret) clearCredential(secret); throw new Error('请选择已有账号或填写新账号凭据。'); }
      let stage = '资产信息';
      try {
        const body = { ...assetBody(values, asset.protocol), enabled: values.asset_enabled === 'true' };
        if (Object.entries(body).some(([key, value]) => JSON.stringify(value) !== JSON.stringify(asset[key as keyof AdminAsset]))) asset = await api.updateAsset(asset.id, asset.revision, body, life.signal);
        if (life.signal.aborted) return;
        stage = '账号';
        if (!account) { account = await api.createAccount(asset.id, { ...accountBody(values, asset.protocol), credential: secret! }, life.signal); accounts.set(account.id, account); }
        else {
          const proposed = { ...accountBody(values, asset.protocol, account), enabled: values.account_enabled === 'true' };
          const patch = Object.fromEntries(Object.entries(proposed).filter(([key, value]) => account![key as keyof AdminAccount] !== value));
          if (Object.keys(patch).length) Object.assign(account, await api.updateAccount(account.id, account.revision, patch, life.signal));
          if (life.signal.aborted) return;
          if (secret) { stage = '凭据'; Object.assign(account, await api.replaceCredential(account.id, account.revision, secret, life.signal)); }
        }
      } catch (error) {
        const blocked = error instanceof ApiError && ['RESULT_UNKNOWN', 'REVISION_CONFLICT'].includes(error.code);
        throw new ApiError(error instanceof ApiError ? error.code : 'ASSET_EDIT_FAILED', `${stage}保存未完成。${blocked ? '请关闭弹窗重新读取并核对，不要重复提交。' : '已确认的修改会保留，可修正后重试。'} ${stateMessage(error)}`, error instanceof ApiError ? error.requestId : '', error instanceof ApiError ? error.status : 0);
      } finally { if (secret) clearCredential(secret); }
      await refresh();
    }, life);
    dialog.classList.add('asset-create-dialog');
    const hint = node('p', '协议不可变：' + asset.protocol + '。现有秘密不回显。SSH 可在首次连接时确认指纹；更换目标地址后请重新核验主机身份。', 'hint asset-create-hint'); dialog.querySelector('h2')!.after(hint);
    const picker = dialog.querySelector<HTMLSelectElement>('[name="account_id"]')!, type = dialog.querySelector<HTMLSelectElement>('[name="credential_type"]')!;
    const removeAccount = button('删除该目标账号', () => {
      const account = accounts.get(picker.value);
      if (!account || life.signal.aborted) return;
      const confirm = confirmDialog(`删除目标账号 ${account.label} · ID ${account.id} · 修订 ${account.revision}？该账号立即从所有用户的可用列表中移除，相关授权一并撤销，未签发票据作废，进行中的会话被断开。审计记录、历史连接和录制保留；账号记录仅标记删除，不可恢复。`, async () => {
        if (life.signal.aborted) return;
        await api.deleteAccount(account.id, account.revision, life.signal);
        if (life.signal.aborted) return;
        accounts.delete(account.id);
        dialog.close();
        await refresh();
      }, life, true, '目标账号删除已确认。');
      confirm.querySelector('h2')!.setAttribute('data-delete-account', account.id);
    }, dialog.querySelector<HTMLElement>('.toolbar') ?? dialog.querySelector('form')!, 'danger-text');
    const syncAccount = () => {
      const account = accounts.get(picker.value), username = dialog.querySelector<HTMLInputElement>('[name="username"]')!, enabled = dialog.querySelector<HTMLInputElement>('[name="account_enabled"]')!;
      username.value = account?.username ?? ''; dialog.querySelector<HTMLInputElement>('[name="label"]')!.value = customAccountLabel(account, asset.protocol); dialog.querySelector<HTMLInputElement>('[name="domain"]')!.value = account?.domain ?? ''; enabled.checked = account?.enabled ?? true; enabled.parentElement!.hidden = !account; enabled.disabled = !account;
      removeAccount.hidden = !account;
      const options = account ? ['keep', 'password', 'private_key'] : ['password', 'private_key'];
      type.replaceChildren(...options.map(value => new Option(credentialFields[0].optionLabels![value], value))); type.value = account ? 'keep' : 'password';
      for (const name of ['password', 'key_pem', 'passphrase']) dialog.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[name="${name}"]`)!.value = '';
      type.dispatchEvent(new Event('change')); protocolDialog(dialog, asset.protocol);
    };
    picker.addEventListener('change', syncAccount); syncAccount();
  }
  const createAssetButton = button('新建资产', () => {
    createAssetButton.disabled = true;
    void routeAction(life, async () => {
    await loadGroups(); if (life.signal.aborted) return;
    let createdAsset: AdminAsset | undefined;
    const dialog = editDialog('新建资产', [
      ...assetFields().map(field => ({ ...field, section: '资产信息' })),
      ...[textField('label', '显示名称（可选，留空自动命名）', '', false), textField('username', 'SSH/RDP 用户名', '', false), textField('domain', 'RDP 域（可选）', '', false), ...credentialFields].map(field => ({ ...field, section: '连接账号与凭据' })),
    ], async values => {
      const secret = credential(values);
      try {
        const account = accountBody(values, createdAsset?.protocol ?? values.protocol as TargetProtocol);
        if (!createdAsset) {
          createdAsset = await api.createAsset({ ...assetBody(values, values.protocol as TargetProtocol), protocol: values.protocol as TargetProtocol }, life.signal);
          if (life.signal.aborted) return;
          dialog.querySelector('fieldset')!.disabled = true;
        }
        await api.createAccount(createdAsset.id, { ...account, credential: secret }, life.signal);
      } catch (error) {
        if (!createdAsset) throw error;
        const unknown = error instanceof ApiError && error.code === 'RESULT_UNKNOWN';
        throw new ApiError(error instanceof ApiError ? error.code : 'ACCOUNT_CREATE_FAILED',
          `资产已创建（${createdAsset.id}），账号${unknown ? '保存结果未知，请关闭弹窗并在账号详情核对，不要重复提交' : '创建失败；可重新填写凭据并重试，不会重复创建资产'}。${stateMessage(error)}`,
          error instanceof ApiError ? error.requestId : '', error instanceof ApiError ? error.status : 0);
      } finally { clearCredential(secret); }
      // Stay on the list after a successful create; navigating into the editor opened a second dialog the user did not ask for.
      await refresh();
    }, life, false, '资产与首个目标账号已创建。');
    dialog.classList.add('asset-create-dialog'); protocolDialog(dialog);
    dialog.querySelector('h2')!.after(node('p', '凭据加密保存，不会回显。SSH 主机公钥和 RDP 证书指纹都无需填写，首次连接时由管理员确认；RDP 安全模式自动识别。普通用户需配置授权。', 'hint asset-create-hint'));
  }, '资产信息已读取。').finally(() => { if (!life.signal.aborted) createAssetButton.disabled = false; });
  }, controls.right, 'primary');
  const groupFilter = node('select'); groupFilter.setAttribute('aria-label', '筛选资产分组'); controls.right.append(groupFilter);
  groupFilter.replaceChildren(new Option('全部分组', '*'));
  const syncGroupFilter = () => { const selected = groupFilter.value || ''; groupFilter.replaceChildren(new Option('全部分组', '*'), new Option('未分组', ''), ...groupTree(groups).map(({ group, depth }) => new Option(`${'　'.repeat(depth)}${group.name}`, group.id))); groupFilter.value = selected && groups.some(group => group.id === selected) || selected === '' ? selected : '*'; };
  const assetPager = paged(view, life, async query => { await loadGroups(); syncGroupFilter(); return api.adminAssets({ ...query, ...(groupFilter.value === '*' ? {} : groupFilter.value ? { group_id: groupFilter.value } : { ungrouped: 'true' }) }, life.signal); }, (items, output) => groupedTables(output, items, item => ({ id: item.group_id, name: groups.find(group => group.id === item.group_id)?.name ?? null }), (items, output) => table(output, items, [
    { label: '名称', value: item => stacked(item.name, item.id) },
    { label: '协议', value: item => tag(item.protocol) },
    { label: '地址', value: item => mono(`${item.host}:${item.port}`) },
    { label: '标签', value: item => tags(item.tags) },
    { label: '状态', value: item => enabledTag(item.enabled) },
    { label: '主机身份', value: item => item.protocol === 'vnc' ? '—' : tag((item.protocol === 'ssh' ? item.ssh_host_key : item.rdp_certificate_sha256) ? '已确认' : '待确认') },
    { label: '修订', value: item => String(item.revision) },
  ], (item, toolbar) => {
    const edit = button('编辑资产与账号', () => { edit.disabled = true; void routeAction(life, () => editAsset(item), '已读取当前资产和账号信息。').finally(() => { if (!life.signal.aborted) edit.disabled = false; }); }, toolbar, 'link');
    if (item.protocol !== 'vnc' && item.enabled) {
      const confirmed = item.protocol === 'ssh' ? item.ssh_host_key : item.rdp_certificate_sha256;
      const verify = button(confirmed ? '重新核验主机指纹' : '确认主机指纹', () => {
        verify.disabled = true;
        void routeAction(life, async () => { const asset = await api.adminAsset(item.id, life.signal); if (await (asset.protocol === 'rdp' ? confirmRdpCertificate : confirmSshHostKey)(asset, life)) await refresh(); }, '主机指纹核验结束。')
          .finally(() => { if (!life.signal.aborted) verify.disabled = false; });
      }, toolbar, 'link');
    }
    const remove = button('删除', () => {
      if (remove.disabled || life.signal.aborted) return;
      // Name the resource, its revision and every consequence, the way user deletion does.
      const dialog = confirmDialog(`删除资产 ${item.name} · ID ${item.id} · 修订 ${item.revision}？该资产及其全部目标账号将立即从所有用户的可用列表中移除，相关授权一并撤销，未签发票据作废，进行中的会话被断开。审计记录、历史连接、录制和已核验的主机指纹保留；资产与账号记录仅标记删除，不可恢复。`, async () => {
        if (remove.disabled || life.signal.aborted) return;
        try { await api.deleteAsset(item.id, item.revision, life.signal); }
        catch (error) { if (error instanceof ApiError && ['RESULT_UNKNOWN', 'REVISION_CONFLICT'].includes(error.code)) remove.disabled = true; throw error; }
        if (life.signal.aborted) return;
        for (const action of toolbar.querySelectorAll('button')) action.disabled = true;
        clearError(); await refresh();
        if (!life.signal.aborted && !errorBox.hidden) errorBox.textContent = `资产删除已确认，但列表刷新失败。${errorBox.textContent}`;
      }, life, true, '资产删除已确认；若列表未更新，请点击刷新。');
      dialog.querySelector('h2')!.setAttribute('data-delete-asset', item.id);
    }, toolbar, 'danger-text');
  }), groups.filter(group => groupFilter.value === '*' || groupFilter.value === group.id)), {}, controls);
  refresh = async () => { await assetPager.filter({}); if (!life.signal.aborted && me) await loadAssets(false, life.signal); };
  groupFilter.onchange = () => { void routeAction(life, () => assetPager.filter({}), '资产列表已更新。'); };
  if (route.id) { const id = route.id; void routeAction(life, async () => { await editAsset(await api.adminAsset(id, life.signal)); }); }
}
function mountGrants(life: RouteLifetime) {
  view.append(node('p', '授权绑定具体用户与精确资产账号，只允许浏览器远程会话。管理员默认访问所有启用资产账号；删除 Grant 不会移除管理员的隐式访问，需降级角色或停用用户。SSH 使用文本终端，RDP/VNC 使用 Guacamole。', 'hint')); const controls = bar(view); let refresh: () => Promise<void>;
  const off = (enabled: boolean) => enabled ? '' : '（已停用）';
  const accountLabel = (account: AdminAccount) => `${account.label}${account.username ? ` · ${account.username}` : ''}${off(account.enabled)}`;
  const accountsOf = (asset: string) => asset ? allPages(cursor => api.accounts(asset, { limit: 200, cursor }, life.signal), '账号列表') : Promise.resolve([]);
  /** Pick from real users, assets and that asset's accounts instead of pasting UUIDs. */
  button('新建授权', () => { void routeAction(life, async () => {
    const [users, assetList] = await Promise.all([
      allPages(cursor => api.users({ limit: 200, cursor }, life.signal), '用户列表'),
      allPages(cursor => api.adminAssets({ limit: 200, cursor }, life.signal), '资产列表'),
    ]);
    const accounts = await accountsOf(assetList[0]?.id ?? ''); if (life.signal.aborted) return;
    const dialog = editDialog('新建授权', [
      { name: 'user_id', label: '用户', options: users.map(user => user.id), optionLabels: Object.fromEntries(users.map(user => [user.id, `${user.username}（${user.role}）${off(user.enabled)}`])), value: users[0]?.id },
      { name: 'asset_id', label: '资产', options: assetList.map(asset => asset.id), optionLabels: Object.fromEntries(assetList.map(asset => [asset.id, `${asset.name} · ${asset.protocol.toUpperCase()} ${asset.host}:${asset.port}${off(asset.enabled)}`])), value: assetList[0]?.id },
      { name: 'account_id', label: '目标账号', options: accounts.map(account => account.id), optionLabels: Object.fromEntries(accounts.map(account => [account.id, accountLabel(account)])), value: accounts[0]?.id },
      { name: 'expires_at', label: '到期时间（空表示不设到期）', type: 'datetime-local', required: false },
    ], async values => { await api.createGrant({ user_id: values.user_id, asset_id: values.asset_id, account_id: values.account_id, expires_at: expiry(values.expires_at) }, life.signal); await refresh(); }, life);
    const assetPicker = dialog.querySelector<HTMLSelectElement>('[name="asset_id"]')!, accountPicker = dialog.querySelector<HTMLSelectElement>('[name="account_id"]')!;
    assetPicker.onchange = () => { const asset = assetPicker.value; accountPicker.replaceChildren(); void routeAction(life, async () => {
      const list = await accountsOf(asset); if (life.signal.aborted || assetPicker.value !== asset) return;
      accountPicker.replaceChildren(...list.map(account => new Option(accountLabel(account), account.id)));
    }, '账号列表已读取。'); };
  }, '授权候选已读取。'); }, controls.right, 'primary');
  refresh = paged(view, life, query => api.grants(query, life.signal), (items, output) => table(output, items, [
    { label: '用户', value: item => item.username ? stacked(item.username, item.user_id) : mono(item.user_id) },
    { label: '资产', value: item => item.asset_name ? stacked(item.asset_name, item.asset_id) : mono(item.asset_id) },
    { label: '账号', value: item => item.account_label ? stacked(item.account_label, item.account_id) : mono(item.account_id) },
    { label: '到期', value: item => item.expires_at ? when(item.expires_at) : '永不' },
    { label: '状态', value: item => enabledTag(item.enabled) },
  ], (item, toolbar) => {
    button('编辑', () => editDialog('编辑授权', [enabledField(item.enabled), { name: 'expires_at', label: '到期（空表示清除）', type: 'datetime-local', required: false, value: item.expires_at ? new Date(new Date(item.expires_at).valueOf() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '' }], async values => { await api.updateGrant(item.id, item.revision, { enabled: values.enabled === 'true', expires_at: expiry(values.expires_at) }, life.signal); await refresh(); }, life), toolbar, 'link');
    button('撤销', () => confirmDialog(`撤销授权 ${item.username ?? item.user_id} → ${item.asset_name ?? item.asset_id} / ${item.account_label ?? item.account_id} · 修订 ${item.revision}`, async () => { await api.revokeGrant(item.id, item.revision, life.signal); await refresh(); }, life), toolbar, 'danger-text');
  }), {}, controls).reload;
}
function mountProfile(life: RouteLifetime) {
  const card = node('section', '', 'card'), list = node('dl', '', 'descriptions');
  for (const [term, value] of [['用户名', me!.user.username], ['角色', me!.user.role], ['用户 ID', me!.user.id], ['当前登录会话', me!.login_session_id], ['策略修订', String(me!.policy_revision)]]) list.append(node('dt', term), node('dd', value));
  const actions = node('div', '', 'toolbar'); card.append(node('h2', '账号信息'), list, actions); view.append(card);
  button('修改密码', () => editDialog('修改密码：现有登录会话将失效', [{ name: 'current_password', label: '当前密码', type: 'password' }, { name: 'new_password', label: passwordLabel('新密码'), type: 'password' }], async values => { await api.changePassword(values.current_password, values.new_password, life.signal); clearMemory(); statusText('密码已修改；请重新登录。'); }, life), actions);
  button('注销所有设备', () => confirmDialog('注销本人所有设备登录', async () => { await api.logout(true, life.signal); clearMemory(); statusText('所有设备已注销。'); }, life), actions, 'danger');
  if (!info?.features?.device_sessions) { view.append(node('p', '服务端未提供设备会话管理能力。', 'hint')); return; }
  const title = node('div', '', 'section-title'); title.append(node('h2', '设备登录')); view.append(title);
  let refresh: () => Promise<void>;
  refresh = paged(view, life, () => api.devices(life.signal), (items, output) => table(output, items, [
    { label: '设备', value: item => { const span = node('span', item.device_label); if (item.current) span.append(node('span', '当前', 'tag blue')); span.append(mono(item.id)); (span.lastChild as HTMLElement).className = 'sub mono'; return span; } },
    { label: '创建时间', value: item => when(item.created_at) },
    { label: '到期时间', value: item => when(item.expires_at) },
    { label: '状态', value: item => item.revoked_at ? tag(`已撤销 ${when(item.revoked_at)}`) : tag('有效', 'green') },
  ], (item, toolbar) => {
    button('撤销设备', () => confirmDialog(`撤销设备 ${item.device_label}${item.current ? '（当前登录将结束）' : ''}`, async () => { await api.revokeDevice(item.id, life.signal); if (item.current) { clearMemory(); statusText('当前设备已撤销。'); } else await refresh(); }, life), toolbar, 'danger-text');
  })).reload;
}
const filterLabels: Record<string, string> = { from: '开始时间', to: '结束时间', actor_id: '操作者 ID', resource_id: '资源 ID', resource_type: '资源类型', action: '动作', state: '状态', target_protocol: '目标协议' };
const filterOptions: Record<string, string[]> = { state: ['pending', 'connecting', 'active', 'closing', 'closed', 'failed', 'expired', 'revoked', 'interrupted'], target_protocol: ['ssh', 'rdp', 'vnc'] };
function mountActivity(kind: 'connections' | 'audit', life: RouteLifetime) {
  const filters = node('form', '', 'filters'); view.append(filters); const fields = kind === 'connections' ? ['from', 'to', 'actor_id', 'resource_id', 'state', 'target_protocol'] : ['from', 'to', 'actor_id', 'resource_id', 'resource_type', 'action'];
  for (const field of fields) {
    let input: HTMLInputElement | HTMLSelectElement;
    if (filterOptions[field]) { input = node('select'); input.replaceChildren(new Option(`全部${filterLabels[field]}`, ''), ...filterOptions[field].map(value => new Option(value, value))); }
    else { input = node('input'); input.placeholder = filterLabels[field]; if (field === 'from' || field === 'to') input.type = 'datetime-local'; }
    input.name = field; input.title = filterLabels[field]; input.setAttribute('aria-label', filterLabels[field]); filters.append(input);
  }
  const apply = node('button', '查询', 'primary'); apply.type = 'submit'; filters.append(apply);
  const page = kind === 'connections' ? paged(view, life, query => api.connections(query, life.signal), (items, output) => table(output, items, [
    { label: '连接', value: item => mono(item.id) },
    { label: '资产 / 账号', value: item => { const span = node('span'); span.append(mono(item.asset_id), mono(item.account_id)); (span.lastChild as HTMLElement).className = 'sub mono'; return span; } },
    { label: '状态', value: item => tag(item.state) },
    { label: '目标协议', value: item => item.target_protocol ?? '—' },
    { label: '创建时间', value: item => when(item.created_at) },
    { label: '失败原因', value: item => item.failure ? tag(item.failure.code, 'red') : '—' },
  ], (item, toolbar) => {
    button('详情', () => { void routeAction(life, async () => { const detail = await api.connection(item.id, life.signal); if (!life.signal.aborted) { const panel = node('section', '', 'card'); panel.append(node('h3', `连接 ${item.id}`), node('pre', JSON.stringify(detail, null, 2))); output.append(panel); panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } }); }, toolbar, 'link');
    if (info?.features?.recording_replay) toolbar.append(link('录制', `#/recordings/${encodeURIComponent(item.id)}`));
    if (!['closed', 'failed', 'expired', 'revoked', 'interrupted'].includes(item.state)) button('断开', () => confirmDialog(`断开连接 ${item.id}`, async () => { await api.disconnect(item.id, life.signal); await page.reload(); }, life), toolbar, 'danger-text');
  })) : paged(view, life, query => api.audit(query, life.signal), (items, output) => table(output, items, [
    { label: '时间', value: item => when(item.occurred_at) },
    { label: '动作', value: item => tag(String(item.action ?? '—'), 'blue') },
    { label: '资源', value: item => stacked(String(item.resource_type ?? '—'), item.resource_id) },
    { label: '操作者', value: item => mono(item.actor_id) },
    { label: 'request_id', value: item => mono(item.request_id) },
    { label: '详情', value: item => details('载荷', item.sanitized_payload ?? item) },
  ]));
  filters.onsubmit = event => { event.preventDefault(); const query: Query = {}; const values = new FormData(filters); for (const field of fields) { const value = String(values.get(field) ?? ''); if (value) query[field] = ['from', 'to'].includes(field) ? new Date(value).toISOString() : value; } void page.filter(query); };
}
function renderRoute() {
  routeLife.dispose(); routeLife = new RouteLifetime(); targetUpdate = () => {}; view.replaceChildren(); clearError();
  document.querySelector<HTMLDetailsElement>('.user-menu')?.removeAttribute('open');
  route = parseRoute(location.hash); renderNavigation(); if (!me) return;
  const current = routes.find(item => item.name === route.name), label = current?.label ?? '页面不存在';
  const isConsole = route.name === 'console';
  document.body.classList?.toggle?.('console', isConsole);
  // Replay owns the full content height so its stage gets the viewport instead of a magic scroll offset.
  document.body.classList?.toggle?.('replay', route.name === 'recordings');
  element('assets-heading').textContent = label; element('crumb').textContent = current ? `${current.group} / ${label}` : label;
  if (!allowedRoute(route.name, me.user.role, info)) { view.append(node('p', route.name === 'not-found' ? '页面不存在。请选择导航中的可用页面。' : '禁止访问或能力不可用：当前角色没有权限，或服务端没有装配此功能。', 'empty')); return; }
  const life = routeLife;
  if (route.name === 'assets') mountAssets();
  else if (route.name === 'console') mountConsole(life, route.id!, route.sub!);
  else if (route.name === 'recordings') mountReplay(view, api, life, statusText, showError, route.id);
  else if (route.name === 'users') mountUsers(life);
  else if (route.name === 'admin-assets') mountAdminAssets(life);
  else if (route.name === 'grants') mountGrants(life);
  else if (route.name === 'profile') mountProfile(life);
  else if (route.name === 'connections' || route.name === 'audit') mountActivity(route.name, life);
  // The console hides the workspace page head; its own bar carries the heading and the session takes focus.
  if (isConsole) document.title = '控制台 · ZeroTerm'; else { document.title = 'ZeroTerm · 堡垒机'; element('assets-heading').focus({ preventScroll: true }); }
}
const collapse = element<HTMLButtonElement>('collapse'); collapse.innerHTML = svg(icons.collapse);
collapse.onclick = () => { const collapsed = element('workspace').classList.toggle('collapsed'); collapse.setAttribute('aria-label', collapsed ? '展开导航' : '折叠导航'); collapse.title = collapse.getAttribute('aria-label')!; };
assetSelect.onchange = renderAccounts; accountSelect.onchange = renderAccounts;
// Shared by the workspace user menu and the popup console menu, so the popup is never an identity dead-end.
const logout = () => authAction(async () => { routeLife.dispose(); try { await api.logout(false, auth.signal); statusText('已注销。'); } finally { clearMemory(); } });
const refreshLogin = () => authAction(async () => {
  try { await api.refresh(); setWorkspace(await api.loadMe(auth.signal)); statusText('登录已刷新。'); } catch (error) { clearMemory(); throw error; }
});
element<HTMLButtonElement>('logout').onclick = () => { void logout(); };
element<HTMLButtonElement>('refresh').onclick = () => { void refreshLogin(); };
element<HTMLFormElement>('login-form').onsubmit = event => {
  event.preventDefault(); void authAction(async () => {
    await api.loadCsrf(auth.signal); const password = element<HTMLInputElement>('password'); const credentials = { username: element<HTMLInputElement>('username').value, password: password.value, device_label: element<HTMLInputElement>('device').value.trim() || 'Web 浏览器' }; password.value = '';
    try { await api.login(credentials, auth.signal); } finally { credentials.password = ''; }
    setWorkspace(await api.loadMe(auth.signal)); if (me?.user.role !== 'auditor') await loadAssets(); statusText('登录成功。');
  });
};
window.addEventListener('hashchange', renderRoute);
window.addEventListener('pagehide', clearMemory);
window.addEventListener('pageshow', event => { if (event.persisted) void initialize(); });
async function initialize() {
  await authAction(async () => {
    statusText('正在读取服务端状态与登录身份…');
    info = await api.info(auth.signal);
    element('discovery').textContent = `server_id: ${info.server_id ?? '未提供'} · protocol v${info.protocol_version} · production_ready: ${info.production_ready} · required recording: ${info.recording?.required ?? '未提供'} · recording available: ${info.recording?.available ?? '未提供'}`;
    const warning = discoveryWarning(info); const badge = element('development-warning'); badge.textContent = warning; badge.hidden = !warning;
    await api.loadCsrf(auth.signal);
    try { setWorkspace(await api.loadMe(auth.signal)); } catch (error) { if (error instanceof ApiError && error.status === 401) { element('login-panel').hidden = false; element('username').focus(); statusText('请登录。'); return; } throw error; }
    if (me?.user.role !== 'auditor') await loadAssets();
  });
  if (!me) element('login-panel').hidden = false;
}
void initialize();
