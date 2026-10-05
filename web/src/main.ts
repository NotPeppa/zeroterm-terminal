import '@xterm/xterm/css/xterm.css';
import './style.css';
import { ApiClient, ApiError, type Me, type Info, type Asset, type AdminAsset, type Credential, type Capability, type Role, type Page, type Query } from './api';
import { allowedRoute, discoveryWarning, parseRoute, RouteLifetime, routes, stateMessage, type Route } from './state';
import { mountTerminal, TargetSocket, type Target } from './terminal';
import { mountExec, mountFiles, mountReplay } from './workspaces';

const api = new ApiClient();
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const view = element('route-view'), status = element('status'), errorBox = element('error');
let me: Me | null = null, info: Info | null = null, assets: Asset[] = [], cursor: string | null = null;
let auth = new RouteLifetime(), routeLife = new RouteLifetime(), route: Route = { name: 'assets' };
let refreshUsed = false, authBusy = false, targetUpdate: () => void = () => {};
const assetSelect = element<HTMLSelectElement>('asset'), accountSelect = element<HTMLSelectElement>('account');
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => { const result = document.createElement(tag); result.textContent = text; if (className) result.className = className; return result; };
function statusText(text: string) { status.textContent = text; }
function showError(error: unknown) {
  if (error instanceof ApiError && (error.status === 401 || ['LOGIN_SESSION_REVOKED', 'USER_DISABLED'].includes(error.code))) clearMemory();
  errorBox.hidden = false; errorBox.textContent = `${stateMessage(error)}${error instanceof ApiError ? ` · ${error.code} · request_id: ${error.requestId || '不可用'}` : ''}`;
}
function clearError() { errorBox.hidden = true; errorBox.textContent = ''; }
export function button(text: string, action: () => void, parent?: HTMLElement) { const result = node('button', text); result.type = 'button'; result.onclick = action; parent?.append(result); return result; }
function link(text: string, hash: string) { const result = node('a', text); result.href = hash; return result; }
function getTarget(): Target | null { const asset = assets.find(value => value.id === assetSelect.value), account = asset?.accounts.find(value => value.id === accountSelect.value); return asset && account ? { asset, account } : null; }
function renderAccounts() {
  const previous = accountSelect.value;
  accountSelect.replaceChildren(...(assets.find(value => value.id === assetSelect.value)?.accounts ?? []).map(account => new Option(account.username, account.id)));
  if ([...accountSelect.options].some(option => option.value === previous)) accountSelect.value = previous;
  const target = getTarget(); element('capabilities').textContent = target ? `资产 ID: ${target.asset.id} · 目标账号 ID: ${target.account.id} · 授权能力: ${target.account.capabilities.join(', ') || '无'}；请求时服务端重新授权。` : '没有已授权目标；联系管理员配置授权。';
  targetUpdate();
}
function renderAssets() { const previous = assetSelect.value; assetSelect.replaceChildren(...assets.map(asset => new Option(asset.name, asset.id))); if ([...assetSelect.options].some(option => option.value === previous)) assetSelect.value = previous; renderAccounts(); element<HTMLButtonElement>('more').hidden = !cursor; }
async function loadAssets(append = false) {
  const signal = auth.signal; const result = await api.assets(append && cursor ? { cursor } : {}, signal); if (signal.aborted) return;
  assets = append ? [...assets, ...result.items.filter(item => !assets.some(old => old.id === item.id))] : result.items; cursor = result.next_cursor; renderAssets();
  if (route.name === 'assets') renderRoute();
  statusText(assets.length ? '授权目标已读取。' : '没有已授权目标。');
}
function renderNavigation() {
  const navigation = element('navigation'); navigation.replaceChildren();
  if (!me) return;
  for (const item of routes.filter(item => allowedRoute(item.name, me!.user.role, info))) {
    const anchor = link(item.label, `#/${item.name}`); if (route.name === item.name) anchor.setAttribute('aria-current', 'page'); navigation.append(anchor);
  }
}
function setWorkspace(identity: Me) {
  me = identity; element('login-panel').hidden = true; element('workspace').hidden = false;
  element('sidebar-user').textContent = `${identity.user.username} · ${identity.user.role}`;
  element('identity').textContent = `当前用户: ${identity.user.username} (${identity.user.id}) · role: ${identity.user.role} · login_session_id: ${identity.login_session_id} · policy_revision: ${identity.policy_revision}`;
  if (!location.hash) location.hash = identity.user.role === 'auditor' ? '#/connections' : '#/assets';
  renderAssets(); renderRoute();
}
function clearMemory() {
  auth.dispose(); auth = new RouteLifetime(); routeLife.dispose(); routeLife = new RouteLifetime(); api.clearAuth();
  me = null; assets = []; cursor = null; targetUpdate = () => {}; view.replaceChildren(); assetSelect.replaceChildren(); accountSelect.replaceChildren(); element<HTMLInputElement>('password').value = '';
  element('workspace').hidden = true; element('login-panel').hidden = false; element('identity').textContent = ''; element('navigation').replaceChildren(); element('capabilities').textContent = ''; element('username').focus();
}
async function authAction(work: () => Promise<void>) {
  if (authBusy) return; authBusy = true; clearError(); element<HTMLButtonElement>('login').disabled = element<HTMLButtonElement>('logout').disabled = element<HTMLButtonElement>('refresh').disabled = true;
  try { await work(); } catch (error) { showError(error); } finally { authBusy = false; element<HTMLButtonElement>('login').disabled = element<HTMLButtonElement>('logout').disabled = false; element<HTMLButtonElement>('refresh').disabled = refreshUsed; }
}
async function routeAction(life: RouteLifetime, work: () => Promise<unknown>, result = '操作已由服务端确认。'): Promise<boolean> {
  clearError();
  try { await work(); if (!life.signal.aborted) statusText(result); return !life.signal.aborted; }
  catch (error) { if (!life.signal.aborted || error instanceof ApiError && error.code === 'RESULT_UNKNOWN') showError(error); return false; }
}

type Field = { name: string; label: string; value?: string; type?: 'password' | 'number' | 'datetime-local' | 'checkbox' | 'textarea'; options?: string[]; required?: boolean; min?: number; max?: number };
function editDialog(title: string, fields: Field[], submit: (values: Record<string, string>) => Promise<unknown>, life: RouteLifetime = routeLife) {
  const opener = document.activeElement as HTMLElement | null;
  const dialog = node('dialog'), form = node('form'), heading = node('h2', title), issue = node('p', '', 'error'); heading.id = 'dialog-heading'; dialog.setAttribute('aria-labelledby', heading.id);
  const controls = new Map<string, HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(); form.append(heading);
  for (const field of fields) {
    const label = node('label', field.label);
    let input: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
    if (field.options) { input = node('select'); input.replaceChildren(...field.options.map(value => new Option(value, value))); }
    else if (field.type === 'textarea') input = node('textarea');
    else { input = node('input'); input.type = field.type ?? 'text'; if (field.type === 'password') input.autocomplete = 'new-password'; if (field.min !== undefined) input.min = String(field.min); if (field.max !== undefined) input.max = String(field.max); }
    input.name = field.name; input.value = field.value ?? ''; input.required = field.required !== false && field.type !== 'checkbox';
    if (input instanceof HTMLInputElement && field.type === 'checkbox') input.checked = field.value === 'true';
    controls.set(field.name, input); label.append(input); form.append(label);
  }
  issue.setAttribute('role', 'alert'); form.append(issue);
  const actions = node('div', '', 'toolbar'), cancel = button('取消', () => dialog.close(), actions), save = node('button', '确认提交', 'primary'); save.type = 'submit'; actions.append(save); form.append(actions); dialog.append(form); document.body.append(dialog);
  let pending = false;
  dialog.addEventListener('cancel', event => { if (pending) event.preventDefault(); });
  const clearSecrets = () => { for (const input of controls.values()) if (input instanceof HTMLInputElement && input.type === 'password' || input.name === 'key_pem') input.value = ''; };
  dialog.addEventListener('close', () => { clearSecrets(); dialog.remove(); if (opener?.isConnected) opener.focus(); });
  life.own(() => { clearSecrets(); dialog.close(); dialog.remove(); });
  form.onsubmit = event => {
    event.preventDefault(); if (pending) return;
    const values: Record<string, string> = {}; for (const [name, input] of controls) values[name] = input instanceof HTMLInputElement && input.type === 'checkbox' ? String(input.checked) : input.value;
    clearSecrets(); pending = true; save.disabled = cancel.disabled = true; issue.textContent = '正在提交；不会自动重试。';
    void submit(values).then(() => { if (!life.signal.aborted) { statusText('操作已由服务端确认。'); dialog.close(); } }).catch(error => { if (!life.signal.aborted) { issue.textContent = stateMessage(error); showError(error); } }).finally(() => { for (const key of Object.keys(values)) values[key] = ''; pending = false; save.disabled = cancel.disabled = false; });
  };
  dialog.showModal(); controls.values().next().value?.focus();
}
function confirmDialog(title: string, action: () => Promise<unknown>, life = routeLife) { editDialog(title, [], action, life); }
const textField = (name: string, label: string, value = '', required = true): Field => ({ name, label, value, required });
const enabledField = (enabled: boolean): Field => ({ name: 'enabled', label: '启用', type: 'checkbox', value: String(enabled) });
const credentialFields: Field[] = [{ name: 'credential_type', label: '凭据类型（只写；不会读取已有值）', options: ['password', 'private_key'] }, { name: 'password', label: '目标密码（password 时必填）', type: 'password', required: false }, { name: 'key_pem', label: '私钥 PEM（private_key 时必填）', type: 'textarea', required: false }, { name: 'passphrase', label: '私钥口令（可选）', type: 'password', required: false }];
function credential(values: Record<string, string>): Credential { if (values.credential_type === 'private_key') { if (!values.key_pem) throw new Error('需要私钥 PEM。'); return { type: 'private_key', key_pem: values.key_pem, passphrase: values.passphrase || null }; } if (!values.password) throw new Error('需要目标密码。'); return { type: 'password', password: values.password }; }
function clearCredential(value: Credential) { if (value.type === 'password') value.password = ''; else { value.key_pem = ''; value.passphrase = null; } }
function capabilities(value: string): Capability[] { const caps = value.split(',').map(cap => cap.trim()); if (!caps.length || caps.some(cap => !['shell', 'exec', 'sftp'].includes(cap))) throw new Error('能力必须为 shell, exec, sftp 的逗号分隔非空集合。'); return [...new Set(caps)] as Capability[]; }
function expiry(value: string) { if (!value) return null; const date = new Date(value); if (!Number.isFinite(date.valueOf()) || date.valueOf() <= Date.now()) throw new Error('到期时间必须在未来。'); return date.toISOString(); }
function dataPanel(parent: HTMLElement, value: unknown) { parent.append(node('pre', JSON.stringify(value, null, 2))); }
function table<T>(parent: HTMLElement, items: T[], columns: { label: string; value: (item: T) => unknown }[], actions?: (item: T, container: HTMLElement) => void) {
  const scroll = node('div', '', 'table-scroll'), table = node('table'), head = node('thead'), header = node('tr'); for (const column of columns) header.append(node('th', column.label)); if (actions) header.append(node('th', '操作')); head.append(header); table.append(head);
  const body = node('tbody'); for (const item of items) { const row = node('tr'); for (const column of columns) { const value = column.value(item); row.append(node('td', typeof value === 'string' ? value : JSON.stringify(value) ?? '—')); } if (actions) { const cell = node('td'), toolbar = node('div', '', 'toolbar'); actions(item, toolbar); cell.append(toolbar); row.append(cell); } body.append(row); } table.append(body); scroll.append(table); parent.append(scroll);
}
function paged<T>(parent: HTMLElement, life: RouteLifetime, load: (query: Query) => Promise<Page<T>>, render: (items: T[], output: HTMLElement) => void, initial: Query = {}) {
  const controls = node('div', '', 'toolbar'), output = node('div'), state = node('p', '正在读取…', 'muted'); parent.append(controls, state, output);
  let busy = false, next: string | null = null, items: T[] = [], filters = initial, serial = 0;
  const reload = button('刷新列表', () => { void read(false); }, controls), more = button('加载更多', () => { void read(true); }, controls); more.hidden = true;
  async function read(append: boolean) {
    if (busy || life.signal.aborted) return; const request = ++serial; busy = true; reload.disabled = more.disabled = true; state.textContent = '正在读取服务端数据…';
    try { const page = await load({ ...filters, ...(append && next ? { cursor: next } : {}) }); if (life.signal.aborted || request !== serial) return; if (!Array.isArray(page?.items) || !(page.next_cursor === null || typeof page.next_cursor === 'string')) throw new ApiError('INVALID_RESPONSE', '分页响应不完整。'); items = append ? [...items, ...page.items] : page.items; next = page.next_cursor; output.replaceChildren(); state.textContent = items.length ? `${items.length} 条已加载。` : '没有符合条件的数据。'; render(items, output); more.hidden = !next; }
    catch (error) { if (!life.signal.aborted) { state.textContent = stateMessage(error); showError(error); } }
    finally { if (request === serial) { busy = false; reload.disabled = more.disabled = false; } }
  }
  void read(false); return { reload: () => read(false), filter: (query: Query) => { filters = query; next = null; items = []; serial++; busy = false; return read(false); } };
}
function mountUsers(life: RouteLifetime) {
  const actions = node('div', '', 'toolbar'); view.append(actions); let refresh: () => Promise<void>;
  button('创建用户', () => editDialog('创建用户', [textField('username', '用户名'), { name: 'password', label: '初始密码（至少 12 字节）', type: 'password' }, { name: 'role', label: '角色', options: ['operator', 'auditor', 'admin'] }], async values => { await api.createUser({ username: values.username, password: values.password, role: values.role as Role }, life.signal); await refresh(); }, life), actions);
  refresh = paged(view, life, query => api.users(query, life.signal), (items, output) => table(output, items, [{ label: '用户名', value: item => item.username }, { label: 'ID / 修订', value: item => `${item.id} / ${item.revision}` }, { label: '角色 / 启用', value: item => `${item.role} / ${item.enabled}` }], (item, toolbar) => {
    button('编辑', () => editDialog(`用户 ${item.username} · revision ${item.revision}`, [{ name: 'role', label: '角色', options: ['operator', 'auditor', 'admin'], value: item.role }, enabledField(item.enabled)], async values => { await api.updateUser(item.id, item.revision, { role: values.role as Role, enabled: values.enabled === 'true' }, life.signal); await refresh(); }, life), toolbar);
    button('重置密码', () => editDialog('重置密码：现有登录会话将撤销', [{ name: 'password', label: '新密码', type: 'password' }], async values => { await api.resetPassword(item.id, item.revision, values.password, life.signal); await refresh(); }, life), toolbar);
  })).reload;
}
function mountAdminAssets(life: RouteLifetime) {
  const actions = node('div', '', 'toolbar'); view.append(actions); let refresh: () => Promise<void>;
  const assetFields = (asset?: AdminAsset): Field[] => [textField('name', '资产名称', asset?.name), textField('host', '目标 Host（仅管理员配置，不用于浏览器直接连接）', asset?.host), { name: 'port', label: 'SSH 端口', type: 'number', value: String(asset?.port ?? 22), min: 1, max: 65535 }, textField('tags', '标签（逗号分隔）', asset?.tags.join(', '), false)];
  const assetBody = (values: Record<string, string>) => ({ name: values.name, host: values.host, port: Number(values.port), tags: values.tags.split(',').map(value => value.trim()).filter(Boolean) });
  button('创建资产', () => editDialog('创建资产', assetFields(), async values => { await api.createAsset(assetBody(values), life.signal); await refresh(); }, life), actions);
  refresh = paged(view, life, query => api.adminAssets(query, life.signal), (items, output) => table(output, items, [{ label: '资产', value: item => `${item.name} (${item.id})` }, { label: 'Host / 端口', value: item => `${item.host}:${item.port}` }, { label: '标签 / 启用 / 修订', value: item => `${item.tags.join(', ')} / ${item.enabled} / ${item.revision}` }], (item, toolbar) => {
    toolbar.append(link('账号 / 主机密钥', `#/admin-assets/${encodeURIComponent(item.id)}`));
    button('编辑', () => editDialog(`资产修订 ${item.revision}`, [...assetFields(item), enabledField(item.enabled)], async values => { await api.updateAsset(item.id, item.revision, { ...assetBody(values), enabled: values.enabled === 'true' }, life.signal); await refresh(); }, life), toolbar);
  })).reload;
  if (route.id) mountAssetDetails(route.id, life);
}
function mountAssetDetails(id: string, life: RouteLifetime) {
  const panel = node('section', '', 'card'); panel.append(node('h2', `资产 ${id} · 账号与主机密钥`)); view.append(panel);
  const accounts = node('section'), keys = node('section'); panel.append(accounts, keys); accounts.append(node('h3', '目标账号（凭据只写）')); let reloadAccounts: () => Promise<void>;
  button('创建目标账号', () => editDialog('创建目标账号及凭据', [textField('username', '目标用户名'), ...credentialFields], async values => { const secret = credential(values); try { await api.createAccount(id, values.username, secret, life.signal); } finally { clearCredential(secret); } await reloadAccounts(); }, life), accounts);
  reloadAccounts = paged(accounts, life, query => api.accounts(id, query, life.signal), (items, output) => table(output, items, [{ label: '账号 / ID', value: item => `${item.username} (${item.id})` }, { label: '凭据元数据', value: item => `${item.credential_kind} · credential_revision ${item.credential_revision}` }, { label: '启用 / 修订', value: item => `${item.enabled} / ${item.revision}` }], (item, toolbar) => {
    button('编辑', () => editDialog('编辑目标账号', [textField('username', '目标用户名', item.username), enabledField(item.enabled)], async values => { await api.updateAccount(item.id, item.revision, { username: values.username, enabled: values.enabled === 'true' }, life.signal); await reloadAccounts(); }, life), toolbar);
    button('替换凭据', () => editDialog(`替换凭据 · account revision ${item.revision}`, credentialFields, async values => { const secret = credential(values); try { await api.replaceCredential(item.id, item.revision, secret, life.signal); } finally { clearCredential(secret); } await reloadAccounts(); }, life), toolbar);
    button('测试认证', () => confirmDialog('由网关测试目标认证；不会批准未知主机密钥', async () => { const result = await api.testAccount(item.id, life.signal); if (!result?.authenticated) throw new ApiError('INVALID_RESPONSE', '服务端未确认认证。'); statusText('服务端确认目标认证成功；不代表所有功能或发布验收通过。'); }, life), toolbar);
  })).reload;
  keys.append(node('h3', '主机密钥（扫描不是信任审批）')); let reloadKeys: () => Promise<void>;
  button('扫描主机密钥', () => confirmDialog('扫描目标主机密钥；需独立核对指纹后审批', async () => { const result = await api.scanHostKey(id, life.signal); await reloadKeys(); if (!life.signal.aborted) dataPanel(keys, result); }, life), keys);
  button('导入并批准', () => editDialog('导入已通过独立渠道核验的主机密钥', [textField('algorithm', '算法，例如 ssh-ed25519'), { name: 'public_key', label: 'OpenSSH 公钥（请独立核验指纹）', type: 'textarea' }], async values => { await api.approveHostKey(id, values.algorithm, values.public_key, life.signal); await reloadKeys(); }, life), keys);
  reloadKeys = paged(keys, life, query => api.hostKeys(id, query, life.signal), (items, output) => table(output, items, [{ label: '指纹 / 算法', value: item => `${item.fingerprint} / ${item.algorithm}` }, { label: '状态 / 修订', value: item => `${item.state} / ${item.revision}` }, { label: '公钥', value: item => item.public_key }], (item, toolbar) => {
    if (item.state !== 'approved') button('核验后批准', () => confirmDialog(`已独立核验此指纹？ ${item.fingerprint}`, async () => { await api.approveHostKey(id, item.algorithm, item.public_key, life.signal); await reloadKeys(); }, life), toolbar);
    button('撤销', () => confirmDialog(`撤销主机密钥 ${item.fingerprint} · revision ${item.revision}`, async () => { await api.revokeHostKey(id, item.id, item.revision, life.signal); await reloadKeys(); }, life), toolbar);
  })).reload;
}
function mountGrants(life: RouteLifetime) {
  view.append(node('p', '授权绑定具体用户、资产和目标账号。purpose 只用于审计，不替代能力授权。', 'muted')); let refresh: () => Promise<void>;
  const fields: Field[] = [textField('user_id', '用户 ID'), textField('asset_id', '资产 ID'), textField('account_id', '该资产的目标账号 ID'), textField('capabilities', '能力（逗号分隔 shell,exec,sftp）', 'shell'), { name: 'expires_at', label: '到期时间（空表示不设到期）', type: 'datetime-local', required: false }];
  button('创建授权', () => editDialog('创建 Grant', fields, async values => { await api.createGrant({ user_id: values.user_id, asset_id: values.asset_id, account_id: values.account_id, capabilities: capabilities(values.capabilities), expires_at: expiry(values.expires_at) }, life.signal); await refresh(); }, life), view);
  refresh = paged(view, life, query => api.grants(query, life.signal), (items, output) => table(output, items, [{ label: '用户 / 资产 / 账号', value: item => `${item.user_id} / ${item.asset_id} / ${item.account_id}` }, { label: '能力 / 到期', value: item => `${item.capabilities.join(', ')} / ${item.expires_at ?? '无到期'}` }, { label: '启用 / 修订', value: item => `${item.enabled} / ${item.revision}` }], (item, toolbar) => {
    button('编辑', () => editDialog(`编辑 Grant ${item.id}`, [textField('capabilities', '能力', item.capabilities.join(',')), enabledField(item.enabled), { name: 'expires_at', label: '到期（空表示清除）', type: 'datetime-local', required: false, value: item.expires_at ? new Date(new Date(item.expires_at).valueOf() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '' }], async values => { await api.updateGrant(item.id, item.revision, { capabilities: capabilities(values.capabilities), enabled: values.enabled === 'true', expires_at: expiry(values.expires_at) }, life.signal); await refresh(); }, life), toolbar);
    button('撤销', () => confirmDialog(`撤销 Grant ${item.id} · revision ${item.revision}`, async () => { await api.revokeGrant(item.id, item.revision, life.signal); await refresh(); }, life), toolbar);
  })).reload;
}
function mountProfile(life: RouteLifetime) {
  view.append(node('p', `用户: ${me!.user.username} · 当前设备登录: ${me!.login_session_id}`));
  button('修改本人密码', () => editDialog('修改密码：现有登录会话将失效', [{ name: 'current_password', label: '当前密码', type: 'password' }, { name: 'new_password', label: '新密码', type: 'password' }], async values => { await api.changePassword(values.current_password, values.new_password, life.signal); clearMemory(); statusText('密码已修改；请重新登录。'); }, life), view);
  button('注销所有设备', () => confirmDialog('注销本人所有设备登录', async () => { await api.logout(true, life.signal); clearMemory(); statusText('所有设备已注销。'); }, life), view);
  if (!info?.features?.device_sessions) { view.append(node('p', '服务端未提供设备会话管理能力。', 'muted')); return; }
  let refresh: () => Promise<void>;
  refresh = paged(view, life, () => api.devices(life.signal), (items, output) => table(output, items, [{ label: '设备', value: item => `${item.device_label} ${item.current ? '（当前）' : ''}` }, { label: '创建 / 到期 / 撤销', value: item => `${item.created_at} / ${item.expires_at ?? '未知'} / ${item.revoked_at ?? '未撤销'}` }, { label: '会话 ID', value: item => item.id }], (item, toolbar) => {
    button('撤销设备', () => confirmDialog(`撤销设备 ${item.device_label}${item.current ? '（当前登录将结束）' : ''}`, async () => { await api.revokeDevice(item.id, life.signal); if (item.current) { clearMemory(); statusText('当前设备已撤销。'); } else await refresh(); }, life), toolbar);
  })).reload;
}
function mountActivity(kind: 'connections' | 'audit', life: RouteLifetime) {
  const filters = node('form', '', 'filters'); view.append(filters); const fields = kind === 'connections' ? ['from', 'to', 'actor_id', 'resource_id', 'state', 'transport'] : ['from', 'to', 'actor_id', 'resource_id', 'resource_type', 'action'];
  for (const field of fields) { const label = node('label', field), input = node('input'); input.name = field; if (field === 'from' || field === 'to') input.type = 'datetime-local'; label.append(input); filters.append(label); }
  const apply = node('button', '查询服务端'); apply.type = 'submit'; filters.append(apply);
  const page = kind === 'connections' ? paged(view, life, query => api.connections(query, life.signal), (items, output) => table(output, items, [{ label: '连接 / 目标', value: item => `${item.id} / ${item.asset_id} / ${item.account_id}` }, { label: '状态 / 传输 / 时间', value: item => `${item.state} / ${item.transport ?? '未提供'} / ${item.created_at}` }, { label: '能力 / 失败', value: item => `${item.capabilities.join(',')} / ${item.failure?.code ?? '无'}` }], (item, toolbar) => {
    button('详情 / 通道', () => { void routeAction(life, async () => { const [detail, channels] = await Promise.all([api.connection(item.id, life.signal), api.channels(item.id, life.signal)]); if (!life.signal.aborted) { const panel = node('section', '', 'card'); panel.append(node('h2', `连接 ${item.id}`)); dataPanel(panel, { connection: detail, channels }); output.append(panel); } }); }, toolbar);
    if (!['closed', 'failed', 'expired', 'revoked', 'interrupted'].includes(item.state)) button('断开', () => confirmDialog(`断开连接 ${item.id}`, async () => { await api.disconnect(item.id, life.signal); await page.reload(); }, life), toolbar);
    if (info?.features?.recording_replay) toolbar.append(link('查录制', `#/recordings/${encodeURIComponent(item.id)}`));
  })) : paged(view, life, query => api.audit(query, life.signal), (items, output) => { for (const item of items) { const panel = node('section', '', 'card'); dataPanel(panel, item); output.append(panel); } });
  filters.onsubmit = event => { event.preventDefault(); const query: Query = {}; const values = new FormData(filters); for (const field of fields) { const value = String(values.get(field) ?? ''); if (value) query[field] = ['from', 'to'].includes(field) ? new Date(value).toISOString() : value; } void page.filter(query); };
}
function renderRoute() {
  routeLife.dispose(); routeLife = new RouteLifetime(); targetUpdate = () => {}; view.replaceChildren(); clearError();
  route = parseRoute(location.hash); renderNavigation(); if (!me) return;
  const label = routes.find(item => item.name === route.name)?.label ?? '页面不存在'; element('assets-heading').textContent = label;
  element('target-bar').hidden = !['assets', 'terminal', 'files', 'exec'].includes(route.name);
  if (!allowedRoute(route.name, me.user.role, info)) { view.append(node('p', route.name === 'not-found' ? '页面不存在。请选择导航中的可用页面。' : '禁止访问或能力不可用：当前角色没有权限，或服务端没有装配此功能。', 'error')); return; }
  const life = routeLife;
  if (route.name === 'assets') {
    if (!assets.length) view.append(node('p', '没有已授权资产。请联系管理员；不会显示未授权目标。', 'muted'));
    const grid = node('div', '', 'grid'); for (const asset of assets) { const card = node('article', '', 'card'); card.append(node('h2', asset.name), node('p', asset.id, 'muted'), node('p', asset.tags?.join(', ') ?? '')); for (const account of asset.accounts) { const row = node('div'); row.append(node('p', `${account.username} · ${account.capabilities.join(', ')}`)); for (const [capability, name, label] of [['shell', 'terminal', '终端'], ['exec', 'exec', '执行'], ['sftp', 'files', '文件']] as const) if (account.capabilities.includes(capability) && allowedRoute(name, me.user.role, info)) button(label, () => { assetSelect.value = asset.id; renderAccounts(); accountSelect.value = account.id; renderAccounts(); location.hash = `#/${name}`; }, row); card.append(row); } grid.append(card); } view.append(grid);
  } else if (route.name === 'terminal') targetUpdate = mountTerminal(view, api, life, getTarget, statusText, showError);
  else if (route.name === 'exec') targetUpdate = mountExec(view, api, life, getTarget, statusText, showError);
  else if (route.name === 'files') targetUpdate = mountFiles(view, api, life, getTarget, statusText, showError, info!);
  else if (route.name === 'recordings') mountReplay(view, api, life, statusText, showError, route.id);
  else if (route.name === 'users') mountUsers(life);
  else if (route.name === 'admin-assets') mountAdminAssets(life);
  else if (route.name === 'grants') mountGrants(life);
  else if (route.name === 'profile') mountProfile(life);
  else if (route.name === 'connections' || route.name === 'audit') mountActivity(route.name, life);
  element('assets-heading').focus({ preventScroll: true });
}
assetSelect.onchange = renderAccounts; accountSelect.onchange = renderAccounts;
element<HTMLButtonElement>('reload').onclick = () => { void authAction(() => loadAssets(false)); };
element<HTMLButtonElement>('more').onclick = () => { void authAction(() => loadAssets(true)); };
element<HTMLFormElement>('login-form').onsubmit = event => {
  event.preventDefault(); void authAction(async () => {
    await api.loadCsrf(auth.signal); const password = element<HTMLInputElement>('password'); const credentials = { username: element<HTMLInputElement>('username').value, password: password.value, device_label: element<HTMLInputElement>('device').value.trim() || 'Web 浏览器', client_type: 'web' as const }; password.value = '';
    try { await api.login(credentials, auth.signal); } finally { credentials.password = ''; }
    refreshUsed = false; setWorkspace(await api.loadMe(auth.signal)); if (me?.user.role !== 'auditor') await loadAssets(); statusText('登录成功。');
  });
};
element<HTMLButtonElement>('logout').onclick = () => { void authAction(async () => { routeLife.dispose(); try { await api.logout(false, auth.signal); statusText('已注销。'); } finally { clearMemory(); } }); };
element<HTMLButtonElement>('refresh').onclick = () => { void authAction(async () => {
  if (refreshUsed) return; if (!navigator.locks) throw new Error('浏览器不能协调多标签页刷新；请注销并重新登录。');
  await navigator.locks.request('bastion-auth-refresh', { ifAvailable: true }, async lock => { if (!lock) throw new Error('另一标签页正在刷新；不会并发重放。'); refreshUsed = true;
    try { await api.refresh(auth.signal); setWorkspace(await api.loadMe(auth.signal)); statusText('本次登录已主动刷新一次。'); } catch (error) { clearMemory(); throw error; }
  });
}); };
window.addEventListener('hashchange', renderRoute);
window.addEventListener('pagehide', clearMemory);
window.addEventListener('pageshow', event => { if (event.persisted) void initialize(); });
async function initialize() {
  await authAction(async () => {
    statusText('正在读取服务端状态与登录身份…');
    info = await api.info(auth.signal);
    if (info.protocol_version !== 1 || info.minimum_client_protocol_version > 1 || info.websocket_protocol_version !== undefined && info.websocket_protocol_version !== 1) throw new ApiError('CLIENT_PROTOCOL_UNSUPPORTED', '服务端协议版本不兼容。');
    element('discovery').textContent = `server_id: ${info.server_id ?? '未提供'} · protocol v${info.protocol_version} · production_ready: ${info.production_ready} · required recording: ${info.recording?.required ?? '未提供'} · recording available: ${info.recording?.available ?? '未提供'}`;
    const warning = discoveryWarning(info); element('development-warning').textContent = warning; element('development-warning').hidden = !warning;
    await api.loadCsrf(auth.signal);
    try { setWorkspace(await api.loadMe(auth.signal)); } catch (error) { if (error instanceof ApiError && error.status === 401) { element('login-panel').hidden = false; element('username').focus(); statusText('请登录。'); return; } throw error; }
    if (me?.user.role !== 'auditor') await loadAssets();
  });
  if (!me) element('login-panel').hidden = false;
}
void initialize();
