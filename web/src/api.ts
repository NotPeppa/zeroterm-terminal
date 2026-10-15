import { requireHTTPS, DEFAULT_DISPLAY, validateDisplay, type DisplaySize } from './protocol.ts';

export type TargetProtocol = 'ssh' | 'rdp' | 'vnc';
export type Role = 'admin' | 'operator' | 'auditor';
export type User = { id: string; username: string; role: Role; enabled: boolean; revision: number };
export type Me = { user: User; login_session_id: string; policy_revision: number; csrf_token: string; access_expires_at?: string | null };
export type Account = { id: string; label: string; username: string | null; domain: string | null; credential_kind: 'none' | 'password' | 'private_key' };
export type Asset = { id: string; name: string; protocol: TargetProtocol; tags?: string[]; group_id: string | null; group_name: string | null; accounts: Account[] };
export type AssetGroup = { id: string; name: string; revision: number; parent_id: string | null; sort_order: number };
export type Page<T> = { items: T[]; next_cursor: string | null; policy_revision?: number };
/** Client-facing asset page also carries the visible group forest, for the ZeroTerm-style tree. */
export type AssetPage = Page<Asset> & { policy_revision: number; groups?: AssetGroup[] };
export type Ticket = { session_id: string; ws_token: string; connection_id: string; expires_at: string; target_protocol: TargetProtocol; stream_protocol: 'bastion.guac.v1' | 'bastion.ssh.v1' };
export type Info = { server_id?: string; schema_version: 2; protocol_version: 2; stream_protocol: 'bastion.guac.v1'; production_ready: false; features: Record<'web_ssh' | 'web_rdp' | 'web_vnc' | 'recording_replay' | 'device_sessions', boolean>; recording: { required: boolean; available: boolean; format_version: 2 }; password_min_length?: number };
export type AdminAsset = { id: string; name: string; host: string; port: number; protocol: TargetProtocol; security: 'nla' | 'tls' | null; ssh_host_key: string | null; rdp_certificate_sha256: string | null; tags: string[]; group_id: string | null; enabled: boolean; revision: number };
export type AdminAccount = Account & { asset_id: string; enabled: boolean; revision: number; credential_revision: number | null };
export type RdpCertificateScan = { asset_id: string; host: string; port: number; revision: number; approved_sha256: string | null; approved_security: 'nla' | 'tls' | null; sha256: string; selected_protocol: 'tls' | 'nla' | 'nla-ex'; security: 'nla' | 'tls' };
export type SshHostKeyScan = { asset_id: string; host: string; port: number; revision: number; approved_fingerprint: string | null; keys: { public_key: string; fingerprint: string; algorithm: string }[] };
export type Credential = { type: 'none' } | { type: 'password'; password: string } | { type: 'private_key'; key_pem: string; passphrase: string | null };
export type AccountInput = { label: string; username: string | null; domain: string | null; credential: Credential };
export type Grant = { id: string; user_id: string; asset_id: string; account_id: string; enabled: boolean; expires_at: string | null; revision: number; username?: string; asset_name?: string; account_label?: string };
export type Connection = { id: string; ticket_id: string; asset_id: string; account_id: string; state: string; target_protocol: TargetProtocol; display: DisplaySize; protocol_version: 2; created_at: string; failure: { code: string; message?: string; request_id?: string } | null; user_id: string | null; login_session_id: string | null };
export type Audit = Record<string, unknown> & { id: string };
export type DeviceSession = { id: string; device_label: string; current: boolean; created_at: string; expires_at?: string; revoked_at?: string | null };
export type Recording = { id: string; state?: string; status?: string; format_version?: number; connection_id?: string; [key: string]: unknown };
export type Query = Record<string, string | number | undefined>;
export function queryString(query: Query = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== '') params.set(key, String(value));
  return params.size ? `?${params}` : '';
}
export class ApiError extends Error {
  code: string; requestId: string; status: number;
  constructor(code: string, message: string, requestId = '', status = 0) { super(message); this.name = 'ApiError'; this.code = code; this.requestId = requestId; this.status = status; }
}
export function validateInfo(info: Info): Info {
  if (!info || info.schema_version !== 2 || info.protocol_version !== 2 || info.stream_protocol !== 'bastion.guac.v1' || info.production_ready !== false || info.recording?.format_version !== 2 || typeof info.recording.required !== 'boolean' || typeof info.recording.available !== 'boolean' || !['web_ssh', 'web_rdp', 'web_vnc', 'recording_replay', 'device_sessions'].every(key => typeof info.features?.[key as keyof Info['features']] === 'boolean')) throw new ApiError('CLIENT_PROTOCOL_UNSUPPORTED', '需要完整的 Guacamole v2 能力发现；当前版本不能宣称生产验收。');
  return info;
}
export type RequestOptions = { method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'; body?: unknown; revision?: number; signal?: AbortSignal; stream?: boolean };
/** Latest access-token expiry any tab has learned from the server, so tabs adopt each other's rotations. */
const EXPIRES_AT = 'bastion.access.expires_at';
/** Renew this long before the server deadline; covers timer throttling and modest clock skew. */
const REFRESH_LEAD = 120_000;
/** Never re-arm faster than this, even if the client clock runs far ahead of the server. */
const REFRESH_MIN_DELAY = 60_000;
export class ApiClient {
  private csrf = '';
  private transport: typeof fetch;
  private origin: string;
  private development: boolean;
  /** Server-issued access-token expiry this page last learned (ms epoch); 0 when signed out. */
  private expiresAt = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private refreshing: Promise<void> | null = null;
  constructor(transport: typeof fetch = fetch, origin = location.origin, development = import.meta.env?.DEV === true) { this.transport = transport.bind(globalThis); this.origin = origin; this.development = development; }
  clearAuth() { this.csrf = ''; this.expiresAt = 0; clearTimeout(this.timer); }
  /**
   * Record a server-issued access deadline and arm the silent refresh ahead of it. Timer refreshes
   * swallow their errors: a real failure (family expired or revoked) resurfaces on the next request
   * as a 401 the UI already handles, and a live console is policed server-side regardless.
   */
  private learn(at: string | null | undefined) {
    const value = Date.parse(at ?? '');
    if (!Number.isFinite(value)) return;
    this.expiresAt = value;
    try { if (value > (Date.parse(localStorage.getItem(EXPIRES_AT) ?? '') || 0)) localStorage.setItem(EXPIRES_AT, at!); } catch { /* Private mode: this page still refreshes itself. */ }
    clearTimeout(this.timer);
    this.timer = setTimeout(() => { void this.reauthenticate().catch(() => {}); }, Math.max(REFRESH_MIN_DELAY, value - REFRESH_LEAD - Date.now()));
  }
  /**
   * Renew the token pair once, for the timer or after an expired access token.
   *
   * Refresh tokens are single-use and the store reads a replay as theft and revokes the whole login
   * family, so two tabs must never present the same one. The Web Lock serialises rotation across
   * tabs; inside it, a tab first checks whether another tab already rotated past what it knows (the
   * EXPIRES_AT stamp) and adopts that pair from the shared cookie jar instead of rotating again.
   * Without `navigator.locks` there is no safe way to coordinate, so the expiry surfaces as-is.
   * The CSRF cookie is not rotated by refresh, so the token already held keeps working.
   */
  private async reauthenticate(): Promise<void> {
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.rotate().finally(() => { this.refreshing = null; });
    return this.refreshing;
  }
  private async rotate(): Promise<void> {
    if (typeof navigator === 'undefined' || !navigator.locks) throw new ApiError('SESSION_EXPIRED', '浏览器不能协调多标签页刷新；请重新登录。', '', 401);
    const seen = this.expiresAt;
    await navigator.locks.request('bastion-auth-refresh', async () => {
      let shared: string | null = null;
      try { shared = localStorage.getItem(EXPIRES_AT); } catch { /* Fall through and rotate. */ }
      if (shared && Date.parse(shared) > seen) { this.learn(shared); return; }
      const result = await this.json<{ access_expires_at?: string }>('/api/v1/auth/refresh', { method: 'POST', body: {} });
      this.learn(result?.access_expires_at);
    });
  }
  async response(path: string, options: RequestOptions = {}): Promise<Response> {
    // Access tokens last 10 minutes but the login family lasts 7 days, so an expired access token is
    // ordinary: renew it and replay the call once. Replaying writes is safe here because only the
    // `authenticate` middleware emits SESSION_EXPIRED, before any handler runs.
    try { return await this.fetch(path, options); }
    catch (error) {
      if (!(error instanceof ApiError) || error.code !== 'SESSION_EXPIRED') throw error;
      await this.reauthenticate();
      return this.fetch(path, options);
    }
  }
  private async fetch(path: string, options: RequestOptions = {}): Promise<Response> {
    const base = new URL(this.origin); requireHTTPS(base.protocol, this.development);
    if (base.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)) throw new ApiError('HTTPS_REQUIRED', 'HTTP 仅允许明确开发的 loopback。');
    const url = new URL(path, base);
    if (!path.startsWith('/api/v1/') || url.origin !== base.origin || url.hash) throw new ApiError('INVALID_API_PATH', '只允许同源 API。');
    const method = options.method ?? 'GET', mutation = method !== 'GET';
    const headers = new Headers({ Accept: options.stream ? '*/*' : 'application/json' });
    if (mutation) {
      if (!this.csrf) throw new ApiError('CSRF_UNAVAILABLE', '请重新读取登录状态。');
      headers.set('X-Bastion-CSRF', this.csrf);
      // Origin is a forbidden browser header: fetch supplies the actual same-origin Origin on mutations.
    }
    if (options.revision !== undefined) {
      if (!Number.isSafeInteger(options.revision) || options.revision <= 0) throw new ApiError('INVALID_REVISION', '修订号必须为正整数。');
      headers.set('If-Match', `"${options.revision}"`);
    }
    if (options.body !== undefined) headers.set('Content-Type', 'application/json');
    let response: Response;
    try {
      response = await this.transport(url.href, { method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body), credentials: 'include', mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: options.stream ? options.signal : options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000) });
    } catch (error) {
      if (options.signal?.aborted && !mutation) throw error;
      throw new ApiError(mutation ? 'RESULT_UNKNOWN' : 'NETWORK_OR_TIMEOUT', mutation ? '请求中断；结果未知。请读取服务端状态，不会自动重试或重放。' : '读取失败或超时。');
    }
    if (!response.ok) {
      const requestId = response.headers.get('X-Request-Id') ?? '';
      let result: { error?: { code?: string; message?: string; request_id?: string } } = {};
      try { result = await response.json(); } catch { /* Keep HTTP status for non-JSON failures. */ }
      throw new ApiError(result.error?.code ?? `HTTP_${response.status}`, result.error?.message ?? '请求被拒绝。', result.error?.request_id ?? requestId, response.status);
    }
    return response;
  }
  async json<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const response = await this.response(path, options);
    if ([202, 204, 205].includes(response.status) && !response.headers.get('Content-Type')?.includes('json')) return undefined as T;
    try { return await response.json() as T; }
    catch { throw new ApiError(options.method && options.method !== 'GET' ? 'RESULT_UNKNOWN' : 'INVALID_RESPONSE', '无法读取 JSON 响应；请重新读取服务端状态。', response.headers.get('X-Request-Id') ?? '', response.status); }
  }
  async loadCsrf(signal?: AbortSignal) { const result = await this.json<{ csrf_token: string }>('/api/v1/auth/csrf', { signal }); if (!result?.csrf_token) throw new ApiError('INVALID_RESPONSE', '缺少 CSRF token。'); this.csrf = result.csrf_token; }
  async loadMe(signal?: AbortSignal) { const result = await this.json<Me>('/api/v1/me', { signal }); if (!result?.user || typeof result.user.username !== 'string' || !result.login_session_id || !Number.isSafeInteger(result.policy_revision) || !result.csrf_token) throw new ApiError('INVALID_RESPONSE', '身份响应不完整。'); this.csrf = result.csrf_token; this.learn(result.access_expires_at); return result; }
  async info(signal?: AbortSignal) { return validateInfo(await this.json<Info>('/api/v1/info', { signal })); }
  login(body: { username: string; password: string; device_label: string }, signal?: AbortSignal) { return this.json('/api/v1/auth/login', { method: 'POST', body, signal }); }
  logout(all = false, signal?: AbortSignal) { return this.json<void>(`/api/v1/auth/${all ? 'logout-all' : 'logout'}`, { method: 'POST', body: {}, signal }); }
  /** Renew now instead of waiting for the next 401. Coordinated with every other tab; never replays a spent refresh token. */
  refresh() { return this.reauthenticate(); }
  changePassword(current_password: string, new_password: string, signal?: AbortSignal) { return this.json<void>('/api/v1/me/password', { method: 'POST', body: { current_password, new_password }, signal }); }
  async assets(query?: Query, signal?: AbortSignal) { return validateAssets(await this.json<AssetPage>(`/api/v1/assets${queryString(query)}`, { signal })); }
  async asset(id: string, signal?: AbortSignal) { const asset = await this.json<Asset>(`/api/v1/assets/${encodeURIComponent(id)}`, { signal }); const value = validateAssets({ items: [asset], next_cursor: null, policy_revision: 1 }).items[0]; if (value.id !== id) throw new ApiError('INVALID_RESPONSE', '目标资产响应不匹配。'); return value; }
  async session(asset_id: string, account_id: string, display: DisplaySize = DEFAULT_DISPLAY, signal?: AbortSignal) { validateDisplay(display); return validateTicket(await this.json<Ticket>('/api/v1/sessions', { method: 'POST', body: { asset_id, account_id, display }, signal })); }
  connection(id: string, signal?: AbortSignal) { return this.json<Connection>(`/api/v1/connections/${encodeURIComponent(id)}`, { signal }); }
  connections(query?: Query, signal?: AbortSignal) { return this.json<Page<Connection>>(`/api/v1/connections${queryString(query)}`, { signal }); }
  disconnect(id: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/connections/${encodeURIComponent(id)}/disconnect`, { method: 'POST', body: {}, signal }); }
  audit(query?: Query, signal?: AbortSignal) { return this.json<Page<Audit>>(`/api/v1/audit-events${queryString(query)}`, { signal }); }
  devices(signal?: AbortSignal) { return this.json<Page<DeviceSession>>('/api/v1/me/sessions', { signal }); }
  revokeDevice(id: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/me/sessions/${encodeURIComponent(id)}`, { method: 'DELETE', signal }); }
  recordings(query?: Query, signal?: AbortSignal) { return this.json<Page<Recording>>(`/api/v1/recordings${queryString(query)}`, { signal }); }
  recording(id: string, signal?: AbortSignal) { return this.json<Recording>(`/api/v1/recordings/${encodeURIComponent(id)}`, { signal }); }
  recordingContent(id: string, signal?: AbortSignal) { return this.response(`/api/v1/recordings/${encodeURIComponent(id)}/content`, { signal, stream: true }); }
  users(query?: Query, signal?: AbortSignal) { return this.json<Page<User>>(`/api/v1/admin/users${queryString(query)}`, { signal }); }
  createUser(body: { username: string; password: string; role: Role }, signal?: AbortSignal) { return this.json<User>('/api/v1/admin/users', { method: 'POST', body, signal }); }
  updateUser(id: string, revision: number, body: { role?: Role; enabled?: boolean }, signal?: AbortSignal) { return this.json<User>(`/api/v1/admin/users/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  deleteUser(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/users/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
  resetPassword(id: string, revision: number, password: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/reset-password`, { method: 'POST', revision, body: { password }, signal }); }
  adminAsset(id: string, signal?: AbortSignal) { return this.json<AdminAsset>(`/api/v1/admin/assets/${encodeURIComponent(id)}`, { signal }); }
  /** Discovery only: nothing is stored and no credential is sent; the admin confirms pin and security with PATCH. */
  scanRdpCertificate(id: string, revision: number, signal?: AbortSignal) { return this.json<RdpCertificateScan>(`/api/v1/admin/assets/${encodeURIComponent(id)}/rdp-certificate/scan`, { method: 'POST', revision, signal }); }
  scanSshHostKey(id: string, revision: number, signal?: AbortSignal) { return this.json<SshHostKeyScan>(`/api/v1/admin/assets/${encodeURIComponent(id)}/ssh-host-key/scan`, { method: 'POST', revision, signal }); }
  adminAssets(query?: Query, signal?: AbortSignal) { return this.json<Page<AdminAsset>>(`/api/v1/admin/assets${queryString(query)}`, { signal }); }
  assetGroups(query?: Query, signal?: AbortSignal) { return this.json<Page<AssetGroup>>(`/api/v1/admin/asset-groups${queryString(query)}`, { signal }); }
  createAssetGroup(body: { name: string; parent_id?: string | null; sort_order?: number }, signal?: AbortSignal) { return this.json<AssetGroup>('/api/v1/admin/asset-groups', { method: 'POST', body, signal }); }
  /** Rename and/or move in one call; `parent_id: null` promotes the group to a root. */
  patchAssetGroup(id: string, revision: number, body: { name?: string; parent_id?: string | null; sort_order?: number }, signal?: AbortSignal) { return this.json<AssetGroup>(`/api/v1/admin/asset-groups/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  deleteAssetGroup(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/asset-groups/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
  createAsset(body: Pick<AdminAsset, 'name' | 'host' | 'port' | 'protocol' | 'tags'> & Partial<Pick<AdminAsset, 'security' | 'ssh_host_key' | 'rdp_certificate_sha256' | 'group_id'>>, signal?: AbortSignal) { return this.json<AdminAsset>('/api/v1/admin/assets', { method: 'POST', body, signal }); }
  updateAsset(id: string, revision: number, body: Partial<Pick<AdminAsset, 'name' | 'host' | 'port' | 'tags' | 'enabled' | 'security' | 'ssh_host_key' | 'rdp_certificate_sha256' | 'group_id'>>, signal?: AbortSignal) { return this.json<AdminAsset>(`/api/v1/admin/assets/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  /** Soft delete: the asset and every account under it leave the catalogs, tickets are revoked and live sessions close. */
  deleteAsset(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/assets/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
  deleteAccount(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
  accounts(asset: string, query?: Query, signal?: AbortSignal) { return this.json<Page<AdminAccount>>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/accounts${queryString(query)}`, { signal }); }
  createAccount(asset: string, body: AccountInput, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/accounts`, { method: 'POST', body, signal }); }
  updateAccount(id: string, revision: number, body: Partial<Pick<AdminAccount, 'label' | 'username' | 'domain' | 'enabled'>>, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  replaceCredential(id: string, revision: number, credential: Credential, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}/credential`, { method: 'PUT', revision, body: credential, signal }); }
  grants(query?: Query, signal?: AbortSignal) { return this.json<Page<Grant>>(`/api/v1/admin/grants${queryString(query)}`, { signal }); }
  createGrant(body: Pick<Grant, 'user_id' | 'asset_id' | 'account_id' | 'expires_at'>, signal?: AbortSignal) { return this.json<Grant>('/api/v1/admin/grants', { method: 'POST', body, signal }); }
  updateGrant(id: string, revision: number, body: Partial<Pick<Grant, 'enabled' | 'expires_at'>>, signal?: AbortSignal) { return this.json<Grant>(`/api/v1/admin/grants/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  revokeGrant(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/grants/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
}
const protocol = (value: unknown): value is TargetProtocol => ['ssh', 'rdp', 'vnc'].includes(String(value));
const validGroup = (value: unknown): value is AssetGroup => !!value && typeof value === 'object'
  && typeof (value as AssetGroup).id === 'string' && !!(value as AssetGroup).id
  && typeof (value as AssetGroup).name === 'string'
  && Number.isSafeInteger((value as AssetGroup).sort_order)
  && ((value as AssetGroup).parent_id === null || (typeof (value as AssetGroup).parent_id === 'string' && !!(value as AssetGroup).parent_id));
export function validateAssets(result: AssetPage): AssetPage {
  if (!result || !Array.isArray(result.items) || !(result.next_cursor === null || typeof result.next_cursor === 'string') || !Number.isSafeInteger(result.policy_revision) || result.policy_revision < 1 || !result.items.every(asset => asset && typeof asset.id === 'string' && !!asset.id && typeof asset.name === 'string' && protocol(asset.protocol) && ((asset.group_id === null && asset.group_name === null) || (typeof asset.group_id === 'string' && !!asset.group_id && typeof asset.group_name === 'string' && !!asset.group_name && [...asset.group_name].length <= 128)) && (asset.tags === undefined || Array.isArray(asset.tags) && asset.tags.every(tag => typeof tag === 'string')) && Array.isArray(asset.accounts) && asset.accounts.every(account => account && typeof account.id === 'string' && !!account.id && typeof account.label === 'string' && !!account.label && (asset.protocol === 'vnc' ? account.username === null : typeof account.username === 'string' && !!account.username) && (asset.protocol === 'rdp' ? account.domain === null || typeof account.domain === 'string' : account.domain === null) && ['none', 'password', 'private_key'].includes(account.credential_kind) && (account.credential_kind !== 'none' || asset.protocol === 'vnc') && (account.credential_kind !== 'private_key' || asset.protocol === 'ssh')))) throw new ApiError('INVALID_RESPONSE', '可用资产响应不完整。');
  // The group forest is optional for older servers, but a malformed one must not silently break the tree.
  if (result.groups !== undefined && (!Array.isArray(result.groups) || !result.groups.every(validGroup))) throw new ApiError('INVALID_RESPONSE', '资产分组响应不完整。');
  return result;
}
/** Nest a flat group list by parent_id into a depth-annotated forest, ordered by sort_order then name. */
export function groupTree(groups: AssetGroup[]): { group: AssetGroup; depth: number }[] {
  const known = new Set(groups.map(group => group.id)), childrenOf = new Map<string | null, AssetGroup[]>();
  for (const group of groups) {
    // A group whose parent is not visible is promoted to a root so a partial forest still renders.
    const parent = group.parent_id !== null && known.has(group.parent_id) ? group.parent_id : null;
    if (!childrenOf.has(parent)) childrenOf.set(parent, []);
    childrenOf.get(parent)!.push(group);
  }
  for (const list of childrenOf.values()) list.sort((a, b) => a.sort_order - b.sort_order || a.name.localeCompare(b.name, undefined, { numeric: true }));
  const out: { group: AssetGroup; depth: number }[] = [], emitted = new Set<string>();
  const walk = (parent: string | null, depth: number, path: Set<string>) => {
    for (const group of childrenOf.get(parent) ?? []) {
      if (path.has(group.id) || emitted.has(group.id)) continue; // a cycle must not loop forever
      emitted.add(group.id); out.push({ group, depth });
      path.add(group.id); walk(group.id, depth + 1, path); path.delete(group.id);
    }
  };
  walk(null, 0, new Set());
  // Groups caught in a cycle have no reachable root; render them rather than dropping them silently.
  for (const group of groups) {
    if (emitted.has(group.id)) continue;
    emitted.add(group.id); out.push({ group, depth: 0 }); walk(group.id, 1, new Set([group.id]));
  }
  return out;
}
export function validateTicket(ticket: Ticket): Ticket {
  if (!ticket || ticket.stream_protocol !== (ticket.target_protocol === 'ssh' ? 'bastion.ssh.v1' : 'bastion.guac.v1')) throw new ApiError('CLIENT_PROTOCOL_UNSUPPORTED', '会话协议与目标不匹配。');
  if (!ticket.session_id || typeof ticket.ws_token !== 'string' || !/^[A-Za-z0-9_-]+$/.test(ticket.ws_token) || !ticket.connection_id || !Number.isFinite(Date.parse(ticket.expires_at)) || !protocol(ticket.target_protocol)) throw new ApiError('INVALID_RESPONSE', '会话票据响应不完整。');
  return ticket;
}
