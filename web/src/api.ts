import { requireHTTPS } from './protocol.ts';

export type Capability = 'shell' | 'exec' | 'sftp';
export type Role = 'admin' | 'operator' | 'auditor';
export type User = { id: string; username: string; role: Role; enabled: boolean; revision: number };
export type Me = { user: User; login_session_id: string; policy_revision: number; csrf_token: string };
export type Account = { id: string; username: string; capabilities: Capability[] };
export type Asset = { id: string; name: string; tags?: string[]; accounts: Account[] };
export type Page<T> = { items: T[]; next_cursor: string | null; policy_revision?: number };
export type AssetPage = Page<Asset> & { policy_revision: number };
export type Ticket = { protocol_version: number; session_id: string; ws_token: string; connection_id: string; expires_at: string; capabilities: Capability[] };
export type Info = { server_id?: string; protocol_version: number; websocket_protocol_version?: number; minimum_client_protocol_version: number; production_ready: boolean; features?: Partial<Record<'web_terminal' | 'web_exec' | 'web_sftp' | 'recording_replay' | 'copy_jobs' | 'device_sessions', boolean>>; recording?: { required: boolean; available?: boolean; format_version: number } };
export type AdminAsset = { id: string; name: string; host: string; port: number; tags: string[]; enabled: boolean; revision: number };
export type AdminAccount = { id: string; asset_id: string; username: string; enabled: boolean; revision: number; credential_kind: string; credential_revision: number };
export type Credential = { type: 'password'; password: string } | { type: 'private_key'; key_pem: string; passphrase: string | null };
export type HostKey = { id: string; asset_id: string; algorithm: string; public_key: string; fingerprint: string; state: string; revision: number };
export type Grant = { id: string; user_id: string; asset_id: string; account_id: string; capabilities: Capability[]; enabled: boolean; expires_at: string | null; revision: number };
export type Connection = { id: string; asset_id: string; account_id: string; state: string; transport?: string; created_at: string; capabilities: Capability[]; failure?: { code: string; message?: string; request_id?: string }; user_id?: string; login_session_id?: string };
export type Audit = Record<string, unknown> & { id: string };
export type DeviceSession = { id: string; device_label: string; current: boolean; created_at: string; expires_at?: string; revoked_at?: string | null };
export type Recording = { id: string; state?: string; status?: string; format_version?: number; connection_id?: string; [key: string]: unknown };
export type FileMetadata = { size?: number | null; permissions?: number | null; mtime?: number | null; kind: 'file' | 'directory' | 'symlink' | 'other' };
export type DirectoryEntry = { name: string; metadata: FileMetadata };
export type CopyRequest = { source_asset_id: string; source_account_id: string; source_path: string; destination_asset_id: string; destination_account_id: string; destination_path: string; bytes_total?: number };
export type CopyJob = { id: string; state: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'interrupted'; [key: string]: unknown };
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
export type RequestOptions = { method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'; body?: unknown; rawBody?: BodyInit; contentType?: string; revision?: number; signal?: AbortSignal; stream?: boolean };
export class ApiClient {
  private csrf = '';
  private transport: typeof fetch;
  private origin: string;
  private development: boolean;
  constructor(transport: typeof fetch = fetch, origin = location.origin, development = import.meta.env?.DEV === true) { this.transport = transport.bind(globalThis); this.origin = origin; this.development = development; }
  clearAuth() { this.csrf = ''; }
  async response(path: string, options: RequestOptions = {}): Promise<Response> {
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
    if (options.body !== undefined && options.rawBody !== undefined) throw new ApiError('INVALID_BODY', 'JSON 与原始请求体不能混用。');
    if (options.body !== undefined) headers.set('Content-Type', 'application/json');
    if (options.rawBody !== undefined) headers.set('Content-Type', options.contentType ?? 'application/octet-stream');
    let response: Response;
    try {
      response = await this.transport(url.href, { method, headers, body: options.rawBody ?? (options.body === undefined ? undefined : JSON.stringify(options.body)), credentials: 'include', mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(options.stream ? 300000 : 15000)]) : AbortSignal.timeout(options.stream ? 300000 : 15000) });
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
  async loadMe(signal?: AbortSignal) { const result = await this.json<Me>('/api/v1/me', { signal }); if (!result?.user || typeof result.user.username !== 'string' || !result.login_session_id || !Number.isSafeInteger(result.policy_revision) || !result.csrf_token) throw new ApiError('INVALID_RESPONSE', '身份响应不完整。'); this.csrf = result.csrf_token; return result; }
  info(signal?: AbortSignal) { return this.json<Info>('/api/v1/info', { signal }); }
  login(body: { username: string; password: string; device_label: string; client_type: 'web' }, signal?: AbortSignal) { return this.json('/api/v1/auth/login', { method: 'POST', body, signal }); }
  logout(all = false, signal?: AbortSignal) { return this.json<void>(`/api/v1/auth/${all ? 'logout-all' : 'logout'}`, { method: 'POST', body: {}, signal }); }
  refresh(signal?: AbortSignal) { return this.json<void>('/api/v1/auth/refresh', { method: 'POST', body: {}, signal }); }
  changePassword(current_password: string, new_password: string, signal?: AbortSignal) { return this.json<void>('/api/v1/me/password', { method: 'POST', body: { current_password, new_password }, signal }); }
  async assets(query?: Query, signal?: AbortSignal) { return validateAssets(await this.json<AssetPage>(`/api/v1/assets${queryString(query)}`, { signal })); }
  async session(asset_id: string, account_id: string, capability: Capability, purpose: 'terminal' | 'sftp' | 'server_tool' = 'terminal', signal?: AbortSignal) { return validateTicket(await this.json<Ticket>('/api/v1/sessions', { method: 'POST', body: { asset_id, account_id, capabilities: [capability], purpose }, signal }), capability); }
  connection(id: string, signal?: AbortSignal) { return this.json<Connection>(`/api/v1/connections/${encodeURIComponent(id)}`, { signal }); }
  connections(query?: Query, signal?: AbortSignal) { return this.json<Page<Connection>>(`/api/v1/connections${queryString(query)}`, { signal }); }
  channels(id: string, signal?: AbortSignal) { return this.json<Page<Record<string, unknown>>>(`/api/v1/connections/${encodeURIComponent(id)}/channels`, { signal }); }
  disconnect(id: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/connections/${encodeURIComponent(id)}/disconnect`, { method: 'POST', body: {}, signal }); }
  audit(query?: Query, signal?: AbortSignal) { return this.json<Page<Audit>>(`/api/v1/audit-events${queryString(query)}`, { signal }); }
  devices(signal?: AbortSignal) { return this.json<Page<DeviceSession>>('/api/v1/me/sessions', { signal }); }
  revokeDevice(id: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/me/sessions/${encodeURIComponent(id)}`, { method: 'DELETE', signal }); }
  files(connection: string, path: string, signal?: AbortSignal) { return this.json<{ items: DirectoryEntry[] }>(`/api/v1/connections/${encodeURIComponent(connection)}/files${queryString({ path, operation: 'list' })}`, { signal }); }
  statFile(connection: string, path: string, signal?: AbortSignal) { return this.json<FileMetadata>(`/api/v1/connections/${encodeURIComponent(connection)}/files${queryString({ path, operation: 'stat' })}`, { signal }); }
  fileOperation(connection: string, body: { operation: 'mkdir' | 'remove' | 'rename'; path: string; destination?: string }, signal?: AbortSignal) { return this.json<void>(`/api/v1/connections/${encodeURIComponent(connection)}/files/operations`, { method: 'POST', body, signal }); }
  download(connection: string, path: string, signal?: AbortSignal) { return this.response(`/api/v1/connections/${encodeURIComponent(connection)}/files/content${queryString({ path })}`, { signal, stream: true }); }
  upload(connection: string, path: string, file: File, signal?: AbortSignal) { return this.json<{ bytes: number }>(`/api/v1/connections/${encodeURIComponent(connection)}/files/content${queryString({ path })}`, { method: 'PUT', rawBody: file, signal, stream: true }); }
  recordings(query?: Query, signal?: AbortSignal) { return this.json<Page<Recording>>(`/api/v1/recordings${queryString(query)}`, { signal }); }
  copyJobs(query?: Query, signal?: AbortSignal) { return this.json<Page<CopyJob>>(`/api/v1/copy-jobs${queryString(query)}`, { signal }); }
  createCopyJob(body: CopyRequest, signal?: AbortSignal) { return this.json<CopyJob>('/api/v1/copy-jobs', { method: 'POST', body, signal }); }
  cancelCopyJob(id: string, signal?: AbortSignal) { return this.json<CopyJob>(`/api/v1/copy-jobs/${encodeURIComponent(id)}/cancel`, { method: 'POST', body: {}, signal }); }
  recording(id: string, signal?: AbortSignal) { return this.json<Recording>(`/api/v1/recordings/${encodeURIComponent(id)}`, { signal }); }
  recordingContent(id: string, signal?: AbortSignal) { return this.response(`/api/v1/recordings/${encodeURIComponent(id)}/content`, { signal, stream: true }); }
  users(query?: Query, signal?: AbortSignal) { return this.json<Page<User>>(`/api/v1/admin/users${queryString(query)}`, { signal }); }
  createUser(body: { username: string; password: string; role: Role }, signal?: AbortSignal) { return this.json<User>('/api/v1/admin/users', { method: 'POST', body, signal }); }
  updateUser(id: string, revision: number, body: { role?: Role; enabled?: boolean }, signal?: AbortSignal) { return this.json<User>(`/api/v1/admin/users/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  resetPassword(id: string, revision: number, password: string, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/reset-password`, { method: 'POST', revision, body: { password }, signal }); }
  adminAssets(query?: Query, signal?: AbortSignal) { return this.json<Page<AdminAsset>>(`/api/v1/admin/assets${queryString(query)}`, { signal }); }
  createAsset(body: { name: string; host: string; port: number; tags: string[] }, signal?: AbortSignal) { return this.json<AdminAsset>('/api/v1/admin/assets', { method: 'POST', body, signal }); }
  updateAsset(id: string, revision: number, body: Partial<Pick<AdminAsset, 'name' | 'host' | 'port' | 'tags' | 'enabled'>>, signal?: AbortSignal) { return this.json<AdminAsset>(`/api/v1/admin/assets/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  accounts(asset: string, query?: Query, signal?: AbortSignal) { return this.json<Page<AdminAccount>>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/accounts${queryString(query)}`, { signal }); }
  createAccount(asset: string, username: string, credential: Credential, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/accounts`, { method: 'POST', body: { username, credential }, signal }); }
  updateAccount(id: string, revision: number, body: { username?: string; enabled?: boolean }, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  replaceCredential(id: string, revision: number, credential: Credential, signal?: AbortSignal) { return this.json<AdminAccount>(`/api/v1/admin/accounts/${encodeURIComponent(id)}/credential`, { method: 'PUT', revision, body: credential, signal }); }
  testAccount(id: string, signal?: AbortSignal) { return this.json<{ authenticated: boolean }>(`/api/v1/admin/accounts/${encodeURIComponent(id)}/test`, { method: 'POST', body: {}, signal }); }
  hostKeys(asset: string, query?: Query, signal?: AbortSignal) { return this.json<Page<HostKey>>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/host-keys${queryString(query)}`, { signal }); }
  scanHostKey(asset: string, signal?: AbortSignal) { return this.json<HostKey>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/host-key-scan`, { method: 'POST', body: {}, signal }); }
  approveHostKey(asset: string, algorithm: string, public_key: string, signal?: AbortSignal) { return this.json<HostKey>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/host-keys`, { method: 'POST', body: { algorithm, public_key }, signal }); }
  revokeHostKey(asset: string, id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/assets/${encodeURIComponent(asset)}/host-keys/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
  grants(query?: Query, signal?: AbortSignal) { return this.json<Page<Grant>>(`/api/v1/admin/grants${queryString(query)}`, { signal }); }
  createGrant(body: Pick<Grant, 'user_id' | 'asset_id' | 'account_id' | 'capabilities' | 'expires_at'>, signal?: AbortSignal) { return this.json<Grant>('/api/v1/admin/grants', { method: 'POST', body, signal }); }
  updateGrant(id: string, revision: number, body: Partial<Pick<Grant, 'capabilities' | 'enabled' | 'expires_at'>>, signal?: AbortSignal) { return this.json<Grant>(`/api/v1/admin/grants/${encodeURIComponent(id)}`, { method: 'PATCH', revision, body, signal }); }
  revokeGrant(id: string, revision: number, signal?: AbortSignal) { return this.json<void>(`/api/v1/admin/grants/${encodeURIComponent(id)}`, { method: 'DELETE', revision, signal }); }
}
export function validateAssets(result: AssetPage): AssetPage {
  if (!result || !Array.isArray(result.items) || (result.next_cursor !== null && typeof result.next_cursor !== 'string') || typeof result.policy_revision !== 'number' || !result.items.every(asset => typeof asset.id === 'string' && typeof asset.name === 'string' && (asset.tags === undefined || Array.isArray(asset.tags) && asset.tags.every(tag => typeof tag === 'string')) && Array.isArray(asset.accounts) && asset.accounts.every(account => typeof account.id === 'string' && typeof account.username === 'string' && Array.isArray(account.capabilities) && account.capabilities.every(cap => ['shell', 'exec', 'sftp'].includes(cap))))) throw new ApiError('INVALID_RESPONSE', '授权资产响应不完整。');
  return result;
}
export function validateTicket(ticket: Ticket, capability: Capability = 'shell'): Ticket {
  if (!ticket || ticket.protocol_version !== 1) throw new ApiError('CLIENT_PROTOCOL_UNSUPPORTED', '需要兼容 v1 的服务端/客户端。');
  if (!ticket.session_id || typeof ticket.ws_token !== 'string' || !/^[A-Za-z0-9_-]+$/.test(ticket.ws_token) || !ticket.connection_id || !Number.isFinite(Date.parse(ticket.expires_at)) || !Array.isArray(ticket.capabilities) || !ticket.capabilities.includes(capability)) throw new ApiError('INVALID_RESPONSE', '会话票据响应不完整。');
  return ticket;
}
