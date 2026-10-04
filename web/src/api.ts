import { requireHTTPS } from './protocol';

export type User = { id?: string; username: string; role?: string };
export type Me = { user: User; login_session_id: string; policy_revision: number; csrf_token: string };
export type Account = { id: string; username: string; capabilities: string[] };
export type Asset = { id: string; name: string; tags?: string[]; accounts: Account[] };
export type AssetPage = { items: Asset[]; next_cursor: string | null; policy_revision: number };
export type Ticket = { protocol_version: number; session_id: string; ws_token: string; connection_id: string; expires_at: string; capabilities: string[] };

export class ApiError extends Error {
  constructor(public code: string, message: string, public requestId: string, public status: number) {
    super(message);
  }
}

let csrf = '';
export function clearAuth() { csrf = ''; }

// No retries, refresh, redirects, or mutation replay are hidden in this transport.
export async function request<T>(path: string, body?: object, signal?: AbortSignal, onRequestId?: (requestId: string) => void): Promise<T> {
  requireHTTPS(location.protocol, import.meta.env.DEV);
  const headers = new Headers({ Accept: 'application/json' });
  if (body !== undefined) {
    if (!csrf) throw new ApiError('CSRF_UNAVAILABLE', '请重新读取登录状态。', '', 0);
    headers.set('Content-Type', 'application/json');
    headers.set('X-Bastion-CSRF', csrf);
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'include', cache: 'no-store', redirect: 'error',
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError('NETWORK_OR_TIMEOUT', '网络请求失败或超时；操作结果可能不明，不会自动重放。', '', 0);
  }
  const requestId = response.headers.get('X-Request-Id') ?? '';
  let result: unknown;
  try { result = response.status === 204 ? undefined : await response.json(); }
  catch { throw new ApiError(`HTTP_${response.status}`, '服务端返回非 JSON 响应。', requestId, response.status); }
  if (!response.ok) {
    const issue = (result as { error?: { code?: unknown; message?: unknown; request_id?: unknown } } | null)?.error;
    throw new ApiError(
      typeof issue?.code === 'string' ? issue.code : `HTTP_${response.status}`,
      typeof issue?.message === 'string' ? issue.message : '请求被拒绝。',
      typeof issue?.request_id === 'string' ? issue.request_id : requestId, response.status,
    );
  }
  onRequestId?.(requestId);
  return result as T;
}

export async function loadCsrf(signal?: AbortSignal) {
  const result = await request<{ csrf_token: string }>('/api/v1/auth/csrf', undefined, signal);
  if (typeof result?.csrf_token !== 'string' || !result.csrf_token) throw new ApiError('INVALID_RESPONSE', '缺少 CSRF token。', '', 0);
  csrf = result.csrf_token;
}

export async function loadMe(signal?: AbortSignal): Promise<Me> {
  const result = await request<Me>('/api/v1/me', undefined, signal);
  if (!result?.user || typeof result.user.username !== 'string' || typeof result.login_session_id !== 'string' ||
      typeof result.policy_revision !== 'number' || typeof result.csrf_token !== 'string' || !result.csrf_token) {
    throw new ApiError('INVALID_RESPONSE', '登录身份响应不完整。', '', 0);
  }
  csrf = result.csrf_token;
  return result;
}

export function validateAssets(result: AssetPage): AssetPage {
  if (!result || !Array.isArray(result.items) ||
      (result.next_cursor !== null && typeof result.next_cursor !== 'string') || typeof result.policy_revision !== 'number' ||
      !result.items.every(asset => typeof asset.id === 'string' && typeof asset.name === 'string' &&
        (asset.tags === undefined || (Array.isArray(asset.tags) && asset.tags.every(tag => typeof tag === 'string'))) &&
        Array.isArray(asset.accounts) && asset.accounts.every(account => typeof account.id === 'string' &&
          typeof account.username === 'string' && Array.isArray(account.capabilities) && account.capabilities.every(cap => typeof cap === 'string')))) {
    throw new ApiError('INVALID_RESPONSE', '授权资产响应不完整。', '', 0);
  }
  return result;
}

export function validateTicket(ticket: Ticket): Ticket {
  if (!ticket || ticket.protocol_version !== 1) throw new ApiError('CLIENT_PROTOCOL_UNSUPPORTED', '需要兼容 v1 的服务端/客户端。', '', 0);
  if (typeof ticket.session_id !== 'string' || !ticket.session_id || typeof ticket.ws_token !== 'string' ||
      !/^[A-Za-z0-9_-]+$/.test(ticket.ws_token) || typeof ticket.connection_id !== 'string' || !ticket.connection_id ||
      typeof ticket.expires_at !== 'string' || !Number.isFinite(Date.parse(ticket.expires_at)) ||
      !Array.isArray(ticket.capabilities) || !ticket.capabilities.includes('shell')) {
    throw new ApiError('INVALID_RESPONSE', '会话票据响应不完整。', '', 0);
  }
  return ticket;
}
