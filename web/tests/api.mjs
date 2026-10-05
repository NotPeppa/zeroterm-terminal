import { strict as assert } from 'node:assert';
import test from 'node:test';
import { ApiClient, ApiError, queryString, validateAssets, validateTicket } from '../src/api.ts';
const response = (body, status = 200) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'X-Request-Id': 'test-request' } });
const transport = handler => async (url, options) => handler(url, options);

test('transport uses globalThis as receiver like native browser fetch', async () => {
  let calls = 0;
  function receiverCheckedFetch(url, options) {
    calls++;
    if (this !== globalThis) throw new TypeError('Illegal invocation');
    assert.equal(url, 'https://example.test/api/v1/info');
    assert.equal(options.method, 'GET');
    return Promise.resolve(response({ protocol_version: 1 }));
  }
  const api = new ApiClient(receiverCheckedFetch, 'https://example.test', false);
  assert.deepEqual(await api.info(), { protocol_version: 1 });
  assert.equal(calls, 1);
});

test('explicit mutation uses cookie, CSRF, If-Match and exact PATCH JSON', async () => {
  const calls = [], api = new ApiClient(transport((url, options) => { calls.push({ url, options }); return response(url.endsWith('/auth/csrf') ? { csrf_token: 'csrf-value' } : { id: 'user' }); }), 'https://example.test', false);
  await api.loadCsrf(); await api.updateUser('id /x', 7, { enabled: false });
  const { url, options } = calls[1]; assert.equal(url, 'https://example.test/api/v1/admin/users/id%20%2Fx'); assert.equal(options.method, 'PATCH'); assert.equal(options.credentials, 'include'); assert.equal(options.mode, 'same-origin'); assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store'); assert.equal(options.headers.get('X-Bastion-CSRF'), 'csrf-value'); assert.equal(options.headers.get('If-Match'), '"7"'); assert.deepEqual(JSON.parse(options.body), { enabled: false });
});

test('raw transfer body stays File rather than JSON or full arrayBuffer', async () => {
  const calls = [], api = new ApiClient(transport((url, options) => { calls.push({ url, options }); return response(url.endsWith('/auth/csrf') ? { csrf_token: 'csrf-value' } : { bytes: 3 }, url.endsWith('/auth/csrf') ? 200 : 201); }), 'https://example.test', false);
  await api.loadCsrf(); const file = new File([new Uint8Array([0, 255, 1])], 'bytes.bin'); const result = await api.upload('connection', '/remote/a?name=#x', file);
  assert.equal(result.bytes, 3); assert.equal(calls[1].options.body, file); assert.equal(calls[1].options.method, 'PUT'); assert.equal(calls[1].options.headers.get('Content-Type'), 'application/octet-stream'); assert.equal(new URL(calls[1].url).searchParams.get('path'), '/remote/a?name=#x');
});

test('unknown mutation outcome is explicit and never replayed', async () => {
  let mutations = 0; const api = new ApiClient(transport((url) => { if (url.endsWith('/auth/csrf')) return response({ csrf_token: 'csrf-value' }); mutations++; throw new TypeError('network failed'); }), 'https://example.test', false);
  await api.loadCsrf(); await assert.rejects(api.revokeDevice('device'), error => error instanceof ApiError && error.code === 'RESULT_UNKNOWN'); assert.equal(mutations, 1);
});

test('revision conflicts preserve status and server request id', async () => {
  const api = new ApiClient(transport(url => url.endsWith('/auth/csrf') ? response({ csrf_token: 'csrf-value' }) : response({ error: { code: 'REVISION_CONFLICT', message: 'changed', request_id: 'server-id' } }, 412)), 'https://example.test', false);
  await api.loadCsrf(); await assert.rejects(api.updateUser('user', 2, { enabled: false }), error => error.code === 'REVISION_CONFLICT' && error.status === 412 && error.requestId === 'server-id');
});

test('cross-origin, missing CSRF, invalid revision, and production HTTP fail before transport', async () => {
  let calls = 0; const api = new ApiClient(transport(() => { calls++; return response({}); }), 'https://example.test', false);
  await assert.rejects(api.json('https://other.test/api/v1/me'), /同源/); await assert.rejects(api.updateUser('user', 2, { enabled: false }), /重新读取/); assert.equal(calls, 0);
  const insecure = new ApiClient(transport(() => { calls++; return response({}); }), 'http://127.0.0.1', false); await assert.rejects(insecure.info(), /HTTPS_REQUIRED/); assert.equal(calls, 0);
});

test('query paths are encoded and ticket capability validation is not shell-only', () => {
  assert.equal(new URLSearchParams(queryString({ action: 'a&b', cursor: undefined }).slice(1)).get('action'), 'a&b');
  const ticket = { protocol_version: 1, session_id: 's', ws_token: 'abc_123', connection_id: 'c', expires_at: '2030-01-01T00:00:00Z', capabilities: ['exec'] };
  assert.equal(validateTicket(ticket, 'exec'), ticket); assert.throws(() => validateTicket(ticket), /不完整/);
  assert.throws(() => validateAssets({ items: [{ id: 'a', name: '<script>', accounts: [{ id: 'c', username: 'u', capabilities: ['root'] }] }], next_cursor: null, policy_revision: 1 }), /不完整/);
});
