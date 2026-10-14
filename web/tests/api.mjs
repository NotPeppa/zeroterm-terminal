import { strict as assert } from 'node:assert';
import test from 'node:test';
import { ApiClient, ApiError, queryString, validateAssets, validateTicket, validateInfo } from '../src/api.ts';
const response = (body, status = 200) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'X-Request-Id': 'test-request' } });
const transport = handler => async (url, options) => handler(url, options);
const info = {schema_version:2,protocol_version:2,stream_protocol:'bastion.guac.v1',production_ready:false,features:{web_ssh:true,web_rdp:false,web_vnc:true,recording_replay:true,device_sessions:true},recording:{required:true,available:true,format_version:2}};
test('discovery requires v2 explicit availability and rejects production-ready claims',()=>{
 assert.equal(validateInfo(info),info);
 for(const value of [{...info,schema_version:1},{...info,production_ready:true},{...info,features:{...info.features,web_rdp:'true'}},{...info,recording:{...info.recording,format_version:1}}]) assert.throws(()=>validateInfo(value),/Guacamole v2/);
});

test('transport uses globalThis as receiver like native browser fetch', async () => {
  let calls = 0;
  function receiverCheckedFetch(url, options) {
    calls++;
    if (this !== globalThis) throw new TypeError('Illegal invocation');
    assert.equal(url, 'https://example.test/api/v1/info');
    assert.equal(options.method, 'GET');
    return Promise.resolve(response(info));
  }
  const api = new ApiClient(receiverCheckedFetch, 'https://example.test', false);
  assert.deepEqual(await api.info(), info);
  assert.equal(calls, 1);
});

test('explicit mutation uses cookie, CSRF, If-Match and exact PATCH JSON', async () => {
  const calls = [], api = new ApiClient(transport((url, options) => { calls.push({ url, options }); return response(url.endsWith('/auth/csrf') ? { csrf_token: 'csrf-value' } : { id: 'user' }); }), 'https://example.test', false);
  await api.loadCsrf(); await api.updateUser('id /x', 7, { enabled: false });
  const { url, options } = calls[1]; assert.equal(url, 'https://example.test/api/v1/admin/users/id%20%2Fx'); assert.equal(options.method, 'PATCH'); assert.equal(options.credentials, 'include'); assert.equal(options.mode, 'same-origin'); assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store'); assert.equal(options.headers.get('X-Bastion-CSRF'), 'csrf-value'); assert.equal(options.headers.get('If-Match'), '"7"'); assert.deepEqual(JSON.parse(options.body), { enabled: false });
});

test('user DELETE encodes id and sends cookie/CSRF/quoted revision without a body; 204 is void', async () => {
  const calls = [], api = new ApiClient(transport((url, options) => { calls.push({ url, options }); return url.endsWith('/auth/csrf') ? response({ csrf_token: 'csrf-value' }) : new Response(null, { status: 204 }); }), 'https://example.test', false);
  await api.loadCsrf(); const controller = new AbortController();
  assert.equal(await api.deleteUser('id /?#%', 9, controller.signal), undefined);
  const { url, options } = calls[1];
  assert.equal(url, 'https://example.test/api/v1/admin/users/id%20%2F%3F%23%25'); assert.equal(options.method, 'DELETE');
  assert.equal(options.credentials, 'include'); assert.equal(options.mode, 'same-origin'); assert.equal(options.redirect, 'error'); assert.equal(options.cache, 'no-store');
  assert.equal(options.headers.get('X-Bastion-CSRF'), 'csrf-value'); assert.equal(options.headers.get('If-Match'), '"9"');
  assert.equal(options.headers.get('Origin'), null); // The browser supplies the real Origin, never an application override.
  assert.equal(options.headers.get('Content-Type'), null); assert.equal(options.body, undefined);
  assert.equal(calls.length, 2); controller.abort(); assert.equal(options.signal.aborted, true);
});

test('user DELETE never retries an unknown outcome or a 412 revision conflict', async () => {
  for (const code of ['RESULT_UNKNOWN', 'REVISION_CONFLICT']) {
    let mutations = 0;
    const api = new ApiClient(transport(url => {
      if (url.endsWith('/auth/csrf')) return response({ csrf_token: 'csrf-value' });
      mutations++; if (code === 'RESULT_UNKNOWN') throw new TypeError('network failed');
      return response({ error: { code, message: 'changed', request_id: 'delete-request' } }, 412);
    }), 'https://example.test', false);
    await api.loadCsrf(); await assert.rejects(api.deleteUser('user', 9), error => error instanceof ApiError && error.code === code && (code !== 'REVISION_CONFLICT' || error.status === 412 && error.requestId === 'delete-request'));
    assert.equal(mutations, 1);
  }
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

test('sessions accept exact target/display only; protocol metadata and account labels validate', async () => {
 const calls = [], ticket = { session_id:'s',connection_id:'c',ws_token:'abc_123',expires_at:'2030-01-01T00:00:00Z',target_protocol:'ssh',stream_protocol:'bastion.ssh.v1' };
 const api = new ApiClient(transport((url,options) => {calls.push(options);return response(url.endsWith('/auth/csrf')?{csrf_token:'csrf'}:ticket);}), 'https://test.invalid',false);
 await api.loadCsrf(); await api.session('a','c'); assert.deepEqual(JSON.parse(calls.at(-1).body),{asset_id:'a',account_id:'c',display:{width:1280,height:720,dpi:96}});
 assert.equal(validateTicket(ticket),ticket); assert.throws(()=>validateTicket({...ticket,stream_protocol:'old'}));
 const asset = {id:'a',name:'Host',protocol:'ssh',group_id:null,group_name:null,accounts:[{id:'c',label:'Root',username:'root',domain:null,credential_kind:'password'}]};
 const page = {items:[asset],next_cursor:null,policy_revision:1}; assert.equal(validateAssets(page),page);
 for(const protocol of ['ssh','rdp','vnc']) { const a={...asset,protocol,accounts:[{...asset.accounts[0],username:protocol==='vnc'?null:'root'}]}; assert.doesNotThrow(()=>validateAssets({...page,items:[a]})); }
 assert.throws(()=>validateAssets({...page,items:[{...asset,protocol:'vnc'}]}));
 assert.throws(()=>validateAssets({...page,items:[{...asset,accounts:[{...asset.accounts[0],label:''}]}]}));
 assert.throws(()=>validateAssets({...page,items:[{...asset,protocol:'rdp',accounts:[{...asset.accounts[0],credential_kind:'private_key'}]}]}));
});

test('group management uses same-origin CSRF and revision headers; public group metadata is paired',async()=>{
 const calls=[];const api=new ApiClient(transport((url,options)=>{if(url.endsWith('/auth/csrf'))return response({csrf_token:'csrf'});calls.push({url,options});return options.method==='DELETE'?new Response(null,{status:204}):response({id:'group /1',name:'生产',revision:5,parent_id:null,sort_order:0});}), 'https://example.test',false);
 await api.loadCsrf();await api.createAssetGroup({name:'生产',parent_id:null,sort_order:0});await api.patchAssetGroup('group /1',4,{name:'生产',parent_id:'parent',sort_order:3});await api.deleteAssetGroup('group /1',5);
 assert(calls[0].url.endsWith('/admin/asset-groups'));assert.equal(calls[0].options.method,'POST');assert.deepEqual(JSON.parse(calls[0].options.body),{name:'生产',parent_id:null,sort_order:0});
 assert(calls[1].url.endsWith('/admin/asset-groups/group%20%2F1'));assert.equal(calls[1].options.headers.get('If-Match'),'"4"');assert.deepEqual(JSON.parse(calls[1].options.body),{name:'生产',parent_id:'parent',sort_order:3});
 assert.equal(calls[2].options.method,'DELETE');assert.equal(calls[2].options.headers.get('If-Match'),'"5"');assert.equal(calls[2].options.body,undefined);
 const asset={id:'a',name:'Host',protocol:'ssh',group_id:'group',group_name:'生产',accounts:[]};const page={items:[asset],next_cursor:null,policy_revision:1};assert.equal(validateAssets(page),page);
 for(const bad of [{...asset,group_name:null},{...asset,group_id:null},{...asset,group_name:'x'.repeat(129)}])assert.throws(()=>validateAssets({...page,items:[bad]}));
 // The client tree forest travels beside the assets; a malformed entry is rejected, not silently dropped.
 const group={id:'g',name:'生产',revision:1,parent_id:null,sort_order:0};
 assert.equal(validateAssets({...page,groups:[group]}).groups[0],group);
 for(const bad of [[{...group,sort_order:'0'}],[{...group,parent_id:5}],[{...group,id:''}],[{...group,name:5}],[null]])assert.throws(()=>validateAssets({...page,groups:bad}),/\u5206\u7ec4/);
});
test('stream reads have no total timeout but honor route cancellation', async()=>{
 let signal; const api=new ApiClient(transport((url,options)=>{signal=options.signal;return new Response('x');}),'https://test.invalid',false);
 const controller=new AbortController();await api.recordingContent('c',controller.signal);assert.equal(signal,controller.signal);controller.abort();assert(signal.aborted);
});
