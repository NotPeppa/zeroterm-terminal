import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';

const contract = JSON.parse(await readFile(new URL('../../docs/openapi-web.json', import.meta.url), 'utf8'));
const schemas = contract.components.schemas;
const resolve = schema => schema.$ref ? schemas[schema.$ref.split('/').at(-1)] : schema;
test('SSH creation accepts pending trust; discovery is bodyless admin confirmation with revision and CSRF', () => {
  assert(!schemas.AssetCreate.allOf[0].then.required?.includes('ssh_host_key'));
  for (const name of ['AssetCreate', 'AssetPatch']) assert.deepEqual(schemas[name].properties.ssh_host_key.type, ['string', 'null']);
  const path = contract.paths['/admin/assets/{id}/ssh-host-key/scan'], operation = path.post;
  assert.equal(operation.requestBody, undefined);
  const parameters = operation.parameters.map(parameter => contract.components.parameters[parameter.$ref.split('/').at(-1)]);
  for (const name of ['Origin', 'X-Bastion-CSRF', 'If-Match']) assert.equal(parameters.find(parameter => parameter.name === name)?.required, true);
  assert.match(operation.description, /without target credentials or automatic trust updates/);
  assert.match(operation.description, /own socket before authentication/);
});
test('user paths exclude soft-deleted identities without changing User fields and isolate reused usernames', () => {
  const users = contract.paths['/admin/users'], user = contract.paths['/admin/users/{id}'];
  assert.match(users.get.description, /Excludes soft-deleted users/); assert.match(users.get.description, /Disabled but undeleted.*reserv/);
  const page = users.get.responses['200'].content['application/json'].schema;
  assert.deepEqual(page.required, ['items', 'next_cursor']); assert.equal(resolve(page.properties.items.items), schemas.User);
  assert.match(user.get.description, /soft-deleted users return 404/); assert(user.get.responses['404']);
  assert.match(users.post.description, /new UUID.*newly supplied password/); assert.match(users.post.description, /no inherited old Grants, login sessions or historical ownership/);
  assert.deepEqual(schemas.User.required, ['id', 'username', 'role', 'enabled', 'revision']); assert.deepEqual(Object.keys(schemas.User.properties), ['id', 'username', 'role', 'enabled', 'revision']);
  assert(user.patch.responses['404']); assert(contract.paths['/admin/users/{id}/reset-password'].post.responses['404']);
});

test('user DELETE documents bodyless admin/self protection, exact Origin/CSRF/cookie and positive If-Match statuses', () => {
  const path = contract.paths['/admin/users/{id}'], operation = path.delete;
  assert.equal(operation.requestBody, undefined); assert.equal(operation.responses['204'].content, undefined);
  for (const status of ['204', '400', '401', '403', '404', '412', '428']) assert(operation.responses[status], status);
  assert.match(operation.responses['400'].description, /INVALID_ARGUMENT.*malformed.*If-Match/);
  assert.match(operation.responses['403'].description, /non-admin or current login user/);
  assert.match(operation.responses['404'].description, /missing or already soft-deleted/);
  assert.match(operation.responses['412'].description, /REVISION_CONFLICT.*live revision/);
  assert.match(operation.responses['428'].description, /PRECONDITION_REQUIRED.*missing/);
  const parameters = [...path.parameters, ...operation.parameters].map(parameter => parameter.$ref ? contract.components.parameters[parameter.$ref.split('/').at(-1)] : parameter);
  for (const name of ['id', 'Origin', 'X-Bastion-CSRF', 'If-Match']) assert.equal(parameters.find(parameter => parameter.name === name)?.required, true, name);
  assert.equal(parameters.find(parameter => parameter.name === 'id').in, 'path');
  for (const name of ['Origin', 'X-Bastion-CSRF', 'If-Match']) assert.equal(parameters.find(parameter => parameter.name === name).in, 'header');
  const ifMatch = parameters.find(parameter => parameter.name === 'If-Match'), pattern = new RegExp(ifMatch.schema.pattern);
  assert(pattern.test('"7"')); for (const value of ['7', '"0"', '"-1"', 'W/"7"', '*', '"1", "2"']) assert(!pattern.test(value), value);
  assert(contract.security.some(security => 'BrowserSession' in security)); assert.equal(contract.components.securitySchemes.BrowserSession.in, 'cookie');
  assert.match(operation.description, /matching X-Bastion-CSRF\/cookie/); assert.match(operation.description, /old access tokens, refresh, unconsumed tickets and runtime connections/);
  assert.match(operation.description, /Audit events, historical connections, recordings, approved host keys and old Grants remain/);
  assert.match(operation.description, /new UUID and password, without inherited Grants, sessions or historical ownership/);
  assert.match(operation.description, /Never automatically retry DELETE/); assert.match(operation.description, /After 204.*read failure.*never repeat DELETE/);
});

test('RFC-005 schemas remove all legacy routes and permissions',()=>{
 // RFC-006 reintroduces tickets only under the Bearer-only /native/ prefix; legacy ticket paths stay removed.
 for(const path of Object.keys(contract.paths)) assert.doesNotMatch(path.replace(/^\/native\/connection-tickets$/,'/native'),/channels|\/files|copy-jobs|connection-tickets|\/test$/);
 for(const path of Object.keys(contract.paths)) if(path.includes('host-key')) assert.equal(path,'/admin/assets/{id}/ssh-host-key/scan');
 for(const name of ['Capability','Purpose','TicketRequest','TicketResponse','NativeLoginResponse']) assert.equal(schemas[name],undefined);
 assert.deepEqual(schemas.WebSessionRequest.required,['asset_id','account_id','display']);
 assert.deepEqual(schemas.WebSessionResponse.required,['session_id','connection_id','ws_token','expires_at','target_protocol','stream_protocol']);
 assert.deepEqual(schemas.WebSessionResponse.properties.stream_protocol.enum,['bastion.ssh.v1','bastion.guac.v1']);
 assert.deepEqual(schemas.TargetProtocol.enum,['ssh','rdp','vnc']);
 for(const key of ['Account','Grant','Connection']) assert.equal(schemas[key].properties.capabilities,undefined);
 assert.equal(schemas.Info.properties.production_ready.const,false);
 assert.equal(schemas.Display.properties.width.maximum,3840);assert.equal(schemas.Display.properties.height.maximum,2160);
 assert.equal(schemas.Display.properties.dpi.minimum,48);assert.equal(schemas.Display.properties.dpi.maximum,192);
 assert.equal(schemas.AssetPatch.properties.protocol,undefined);
});
test('vendored official artifact is hash-pinned and loaded before module with no external runtime',async()=>{
 const {createHash}=await import('node:crypto');
 const artifact=await readFile(new URL('../public/guacamole/all.js',import.meta.url));
 assert.equal(artifact.length,533971);assert.equal(createHash('sha256').update(artifact).digest('hex'),'b31a4384599f7498bcabf91ed934124ea5df30231310aa78407d3c3754287633');
 const html=await readFile(new URL('../index.html',import.meta.url),'utf8');assert(html.indexOf('/guacamole/all.js')<html.indexOf('type="module"'));
 const pkg=JSON.parse(await readFile(new URL('../package.json',import.meta.url),'utf8'));assert.deepEqual(pkg.dependencies,{'@xterm/addon-fit':'0.11.0','@xterm/addon-search':'0.16.0','@xterm/xterm':'6.0.0'});
 for(const name of ['api','main','guac','workspaces','protocol']) {
 const source=await readFile(new URL('../src/'+name+'.ts',import.meta.url),'utf8');assert.doesNotMatch(source,/@xterm|TargetSocket|mountFiles|mountExec|copyJobs|client_type|purpose:/);
 }
});

test('RDP creation accepts pending trust; discovery is bodyless asset confirmation with revision and CSRF', () => {
 assert(!schemas.AssetCreate.allOf[1].then.required?.includes('rdp_certificate_sha256'));
 for (const name of ['AssetCreate', 'AssetPatch']) assert.deepEqual(schemas[name].properties.rdp_certificate_sha256.type, ['string', 'null']);
 const operation = contract.paths['/admin/assets/{id}/rdp-certificate/scan'].post;
 assert.equal(operation.requestBody, undefined); assert.equal(contract.paths['/admin/rdp-certificate/scan'], undefined);
 const parameters = operation.parameters.map(parameter => contract.components.parameters[parameter.$ref.split('/').at(-1)]);
 for (const name of ['Origin', 'X-Bastion-CSRF', 'If-Match']) assert.equal(parameters.find(parameter => parameter.name === name)?.required, true);
 assert.deepEqual(resolve(operation.responses['200'].content['application/json'].schema).properties.security.enum, ['nla', 'tls']);
 assert.match(operation.description, /no target credentials are ever sent and nothing is stored/);
 assert.match(operation.description, /own socket before authentication/);
});

test('RFC-006 native routes are Bearer-only and never cookie-authenticated', () => {
  assert.equal(contract.components.securitySchemes.NativeBearer.scheme, 'bearer');
  const native = Object.keys(contract.paths).filter(path => path.startsWith('/native/'));
  assert.deepEqual(native.sort(), ['/native/assets', '/native/assets/{id}', '/native/auth/login', '/native/auth/logout', '/native/auth/refresh', '/native/connection-tickets', '/native/connections/{id}']);
  for (const path of native) for (const operation of Object.values(contract.paths[path]).filter(value => value && value.responses)) {
    assert(!(operation.security ?? []).some(security => 'BrowserSession' in security), path);
    assert(!(operation.parameters ?? []).some(parameter => ['Origin', 'X-Bastion-CSRF'].includes(parameter.name ?? '') || /Origin|Csrf/.test(parameter.$ref ?? '')), path);
  }
  assert.deepEqual(schemas.NativeLogin.required, ['username', 'password', 'device_label']);
  assert.deepEqual(schemas.NativeTicketRequest.required, ['asset_id', 'account_id', 'capabilities']);
  assert.equal(schemas.NativeTicketRequest.properties.purpose, undefined);
  assert.deepEqual(schemas.NativeTicket.required, ['protocol_version', 'ticket_id', 'ticket_secret', 'connection_id', 'gateway', 'capabilities', 'expires_at']);
  assert.deepEqual(schemas.Info.properties.native.required, ['protocol_version', 'minimum_client_protocol_version', 'available', 'gateway', 'features']);
  assert.deepEqual(schemas.NativeAccount.required, ['id', 'label', 'username', 'domain', 'credential_kind', 'capabilities']);
  assert.equal(schemas.Account.properties.capabilities, undefined, 'browser accounts stay capability-free');
});
