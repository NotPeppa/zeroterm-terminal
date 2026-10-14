import { strict as assert } from 'node:assert';
import test from 'node:test';
import { allowedRoute, discoveryWarning, parseRoute, RouteLifetime, stateMessage } from '../src/state.ts';

test('target network rejection is distinct from account permissions even with HTTP 403', () => {
  const message = stateMessage({ code: 'TARGET_ADDRESS_DENIED', status: 403 });
  assert.match(message, /出站网络策略拒绝/); assert.match(message, /不是账号权限不足/);
  assert.doesNotMatch(message, /当前身份没有此操作权限/);
  assert.equal(stateMessage({ code: 'PERMISSION_DENIED', status: 403 }), '禁止访问：当前身份没有此操作权限。');
});

test('hash routes parse and reject malformed or unknown routes', () => {
  assert.deepEqual(parseRoute(''), { name: 'assets' });
  assert.deepEqual(parseRoute('#/console/ast%201/acc%202'), { name: 'console', id: 'ast 1', sub: 'acc 2' });
  assert.equal(parseRoute('#/console').name, 'not-found');
  assert.equal(parseRoute('#/console/only-asset').name, 'not-found');
  assert.equal(parseRoute('#/session').name, 'not-found');
  assert.deepEqual(parseRoute('#/recordings/id%201'), { name: 'recordings', id: 'id 1' });
  assert.equal(parseRoute('#/not-real').name, 'not-found');
  assert.equal(parseRoute('#/recordings/%E0%A4%A').name, 'not-found');
  assert.equal(parseRoute('#/recordings/a/b').name, 'not-found');
});

test('role and feature gates do not infer unavailable capabilities', () => {
  const info = {protocol_version:2,production_ready:false,features:{web_ssh:true}};
  assert.equal(allowedRoute('console', 'operator', info), true);
  assert.equal(allowedRoute('files', 'operator', info), false);
  assert.equal(allowedRoute('users', 'operator', info), false);
  assert.equal(allowedRoute('audit', 'auditor', info), true);
  assert.equal(allowedRoute('assets', 'auditor', info), false);
});

test('discovery warning stays honest about candidate and unrecorded entry', () => {
  assert.equal(discoveryWarning({ production_ready: true, recording: { required: true } }), '');
  assert.match(discoveryWarning({ production_ready: false, recording: { required: true } }), /未通过生产发布验收/);
  const warning = discoveryWarning({ production_ready: false, recording: { required: false } });
  assert.match(warning, /开发\/候选版本/); assert.match(warning, /当前入口不提供 required 会话录制/);
  assert.match(discoveryWarning({ production_ready: true, recording: { required: false } }), /未通过生产发布验收/);
});

test('route lifetime aborts and disposes in reverse order', () => {
  const life = new RouteLifetime(), events = [];
  life.own(() => events.push('first')); life.own(() => events.push('second')); life.dispose(); life.dispose();
  assert.equal(life.signal.aborted, true); assert.deepEqual(events, ['second', 'first']);
});
