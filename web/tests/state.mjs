import { strict as assert } from 'node:assert';
import test from 'node:test';
import { allowedRoute, discoveryWarning, parseRoute, RouteLifetime } from '../src/state.ts';

test('hash routes parse and reject malformed or unknown routes', () => {
  assert.deepEqual(parseRoute(''), { name: 'assets' });
  assert.deepEqual(parseRoute('#/terminal'), { name: 'terminal' });
  assert.deepEqual(parseRoute('#/recordings/id%201'), { name: 'recordings', id: 'id 1' });
  assert.equal(parseRoute('#/not-real').name, 'not-found');
  assert.equal(parseRoute('#/recordings/%E0%A4%A').name, 'not-found');
});

test('role and feature gates do not infer unavailable capabilities', () => {
  const info = { protocol_version: 1, minimum_client_protocol_version: 1, production_ready: false, features: { web_terminal: true, web_exec: false } };
  assert.equal(allowedRoute('terminal', 'operator', info), true);
  assert.equal(allowedRoute('exec', 'operator', info), false);
  assert.equal(allowedRoute('users', 'operator', info), false);
  assert.equal(allowedRoute('audit', 'auditor', info), true);
  assert.equal(allowedRoute('assets', 'auditor', info), false);
});

test('discovery warning stays honest about candidate and unrecorded entry', () => {
  assert.equal(discoveryWarning({ production_ready: true, recording: { required: true } }), '');
  assert.match(discoveryWarning({ production_ready: false, recording: { required: true } }), /未通过生产发布验收/);
  const warning = discoveryWarning({ production_ready: false, recording: { required: false } });
  assert.match(warning, /开发\/候选版本/); assert.match(warning, /当前入口不提供 required 终端录制/);
  assert.match(discoveryWarning({ production_ready: true, recording: { required: false } }), /未通过生产发布验收/);
});

test('route lifetime aborts and disposes in reverse order', () => {
  const life = new RouteLifetime(), events = [];
  life.own(() => events.push('first')); life.own(() => events.push('second')); life.dispose(); life.dispose();
  assert.equal(life.signal.aborted, true); assert.deepEqual(events, ['second', 'first']);
});
