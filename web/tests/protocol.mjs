import { strict as assert } from 'node:assert';
import test from 'node:test';
import { CHANNEL, HEADER_BYTES, MAX_CONTROL_BYTES, MAX_PAYLOAD, advance, canSend, inputFrames, outputPayload, parseControl, requireHTTPS, streamURL } from '../src/protocol.ts';

test('production HTTP is rejected before transport while Vite DEV permits HTTP', () => {
  assert.throws(() => requireHTTPS('http:', false), /HTTPS_REQUIRED/);
  assert.throws(() => requireHTTPS('file:', false), /HTTPS_REQUIRED/);
  assert.doesNotThrow(() => requireHTTPS('https:', false));
  assert.doesNotThrow(() => requireHTTPS('http:', true));
});

test('control limit counts UTF-8 bytes including exact 8192-byte boundary', () => {
  const base = JSON.stringify({ v: 1, type: 'pong', note: '' });
  const remaining = MAX_CONTROL_BYTES - new TextEncoder().encode(base).length;
  const note = '中'.repeat(Math.floor(remaining / 3)) + 'a'.repeat(remaining % 3);
  const exact = JSON.stringify({ v: 1, type: 'pong', note });
  assert.equal(new TextEncoder().encode(exact).length, MAX_CONTROL_BYTES);
  assert.equal(parseControl(exact).type, 'pong');
  assert.throws(() => parseControl(JSON.stringify({ v: 1, type: 'pong', note: note + 'a' })), /CONTROL_FRAME_TOO_LARGE/);
});

test('input frames use six-byte header and 32KiB chunks', () => {
  const payload = new Uint8Array(MAX_PAYLOAD + 1).fill(7);
  const frames = [...inputFrames(payload)];
  assert.equal(frames.length, 2);
  assert.equal(frames[0].length, HEADER_BYTES + MAX_PAYLOAD);
  assert.equal(frames[0][0], 1); assert.equal(frames[0][1], 1);
  assert.equal(new DataView(frames[0].buffer).getUint32(2), CHANNEL);
  assert.equal(frames[1].length, HEADER_BYTES + 1);
});

test('binary output validates protocol and returns raw bytes', () => {
  const frame = new Uint8Array(HEADER_BYTES + 2); frame.set([1, 2, 0, 0, 0, 1, 0xff, 0]);
  assert.deepEqual([...outputPayload(frame.buffer)], [0xff, 0]);
  assert.throws(() => outputPayload(new Uint8Array([1, 9, 0, 0, 0, 1]).buffer), /INVALID_BINARY_FRAME/);
});

test('control state sequence is strict', () => {
  assert.deepEqual(advance('connecting', 'session_ready'), { phase: 'opening', send: 'open' });
  assert.throws(() => advance('connecting', 'ready'), /UNEXPECTED/);
  assert.throws(() => parseControl('{"v":1,"type":"ready"}'), /INVALID_CHANNEL/);
  assert.equal(parseControl('{"v":1,"type":"pong"}').type, 'pong');
});

test('UTF-8 split across frame boundaries is not decoded or rewritten', () => {
  const payload = new TextEncoder().encode('a'.repeat(MAX_PAYLOAD - 1) + '中文😀');
  const frames = [...inputFrames(payload)];
  const reconstructed = Uint8Array.from(frames.flatMap(frame => [...frame.subarray(HEADER_BYTES)]));
  assert.deepEqual(reconstructed, payload);
  assert.equal(frames[0][MAX_PAYLOAD + HEADER_BYTES - 1], 0xe4);
});

test('stderr and frame limits preserve bytes and reject wrong channels', () => {
  const frame = new Uint8Array([1, 3, 0, 0, 0, 1, 0x80]);
  assert.deepEqual([...outputPayload(frame.buffer)], [0x80]);
  frame[5] = 2;
  assert.throws(() => outputPayload(frame.buffer), /INVALID_BINARY_FRAME/);
  assert.throws(() => outputPayload(new ArrayBuffer(5)), /INVALID_BINARY_FRAME/);
  assert.throws(() => outputPayload(new ArrayBuffer(MAX_PAYLOAD + HEADER_BYTES + 1)), /INVALID_BINARY_FRAME/);
});

test('ready is reached only after actual shell acknowledgement', () => {
  let phase = 'connecting';
  for (const type of ['session_ready', 'opened', 'pty_ready']) phase = advance(phase, type).phase;
  assert.equal(phase, 'shell');
  assert.equal(advance(phase, 'ready').phase, 'streaming');
  assert.throws(() => parseControl('{"v":2,"type":"ready","channel_id":1}'), /INVALID_CONTROL_FRAME/);
  assert.throws(() => parseControl('{"v":1,"type":"error"}'), /INVALID_ERROR/);
  assert.throws(() => streamURL('http://example.test', 'session', false), /HTTPS_REQUIRED/);
  assert.equal(streamURL('https://example.test', 'session', false), 'wss://example.test/api/v1/sessions/session/stream');
});

test('backpressure and websocket URL', () => {
  assert.equal(canSend(256 * 1024 - 1, 1), true);
  assert.equal(canSend(256 * 1024, 1), false);
  assert.equal(streamURL('http://localhost:5173', 's id', true), 'ws://localhost:5173/api/v1/sessions/s%20id/stream');
});
