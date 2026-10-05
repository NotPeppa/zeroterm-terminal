import { strict as assert } from 'node:assert';
import test from 'node:test';
import { decodeBase64, readNDJSON, ReplaySequence } from '../src/replay.ts';
const meta = { type: 'meta', seq: 0, elapsed_us: 0, format_version: 1, term: 'xterm-256color', cols: 80, rows: 24 };

test('strict readonly replay sequence preserves stdout and stderr raw bytes', () => {
  const sequence = new ReplaySequence(); sequence.parse(JSON.stringify(meta));
  const event = sequence.parse(JSON.stringify({ type: 'output', seq: 1, elapsed_us: 1, stream: 'stderr', data_base64: '/wA=' }));
  assert.deepEqual([...decodeBase64(event.data_base64)], [255, 0]);
  sequence.parse(JSON.stringify({ type: 'exit', seq: 2, elapsed_us: 2, exit_code: 7 })); sequence.parse(JSON.stringify({ type: 'end', seq: 3, elapsed_us: 3, reason: 'closed' })); sequence.finish();
  assert.throws(() => sequence.parse(JSON.stringify({ type: 'end', seq: 4, elapsed_us: 4, reason: 'closed' })), /INVALID_REPLAY_SEQUENCE/);
});

test('missing end, bad sequence, backward time, invalid bytes and dual exit are rejected', () => {
  const sequence = new ReplaySequence(); sequence.parse(JSON.stringify(meta)); assert.throws(() => sequence.finish(), /PARTIAL/);
  assert.throws(() => sequence.parse(JSON.stringify({ type: 'end', seq: 2, elapsed_us: 0, reason: 'closed' })), /SEQUENCE/);
  assert.throws(() => decodeBase64('!!!!'), /BYTES/); assert.throws(() => decodeBase64('AA=='.repeat(9000)), /BYTES/);
  assert.throws(() => sequence.parse(JSON.stringify({ type: 'exit', seq: 1, elapsed_us: 1, exit_code: 0, exit_signal: 'TERM' })), /EXIT/);
  sequence.parse(JSON.stringify({ type: 'resize', seq: 1, elapsed_us: 4, cols: 100, rows: 30 })); assert.throws(() => sequence.parse(JSON.stringify({ type: 'end', seq: 2, elapsed_us: 3, reason: 'closed' })), /SEQUENCE/);
});

test('NDJSON handles split UTF-8 and refuses non-newline tails', async () => {
  const bytes = new TextEncoder().encode(JSON.stringify({ ...meta, term: '中文' }) + '\n' + JSON.stringify({ type: 'end', seq: 1, elapsed_us: 1, reason: 'closed' }) + '\n');
  const body = new ReadableStream({ start(controller) { for (let index = 0; index < bytes.length; index++) controller.enqueue(bytes.slice(index, index + 1)); controller.close(); } });
  const response = new Response(body, { headers: { 'Content-Type': 'application/x-ndjson' } }), sequence = new ReplaySequence(); await readNDJSON(response, new AbortController().signal, async line => { sequence.parse(line); }); sequence.finish();
  await assert.rejects(readNDJSON(new Response('{}', { headers: { 'Content-Type': 'application/x-ndjson' } }), new AbortController().signal, async () => {}), /PARTIAL/);
});
