import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTerminalFrame, sizeFrame, dataFrames, ackFrame } from '../src/terminal-protocol.ts';
import { MAX_PAYLOAD, MAX_BUFFER } from '../src/protocol.ts';
import { ReplaySequence } from '../src/replay.ts';

test('PTY byte frames preserve Chinese, emoji and escape sequences across chunk boundaries', () => {
  const bytes = new TextEncoder().encode('中😀\x1b[31m'.repeat(9000)), frames = dataFrames(bytes, 0);
  assert(frames.every(frame => frame.length <= MAX_PAYLOAD));
  assert.deepEqual(Buffer.concat(frames.map(frame => Buffer.from(parseTerminalFrame(frame).bytes))), Buffer.from(bytes));
  assert.deepEqual(parseTerminalFrame(sizeFrame(120, 40)), {type:'size',cols:120,rows:40});
  assert.equal(new DataView(ackFrame(123).buffer).getUint32(1), 123);
});
test('invalid frame, size and paste overload reject without truncation', () => {
  for (const frame of [[],[1],[2,0,80],[2,0,0,0,24],[2,1,245,0,24],[3,0],[4,0,0,0,1],[9]]) assert.throws(() => parseTerminalFrame(Uint8Array.from(frame)));
  assert.throws(() => dataFrames(new Uint8Array(MAX_BUFFER), 0), /BACKPRESSURE/);
  assert.throws(() => dataFrames(Uint8Array.of(1,2), MAX_BUFFER-2), /BACKPRESSURE/);
  assert.throws(() => sizeFrame(501,24)); assert.throws(() => sizeFrame(80,201));
});
test('recording renderer is selected from authenticated meta and terminal is limited to SSH', () => {
  const meta={type:'meta',seq:0,elapsed_us:0,format_version:2,connection_id:'c',target_protocol:'ssh',width:1280,height:720,dpi:96,stream_protocol:'bastion.ssh.v1'};
  assert.equal(new ReplaySequence('c').parse(JSON.stringify(meta)).stream_protocol, 'bastion.ssh.v1');
  for (const value of [{...meta,target_protocol:'rdp'},{...meta,stream_protocol:'unknown'}]) assert.throws(() => new ReplaySequence('c').parse(JSON.stringify(value)),/REPLAY_STREAM/);
});
