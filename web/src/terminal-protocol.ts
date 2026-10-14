import { MAX_PAYLOAD, MAX_BUFFER } from './protocol.ts';
export const SSH_STREAM_PROTOCOL = 'bastion.ssh.v1';
export function sizeFrame(cols: number, rows: number): Uint8Array {
  if (!Number.isInteger(cols) || cols < 2 || cols > 500 || !Number.isInteger(rows) || rows < 1 || rows > 200) throw new Error('INVALID_TERMINAL_SIZE');
  return Uint8Array.of(2, cols >> 8, cols & 255, rows >> 8, rows & 255);
}
export function parseTerminalFrame(bytes: Uint8Array): { type: 'data'; bytes: Uint8Array } | { type: 'size'; cols: number; rows: number } | { type: 'ready' } {
  if (bytes.length < 1 || bytes.length > MAX_PAYLOAD) throw new Error('INVALID_TERMINAL_FRAME');
  if (bytes[0] === 1 && bytes.length > 1) return { type: 'data', bytes: bytes.subarray(1) };
  if (bytes[0] === 2 && bytes.length === 5) { const cols = bytes[1] * 256 + bytes[2], rows = bytes[3] * 256 + bytes[4]; sizeFrame(cols, rows); return { type: 'size', cols, rows }; }
  if (bytes[0] === 3 && bytes.length === 1) return { type: 'ready' };
  throw new Error('INVALID_TERMINAL_FRAME');
}
export function dataFrames(bytes: Uint8Array, buffered: number): Uint8Array[] {
  const count = Math.ceil(bytes.length / (MAX_PAYLOAD - 1));
  if (bytes.length + count + buffered > MAX_BUFFER) throw new Error('INPUT_BACKPRESSURE：输入未发送，不会自动重放。');
  const result: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.length; offset += MAX_PAYLOAD - 1) { const chunk = bytes.subarray(offset, offset + MAX_PAYLOAD - 1), frame = new Uint8Array(chunk.length + 1); frame[0] = 1; frame.set(chunk, 1); result.push(frame); }
  return result;
}
export function ackFrame(size: number): Uint8Array { const bytes = new Uint8Array(5); bytes[0] = 4; new DataView(bytes.buffer).setUint32(1, size); return bytes; }
