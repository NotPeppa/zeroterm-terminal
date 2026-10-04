export const CHANNEL = 1;
export const MAX_PAYLOAD = 32 * 1024;
export const MAX_BUFFER = 256 * 1024;
export const HEADER_BYTES = 6;
export const MAX_CONTROL_BYTES = 8192;

export function requireHTTPS(protocol: string, development: boolean): void {
  if (protocol !== 'https:' && !development) throw new Error('HTTPS_REQUIRED：生产请求必须使用 HTTPS。');
}

export function inputFrame(payload: Uint8Array): Uint8Array {
  if (!payload.length || payload.length > MAX_PAYLOAD) throw new Error('INVALID_FRAME_SIZE');
  const frame = new Uint8Array(HEADER_BYTES + payload.length);
  frame[0] = 1;
  frame[1] = 1;
  new DataView(frame.buffer).setUint32(2, CHANNEL, false);
  frame.set(payload, HEADER_BYTES);
  return frame;
}

export function* inputFrames(payload: Uint8Array): Generator<Uint8Array> {
  for (let offset = 0; offset < payload.length; offset += MAX_PAYLOAD) {
    yield inputFrame(payload.subarray(offset, offset + MAX_PAYLOAD));
  }
}

export function outputPayload(buffer: ArrayBuffer): Uint8Array {
  const frame = new Uint8Array(buffer);
  if (frame.length < HEADER_BYTES || frame.length > HEADER_BYTES + MAX_PAYLOAD ||
      frame[0] !== 1 || (frame[1] !== 2 && frame[1] !== 3) ||
      new DataView(buffer).getUint32(2, false) !== CHANNEL) {
    throw new Error('INVALID_BINARY_FRAME');
  }
  return frame.subarray(HEADER_BYTES);
}

export function canSend(bufferedAmount: number, frameBytes: number): boolean {
  return bufferedAmount + frameBytes <= MAX_BUFFER;
}

export type Control = {
  v: 1;
  type: string;
  channel_id?: number;
  connection_id?: string;
  code?: string;
  request_id?: string;
  exit_code?: number;
  exit_signal?: string;
};

export function parseControl(text: string): Control {
  if (new TextEncoder().encode(text).length > MAX_CONTROL_BYTES) throw new Error('CONTROL_FRAME_TOO_LARGE');
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== 'object') throw new Error('INVALID_CONTROL_FRAME');
  const frame = value as Control;
  if (frame.v !== 1 || typeof frame.type !== 'string' ||
      (frame.channel_id !== undefined && frame.channel_id !== CHANNEL)) {
    throw new Error('INVALID_CONTROL_FRAME');
  }
  if (['opened', 'pty_ready', 'ready', 'exit', 'closed'].includes(frame.type) && frame.channel_id !== CHANNEL) {
    throw new Error('INVALID_CHANNEL');
  }
  if (frame.type === 'session_ready' && typeof frame.connection_id !== 'string') throw new Error('INVALID_CONNECTION');
  if (frame.type === 'error' && typeof frame.code !== 'string') throw new Error('INVALID_ERROR');
  if (frame.request_id !== undefined && typeof frame.request_id !== 'string') throw new Error('INVALID_REQUEST_ID');
  if (frame.exit_code !== undefined && (!Number.isInteger(frame.exit_code) || frame.exit_code < 0)) throw new Error('INVALID_EXIT');
  if (frame.exit_signal !== undefined && typeof frame.exit_signal !== 'string') throw new Error('INVALID_EXIT');
  return frame;
}

export type Phase = 'connecting' | 'opening' | 'pty' | 'shell' | 'streaming';

export function advance(phase: Phase, type: string): { phase: Phase; send?: 'open' | 'pty' | 'shell' } {
  if (phase === 'connecting' && type === 'session_ready') return { phase: 'opening', send: 'open' };
  if (phase === 'opening' && type === 'opened') return { phase: 'pty', send: 'pty' };
  if (phase === 'pty' && type === 'pty_ready') return { phase: 'shell', send: 'shell' };
  if (phase === 'shell' && type === 'ready') return { phase: 'streaming' };
  throw new Error('UNEXPECTED_CONTROL_SEQUENCE');
}

export function streamURL(origin: string, sessionId: string, development: boolean): string {
  const url = new URL(`/api/v1/sessions/${encodeURIComponent(sessionId)}/stream`, origin);
  if (url.protocol === 'https:') url.protocol = 'wss:';
  else if (url.protocol === 'http:' && development) url.protocol = 'ws:';
  else throw new Error('HTTPS_REQUIRED');
  return url.href;
}
