import { MAX_PAYLOAD } from './protocol.ts';
export const MAX_REPLAY_LINE = 256 * 1024;
export type ReplayEvent = { type: 'meta' | 'output' | 'end'; seq: number; elapsed_us: number; format_version?: number; connection_id?: string; target_protocol?: 'ssh' | 'rdp' | 'vnc'; stream_protocol?: 'bastion.guac.v1' | 'bastion.ssh.v1'; width?: number; height?: number; dpi?: number; data_base64?: string; reason?: string };
export function decodeBase64(text: string): Uint8Array {
  if (!text || text.length > Math.ceil(MAX_PAYLOAD / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new Error('INVALID_REPLAY_BYTES');
  const raw = atob(text), bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
  if (bytes.length > MAX_PAYLOAD || btoa(raw) !== text) throw new Error('INVALID_REPLAY_BYTES');
  return bytes;
}
export class ReplaySequence {
  next = 0; elapsed = 0; ended = false;
  private connectionId?: string;
  constructor(connectionId?: string) { this.connectionId = connectionId; }
  parse(line: string): ReplayEvent {
    if (new TextEncoder().encode(line).length > MAX_REPLAY_LINE) throw new Error('REPLAY_LINE_TOO_LARGE');
    const event = JSON.parse(line) as ReplayEvent;
    if (!event || typeof event !== 'object' || this.ended || event.seq !== this.next || !Number.isSafeInteger(event.elapsed_us) || event.elapsed_us < this.elapsed) throw new Error('INVALID_REPLAY_SEQUENCE');
    if (this.next === 0 && event.type !== 'meta' || this.next > 0 && event.type === 'meta') throw new Error('INVALID_REPLAY_META');
    if (event.type === 'meta') {
      if (event.stream_protocol !== undefined && event.stream_protocol !== 'bastion.guac.v1' && !(event.stream_protocol === 'bastion.ssh.v1' && event.target_protocol === 'ssh')) throw new Error('INVALID_REPLAY_STREAM');
      if (event.format_version !== 2 || event.elapsed_us !== 0 || typeof event.connection_id !== 'string' || !event.connection_id || this.connectionId && event.connection_id !== this.connectionId || !['ssh', 'rdp', 'vnc'].includes(event.target_protocol ?? '') || !Number.isInteger(event.width) || event.width! < 1 || event.width! > 3840 || !Number.isInteger(event.height) || event.height! < 1 || event.height! > 2160 || !Number.isInteger(event.dpi) || event.dpi! < 48 || event.dpi! > 192) throw new Error('INVALID_REPLAY_META');
    } else if (event.type === 'output') {
      if (typeof event.data_base64 !== 'string') throw new Error('INVALID_REPLAY_OUTPUT'); decodeBase64(event.data_base64);
    } else if (event.type === 'end') {
      if (typeof event.reason !== 'string' || !event.reason || event.reason.length > 512) throw new Error('INVALID_REPLAY_END'); this.ended = true;
    } else throw new Error('UNKNOWN_REPLAY_EVENT');
    this.next++; this.elapsed = event.elapsed_us; return event;
  }
  finish() { if (!this.ended) throw new Error('PARTIAL_RECORDING：未收到有效 end，不能认为回放完整。'); }
}
export async function readNDJSON(response: Response, signal: AbortSignal, consume: (line: string) => Promise<void>): Promise<void> {
  if (response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/x-ndjson' || !response.body) throw new Error('INVALID_REPLAY_RESPONSE');
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true }); let pending = '';
  const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
      const chunk = await reader.read(); if (chunk.done) break;
      for (let offset = 0; offset < chunk.value.length; offset += MAX_PAYLOAD) {
        pending += decoder.decode(chunk.value.subarray(offset, offset + MAX_PAYLOAD), { stream: true });
        let newline: number;
        while ((newline = pending.indexOf('\n')) >= 0) { const line = pending.slice(0, newline); pending = pending.slice(newline + 1); if (!line) throw new Error('INVALID_EMPTY_REPLAY_EVENT'); await consume(line); }
        if (new TextEncoder().encode(pending).length > MAX_REPLAY_LINE) throw new Error('REPLAY_LINE_TOO_LARGE');
      }
    }
    pending += decoder.decode(); if (pending) throw new Error('PARTIAL_RECORDING：结尾缺少 NDJSON 换行。');
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
  } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
