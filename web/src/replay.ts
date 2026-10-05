import { MAX_PAYLOAD } from './protocol.ts';
export const MAX_REPLAY_LINE = 256 * 1024;
export type ReplayEvent = { type: 'meta' | 'output' | 'resize' | 'exit' | 'end'; seq: number; elapsed_us: number; format_version?: number; term?: string; cols?: number; rows?: number; stream?: 'stdout' | 'stderr'; data_base64?: string; exit_code?: number | null; exit_signal?: string | null; reason?: string };
export function decodeBase64(text: string): Uint8Array {
  if (text.length > Math.ceil(MAX_PAYLOAD / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new Error('INVALID_REPLAY_BYTES');
  const raw = atob(text), bytes = Uint8Array.from(raw, char => char.charCodeAt(0));
  if (bytes.length > MAX_PAYLOAD || btoa(raw) !== text) throw new Error('INVALID_REPLAY_BYTES');
  return bytes;
}
export class ReplaySequence {
  next = 0; elapsed = 0; ended = false;
  parse(line: string): ReplayEvent {
    if (new TextEncoder().encode(line).length > MAX_REPLAY_LINE) throw new Error('REPLAY_LINE_TOO_LARGE');
    const event = JSON.parse(line) as ReplayEvent;
    if (!event || typeof event !== 'object' || this.ended || event.seq !== this.next || !Number.isSafeInteger(event.elapsed_us) || event.elapsed_us < this.elapsed) throw new Error('INVALID_REPLAY_SEQUENCE');
    if (this.next === 0 && event.type !== 'meta' || this.next > 0 && event.type === 'meta') throw new Error('INVALID_REPLAY_META');
    if (['meta', 'resize'].includes(event.type)) {
      if (![event.cols, event.rows].every(value => Number.isInteger(value) && value! > 0 && value! <= 4096)) throw new Error('INVALID_REPLAY_SIZE');
      if (event.type === 'meta' && (event.format_version !== 1 || typeof event.term !== 'string' || event.term.length > 128)) throw new Error('INVALID_REPLAY_META');
    } else if (event.type === 'output') {
      if (!['stdout', 'stderr'].includes(event.stream ?? '') || typeof event.data_base64 !== 'string') throw new Error('INVALID_REPLAY_OUTPUT'); decodeBase64(event.data_base64);
    } else if (event.type === 'exit') {
      const code = event.exit_code !== undefined && event.exit_code !== null, signal = event.exit_signal !== undefined && event.exit_signal !== null;
      if (code === signal || code && (!Number.isInteger(event.exit_code) || event.exit_code! < 0) || signal && typeof event.exit_signal !== 'string') throw new Error('INVALID_REPLAY_EXIT');
    } else if (event.type === 'end') {
      if (typeof event.reason !== 'string' || !event.reason || event.reason.length > 512) throw new Error('INVALID_REPLAY_END'); this.ended = true;
    } else throw new Error('UNKNOWN_REPLAY_EVENT');
    this.next++; this.elapsed = event.elapsed_us; return event;
  }
  finish() { if (!this.ended) throw new Error('PARTIAL_RECORDING：未收到有效 end，不能认为回放完整。'); }
}
export async function readNDJSON(response: Response, signal: AbortSignal, consume: (line: string) => Promise<void>): Promise<void> {
  if (!response.headers.get('Content-Type')?.split(';')[0].trim().includes('application/x-ndjson') || !response.body) throw new Error('INVALID_REPLAY_RESPONSE');
  const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true }); let pending = '';
  const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
  try {
    for (;;) {
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
      const chunk = await reader.read(); if (chunk.done) break;
      // Decode bounded pieces; a transport chunk itself is not assumed to be bounded.
      for (let offset = 0; offset < chunk.value.length; offset += 32768) {
        pending += decoder.decode(chunk.value.subarray(offset, offset + 32768), { stream: true });
        let newline: number;
        while ((newline = pending.indexOf('\n')) >= 0) { const line = pending.slice(0, newline); pending = pending.slice(newline + 1); if (!line) throw new Error('INVALID_EMPTY_REPLAY_EVENT'); await consume(line); }
        if (new TextEncoder().encode(pending).length > MAX_REPLAY_LINE) throw new Error('REPLAY_LINE_TOO_LARGE');
      }
    }
    pending += decoder.decode(); if (pending) throw new Error('PARTIAL_RECORDING：结尾缺少 NDJSON 换行。');
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
  } finally { signal.removeEventListener('abort', cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
}
