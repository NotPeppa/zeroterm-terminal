export const STREAM_PROTOCOL = 'bastion.guac.v1';
export const MAX_PAYLOAD = 32 * 1024;
export const MAX_BUFFER = 256 * 1024;
export const MAX_INSTRUCTION = 8 * 1024 * 1024;
export const MAX_CLIPBOARD = 256 * 1024;
export type DisplaySize = { width: number; height: number; dpi: number };
export const DEFAULT_DISPLAY: DisplaySize = { width: 1280, height: 720, dpi: 96 };
export function validateDisplay(value: DisplaySize): DisplaySize {
  if (!value || !Number.isInteger(value.width) || value.width < 1 || value.width > 3840 || !Number.isInteger(value.height) || value.height < 1 || value.height > 2160 || !Number.isInteger(value.dpi) || value.dpi < 48 || value.dpi > 192) throw new Error('INVALID_DISPLAY');
  return value;
}
export function requireHTTPS(protocol: string, development: boolean): void {
  if (protocol !== 'https:' && !development) throw new Error('HTTPS_REQUIRED：生产请求必须使用 HTTPS。');
}
export function serializeInstruction(elements: string[]): string {
  for (const value of elements) if (!value.isWellFormed()) throw new Error('INVALID_UNICODE');
  const text = elements.map(value => `${Array.from(value).length}.${value}`).join(',') + ';';
  if (new TextEncoder().encode(text).length > MAX_INSTRUCTION) throw new Error('INSTRUCTION_TOO_LARGE');
  return text;
}
export function streamURL(origin: string, sessionId: string, development: boolean): string {
  const url = new URL(`/api/v1/sessions/${encodeURIComponent(sessionId)}/stream`, origin);
  if (url.protocol === 'https:') url.protocol = 'wss:';
  else if (url.protocol === 'http:' && development && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) url.protocol = 'ws:';
  else throw new Error('HTTPS_REQUIRED');
  return url.href;
}
/** Stream creation is forbidden by purpose, not by blob/ack/end opcodes. */
export function validateInstruction(opcode: string, args: string[]): void {
  if (['audio', 'video', 'file', 'pipe', 'filesystem', 'connect', 'select', 'args', 'nest'].includes(opcode)) throw new Error('FORBIDDEN_GUAC_INSTRUCTION');
  if (opcode === 'clipboard' && (args.length !== 2 || !/^[0-9]+$/.test(args[0]) || Number(args[0]) > 0x7fffffff || args[1] !== 'text/plain')) throw new Error('FORBIDDEN_CLIPBOARD_TYPE');
  if (opcode === 'size' && args[0] === '0' && (!Number.isInteger(Number(args[1])) || Number(args[1]) < 1 || Number(args[1]) > 3840 || !Number.isInteger(Number(args[2])) || Number(args[2]) < 1 || Number(args[2]) > 2160)) throw new Error('INVALID_DISPLAY');
}
