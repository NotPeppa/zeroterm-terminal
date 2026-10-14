import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon } from '@xterm/addon-search';
import '@xterm/xterm/css/xterm.css';
import { ApiClient, ApiError } from './api';
import { RouteLifetime, type SessionState } from './state';
import type { Target } from './guac';
import { MAX_BUFFER, streamURL } from './protocol';
import { SSH_STREAM_PROTOCOL, ackFrame, dataFrames, parseTerminalFrame, sizeFrame } from './terminal-protocol';

const options = { fontFamily: 'Consolas, "Cascadia Mono", "Noto Sans Mono", monospace', fontSize: 15, scrollback: 10000, theme: { background: '#10141b', foreground: '#dce3ee', cursor: '#dce3ee', selectionBackground: '#4b638c88' } };
export class OfflineTerminalClient {
  readonly terminal = new Terminal({ ...options, disableStdin: true });
  constructor(parent: HTMLElement, private signal: AbortSignal) { this.terminal.open(parent); }
  async feed(bytes: Uint8Array) {
    if (this.signal.aborted) throw new DOMException('Aborted', 'AbortError');
    const frame = parseTerminalFrame(bytes);
    if (frame.type === 'ready') throw new Error('REPLAY_READY_FORBIDDEN');
    if (frame.type === 'size') { this.terminal.resize(frame.cols, frame.rows); return; }
    await new Promise<void>((resolve, reject) => {
      const abort = () => reject(new DOMException('Aborted', 'AbortError'));
      this.signal.addEventListener('abort', abort, { once: true });
      this.terminal.write(frame.bytes, () => { this.signal.removeEventListener('abort', abort); if (this.signal.aborted) abort(); else resolve(); });
    });
  }
  finish() {}
  close() { this.terminal.dispose(); }
}

export function mountTerminalSession(parent: HTMLElement, api: ApiClient, life: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown, target?: Target) => void, enabled: (target: Target) => boolean, prepare?: (target: Target) => Promise<boolean>, state?: (value: SessionState) => void): () => void {
  const toolbar = document.createElement('div'); toolbar.className = 'toolbar';
  const viewport = document.createElement('div'); viewport.className = 'terminal-viewport'; viewport.setAttribute('aria-label', 'SSH 文本终端');
  const hint = document.createElement('p'); hint.className = 'hint'; hint.textContent = 'SSH · xterm.js：拖动选择文本，Ctrl+Shift+C 复制，Ctrl+Shift+V / Ctrl+V 粘贴，Ctrl+Shift+F 搜索；Shift+拖动可在远端启用鼠标时选择。搜索当前 10000 行滚动缓冲。粘贴文本会作为终端输入执行。';
  parent.append(toolbar, viewport, hint);
  // Toolbar stays flat so the shell can drive the session buttons by data-session, never by position.
  const button = (text: string, action: () => void, className = '', session = '') => { const b = document.createElement('button'); b.type = 'button'; b.textContent = text; b.onclick = action; if (className) b.className = className; if (session) b.setAttribute('data-session', session); toolbar.append(b); return b; };
  const separator = () => { const mark = document.createElement('span'); mark.className = 'toolbar-sep'; mark.setAttribute('aria-hidden', 'true'); toolbar.append(mark); };
  let terminal: Terminal | null = null, fit: FitAddon | null = null, search: SearchAddon | null = null;
  let socket: WebSocket | null = null, pending: AbortController | null = null, bound: Target | null = null, ready = false, preparing = false, generation = 0;
  let timer: ReturnType<typeof setTimeout> | undefined, resizeTimer: ReturnType<typeof setTimeout> | undefined, requestedSize = '', connectionId = '';
  function close(graceful = true) {
    ++generation; pending?.abort(); pending = null; clearTimeout(timer); clearTimeout(resizeTimer);
    if (socket) { socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null; socket.close(graceful ? 1000 : 1002); socket = null; }
    terminal?.dispose(); terminal = null; fit = search = null; viewport.replaceChildren(); ready = false; bound = null; update();
  }
  function update() { const target = getTarget(); if (bound && (!target || bound.asset.id !== target.asset.id || bound.account.id !== target.account.id)) close(); connect.disabled = preparing || !!socket || !!pending || !target || !enabled(target); disconnect.disabled = !socket && !pending; state?.(preparing || pending || socket && !ready ? 'connecting' : ready ? 'ready' : bound ? 'closed' : 'idle'); }
  function send(bytes: Uint8Array) { if (!ready || socket?.readyState !== WebSocket.OPEN) return; if (socket.bufferedAmount + bytes.length > MAX_BUFFER) throw new Error('INPUT_BACKPRESSURE'); socket.send(bytes); }
  function input(bytes: Uint8Array) { if (!ready || socket?.readyState !== WebSocket.OPEN) return; try { for (const frame of dataFrames(bytes, socket.bufferedAmount)) socket.send(frame); } catch (error) { const target = bound; close(false); fail(error, target ?? undefined); } }
  function fitTerminal() {
    if (!terminal || !fit || life.signal.aborted) return;
    const proposed = fit.proposeDimensions();
    if (!proposed || proposed.cols < 2 || proposed.rows < 1) return;
    const cols = Math.min(500, proposed.cols), rows = Math.min(200, proposed.rows);
    if (terminal.cols !== cols || terminal.rows !== rows) terminal.resize(cols, rows);
    const size = `${cols}x${rows}`;
    if (ready && requestedSize !== size) { try { send(sizeFrame(cols, rows)); requestedSize = size; } catch (error) { close(false); fail(error); } }
  }
  function scheduleFit() { clearTimeout(resizeTimer); resizeTimer = setTimeout(fitTerminal, 100); }
  let lastInteraction = 0;
  const interaction = (event: Event) => {
    if (!event.isTrusted || !ready || Date.now() - lastInteraction < 1000) return;
    lastInteraction = Date.now(); try { send(Uint8Array.of(5)); } catch (error) { close(false); fail(error); }
  };
  for (const name of ['keydown', 'paste', 'compositionend', 'pointerdown', 'wheel']) viewport.addEventListener(name, interaction, true);
  async function start() {
    const target = getTarget(); if (!target || !enabled(target) || preparing || socket || pending || life.signal.aborted) return;
    preparing = true; update();
    try {
      if (prepare && !await prepare(target)) return;
      if (life.signal.aborted || getTarget()?.asset.id !== target.asset.id || getTarget()?.account.id !== target.account.id) return;
      close(); bound = target; const run = generation, controller = new AbortController(); pending = controller;
      const signal = AbortSignal.any([controller.signal, life.signal]), owns = () => run === generation && !signal.aborted;
      terminal = new Terminal({ ...options, fontSize: Number(font.value), disableStdin: true }); fit = new FitAddon(); search = new SearchAddon(); terminal.loadAddon(fit); terminal.loadAddon(search); terminal.open(viewport); fitTerminal();
      const current = terminal;
      current.onData(data => { if (owns()) input(new TextEncoder().encode(data)); });
      current.onBinary(data => { if (owns()) input(Uint8Array.from(data, char => char.charCodeAt(0))); });
      current.attachCustomKeyEventHandler(event => {
        if ((event.ctrlKey || event.metaKey) && event.shiftKey && ['c','f','v'].includes(event.key.toLowerCase())) {
          if (event.type === 'keydown') { event.preventDefault(); if (event.key.toLowerCase() === 'c') copy(); else if (event.key.toLowerCase() === 'f') query.focus(); else paste(); }
          return false;
        }
        // xterm maps plain Ctrl+V to ^V and swallows the native paste; hand it back to the browser so xterm's paste handler runs.
        if (event.ctrlKey && !event.shiftKey && !event.altKey && !event.metaKey && event.key.toLowerCase() === 'v') return false;
        return true;
      });
      const ticket = await api.session(target.asset.id, target.account.id, { width: Math.min(3840, Math.max(1, viewport.offsetWidth)), height: Math.min(2160, Math.max(1, viewport.offsetHeight)), dpi: 96 }, signal);
      if (!owns()) { ticket.ws_token = ''; return; }
      if (ticket.target_protocol !== 'ssh' || ticket.stream_protocol !== SSH_STREAM_PROTOCOL) { ticket.ws_token = ''; throw new Error('CLIENT_PROTOCOL_UNSUPPORTED'); }
      connectionId = ticket.connection_id;
      let ws: WebSocket; try { ws = new WebSocket(streamURL(location.origin, ticket.session_id, import.meta.env.DEV), [SSH_STREAM_PROTOCOL, ticket.ws_token]); } finally { ticket.ws_token = ''; }
      socket = ws; pending = null; ws.binaryType = 'arraybuffer'; let queued = 0;
      const reject = (error: unknown) => { if (owns()) { close(false); fail(error, target); } };
      timer = setTimeout(() => reject(new Error('START_TIMEOUT')), 45000);
      ws.onopen = () => { if (!owns()) return; if (ws.protocol !== SSH_STREAM_PROTOCOL) { reject(new Error('CLIENT_PROTOCOL_UNSUPPORTED')); return; } try { ws.send(sizeFrame(current.cols,current.rows)); } catch (error) { reject(error); return; } status('正在校验 SSH 主机身份并建立终端…'); };
      ws.onmessage = event => {
        if (!owns()) return;
        try {
          if (!(event.data instanceof ArrayBuffer)) throw new Error('BINARY_SSH_REQUIRED');
          const bytes = new Uint8Array(event.data), frame = parseTerminalFrame(bytes);
          if (frame.type === 'ready') { if (ready) throw new Error('DUPLICATE_READY'); clearTimeout(timer); ready = true; current.options.disableStdin = false; requestedSize = ''; fitTerminal(); current.focus(); status(`SSH 终端已就绪 · ${connectionId}`); update(); }
          else if (frame.type === 'size') { current.resize(frame.cols, frame.rows); }
          else {
            if (!ready || queued + bytes.length > MAX_BUFFER) throw new Error('OUTPUT_BACKPRESSURE');
            queued += bytes.length; current.write(frame.bytes, () => { if (owns()) { queued -= bytes.length; try { send(ackFrame(bytes.length)); } catch (error) { reject(error); } } });
          }
        } catch (error) { reject(error); }
      };
      ws.onerror = () => { if (owns()) status('网络失败，等待连接诊断；请手动重连。'); };
      ws.onclose = () => {
        if (!owns()) return; clearTimeout(timer); socket = null; ready = false; current.options.disableStdin = true; update(); status('SSH 已断开；终端内容保留，可选择和搜索。手动重连使用新票据。');
        void api.connection(connectionId, life.signal).then(value => { if (owns() && value.failure) fail(new ApiError(value.failure.code, value.failure.message ?? 'SSH 连接失败'), target); }).catch(error => { if (owns()) fail(error, target); });
      };
    } catch (error) { if (!life.signal.aborted) { close(false); fail(error, target); } }
    finally { preparing = false; if (!life.signal.aborted) update(); }
  }
  const connect = button('连接 / 手动新票据重连', () => { void start(); }, 'primary', 'connect');
  const disconnect = button('断开', () => close(), '', 'disconnect');
  separator();
  function copy() { const text = terminal?.getSelection(); if (!text) { status('请先拖动选择要复制的文本。'); return; } if (!navigator.clipboard?.writeText) { status('请使用 Ctrl+C 或右键复制选中文本。'); return; } void navigator.clipboard.writeText(text).then(() => { if (!life.signal.aborted) status('已复制选中文本。'); }).catch(() => { if (!life.signal.aborted) status('浏览器未授权复制，请使用 Ctrl+C 或右键复制选中文本。'); }); }
  function paste() { const run = generation, current = terminal; if (!ready || !current) return; if (!navigator.clipboard?.readText) { status('请聚焦终端并按 Ctrl+V 粘贴。'); return; } void navigator.clipboard.readText().then(text => { if (run === generation && !life.signal.aborted && ready) { const encoded = new TextEncoder().encode(text); dataFrames(encoded, socket?.bufferedAmount ?? 0); if (text) { send(Uint8Array.of(5)); lastInteraction = Date.now(); } current.paste(text); } }).catch(error => { if (run === generation && !life.signal.aborted) fail(error); }); }
  button('复制选中', copy); button('粘贴', paste);
  separator();
  const query = document.createElement('input'); query.type = 'search'; query.placeholder = '搜索终端文本'; query.setAttribute('aria-label', '搜索终端文本'); toolbar.append(query);
  const find = (previous: boolean) => { if (!search || !query.value) return; const found = previous ? search.findPrevious(query.value) : search.findNext(query.value); status(found ? '已定位匹配文本。' : '当前终端缓冲中没有匹配文本。'); };
  query.onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); find(event.shiftKey); } if (event.key === 'Escape') terminal?.focus(); };
  button('上一个', () => find(true)); button('下一个', () => find(false));
  separator();
  const font = document.createElement('select'); font.setAttribute('aria-label', '终端字号'); for (const size of [12, 14, 15, 16, 18, 20, 24]) font.append(new Option(`${size}px`, String(size))); font.value = '15'; toolbar.append(font);
  font.onchange = () => { if (terminal) { terminal.options.fontSize = Number(font.value); fitTerminal(); } };
  const observer = new ResizeObserver(scheduleFit); observer.observe(viewport);
  life.own(() => { observer.disconnect(); for (const name of ['keydown', 'paste', 'compositionend', 'pointerdown', 'wheel']) viewport.removeEventListener(name, interaction, true); close(); toolbar.remove(); hint.remove(); }); update(); return update;
}
