import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import type { ApiClient, Asset, Account, Capability } from './api';
import { ApiError } from './api';
import { advance, canSend, CHANNEL, inputFrames, MAX_BUFFER, outputFrame, parseControl, streamURL, encodeControl, type Phase } from './protocol';
import type { RouteLifetime } from './state';

export type Target = { asset: Asset; account: Account };
export class TargetSocket {
  socket: WebSocket | null = null;
  connectionId = '';
  private pending: AbortController | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private heartbeat: ReturnType<typeof setInterval> | undefined;
  private awaitingPong = false;
  private generation = 0;
  private api: ApiClient;
  private lifetime: RouteLifetime;
  private status: (text: string) => void;
  private fail: (error: unknown) => void;
  constructor(api: ApiClient, lifetime: RouteLifetime, status: (text: string) => void, fail: (error: unknown) => void) {
    this.api = api; this.lifetime = lifetime; this.status = status; this.fail = fail;
    lifetime.own(() => this.close());
  }
  get active() { return !!this.socket || !!this.pending; }
  close() {
    ++this.generation; this.pending?.abort(); this.pending = null;
    clearTimeout(this.timer); clearInterval(this.heartbeat); this.awaitingPong = false;
    const current = this.socket; this.socket = null;
    if (current) { current.onopen = current.onmessage = current.onclose = current.onerror = null; current.close(1000, 'client close'); }
  }
  send(value: object) {
    const current = this.socket;
    if (!current || current.readyState !== WebSocket.OPEN) return false;
    const text = encodeControl(value);
    if (!canSend(current.bufferedAmount, new TextEncoder().encode(text).length)) throw new Error('BACKPRESSURE：发送队列超过 256 KiB；不会静默丢弃或重放。');
    current.send(text); return true;
  }
  input(bytes: Uint8Array, channel = CHANNEL) {
    const current = this.socket; if (!current || current.readyState !== WebSocket.OPEN) return;
    let sent = 0;
    for (const frame of inputFrames(bytes, channel)) {
      if (!canSend(current.bufferedAmount, frame.length)) throw new Error(`BACKPRESSURE：${bytes.length} 字节输入已提交 ${sent} 字节，其余未发送。`);
      current.send(frame); sent += frame.length - 6;
    }
  }
  async connect(target: Target, capability: Capability, onControl: (frame: ReturnType<typeof parseControl>) => void, onOutput: (frame: ReturnType<typeof outputFrame>) => void, onClose: () => void) {
    if (this.active) return;
    const generation = ++this.generation, controller = new AbortController(); this.pending = controller;
    const signal = AbortSignal.any([controller.signal, this.lifetime.signal]);
    this.status(`申请 ${capability} 新会话：${target.asset.name} (${target.asset.id}) / ${target.account.username} (${target.account.id})`);
    try {
      const ticket = await this.api.session(target.asset.id, target.account.id, capability, capability === 'sftp' ? 'sftp' : capability === 'exec' ? 'server_tool' : 'terminal', signal);
      if (signal.aborted || generation !== this.generation) { ticket.ws_token = ''; return; }
      this.connectionId = ticket.connection_id;
      const current = new WebSocket(streamURL(location.origin, ticket.session_id, import.meta.env.DEV), ['bastion.v1', ticket.ws_token]);
      ticket.ws_token = ''; this.socket = current; this.pending = null; current.binaryType = 'arraybuffer';
      let ready = false, reported = false;
      const failed = (error: unknown) => { if (this.socket !== current) return; reported = true; this.fail(error); this.close(); onClose(); };
      this.timer = setTimeout(() => failed(new Error('START_TIMEOUT：45 秒内未建立目标通道。')), 45000);
      current.onopen = () => { if (current.protocol !== 'bastion.v1') failed(new Error('CLIENT_PROTOCOL_UNSUPPORTED')); else this.status(`连接 ${this.connectionId}：等待目标就绪。`); };
      current.onmessage = event => {
        if (this.socket !== current) return;
        try {
          if (typeof event.data !== 'string') { onOutput(outputFrame(event.data as ArrayBuffer)); return; }
          const frame = parseControl(event.data);
          if (frame.type === 'pong') { this.awaitingPong = false; return; }
          if (frame.type === 'session_ready') {
            if (frame.connection_id !== this.connectionId) throw new Error('CONNECTION_ID_MISMATCH');
            ready = true;
            this.heartbeat = setInterval(() => { try { if (this.awaitingPong) throw new Error('PONG_TIMEOUT'); this.awaitingPong = true; this.send({ type: 'ping' }); } catch (error) { failed(error); } }, 30000);
          }
          if (frame.type === 'error' && frame.channel_id === undefined) { failed(new ApiError(frame.code!, '服务端拒绝或终止连接。', frame.request_id)); return; }
          if (frame.type === 'ready') clearTimeout(this.timer);
          onControl(frame);
        } catch (error) { failed(error); }
      };
      current.onerror = () => { if (this.socket === current) { reported = true; this.fail(new ApiError('AUTH_OR_GATEWAY_FAILED', '握手或网络失败；无法由浏览器判断认证原因。')); } };
      current.onclose = event => {
        if (this.socket !== current) return;
        const id = this.connectionId; this.close(); onClose(); this.status('连接已结束；重连需新票据，不会重放输入或命令。');
        if (!reported && event.code !== 1000) this.fail(new Error(`连接断开（close_code: ${event.code}）。`));
        if (!ready) void this.api.connection(id, this.lifetime.signal).then(result => { if (!this.active && !this.lifetime.signal.aborted && result.failure) this.fail(new ApiError(result.failure.code, result.failure.message ?? '目标连接失败。', result.failure.request_id)); }).catch(error => { if (!this.lifetime.signal.aborted) this.fail(error); });
      };
    } catch (error) { if (!signal.aborted) this.fail(error); }
    finally { if (this.pending === controller) this.pending = null; onClose(); }
  }
}
export function mountTerminal(container: HTMLElement, api: ApiClient, lifetime: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown) => void): () => void {
  const toolbar = document.createElement('div'); toolbar.className = 'toolbar';
  const label = document.createElement('p'); label.id = 'connection'; label.textContent = '尚未建立连接';
  const button = (id: string, text: string) => { const node = document.createElement('button'); node.id = id; node.type = 'button'; node.textContent = text; toolbar.append(node); return node; };
  const connect = button('connect', '连接终端'), eof = button('eof', '发送 EOF'), close = button('close', '关闭连接');
  const viewport = document.createElement('div'); viewport.id = 'terminal'; viewport.className = 'terminal'; viewport.setAttribute('aria-label', '授权目标终端');
  const hint = document.createElement('p'); hint.className = 'muted'; hint.textContent = '路由离开会关闭此终端；断线只允许手动新会话，不恢复旧通道或重放输入。SSH 经网关连接目标，并非浏览器到目标的端到端加密。';
  container.append(toolbar, label, viewport, hint);
  const term = new Terminal({ convertEol: false, scrollback: 5000, cursorBlink: true, screenReaderMode: true, disableStdin: true, theme: { background: '#101621' } });
  const fit = new FitAddon(); term.loadAddon(fit); term.open(viewport);
  let phase: Phase = 'connecting', eofSent = false, queued = 0, everConnected = false;
  let resizeTimer: ReturnType<typeof setTimeout> | undefined;
  const connection = new TargetSocket(api, lifetime, status, error => { fail(error); update(); });
  const update = () => { connect.disabled = connection.active || !getTarget()?.account.capabilities.includes('shell'); connect.textContent = everConnected ? '重新连接（新会话）' : '连接终端'; eof.disabled = !connection.socket || phase !== 'streaming' || eofSent; close.disabled = !connection.active; term.options.disableStdin = eof.disabled; };
  const dimensions = () => { fit.fit(); return { cols: Math.min(4096, Math.max(1, term.cols)), rows: Math.min(4096, Math.max(1, term.rows)) }; };
  const safe = (work: () => void) => { try { work(); } catch (error) { fail(error); connection.close(); update(); } };
  connect.onclick = () => {
    const target = getTarget(); if (!target || !target.account.capabilities.includes('shell')) return;
    eofSent = false; phase = 'connecting';
    label.textContent = `${target.asset.name} (${target.asset.id}) / ${target.account.username} (${target.account.id}) · shell`;
    void connection.connect(target, 'shell', frame => {
      if (frame.channel_id !== undefined && frame.channel_id !== CHANNEL) throw new Error('UNEXPECTED_CHANNEL');
      if (frame.type === 'error') { fail(new ApiError(frame.code!, '目标通道被拒绝。', frame.request_id)); connection.close(); update(); return; }
      if (frame.type === 'exit') { eofSent = true; update(); status(`目标进程退出：${frame.exit_code ?? '无 exit code'} ${frame.exit_signal ?? ''}；继续等待输出。`); return; }
      if (frame.type === 'closed') { connection.close(); update(); status('目标通道关闭；历史保留至离开本页。'); return; }
      if (!['session_ready', 'opened', 'pty_ready', 'ready'].includes(frame.type)) return;
      const next = advance(phase, frame.type); phase = next.phase;
      if (next.send === 'open') connection.send({ type: 'open', channel_id: CHANNEL });
      if (next.send === 'pty') connection.send({ type: 'pty', channel_id: CHANNEL, term: 'xterm-256color', ...dimensions() });
      if (next.send === 'shell') connection.send({ type: 'shell', channel_id: CHANNEL });
      if (phase === 'streaming') { everConnected = true; label.textContent += ` · connection_id: ${connection.connectionId}`; update(); term.focus(); status('目标 shell 已就绪。'); }
    }, frame => {
      if (frame.channel !== CHANNEL || !['shell', 'streaming'].includes(phase)) throw new Error('OUTPUT_BEFORE_SHELL_OR_WRONG_CHANNEL');
      if (queued + frame.payload.length > MAX_BUFFER) throw new Error('OUTPUT_BACKPRESSURE：渲染队列超过 256 KiB。');
      queued += frame.payload.length; term.write(frame.payload, () => { queued = Math.max(0, queued - frame.payload.length); });
    }, update);
    update();
  };
  const sendInput = (bytes: Uint8Array) => { if (phase === 'streaming' && !eofSent) safe(() => connection.input(bytes)); };
  const data = term.onData(text => sendInput(new TextEncoder().encode(text))), binary = term.onBinary(text => sendInput(Uint8Array.from(text, char => char.charCodeAt(0) & 255)));
  eof.onclick = () => safe(() => { if (connection.send({ type: 'eof', channel_id: CHANNEL })) { eofSent = true; update(); status('EOF 已发送；继续接收输出。'); } });
  close.onclick = () => safe(() => { connection.send({ type: 'close', channel_id: CHANNEL }); connection.close(); update(); status('用户关闭连接；无自动重连。'); });
  const observer = new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => safe(() => { const size = dimensions(); if (phase === 'streaming') connection.send({ type: 'resize', channel_id: CHANNEL, ...size }); }), 100); }); observer.observe(viewport);
  lifetime.own(() => { clearTimeout(resizeTimer); observer.disconnect(); data.dispose(); binary.dispose(); term.dispose(); });
  dimensions(); update(); return update;
}
