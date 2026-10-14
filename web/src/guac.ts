import { ApiClient, ApiError, type Asset, type Account } from './api';
import { RouteLifetime, type SessionState } from './state';
import { DEFAULT_DISPLAY, MAX_PAYLOAD, MAX_BUFFER, MAX_INSTRUCTION, MAX_CLIPBOARD, STREAM_PROTOCOL, serializeInstruction, streamURL, validateInstruction, validateDisplay, type DisplaySize } from './protocol';
export type Target = { asset: Asset; account: Account };
let inputSupport: { sink: Guacamole.InputSink; keyboard: Guacamole.Keyboard } | undefined;
function localInput() {
  if (!inputSupport) { const sink = new Guacamole.InputSink(); inputSupport = { sink, keyboard: new Guacamole.Keyboard(sink.getElement()) }; }
  return inputSupport;
}

/** One fatal decoder and the official incremental parser per connection/replay. */
export class GuacStream {
  private decoder = new TextDecoder('utf-8', { fatal: true });
  private parser = new Guacamole.Parser();
  private pending = 0;
  constructor(consume: (opcode: string, args: string[]) => void) {
    this.parser.oninstruction = (opcode, args) => {
      validateInstruction(opcode, args);
      const bytes = new TextEncoder().encode(serializeInstruction([opcode, ...args])).length;
      if (bytes > MAX_INSTRUCTION) throw new Error('INSTRUCTION_TOO_LARGE');
      this.pending -= bytes;
      if (this.pending < 0) throw new Error('INVALID_GUAC_FRAMING');
      consume(opcode, args);
    };
  }
  feed(bytes: Uint8Array) {
    if (!bytes.length || bytes.length > MAX_PAYLOAD) throw new Error('INVALID_GUAC_CHUNK');
    this.pending += bytes.length;
    this.parser.receive(this.decoder.decode(bytes, { stream: true }));
    if (this.pending > MAX_INSTRUCTION) throw new Error('INSTRUCTION_TOO_LARGE');
  }
  finish() { this.parser.receive(this.decoder.decode()); if (this.pending !== 0) throw new Error('TRUNCATED_GUAC_INSTRUCTION'); }
}

export class GuacTunnelClient {
  readonly tunnel = new Guacamole.Tunnel();
  readonly client = new Guacamole.Client(this.tunnel);
  socket: WebSocket | null = null;
  ready = false;
  connectionId = '';
  clipboardText = '';
  private clipboardVersion = 0;
  private targetProtocol: Asset['protocol'] = 'ssh';
  private cancelClipboard: (() => void) | null = null;
  private pending: AbortController | null = null;
  private generation = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private closing: false | 'graceful' | 'failed' = false;
  constructor(private api: ApiClient, private life: RouteLifetime, private status: (text: string) => void, private fail: (error: unknown, target?: Target) => void, private changed: () => void = () => {}) {
    this.tunnel.connect = () => {};
    this.tunnel.disconnect = () => this.close();
    this.tunnel.sendMessage = (...elements) => {
      const socket = this.socket; if (!socket || socket.readyState !== WebSocket.OPEN || this.life.signal.aborted || this.closing === 'failed') return;
      try {
        const opcode = String(elements[0]); if (!['sync', 'ack', 'key', 'mouse', 'size', 'nop', 'disconnect', 'clipboard', 'blob', 'end'].includes(opcode)) throw new Error('FORBIDDEN_GUAC_INPUT');
        if (['key', 'mouse', 'size', 'clipboard', 'blob', 'end'].includes(opcode) && !this.ready) return;
        const bytes = new TextEncoder().encode(serializeInstruction(elements.map(String)));
        if (socket.bufferedAmount + bytes.length > MAX_BUFFER) throw new Error('INPUT_BACKPRESSURE：输入不会重放。');
        for (let offset = 0; offset < bytes.length; offset += MAX_PAYLOAD) socket.send(bytes.slice(offset, offset + MAX_PAYLOAD));
      } catch (error) { if (this.closing) this.closing = 'failed'; this.close(false); this.fail(error); }
    };
    this.client.onerror = value => { if (!this.socket || this.life.signal.aborted) return; this.close(false); this.fail(new Error(`Guacamole ${value.code}: ${value.message}`)); };
    this.client.onclipboard = (stream, mimetype) => {
      const generation = this.generation, version = ++this.clipboardVersion;
      const owns = () => generation === this.generation && !!this.socket && !this.life.signal.aborted;
      if (mimetype !== 'text/plain') { stream.sendAck('Unsupported clipboard type', 0x030f); return; }
      const decoder = new TextDecoder('utf-8', {fatal:true});let text = '', count = 0;
      stream.onblob = data => {
        if (!owns()) return;
        try {
          const binary = atob(data), bytes = Uint8Array.from(binary, char => char.charCodeAt(0));count += bytes.length;
          if (count > MAX_CLIPBOARD) throw new Error('CLIPBOARD_TOO_LARGE：文本剪贴板最多 256 KiB。');
          text += decoder.decode(bytes, {stream:true});stream.sendAck('OK',0);
        } catch(error) { text = '';stream.sendAck('Invalid clipboard',0x030d);this.close(false);this.fail(error); }
      };
      stream.onend = () => {
        if (!owns()) return;
        try { text += decoder.decode();if(version===this.clipboardVersion){this.clipboardText=text;this.changed();}text=''; }
        catch(error){text='';this.close(false);this.fail(error);}
      };
      stream.sendAck('OK',0);
    };
    life.own(() => this.close());
  }
  async pasteText(text: string, pasteKeys?: {shift?: boolean}): Promise<void> {
    if (!this.ready || this.socket?.readyState !== WebSocket.OPEN || this.life.signal.aborted) throw new Error('CLIPBOARD_SESSION_NOT_READY');
    if (this.cancelClipboard) throw new Error('CLIPBOARD_BUSY：上一次文本传输尚未完成。');
    if (!text.isWellFormed()) throw new Error('INVALID_CLIPBOARD_UNICODE');
    if(text.includes('\0'))throw new Error('INVALID_CLIPBOARD_TEXT：文本不能包含 NUL 字符。');
    if(this.targetProtocol==='vnc' && [...text].some(char=>char.codePointAt(0)!>255))throw new Error('VNC_CLIPBOARD_CHARSET：当前 VNC 标准剪贴板仅支持 Latin-1，不能传输中文或 emoji。');
    const bytes = new TextEncoder().encode(text);
    if (bytes.length > MAX_CLIPBOARD) throw new Error('CLIPBOARD_TOO_LARGE：文本剪贴板最多 256 KiB。');
    const generation = this.generation;
    const stream = this.client.createClipboardStream('text/plain'), writer = new Guacamole.ArrayBufferWriter(stream);
    writer.blobLength = 6048;
    await new Promise<void>((resolve,reject) => {
      let offset = 0, finished = false, timer: ReturnType<typeof setTimeout>;
      const finish = (error?: unknown) => {
        if (finished) return;finished=true;clearTimeout(timer);writer.onack=null;this.cancelClipboard=null;
        if (error) { this.close(false);reject(error); } else resolve();
      };
      const deadline = () => { clearTimeout(timer);timer=setTimeout(()=>finish(new Error('CLIPBOARD_TIMEOUT：传输失败，不会自动重发。')),10000); };
      this.cancelClipboard=()=>finish(new DOMException('Clipboard cancelled','AbortError'));
      writer.onack = status => {
        if (generation!==this.generation || this.life.signal.aborted) { finish(new DOMException('Clipboard cancelled','AbortError'));return; }
        if (status.code!==0) { finish(new Error(`CLIPBOARD_REJECTED：目标拒绝文本（${status.code}）。`));return; }
        if (offset<bytes.length) {
          let end=Math.min(offset+6048,bytes.length);
          while(end<bytes.length && (bytes[end]&0xc0)===0x80)end--;
          const next=bytes.slice(offset,end);offset=end;deadline();writer.sendData(next);
        }
        else { writer.sendEnd();finish(); }
      };
      deadline();
    });
    if (generation !== this.generation || this.life.signal.aborted) throw new DOMException('Clipboard cancelled','AbortError');
    if (pasteKeys) {
      this.client.sendKeyEvent(1,0xffe3);
      if(pasteKeys.shift)this.client.sendKeyEvent(1,0xffe1);
      const key=pasteKeys.shift?0x56:0x76;
      this.client.sendKeyEvent(1,key);this.client.sendKeyEvent(0,key);
      if(pasteKeys.shift)this.client.sendKeyEvent(0,0xffe1);
      this.client.sendKeyEvent(0,0xffe3);
    }
  }
  get active() { return !!this.pending || !!this.socket; }
  close(graceful = true) {
    // Graceful disconnect is queued before normal WS close; close the transport before invalidation.
    if (this.closing) return; this.closing = graceful ? 'graceful' : 'failed';
    this.cancelClipboard?.();this.clipboardText='';++this.clipboardVersion;
    const socket = this.socket;
    this.client.onerror = null; this.client.disconnect();
    if (socket) { socket.onopen = socket.onmessage = socket.onclose = socket.onerror = null; socket.close(this.closing === 'graceful' ? 1000 : 4000, this.closing === 'graceful' ? 'client close' : 'client stream failure'); }
    this.socket = null; this.ready = false; ++this.generation; this.pending?.abort(); this.pending = null; clearTimeout(this.timer); this.tunnel.setState(2); this.closing = false; this.changed();
  }
  async connect(target: Target, displayHint?: DisplaySize) {
    if (this.active || this.life.signal.aborted) return;
    this.targetProtocol = target.asset.protocol;
    const generation = ++this.generation, controller = new AbortController(); this.pending = controller;
    const signal = AbortSignal.any([controller.signal, this.life.signal]);
    const current = () => generation === this.generation && !signal.aborted;
    this.status(`申请新会话：${target.asset.name} / ${target.account.label}`); this.changed();
    try {
      let display = DEFAULT_DISPLAY;
      try { if (displayHint) display = validateDisplay(displayHint); } catch { /* use DEFAULT */ }
      const ticket = await this.api.session(target.asset.id, target.account.id, display, signal);
      if (!current()) { ticket.ws_token = ''; return; }
      if (ticket.target_protocol !== target.asset.protocol) { ticket.ws_token = ''; throw new Error('TARGET_PROTOCOL_MISMATCH'); }
      this.connectionId = ticket.connection_id;
      let socket: WebSocket;
      try { socket = new WebSocket(streamURL(location.origin, ticket.session_id, import.meta.env.DEV), [STREAM_PROTOCOL, ticket.ws_token]); }
      finally { ticket.ws_token = ''; }
      this.socket = socket; this.pending = null; socket.binaryType = 'arraybuffer';
      const owns = () => current() && this.socket === socket;
      const rejected = (error: unknown) => { if (!owns()) return; this.close(false); this.fail(error, target); };
      let queued = 0;
      const stream = new GuacStream((opcode, args) => { if (!owns()) return; clearTimeout(this.timer); if (!this.ready) { this.ready = true; this.status(`目标显示流已就绪 · ${this.connectionId} · ${target.asset.protocol}`); this.changed(); } this.tunnel.oninstruction?.(opcode, args); });
      this.client.connect('');
      this.timer = setTimeout(() => rejected(new Error('START_TIMEOUT')), 45000);
      socket.onopen = () => { if (!owns()) return; if (socket.protocol !== STREAM_PROTOCOL) { rejected(new Error('CLIENT_PROTOCOL_UNSUPPORTED')); return; } this.tunnel.setState(1); this.status(`WebSocket 已接通；正在建立 ${target.asset.protocol} 目标连接…`); this.changed(); };
      socket.onmessage = event => { if (!owns()) return; try { if (!(event.data instanceof ArrayBuffer)) throw new Error('BINARY_GUAC_REQUIRED'); const bytes = new Uint8Array(event.data); if (queued + bytes.length > MAX_BUFFER) throw new Error('OUTPUT_BACKPRESSURE'); queued += bytes.length; stream.feed(bytes); this.client.getDisplay().flush(() => { if (owns()) queued -= bytes.length; }); } catch (error) { rejected(error); } };
      socket.onerror = () => { if (owns()) this.status('握手或网络失败；等待连接诊断，不自动重连。'); };
      socket.onclose = event => {
        if (!owns()) return;
        let error: unknown; try { stream.finish(); } catch (failure) { error = failure; }
        const id = this.connectionId; this.close(); const closed = this.generation;
        this.status('连接已结束；手动重新连接会取得新票据，不重放输入。');
        if (error) this.fail(error, target); else if (event.code !== 1000) this.fail(new Error(`连接断开 ${event.code}`), target);
        const diagnosticCurrent = () => this.generation === closed && !this.life.signal.aborted;
        void this.api.connection(id, this.life.signal).then(value => { if (diagnosticCurrent() && value.failure) this.fail(new ApiError(value.failure.code, value.failure.message ?? '目标连接失败。', value.failure.request_id), target); }).catch(failure => { if (diagnosticCurrent()) this.fail(failure, target); });
      };
    } catch (error) { if (current()) { this.close(false); this.fail(error, target); } }
    finally { if (this.pending === controller) this.pending = null; if (current()) this.changed(); }
  }
}

export function mountSession(parent: HTMLElement, api: ApiClient, life: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown, target?: Target) => void, enabled: (target: Target) => boolean, prepare?: (target: Target) => Promise<boolean>, state?: (value: SessionState) => void): () => void {
  const toolbar = document.createElement('div'); toolbar.className = 'toolbar';
  // Toolbar stays flat so the shell can drive the session buttons by data-session, never by position.
  const button = (text: string, action: () => void, className = '', session = '') => { const result = document.createElement('button'); result.type = 'button'; result.textContent = text; result.onclick = action; if (className) result.className = className; if (session) result.setAttribute('data-session', session); toolbar.append(result); return result; };
  const separator = () => { const mark = document.createElement('span'); mark.className = 'toolbar-sep'; mark.setAttribute('aria-hidden', 'true'); toolbar.append(mark); };
  const viewport = document.createElement('div'); viewport.className = 'guac-viewport'; viewport.style.overflow = 'hidden'; viewport.tabIndex = 0; viewport.setAttribute('aria-label', '远程会话 Canvas，点击后输入');
  parent.append(toolbar, viewport);
  let bound: Target | null = null, connection: GuacTunnelClient, composing = false, preparing = false, display: Guacamole.Display;
  let resizeTimer: ReturnType<typeof setTimeout> | undefined, requestedSize = '';
  const { sink, keyboard } = localInput(), input = sink.getElement(); viewport.append(input);
  function update() { const target = getTarget(); connect.disabled = preparing || connection.active || !target || !enabled(target); close.disabled = !connection.active; if (bound && (!target || bound.asset.id !== target.asset.id || bound.account.id !== target.account.id)) { release(); bound = null; connection.close(); } state?.(preparing || connection.active && !connection.ready ? 'connecting' : connection.ready ? 'ready' : bound ? 'closed' : 'idle'); hint.textContent = `SSH/RDP/VNC 支持双向文本剪贴板（最多 256 KiB）；Ctrl+V 可粘贴，也可使用剪贴板按钮。浏览器权限受限时可手动复制/粘贴。VNC 仅本地缩放；离页关闭连接。禁用文件、音视频。${target?.asset.protocol !== 'vnc' ? ' 键盘组合输入暂不支持 emoji 等非 BMP 字符；剪贴板按 UTF-8 传输，字符显示取决于目标。' : ''}${target?.asset.protocol === 'rdp' ? ' RDP 中文组合输入取决于目标服务和输入环境；部分旧版 xrdp 剪贴板不支持 emoji。' : ''}${target?.asset.protocol === 'vnc' ? ' VNC 标准剪贴板仅支持 Latin-1（不含中文/emoji）。' : ''}`; scheduleResize(); }
  connection = new GuacTunnelClient(api, life, status, fail, update); display = connection.client.getDisplay(); viewport.append(display.getElement());
  const connect = button('连接 / 手动新票据重连', () => {
    const target = getTarget(); if (!target || !enabled(target) || connection.active || preparing || life.signal.aborted) return;
    const start = () => {
      const selected = getTarget();
      if (life.signal.aborted || selected?.asset.id !== target.asset.id || selected.account.id !== target.account.id || !enabled(selected)) return;
      release(); connection.close(); mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = mouse.onmouseout = null; display.onresize = null; display.getElement().remove();
      requestedSize = '';
      connection = new GuacTunnelClient(api, life, status, fail, update); display = connection.client.getDisplay(); viewport.append(display.getElement()); bindMouse(); display.onresize = scale; bound = target;
      // Ask the server to render at the viewport's physical size on the first frame, not the 1280x720 default.
      const w = Math.min(3840, Math.max(64, (viewport.offsetWidth || viewport.clientWidth) | 0)), h = Math.min(2160, Math.max(64, (viewport.offsetHeight || viewport.clientHeight) | 0));
      void connection.connect(target, { width: w, height: h, dpi: 96 });
    };
    if (!prepare) { start(); return; }
    preparing = true; update();
    void prepare(target).then(approved => { if (approved) start(); }).catch(error => { if (!life.signal.aborted) fail(error, target); }).finally(() => { preparing = false; if (!life.signal.aborted) update(); });
  }, 'primary', 'connect');
  const close = button('断开', () => { release(); connection.close(); }, '', 'disconnect');
  separator();
  const zoom = document.createElement('select'); zoom.setAttribute('aria-label', '显示缩放'); zoom.replaceChildren(...['fit', '0.5', '1', '1.5', '2'].map(value => new Option(value === 'fit' ? '适应窗口' : `${Number(value) * 100}%`, value))); toolbar.append(zoom);
  separator();
  let clipboardDialog: HTMLDialogElement | null = null;
  const sendText = async (text: string, shift = false) => {
    const current = connection;release();
    await current.pasteText(text,{shift:bound?.asset.protocol==='ssh' || shift});
    if (current===connection && !life.signal.aborted) status('文本已发送到目标。');
  };
  function showClipboard() {
    if (clipboardDialog?.open || life.signal.aborted) return;
    const current = connection, dialog = document.createElement('dialog');clipboardDialog=dialog;
    const heading=document.createElement('h2');heading.textContent='文本剪贴板';heading.id='clipboard-heading';dialog.setAttribute('aria-labelledby',heading.id);
    const note=document.createElement('p');note.textContent='最多 256 KiB。可在此粘贴文本并发送，或复制从目标收到的文本。文件和图片不通过剪贴板传输。';
    const text=document.createElement('textarea');text.setAttribute('aria-label','剪贴板文本');text.value=current.clipboardText;text.rows=10;
    const actions=document.createElement('div');actions.className='toolbar';
    const send=document.createElement('button');send.textContent='粘贴到目标';send.type='button';send.disabled=!current.ready;
    send.onclick=()=>{if(current!==connection || life.signal.aborted)return;send.disabled=true;void sendText(text.value).then(()=>{if(dialog.open)dialog.close();}).catch(error=>{if(!life.signal.aborted && current===connection)fail(error);}).finally(()=>{send.disabled=!current.ready;});};
    const copy=document.createElement('button');copy.textContent='复制到本机';copy.type='button';
    copy.onclick=()=>{text.focus();text.select();if(navigator.clipboard?.writeText)void navigator.clipboard.writeText(text.value).then(()=>{if(!life.signal.aborted)status('文本已复制到本机剪贴板。');}).catch(()=>{if(!life.signal.aborted)status('浏览器未授权剪贴板写入；文本已选中，请按 Ctrl+C。');});else status('文本已选中，请按 Ctrl+C。');};
    const closeDialog=document.createElement('button');closeDialog.textContent='关闭';closeDialog.type='button';closeDialog.onclick=()=>dialog.close();
    actions.append(send,copy,closeDialog);dialog.append(heading,note,text,actions);parent.append(dialog);
    dialog.addEventListener('close',()=>{text.value='';dialog.remove();if(clipboardDialog===dialog)clipboardDialog=null;});
    dialog.showModal();text.focus();
  }
  button('剪贴板',showClipboard);
  button('粘贴',()=>{
    const current=connection;if(!current.ready)return;
    if(!navigator.clipboard?.readText){showClipboard();return;}
    void navigator.clipboard.readText().then(text=>{if(current===connection && !life.signal.aborted)return sendText(text);}).catch(error=>{if(current===connection && !life.signal.aborted){if(error instanceof DOMException && ['NotAllowedError','SecurityError'].includes(error.name))showClipboard();else fail(error);}});
  });
  button('复制',()=>{
    if(!connection.ready)return;
    if(!navigator.clipboard?.writeText){showClipboard();return;}
    const current=connection;void navigator.clipboard.writeText(current.clipboardText).then(()=>{if(current===connection && !life.signal.aborted)status('目标文本已复制到本机剪贴板。');}).catch(()=>{if(current===connection && !life.signal.aborted)showClipboard();});
  });
  let mouse: Guacamole.Mouse;
  function sendPointer(state: Guacamole.Mouse.State) {
    if (connection.socket?.readyState !== WebSocket.OPEN || life.signal.aborted) return;
    const width = display.getWidth(), height = display.getHeight(), scale = display.getScale();
    if (!width || !height || scale <= 0) return;
    // Fractional scaling and edge events can round outside the remote framebuffer.
    const x = Math.min(width - 1, Math.max(0, Math.floor(state.x / scale))), y = Math.min(height - 1, Math.max(0, Math.floor(state.y / scale)));
    connection.client.sendMouseState(new Guacamole.Mouse.State(x, y, state.left, state.middle, state.right, state.up, state.down));
  }
  const sendMouse = (state: Guacamole.Mouse.State) => { display.showCursor(true); if (document.activeElement === input) sendPointer(state); };
  function bindMouse() { mouse = new Guacamole.Mouse(display.getElement()); display.showCursor(false); mouse.onmousedown = state => { display.showCursor(true); sink.focus(); sendPointer(state); }; mouse.onmouseup = mouse.onmousemove = sendMouse; mouse.onmouseout = () => display.showCursor(false); } bindMouse();
  const scalarKeysym = (keysym: number) => !(keysym >= 0x0100d800 && keysym <= 0x0100dfff);
  keyboard.onkeydown = keysym => { if (!composing && scalarKeysym(keysym) && connection.socket?.readyState === WebSocket.OPEN && !life.signal.aborted) connection.client.sendKeyEvent(1, keysym); return false; };
  keyboard.onkeyup = keysym => { if (!composing && scalarKeysym(keysym) && connection.socket?.readyState === WebSocket.OPEN && !life.signal.aborted) connection.client.sendKeyEvent(0, keysym); };
  function release() { keyboard.reset(); const state = mouse.currentState; state.left = state.middle = state.right = state.up = state.down = false; sendPointer(new Guacamole.Mouse.State(state.x, state.y, false, false, false, false, false)); }
  const focus = () => sink.focus(), blur = () => { release(); composing = false; };
  viewport.addEventListener('click', focus); input.addEventListener('blur', blur); window.addEventListener('blur', blur);
  const compositionStart = () => { release(); composing = true; }, compositionEnd = (event: Event) => {
    if (!composing) { event.stopImmediatePropagation(); (input as HTMLTextAreaElement).value = ''; return; }
    composing = false;
    if (bound?.asset.protocol !== 'vnc' && [...((event as CompositionEvent).data ?? '')].some(char => char.codePointAt(0)! > 0xffff)) {
      event.stopImmediatePropagation(); (input as HTMLTextAreaElement).value = '';
      fail(new Error('当前 SSH/RDP 输入暂不支持 emoji 等非 BMP 字符；整段组合文本未发送。'));
    }
  };
  let pasteShift=false;
  const clipboardKey = (event: Event) => {
    const key=event as KeyboardEvent;
    if((key.ctrlKey || key.metaKey) && key.key?.toLowerCase()==='v' || key.shiftKey && key.key==='Insert'){
      if(key.type==='keydown')pasteShift=key.shiftKey;event.stopImmediatePropagation();
    }
  };
  const paste = (event: Event) => {
    event.preventDefault();event.stopImmediatePropagation();
    const text=(event as ClipboardEvent).clipboardData?.getData('text/plain');
    if(text===undefined || !connection.ready)return;
    const current=connection;void sendText(text,pasteShift).catch(error=>{if(current===connection && !life.signal.aborted)fail(error);});pasteShift=false;
  };
  const copy = (event: Event) => {
    if(!connection.ready)return;
    event.preventDefault();(event as ClipboardEvent).clipboardData?.setData('text/plain',connection.clipboardText);
  };
  // Capture before the official keyboard's target listeners, so Ctrl+V cannot paste stale remote text.
  viewport.addEventListener('keydown',clipboardKey,true);viewport.addEventListener('keyup',clipboardKey,true);
  input.addEventListener('compositionstart', compositionStart, true);
  input.addEventListener('compositionend', compositionEnd, true);
  // IME uses the official keyboard; explicit paste uses UTF-8 clipboard streams.
  input.addEventListener('paste', paste,true);input.addEventListener('copy',copy);
  function applySmoothing() { const canvas = display.getElement()?.querySelector?.('canvas') as HTMLCanvasElement | null | undefined; if (canvas?.style) canvas.style.imageRendering = display.getScale() === 1 ? 'pixelated' : 'auto'; }
  function scale() { if (life.signal.aborted) return; viewport.style.overflow = zoom.value === 'fit' ? 'hidden' : 'auto'; const width = display.getWidth(), height = display.getHeight(); if (width && height) { const next = zoom.value === 'fit' ? Math.min(viewport.clientWidth / width, viewport.clientHeight / height, 1) : Number(zoom.value); if (next !== display.getScale()) display.scale(next); applySmoothing(); } }
  function scheduleResize() {
    clearTimeout(resizeTimer);
    const current = connection;
    resizeTimer = setTimeout(() => {
      if (life.signal.aborted || current !== connection || !connection.ready || !bound || bound.asset.protocol === 'vnc' || connection.socket?.readyState !== WebSocket.OPEN) return;
      // Scrollbars change client size without changing the workspace's layout box.
      const width = Math.min(3840, Math.max(1, (viewport.offsetWidth || viewport.clientWidth) - 2 * viewport.clientLeft)), height = Math.min(2160, Math.max(1, (viewport.offsetHeight || viewport.clientHeight) - 2 * viewport.clientTop));
      const size = `${width}x${height}`;
      if (size !== requestedSize) { requestedSize = size; connection.client.sendSize(width, height); }
    }, 100);
  }
  const observer = new ResizeObserver(() => { scale(); scheduleResize(); }); observer.observe(viewport); display.onresize = scale;
  zoom.onchange = scale;
  zoom.style.maxWidth = '120px';
  const hint = document.createElement('p'); hint.className = 'hint'; parent.append(hint);
  life.own(() => { release();clipboardDialog?.close(); clearTimeout(resizeTimer); observer.disconnect(); window.removeEventListener('blur', blur); input.removeEventListener('blur', blur); input.removeEventListener('compositionstart', compositionStart, true); input.removeEventListener('compositionend', compositionEnd, true);viewport.removeEventListener('keydown',clipboardKey,true);viewport.removeEventListener('keyup',clipboardKey,true); input.removeEventListener('paste', paste,true);input.removeEventListener('copy',copy); (input as HTMLTextAreaElement).value = ''; input.remove(); keyboard.onkeydown = keyboard.onkeyup = null; mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = mouse.onmouseout = null; display.onresize = null; });
  update(); return update;
}
