import { ApiClient, ApiError, type Recording } from './api';
import { RouteLifetime } from './state';
import { GuacStream } from './guac';
import { decodeBase64, readNDJSON, ReplaySequence } from './replay';
import { MAX_INSTRUCTION } from './protocol';
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => { const result = document.createElement(tag); result.textContent = text; if (className) result.className = className; return result; };
export class OfflineGuacClient {
  readonly tunnel = new Guacamole.Tunnel();
  readonly client = new Guacamole.Client(this.tunnel);
  private stream: GuacStream;
  private images = new Set<string>();
  private pendingBytes = 0;
  constructor(private signal: AbortSignal) {
    this.tunnel.connect = () => this.tunnel.setState(1);
    this.tunnel.disconnect = () => this.tunnel.setState(2);
    this.tunnel.sendMessage = () => {}; // Offline: no network and no remote input.
    this.stream = new GuacStream((opcode, args) => {
      if(opcode==='clipboard')throw new Error('REPLAY_CLIPBOARD_FORBIDDEN');
      if (opcode === 'img') this.images.add(args[0]);
      if (opcode === 'end') this.images.delete(args[0]);
      if (!signal.aborted) this.tunnel.oninstruction?.(opcode, args);
    });
    this.client.connect('');
  }
  async feed(bytes: Uint8Array) {
    if (this.signal.aborted) throw new DOMException('Aborted', 'AbortError');
    this.pendingBytes += bytes.length;
    if (this.pendingBytes > MAX_INSTRUCTION) throw new Error('REPLAY_DISPLAY_BACKPRESSURE');
    this.stream.feed(bytes);
    // Image drawing cannot flush until a later img stream end has been fed.
    if (this.images.size) return;
    await new Promise<void>((resolve, reject) => {
      const aborted = () => reject(new DOMException('Aborted', 'AbortError'));
      this.signal.addEventListener('abort', aborted, { once: true });
      this.client.getDisplay().flush(() => { this.signal.removeEventListener('abort', aborted); if (this.signal.aborted) aborted(); else resolve(); });
    });
    this.pendingBytes = 0;
  }
  finish() { this.stream.finish(); if (this.images.size) throw new Error('TRUNCATED_REPLAY_IMAGE'); }
  close() { this.client.disconnect(); }
}
export function mountReplay(parent: HTMLElement, api: ApiClient, life: RouteLifetime, status: (text: string) => void, fail: (error: unknown) => void, connectionId?: string) {
  // Display vocabulary: the replay page renders outside the workspace shell, so it carries its own small helpers.
  const tones: Record<string, string> = { preparing: 'blue', active: 'blue', streaming: 'blue', complete: 'green', partial: 'orange', failed: 'red', corrupt: 'red', missing: 'red', expired: 'red', interrupted: 'red', ssh: 'blue', rdp: 'purple', vnc: 'green' };
  const words: Record<string, string> = { preparing: '录制准备中', active: '录制中', streaming: '录制中', complete: '完整录制', partial: '部分录制', failed: '录制失败', corrupt: '录制文件损坏', missing: '录制文件缺失', expired: '已过保留期', interrupted: '录制被中断' };
  const stateOf = (recording: Recording) => String(recording.state ?? recording.status ?? 'unknown');
  const size = (value: unknown) => { const bytes = Number(value); if (!Number.isFinite(bytes) || bytes < 0) return '—'; return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KiB` : `${(bytes / 1048576).toFixed(1)} MiB`; };
  const clock = (us: number) => { const seconds = us / 1e6, minutes = Math.floor(seconds / 60); return `${minutes}:${(seconds - minutes * 60).toFixed(3).padStart(6, '0')}`; };
const short = (value: unknown) => { const text = String(value ?? ''); return text.length > 13 ? `${text.slice(0, 8)}…` : text; };
  const svg = (paths: string) => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;

  const intro = node('p', '只读回放：SSH 用 xterm.js，RDP/VNC 用 Guacamole。播放器不连接目标、不接受远程输入，也不能跳转进度。', 'hint');
  if (connectionId) intro.append(node('span', ` 已按连接 ${connectionId} 筛选`, 'chip live'));
  const wrap = node('div', '', 'console-wrap replay-wrap'), side = node('aside', '', 'console-side'), rail = node('div', '', 'console-rail');
  const main = node('section', '', 'console-main'), topbar = node('header', '', 'console-bar'), opener = node('div', '', 'replay-open'), stage = node('div', '', 'replay-stage'), track = node('div', '', 'replay-track'), foot = node('footer', '', 'console-status');
  wrap.append(side, main); main.append(topbar, opener, stage, track, foot); parent.append(intro, wrap);
  stage.setAttribute('aria-label', '只读录制回放画面');
  stage.append(node('p', '请选择录制。', 'empty'));

  const sideHead = node('div', '', 'console-side-head'), collapse = node('button', '', 'console-collapse');
  collapse.type = 'button'; collapse.title = '折叠录制列表'; collapse.setAttribute('aria-label', '折叠录制列表'); collapse.setAttribute('aria-expanded', 'true'); collapse.innerHTML = svg('<polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/>');
  const count = node('span', '0', 'console-side-count'); sideHead.append(collapse, node('span', '录制', 'console-side-title'), count);
  const searchBox = node('div', '', 'console-side-search'), search = node('input', '', 'console-search');
  search.type = 'search'; search.placeholder = '搜索录制 ID、连接或状态'; search.setAttribute('aria-label', '搜索录制');
  searchBox.append(search); const pager = node('div', '', 'replay-pager'); side.append(sideHead, searchBox, rail, pager);

  const badge = node('span', '未选择', 'console-state'), protocol = node('span', '—', 'tag'), title = node('h1', '未选择录制', 'console-title'), account = node('span', '', 'console-account');
  const identity = node('div', '', 'console-identity'); identity.append(badge, protocol, title, account);
  const actions = node('div', '', 'console-bar-actions'); topbar.append(identity, actions);

  const label = node('label', '录制 ID', 'replay-label'); label.htmlFor = 'replay-id';
  const selected = node('input', '', 'replay-input'); selected.id = 'replay-id'; selected.type = 'text'; selected.autocomplete = 'off'; selected.spellcheck = false; selected.placeholder = '粘贴录制 ID';
  const suggestions = node('datalist'); suggestions.id = 'replay-id-list'; selected.setAttribute('list', suggestions.id);
  opener.append(label, selected, suggestions);

  const mark = node('span', '', 'console-status-mark'), phase = node('span', '请选择录制。', 'console-status-text'), detailLine = node('span', '', 'console-status-detail');
  phase.setAttribute('role', 'status'); phase.setAttribute('aria-live', 'polite'); foot.append(mark, phase, detailLine);

  let controller: AbortController | null = null, offline: OfflineGuacClient | import('./terminal').OfflineTerminalClient | null = null, paused = false, next: string | null = null, listBusy = false, generation = 0, loadedId = '';
  const items: Recording[] = [], known = new Map<string, Recording>(), rows = new Map<HTMLElement, string>();
  const button = (text: string, action: () => void, container: HTMLElement = actions, className = '') => { const result = node('button', text, className); result.type = 'button'; result.onclick = action; container.append(result); return result; };
  const report = (text: string, tone = '', running = false) => { mark.className = `console-status-mark ${tone}`.trim(); phase.textContent = text; if (!running) detailLine.textContent = ''; track.hidden = !running; };
  const clearStage = (message: string) => { offline?.close(); offline = null; stage.className = 'replay-stage'; stage.replaceChildren(node('p', message, 'empty')); };
  const syncButtons = () => { const id = selected.value.trim(); play.disabled = !id || !!controller; pause.disabled = stopButton.disabled = !controller; };

  function markActive() {
    const id = selected.value.trim();
    for (const [row, value] of rows) row.classList.toggle('active', value === id);
  }
  function select(id: string, recording?: Recording) {
    selected.value = id;
    const current = recording ?? known.get(id) ?? null, state = current ? stateOf(current) : 'unknown';
    badge.textContent = current ? (words[state] ?? state) : '未选择录制';
    badge.className = `console-state ${current ? (tones[state] ?? '') : ''}`.trim();
    badge.title = current ? `服务端状态 ${state}` : '尚未选择录制';
    protocol.textContent = String(current?.target_protocol ?? '—');
    protocol.className = `tag ${tones[String(current?.target_protocol ?? '')] ?? ''}`.trim();
    title.textContent = short(id) || '未选择录制'; title.title = id;
    const link = String(current?.connection_id ?? ''); account.textContent = link ? `连接 ${short(link)}` : ''; account.title = link;
    syncButtons(); markActive();
    if (id === loadedId) return;
    clearStage(id ? '尚未回放。点击「播放 / 从头重播」开始。' : '从左侧选择一条录制，或在上方粘贴录制 ID 后打开。');
    report(id ? (current ? '已选择这条录制；回放不会连接目标。' : '该录制 ID 不在左侧列表中，可直接回放。') : '请选择录制。');
  }

  const play = button('播放 / 从头重播', () => { stop(); void start(); }, actions, 'primary');
  const pause = button('暂停', () => { paused = !paused; pause.textContent = paused ? '继续' : '暂停'; pause.setAttribute('aria-pressed', String(paused)); report(paused ? '已暂停；回放未结束，不宣称完整。' : '继续回放…', paused ? 'orange' : 'green', !paused); });
  const stopButton = button('停止', () => { stop(); report('已停止；不宣称完整。', 'orange'); });
  const refresh = button('刷新', () => { void load(false); }, pager), more = button('加载更多', () => { void load(true); }, pager); more.hidden = true;
  button('打开', () => select(selected.value.trim()), opener);
  button('全屏', () => { void (document.fullscreenElement ? document.exitFullscreen() : wrap.requestFullscreen()).catch(fail); }, actions);
  collapse.onclick = () => { const collapsed = wrap.classList.toggle('collapsed'); collapse.title = collapsed ? '展开录制列表' : '折叠录制列表'; collapse.setAttribute('aria-label', collapse.title); collapse.setAttribute('aria-expanded', String(!collapsed)); };
  search.oninput = renderRail;
  selected.oninput = () => select(selected.value.trim());
  selected.onkeydown = event => { if (event.key === 'Enter') play.click(); };

  function renderRail() {
    const query = search.value.trim().toLowerCase();
    const shown = items.filter(item => !query || [String(item.id), String(item.connection_id ?? ''), stateOf(item), String(item.target_protocol ?? '')].some(value => value.toLowerCase().includes(query)));
    count.textContent = query ? `${shown.length} / ${items.length}` : String(items.length);
    rail.replaceChildren(); rows.clear();
    if (!shown.length) { rail.append(node('p', items.length ? '没有匹配的录制' : '暂无可回放的录制', 'hint console-empty')); return; }
    for (const recording of shown) {
      const state = stateOf(recording), row = node('button', '', 'console-target');
      row.type = 'button'; row.title = `${recording.id} · 连接 ${recording.connection_id ?? '—'} · 服务端状态 ${state}`;
      const text = node('span', '', 'console-target-text');
      text.append(node('span', String(recording.id), 'console-target-name'), node('span', `${recording.target_protocol ?? '—'} · ${size(recording.bytes)} · ${words[state] ?? state}`, 'console-target-account'));
      row.append(node('span', state, `tag dot ${tones[state] ?? ''}`.trim()), text);
      row.onclick = () => select(String(recording.id), recording);
      rows.set(row, String(recording.id)); rail.append(row);
    }
    markActive();
  }
  function stop() {
    controller?.abort(); offline?.close(); controller = null; offline = null; ++generation;
    paused = false; pause.textContent = '暂停'; pause.setAttribute('aria-pressed', 'false'); track.hidden = true; syncButtons();
  }
  async function load(append: boolean) {
    if (listBusy || life.signal.aborted) return; listBusy = true; refresh.disabled = more.disabled = true;
    try {
      const page = await api.recordings({ ...(connectionId ? { connection_id: connectionId } : {}), ...(append && next ? { cursor: next } : {}) }, life.signal);
      if (life.signal.aborted) return;
      if (!Array.isArray(page?.items) || !(page.next_cursor === null || typeof page.next_cursor === 'string')) throw new ApiError('INVALID_RESPONSE', '录制列表响应不完整。');
      if (!append) { items.length = 0; known.clear(); }
      for (const recording of page.items) { items.push(recording); known.set(String(recording.id), recording); }
      next = page.next_cursor; more.hidden = !next; renderRail();
      suggestions.replaceChildren(...items.map(item => { const option = node('option'); option.value = String(item.id); return option; }));
      // Landing from a connection, or with nothing picked yet, selects a row so the page never sits blank.
      if (!selected.value.trim() && items.length) select(String(items[0].id), items[0]);
    } catch (error) { if (!life.signal.aborted) fail(error); }
    finally { if (!life.signal.aborted) { listBusy = false; refresh.disabled = more.disabled = false; } }
  }
  async function delay(ms: number, signal: AbortSignal) {
    await new Promise<void>((resolve, reject) => { const abort = () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')); }; const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms); signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort(); });
  }
  async function start() {
    const id = selected.value.trim();
    if (!id || life.signal.aborted) return;
    const run = ++generation, current = new AbortController(); controller = current;
    const signal = AbortSignal.any([current.signal, life.signal]), owns = () => run === generation && !signal.aborted;
    syncButtons(); report(`读取 ${id}…`, 'blue', true);
    stage.className = 'replay-stage'; stage.replaceChildren();
    const player: { current: OfflineGuacClient | import('./terminal').OfflineTerminalClient | null } = { current: null };
    let completed = false;
    try {
      const detail = await api.recording(id, signal); if (!owns()) return;
      if (detail.format_version !== 2) throw new Error('UNSUPPORTED_RECORDING_FORMAT');
      if ((detail.state ?? detail.status) !== 'complete') throw new Error(`PARTIAL_RECORDING：服务端状态 ${detail.state ?? detail.status ?? 'unknown'}，不能声明完整。`);
      loadedId = id; known.set(id, detail); select(id, detail);
      const response = await api.recordingContent(id, signal), sequence = new ReplaySequence(detail.connection_id); let previous = 0;
      await readNDJSON(response, signal, async line => {
        const event = sequence.parse(line); let remaining = (event.elapsed_us - previous) / 1000;
        while (paused || remaining > 0) { const tick = paused ? 50 : Math.min(remaining, 50); await delay(tick, signal); if (!paused) remaining -= tick; }
        previous = event.elapsed_us; if (!owns()) throw new DOMException('Aborted', 'AbortError');
        if (event.type === 'meta') {
          if (event.stream_protocol === 'bastion.ssh.v1') {
            const { OfflineTerminalClient } = await import('./terminal'); if (!owns()) throw new DOMException('Aborted', 'AbortError');
            stage.className = 'replay-stage terminal-viewport'; player.current = new OfflineTerminalClient(stage, signal);
          } else {
            stage.className = 'replay-stage guac-viewport'; const guac = new OfflineGuacClient(signal); player.current = guac;
            const display = guac.client.getDisplay(); stage.append(display.getElement());
            guac.client.onerror = value => { current.abort(); if (run === generation && !life.signal.aborted) { report(`回放错误 ${value.code}：${value.message}`, 'red'); fail(new Error(value.message)); } };
            display.onresize = () => { if (owns() && display.getWidth() && display.getHeight()) display.scale(Math.min(stage.clientWidth / display.getWidth(), stage.clientHeight / display.getHeight(), 1)); };
          }
          offline = player.current;
        }
        if (event.type === 'output') await player.current!.feed(decodeBase64(event.data_base64!));
        if (event.type === 'end') player.current!.finish();
        if (owns()) { report(`回放中 · ${event.type}`, paused ? 'orange' : 'green', true); detailLine.textContent = `seq ${event.seq} · ${clock(event.elapsed_us)} · ${event.type}`; }
      });
      sequence.finish(); if (!player.current) throw new Error('MISSING_REPLAY_META'); player.current.finish();
      completed = true;
      if (owns()) { report('已读有效 end、干净 EOF；服务端 complete 内容校验成功。', 'green'); status('只读回放完成。'); }
    } catch (error) { if (owns()) { report('回放失败：部分、未知格式、序列、截断、UTF-8 或完整性错误；不宣称完整。', 'red'); fail(error); } }
    finally { if (!completed) player.current?.close(); if (run === generation) { controller = null; if (!completed) { offline = null; loadedId = ''; clearStage('回放未完成；画面已清空，不宣称完整。'); } syncButtons(); } }
  }
  life.own(() => { stop(); play.onclick = null; }); track.hidden = true; syncButtons(); void load(false);
}
