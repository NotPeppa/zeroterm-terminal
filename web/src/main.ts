import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import './style.css';
import { ApiError, clearAuth, loadCsrf, loadMe, request, validateAssets, validateTicket, type Asset, type AssetPage, type Me, type Ticket } from './api';
import { advance, canSend, CHANNEL, inputFrames, MAX_BUFFER, outputPayload, parseControl, streamURL, type Phase } from './protocol';

const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = element('status'), errorBox = element('error'), loginPanel = element('login-panel'), workspace = element('workspace');
const loginForm = element<HTMLFormElement>('login-form'), password = element<HTMLInputElement>('password');
const assetSelect = element<HTMLSelectElement>('asset'), accountSelect = element<HTMLSelectElement>('account');
const connectButton = element<HTMLButtonElement>('connect'), eofButton = element<HTMLButtonElement>('eof');
const closeButton = element<HTMLButtonElement>('close'), refreshButton = element<HTMLButtonElement>('refresh');
const reloadButton = element<HTMLButtonElement>('reload'), moreButton = element<HTMLButtonElement>('more');
const logoutButton = element<HTMLButtonElement>('logout'), loginButton = element<HTMLButtonElement>('login');
const connectionLabel = element('connection');
const term = new Terminal({ convertEol: false, scrollback: 5000, cursorBlink: true, screenReaderMode: true, disableStdin: true,
  theme: { background: '#101621' } });
const fit = new FitAddon(); term.loadAddon(fit);
let terminalOpened = false;
let me: Me | null = null, assets: Asset[] = [], cursor: string | null = null;
let busy = false, refreshUsed = false, eofSent = false, everConnected = false;
let phase: Phase = 'connecting';
let socket: WebSocket | null = null;
let lifetime = new AbortController();
let pendingConnection: AbortController | null = null;
let resizeTimer: number | undefined, startTimer: number | undefined;
let heartbeat: number | undefined, awaitingPong = false;
let outputQueued = 0;

const selectedAsset = () => assets.find(asset => asset.id === assetSelect.value);
const selectedAccount = () => selectedAsset()?.accounts.find(account => account.id === accountSelect.value);
const statusText = (text: string) => { status.textContent = text; };
const clearError = () => { errorBox.hidden = true; errorBox.textContent = ''; };
function showError(stage: string, caught: unknown) {
  const issue = caught instanceof ApiError ? `${caught.code}：${caught.message}` : caught instanceof Error ? caught.message : '未知错误';
  const requestId = caught instanceof ApiError && caught.requestId ? caught.requestId : '不可用';
  errorBox.hidden = false;
  errorBox.textContent = `${stage}失败：${issue}（request_id: ${requestId}）`;
}
function updateControls() {
  const active = !!socket || !!pendingConnection;
  loginButton.disabled = busy;
  logoutButton.disabled = busy;
  refreshButton.disabled = busy || refreshUsed;
  reloadButton.disabled = busy || active;
  moreButton.disabled = busy || active;
  moreButton.hidden = !cursor;
  assetSelect.disabled = busy || active;
  accountSelect.disabled = busy || active;
  connectButton.disabled = busy || active || !me || !selectedAccount()?.capabilities.includes('shell');
  connectButton.textContent = everConnected ? '重新连接（新会话）' : '连接终端';
  eofButton.disabled = busy || !socket || phase !== 'streaming' || eofSent;
  closeButton.disabled = !active;
  term.options.disableStdin = !socket || phase !== 'streaming' || eofSent;
}
function renderAccounts() {
  const previous = accountSelect.value;
  accountSelect.replaceChildren(...(selectedAsset()?.accounts ?? []).map(account => new Option(account.username, account.id)));
  if ([...accountSelect.options].some(option => option.value === previous)) accountSelect.value = previous;
  const account = selectedAccount();
  element('capabilities').textContent = account ? `账号 ID: ${account.id} · 展示能力: ${account.capabilities.join(', ') || '无'}` : '没有可用目标账号';
  updateControls();
}
function renderAssets() {
  const previous = assetSelect.value;
  assetSelect.replaceChildren(...assets.map(asset => new Option(`${asset.name}${asset.tags?.length ? ` · ${asset.tags.join(', ')}` : ''}`, asset.id)));
  if ([...assetSelect.options].some(option => option.value === previous)) assetSelect.value = previous;
  renderAccounts();
}
async function loadAssets(append: boolean) {
  const signal = lifetime.signal;
  const query = append && cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
  const page = validateAssets(await request<AssetPage>(`/api/v1/assets${query}`, undefined, signal));
  if (signal.aborted) return;
  assets = append ? [...assets, ...page.items.filter(item => !assets.some(existing => item.id === existing.id))] : page.items;
  cursor = page.next_cursor;
  renderAssets();
  statusText(assets.length ? '请选择授权资产和目标账号。' : '没有已授权资产；请联系管理员。');
}
function openWorkspace(identity: Me) {
  me = identity; loginPanel.hidden = true; workspace.hidden = false;
  element('identity').textContent = `${identity.user.username}${identity.user.role ? ` · ${identity.user.role}` : ''} · login_session_id: ${identity.login_session_id} · policy_revision: ${identity.policy_revision}`;
  if (!terminalOpened) { term.open(element('terminal')); terminalOpened = true; }
  fit.fit(); renderAssets();
}
function stopSocket() {
  pendingConnection?.abort(); pendingConnection = null;
  window.clearTimeout(startTimer); window.clearTimeout(resizeTimer); window.clearInterval(heartbeat);
  awaitingPong = false; eofSent = false;
  const current = socket; socket = null;
  if (current) {
    current.onopen = current.onmessage = current.onclose = current.onerror = null;
    current.close(1000, 'client close');
  }
  updateControls();
}
function clearMemory() {
  lifetime.abort(); lifetime = new AbortController(); stopSocket(); clearAuth();
  me = null; assets = []; cursor = null; password.value = ''; outputQueued = 0; everConnected = false;
  if (terminalOpened) term.reset();
  element('identity').textContent = ''; connectionLabel.textContent = '尚未建立连接';
  assetSelect.replaceChildren(); accountSelect.replaceChildren(); element('capabilities').textContent = '';
  workspace.hidden = true; loginPanel.hidden = false; updateControls();
}
function handleAuthError(caught: unknown) {
  if (caught instanceof ApiError && (caught.status === 401 || ['LOGIN_SESSION_REVOKED', 'USER_DISABLED', 'UNAUTHENTICATED', 'SESSION_EXPIRED'].includes(caught.code))) {
    clearMemory(); statusText('登录失效。请重新登录；不会自动刷新或重放请求。'); element('username').focus();
  }
}
async function action(stage: string, work: () => Promise<void>) {
  if (busy) return;
  busy = true; clearError(); updateControls();
  try { await work(); }
  catch (caught) { handleAuthError(caught); showError(stage, caught); }
  finally { busy = false; updateControls(); }
}
function sendControl(value: object): boolean {
  if (!socket || socket.readyState !== WebSocket.OPEN) return false;
  const text = JSON.stringify({ v: 1, ...value });
  if (!canSend(socket.bufferedAmount, new TextEncoder().encode(text).length)) {
    showError('发送控制帧', new Error('BACKPRESSURE：发送队列超过 256 KiB，已断开；不静默丢弃数据。'));
    stopSocket(); statusText('会话已结束；终端历史保留。'); return false;
  }
  socket.send(text); return true;
}
function size() { fit.fit(); return { cols: Math.min(4096, Math.max(1, term.cols)), rows: Math.min(4096, Math.max(1, term.rows)) }; }
function fitAndResize() {
  if (!terminalOpened || workspace.hidden) return;
  const dimensions = size();
  if (socket && phase === 'streaming') sendControl({ type: 'resize', channel_id: CHANNEL, ...dimensions });
}
function scheduleResize() { window.clearTimeout(resizeTimer); resizeTimer = window.setTimeout(fitAndResize, 100); }

async function explainConnectionFailure(id: string, signal: AbortSignal, original: string) {
  try {
    let headerRequestId = '';
    const result = await request<{ failure?: { code?: string; message?: string; request_id?: string }; request_id?: string }>(`/api/v1/connections/${encodeURIComponent(id)}`, undefined, signal, requestId => { headerRequestId = requestId; });
    if (signal.aborted || socket || pendingConnection) return;
    if (typeof result?.failure?.code === 'string') {
      showError(original, new ApiError(result.failure.code, result.failure.message ?? '目标连接失败。', result.failure.request_id ?? result.request_id ?? headerRequestId, 0));
    }
  } catch (caught) {
    if (!signal.aborted && !socket && !pendingConnection) { handleAuthError(caught); showError(`${original} / 读取连接诊断`, caught); }
  }
}
async function connect() {
  if (socket || pendingConnection) return;
  const asset = selectedAsset(), account = selectedAccount();
  if (!asset || !account?.capabilities.includes('shell')) return;
  // Capture target labels, not the live selectors: a connection cannot silently switch targets.
  const target = `资产: ${asset.name} (${asset.id}) · 账号: ${account.username} (${account.id})`;
  const controller = new AbortController(); pendingConnection = controller;
  connectionLabel.textContent = `${target} · 会话能力: shell · 尚未建立 connection_id`;
  const signal = AbortSignal.any([controller.signal, lifetime.signal]);
  updateControls(); clearError(); statusText('申请会话：正在请求一次性票据…');
  let ticket: Ticket | null = null;
  try {
    ticket = validateTicket(await request<Ticket>('/api/v1/sessions', {
      asset_id: asset.id, account_id: account.id, capabilities: ['shell'], purpose: 'terminal',
    }, signal));
    if (signal.aborted) return;
    const id = ticket.connection_id;
    connectionLabel.textContent = `${target} · 会话能力: ${ticket.capabilities.join(', ')} · connection_id: ${id}`;
    let secret = ticket.ws_token;
    const current = new WebSocket(streamURL(location.origin, ticket.session_id, import.meta.env.DEV), ['bastion.v1', secret]);
    ticket.ws_token = ''; ticket = null;
    socket = current; pendingConnection = null; phase = 'connecting'; eofSent = false;
    current.binaryType = 'arraybuffer';
    let failureReported = false;
    const fail = (stage: string, caught: unknown) => {
      if (socket !== current) return;
      failureReported = true; secret = '';
      showError(stage, caught); stopSocket(); statusText('会话已结束；终端历史保留。'); handleAuthError(caught);
    };
    statusText('建立 WebSocket：正在进行握手…');
    startTimer = window.setTimeout(() => fail('建立目标/启动终端', new Error('START_TIMEOUT：45 秒内未启动终端。')), 45000);
    current.onopen = () => {
      secret = ''; // Browser owns the consumed subprotocol; application keeps no ticket reference after open.
      if (socket !== current) return;
      if (current.protocol !== 'bastion.v1') { fail('WebSocket 握手', new Error('CLIENT_PROTOCOL_UNSUPPORTED')); return; }
      statusText('连接目标：等待 SSH 连接就绪…');
    };
    current.onmessage = event => {
      if (socket !== current) return;
      try {
        if (typeof event.data !== 'string') {
          const bytes = outputPayload(event.data as ArrayBuffer);
          if (!['shell', 'streaming'].includes(phase)) throw new Error('OUTPUT_BEFORE_SHELL');
          if (outputQueued + bytes.length > MAX_BUFFER) throw new Error('OUTPUT_BACKPRESSURE：渲染队列超过 256 KiB，已断开。');
          outputQueued += bytes.length;
          term.write(bytes, () => { outputQueued = Math.max(0, outputQueued - bytes.length); });
          return;
        }
        const frame = parseControl(event.data);
        if (frame.type === 'pong') { awaitingPong = false; return; }
        if (frame.type === 'error') {
          fail(`目标/通道（${phase}）`, new ApiError(frame.code!, '服务端拒绝或终止会话。', frame.request_id ?? '', 0));
          return;
        }
        if (frame.type === 'exit') {
          eofSent = true; updateControls();
          statusText(`目标进程已退出${frame.exit_code === undefined ? '' : ` · exit_code: ${frame.exit_code}`}${frame.exit_signal ? ` · exit_signal: ${frame.exit_signal}` : ''}；等待剩余输出。`);
          return;
        }
        if (frame.type === 'closed') { secret = ''; stopSocket(); statusText('目标通道已关闭；终端历史保留。'); return; }
        if (!['session_ready', 'opened', 'pty_ready', 'ready'].includes(frame.type)) return; // Ignore future noncritical controls.
        if (frame.type === 'session_ready' && frame.connection_id !== id) throw new Error('CONNECTION_ID_MISMATCH');
        const next = advance(phase, frame.type); phase = next.phase;
        if (next.send === 'open') { statusText('启动终端：打开目标通道…'); sendControl({ type: 'open', channel_id: CHANNEL }); }
        if (next.send === 'pty') { statusText('启动终端：申请 PTY…'); sendControl({ type: 'pty', channel_id: CHANNEL, term: 'xterm-256color', ...size() }); }
        if (next.send === 'shell') { statusText('启动终端：等待目标 shell…'); sendControl({ type: 'shell', channel_id: CHANNEL }); }
        if (phase === 'streaming' && socket === current) {
          window.clearTimeout(startTimer); everConnected = true; statusText('目标终端已连接。'); updateControls(); term.focus(); fitAndResize();
          heartbeat = window.setInterval(() => {
            if (socket !== current) return;
            if (awaitingPong) { fail('堡垒机心跳', new Error('PONG_TIMEOUT')); return; }
            awaitingPong = true; sendControl({ type: 'ping' });
          }, 30000);
        }
      } catch (caught) { fail(`终端协议（${phase}）`, caught); }
    };
    current.onerror = () => {
      if (socket !== current) return;
      failureReported = true;
      showError(`WebSocket/目标（${phase}）`, new ApiError('AUTH_OR_GATEWAY_FAILED', '握手或网络失败；无法由浏览器判断认证原因。', '', 0));
    };
    current.onclose = event => {
      secret = '';
      if (socket !== current) return;
      const wasStreaming = phase === 'streaming'; stopSocket();
      statusText('连接已结束；终端历史保留，重连需申请新会话。');
      if (!failureReported && event.code !== 1000) showError(`WebSocket/目标（${phase}）`, new Error(`连接断开（close_code: ${event.code}）。`));
      if (!wasStreaming) void explainConnectionFailure(id, lifetime.signal, '建立 WebSocket/目标');
    };
    updateControls();
  } catch (caught) {
    if (!signal.aborted) { handleAuthError(caught); showError('申请/建立会话', caught); statusText('会话未建立。'); }
  } finally {
    if (ticket) ticket.ws_token = '';
    if (pendingConnection === controller) pendingConnection = null;
    updateControls();
  }
}
function sendInput(bytes: Uint8Array) {
  const current = socket;
  if (!current || phase !== 'streaming' || eofSent || current.readyState !== WebSocket.OPEN) return;
  let sent = 0;
  try {
    for (const frame of inputFrames(bytes)) {
      if (!canSend(current.bufferedAmount, frame.length)) throw new Error(`BACKPRESSURE：发送队列超过 256 KiB；本次 ${bytes.length} 字节输入已提交 ${sent} 字节，剩余未发送，已断开。`);
      current.send(frame); sent += frame.length - 6;
    }
  } catch (caught) { showError('发送终端输入', caught); stopSocket(); statusText('会话已结束；不会自动重放未确认的输入。'); }
}
term.onData(text => sendInput(new TextEncoder().encode(text)));
term.onBinary(data => sendInput(Uint8Array.from(data, character => character.charCodeAt(0) & 255)));
assetSelect.addEventListener('change', renderAccounts);
accountSelect.addEventListener('change', () => { renderAccounts(); });
window.addEventListener('resize', scheduleResize);
new ResizeObserver(scheduleResize).observe(element('terminal'));
connectButton.addEventListener('click', () => { void connect(); });
closeButton.addEventListener('click', () => {
  sendControl({ type: 'close', channel_id: CHANNEL }); stopSocket(); statusText('连接已由用户关闭；终端历史保留。');
});
eofButton.addEventListener('click', () => {
  if (sendControl({ type: 'eof', channel_id: CHANNEL })) { eofSent = true; updateControls(); statusText('输入 EOF 已发送；继续接收目标输出和退出状态。'); }
});
reloadButton.addEventListener('click', () => { void action('读取授权资产', () => loadAssets(false)); });
moreButton.addEventListener('click', () => { void action('加载更多资产', () => loadAssets(true)); });
loginForm.addEventListener('submit', event => {
  event.preventDefault();
  void action('登录/读取身份', async () => {
    statusText('登录：读取 CSRF 并提交认证…');
    await loadCsrf(lifetime.signal);
    const username = element<HTMLInputElement>('username').value;
    const deviceLabel = element<HTMLInputElement>('device').value;
    let credentials: { username: string; password: string; device_label: string; client_type: 'web' } | null = {
      username, password: password.value, device_label: deviceLabel, client_type: 'web',
    };
    password.value = '';
    try { await request('/api/v1/auth/login', credentials, lifetime.signal); }
    finally { credentials.password = ''; credentials = null; }
    refreshUsed = false;
    openWorkspace(await loadMe(lifetime.signal));
    await loadAssets(false); assetSelect.focus();
  });
});
logoutButton.addEventListener('click', () => {
  void action('注销', async () => {
    stopSocket();
    try { await request('/api/v1/auth/logout', {}, lifetime.signal); statusText('已注销。'); }
    finally { clearMemory(); element('username').focus(); }
  });
});
refreshButton.addEventListener('click', () => {
  void action('主动刷新登录', async () => {
    if (refreshUsed) return;
    if (!navigator.locks) throw new Error('无法协调多标签页刷新；请注销后重新登录。');
    await navigator.locks.request('bastion-auth-refresh', { ifAvailable: true }, async lock => {
      if (!lock) throw new Error('另一标签页正在刷新；本标签页不会并发提交。');
      refreshUsed = true; updateControls();
      try {
        await request('/api/v1/auth/refresh', {}, lifetime.signal);
        openWorkspace(await loadMe(lifetime.signal)); statusText('登录会话已主动刷新一次。');
      } catch (caught) { clearMemory(); statusText('刷新失败，需重新登录；不会重放刷新请求。'); throw caught; }
    });
  });
});
async function initialize() {
  await action('读取登录状态', async () => {
    if (!import.meta.env.DEV && location.protocol !== 'https:') throw new Error('HTTPS_REQUIRED：生产部署必须使用 HTTPS。');
    statusText('正在读取登录状态…');
    await loadCsrf(lifetime.signal);
    try { openWorkspace(await loadMe(lifetime.signal)); }
    catch (caught) {
      if (caught instanceof ApiError && caught.status === 401) { loginPanel.hidden = false; statusText('请登录以继续。'); element('username').focus(); return; }
      throw caught;
    }
    await loadAssets(false);
  });
  if (!me) loginPanel.hidden = false;
}
window.addEventListener('pagehide', () => { clearMemory(); });
window.addEventListener('pageshow', event => { if (event.persisted) void initialize(); });
void initialize();
