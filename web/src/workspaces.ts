import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { ApiClient, ApiError, type Info, type DirectoryEntry, type Recording, type Page, type CopyJob } from './api';
import { RouteLifetime } from './state';
import { TargetSocket, type Target } from './terminal';
import { CHANNEL, MAX_BUFFER, MAX_COMMAND_BYTES, commandBase64 } from './protocol';
import { decodeBase64, readNDJSON, ReplaySequence } from './replay';
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => { const result = document.createElement(tag); result.textContent = text; result.className = className; return result; };
const button = (parent: HTMLElement, text: string, action: () => void) => { const result = node('button', text); result.type = 'button'; result.onclick = action; parent.append(result); return result; };
const input = (parent: HTMLElement, labelText: string, value = '') => { const label = node('label', labelText), control = node('input'); control.value = value; label.append(control); parent.append(label); return control; };
const abortError = () => new DOMException('Aborted', 'AbortError');
function write(term: Terminal, bytes: Uint8Array, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => { if (signal.aborted) { reject(abortError()); return; } const abort = () => reject(abortError()); signal.addEventListener('abort', abort, { once: true }); term.write(bytes, () => { signal.removeEventListener('abort', abort); if (signal.aborted) reject(abortError()); else resolve(); }); });
}

export function mountExec(parent: HTMLElement, api: ApiClient, life: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown) => void): () => void {
  parent.append(node('p', '命令仅在当前授权目标执行，不在网关本机执行。此页不会声明 exec 被 shell 录制覆盖。UTF-8 文本或原始命令文件最多 64 KiB，禁止 NUL；断线不自动重放。', 'muted'));
  const form = node('form'), label = node('label', '命令（目标执行）'), command = node('textarea'); command.id = 'command'; command.spellcheck = false; label.append(command); form.append(label);
  const tools = node('select'); tools.setAttribute('aria-label', '选择目标只读工具命令'); tools.replaceChildren(new Option('选择工具（仅填入命令）', ''), new Option('目标系统信息', 'uname -a'), new Option('目标磁盘空间', 'df -h'), new Option('目标运行时长', 'uptime')); tools.onchange = () => { if (tools.value) command.value = tools.value; }; form.append(tools);
  const raw = input(form, '或上传原始 command bytes 文件（不会持久保存）'); raw.type = 'file';
  const run = node('button', '在授权目标执行', 'primary'); run.type = 'submit'; form.append(run); const close = button(form, '关闭整个执行连接', () => { connection.close(); for (const channel of channels.values()) channel.state = 'closed'; update(); status('执行连接已关闭；结果可能未知，命令不会重放。'); }); parent.append(form);
  const connectionLabel = node('p', '尚未建立执行连接', 'muted'); parent.append(connectionLabel);
  const output = node('section'); parent.append(output);
  type Channel = { id: number; command: string; state: 'opening' | 'starting' | 'running' | 'closed'; queued: number; stdout: Terminal; stderr: Terminal; stateLabel: HTMLElement; eof: HTMLButtonElement; cancel: HTMLButtonElement; eofSent: boolean };
  let outputLife = new RouteLifetime(); life.own(() => outputLife.dispose());
  const channels = new Map<number, Channel>(); let next = 1, ready = false, preparing = false, bound: Target | null = null;
  const connection = new TargetSocket(api, life, status, error => { fail(error); ready = false; update(); });
  function update() { run.disabled = preparing || !getTarget()?.account.capabilities.includes('exec') || connection.active && !ready || connection.active && next > 16; close.disabled = !connection.active; for (const channel of channels.values()) { channel.eof.disabled = channel.state !== 'running' || channel.eofSent; channel.cancel.disabled = !connection.active || channel.state === 'closed'; } }
  function start(channel: Channel) { channel.state = 'opening'; connection.send({ type: 'open', kind: 'exec', channel_id: channel.id }); }
  const control = (frame: Parameters<Parameters<TargetSocket['connect']>[2]>[0]) => {
    if (frame.type === 'session_ready') { ready = true; connectionLabel.textContent = `${bound!.asset.name} (${bound!.asset.id}) / ${bound!.account.username} (${bound!.account.id}) · connection_id: ${connection.connectionId}`; for (const channel of channels.values()) if (channel.command && channel.state === 'opening') start(channel); update(); return; }
    if (frame.channel_id === undefined) return; const channel = channels.get(frame.channel_id); if (!channel) throw new Error('UNKNOWN_EXEC_CHANNEL');
    if (frame.type === 'opened') { if (channel.state !== 'opening') throw new Error('UNEXPECTED_EXEC_SEQUENCE'); channel.state = 'starting'; connection.send({ type: 'exec_start', channel_id: channel.id, command_base64: channel.command }); channel.command = ''; }
    else if (frame.type === 'ready') { if (channel.state !== 'starting') throw new Error('UNEXPECTED_EXEC_SEQUENCE'); channel.state = 'running'; channel.stateLabel.textContent = `channel ${channel.id} 已由目标确认启动`; }
    else if (frame.type === 'exit') { channel.stateLabel.textContent = `channel ${channel.id} exit_code: ${frame.exit_code ?? '未提供'} exit_signal: ${frame.exit_signal ?? '未提供'}；等待余下输出`; channel.eofSent = true; }
    else if (frame.type === 'closed' || frame.type === 'error') { channel.state = 'closed'; channel.command = ''; channel.stateLabel.textContent = frame.type === 'error' ? `channel ${channel.id} 失败：${frame.code}` : `channel ${channel.id} 已关闭`; if (frame.type === 'error') fail(new ApiError(frame.code!, '此执行通道被拒绝；其他通道保持独立。', frame.request_id)); }
    update();
  };
  form.onsubmit = event => {
    event.preventDefault(); if (preparing) return; const target = getTarget(); if (!target?.account.capabilities.includes('exec')) return;
    if (bound && connection.active && (bound.asset.id !== target.asset.id || bound.account.id !== target.account.id)) { fail(new Error('目标已锁定：关闭当前执行连接后才能切换目标。')); return; }
    preparing = true; update();
    void (async () => {
      try {
        const file = raw.files?.[0]; if (file && file.size > MAX_COMMAND_BYTES) throw new Error('COMMAND_TOO_LARGE：原始命令文件超过 64 KiB。');
        const bytes = file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(command.value); const encoded = commandBase64(bytes);
        if (life.signal.aborted) return;
        if (!connection.active) { outputLife.dispose(); outputLife = new RouteLifetime(); channels.clear(); output.replaceChildren(); next = 1; }
        const id = next++; if (id > 16) throw new Error('CHANNEL_LIMIT：每个连接最多创建 16 个通道，ID 不复用；请新建连接。');
        const panel = node('article', '', 'card'), stateLabel = node('p', `channel ${id} 正在建立`); panel.append(node('h2', `执行通道 ${id}`), stateLabel);
        const terms: Terminal[] = []; for (const stream of ['stdout', 'stderr']) { panel.append(node('h3', stream)); const viewport = node('div', '', 'terminal'); viewport.style.height = '260px'; viewport.style.minHeight = '220px'; panel.append(viewport); const term = new Terminal({ disableStdin: true, screenReaderMode: true, scrollback: 3000 }); const fit = new FitAddon(); term.loadAddon(fit); term.open(viewport); fit.fit(); const observer = new ResizeObserver(() => fit.fit()); observer.observe(viewport); outputLife.own(() => { observer.disconnect(); term.dispose(); }); terms.push(term); }
        const actions = node('div', '', 'toolbar'); panel.append(actions); output.append(panel);
        const eof = button(actions, '发送 EOF', () => safe(() => { if (connection.send({ type: 'eof', channel_id: id })) { channels.get(id)!.eofSent = true; update(); } }));
        const cancel = button(actions, '取消此通道', () => safe(() => { connection.send({ type: 'close', channel_id: id }); const channel = channels.get(id)!; channel.state = 'closed'; channel.command = ''; channel.stateLabel.textContent = '已提交关闭；服务端进程结果可能未知。'; update(); }));
        const channel: Channel = { id, command: encoded, state: 'opening', queued: 0, stdout: terms[0], stderr: terms[1], stateLabel, eof, cancel, eofSent: false }; channels.set(id, channel);
        raw.value = ''; command.value = ''; bound = target;
        if (ready && connection.active) start(channel);
        else { ready = false; await connection.connect(target, 'exec', control, frame => {
          const channel = channels.get(frame.channel); if (!channel || !['starting', 'running'].includes(channel.state)) throw new Error('INVALID_EXEC_OUTPUT');
          if (channel.queued + frame.payload.length > MAX_BUFFER) throw new Error('OUTPUT_BACKPRESSURE'); channel.queued += frame.payload.length;
          (frame.kind === 3 ? channel.stderr : channel.stdout).write(frame.payload, () => { channel.queued = Math.max(0, channel.queued - frame.payload.length); });
        }, () => { if (!connection.active) { ready = false; for (const channel of channels.values()) { channel.command = ''; channel.state = 'closed'; } } update(); }); }
      } catch (error) { if (!life.signal.aborted) fail(error); }
      finally { preparing = false; update(); }
    })();
  };
  function safe(action: () => void) { try { action(); } catch (error) { fail(error); connection.close(); ready = false; update(); } }
  life.own(() => { command.value = ''; raw.value = ''; for (const channel of channels.values()) channel.command = ''; }); update(); return update;
}

export function mountFiles(parent: HTMLElement, api: ApiClient, life: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown) => void, info: Info): () => void {
  parent.append(node('p', '文件操作由服务端 SFTP 完成，浏览器不解析 SFTP。先建立授权目标文件连接；连接存在期间目标锁定。上传与重命名默认不覆盖、不续传、无自动重试；删除仅支持 regular file，不删除目录。', 'muted'));
  const toolbar = node('div', '', 'toolbar'); parent.append(toolbar); const connectionLabel = node('p', '文件连接尚未建立', 'muted'); parent.append(connectionLabel);
  const connection = new TargetSocket(api, life, status, error => { fail(error); ready = false; update(); }); let ready = false, bound: Target | null = null, busy = false, transfer: AbortController | null = null, generation = 0;
  const connect = button(toolbar, '建立 SFTP 连接', () => {
    const target = getTarget(); if (!target?.account.capabilities.includes('sftp')) return; bound = target;
    void connection.connect(target, 'sftp', frame => {
      if (frame.type === 'session_ready') connection.send({ type: 'open', kind: 'sftp', channel_id: CHANNEL });
      else if (frame.type === 'opened' && frame.channel_id === CHANNEL) connection.send({ type: 'sftp_open', channel_id: CHANNEL });
      else if (frame.type === 'ready' && frame.channel_id === CHANNEL) { ready = true; connectionLabel.textContent = `${target.asset.name} (${target.asset.id}) / ${target.account.username} (${target.account.id}) · connection_id: ${connection.connectionId}`; update(); void list(); }
      else if (frame.type === 'closed' || frame.type === 'error') { ready = false; fail(new ApiError(frame.code ?? 'SFTP_CHANNEL_CLOSED', '文件连接已关闭；在途操作结果需重新读取。')); update(); }
    }, () => { throw new Error('UNEXPECTED_SFTP_BINARY'); }, () => { if (!connection.active) ready = false; update(); }); update();
  });
  const disconnect = button(toolbar, '关闭文件连接', () => { transfer?.abort(); connection.close(); ready = false; busy = false; generation++; update(); status('文件连接已关闭；在途写入结果可能未知。'); });
  const path = input(parent, '远程目录路径', '.'); path.id = 'file-path'; const actions = node('div', '', 'toolbar'); parent.append(actions); const listing = node('section'), result = node('p', '', 'muted'); parent.append(result, listing);
  const listButton = button(actions, '读取目录', () => { void list(); });
  const statButton = button(actions, '读取路径元数据', () => { void action(async signal => { const metadata = await api.statFile(connection.connectionId, path.value, signal); result.textContent = JSON.stringify(metadata); }); });
  const mkdir = button(actions, '创建目录', () => operation('mkdir'));
  const uploadPanel = node('section', '', 'card upload-card');
  uploadPanel.append(node('h2', '上传文件到当前目标'), node('p', '先建立上方 SFTP 连接，再选择本地文件。默认保存到上方远程目录，文件同名已存在时服务端会拒绝；不会自动覆盖或重试。', 'muted'));
  parent.append(uploadPanel);
  const uploadTarget = node('p', '', 'muted'); uploadPanel.append(uploadTarget);
  const uploadInput = input(uploadPanel, '1. 选择本地文件'); uploadInput.type = 'file'; uploadInput.id = 'upload-file';
  const destination = input(uploadPanel, '2. 目标文件路径（包含文件名，可修改）'); destination.id = 'upload-destination'; destination.placeholder = '选择文件后自动填入 当前远程目录/文件名';
  const uploadActions = node('div', '', 'toolbar'); uploadPanel.append(uploadActions);
  const uploadState = node('p', '', 'muted'); uploadState.setAttribute('role', 'status'); uploadState.setAttribute('aria-live', 'polite'); uploadPanel.append(uploadState);
  let destinationEdited = false, uploadOutcome = '';
  const upload = button(uploadActions, '3. 上传到当前目标', () => {
    const file = uploadInput.files?.[0];
    if (!file || !destination.value || destination.value.includes('\0')) { uploadState.textContent = '请选择本地文件，并填写不含 NUL 的目标文件路径。'; return; }
    uploadOutcome = ''; uploadState.textContent = `正在上传 ${file.name}，无覆盖、无自动重试…`;
    void action(async signal => {
      try {
        const reply = await api.upload(connection.connectionId, destination.value, file, signal);
        if (!reply || !Number.isSafeInteger(reply.bytes) || reply.bytes < 0) throw new ApiError('RESULT_UNKNOWN', '上传响应无效；请检查服务端文件状态。');
        uploadOutcome = `服务端确认写入 ${reply.bytes} 字节到 ${destination.value}。`; uploadState.textContent = uploadOutcome;
        uploadInput.value = ''; await readList(signal);
      } catch (error) { uploadOutcome = error instanceof ApiError && error.code === 'RESULT_UNKNOWN' ? '上传结果未知：请读取目录或元数据确认，不要直接重复提交。' : '上传未完成；请查看错误信息。'; uploadState.textContent = uploadOutcome; throw error; }
    });
  });
  upload.className = 'primary'; upload.id = 'upload-submit';
  const cancel = button(uploadActions, '取消在途操作', () => { transfer?.abort(); uploadOutcome = '已请求取消；上传结果可能未知，请重新读取目录或元数据。'; uploadState.textContent = result.textContent = uploadOutcome; });
  function suggestUploadDestination() {
    uploadOutcome = '';
    const file = uploadInput.files?.[0];
    if (!destinationEdited) {
      try { destination.value = file ? fullPath(path.value, file.name) : ''; }
      catch (error) { fail(error); }
    }
    update();
  }
  uploadInput.onchange = suggestUploadDestination; path.onchange = suggestUploadDestination;
  destination.oninput = () => { destinationEdited = true; uploadOutcome = ''; update(); };
  function update() {
    connect.disabled = connection.active || !getTarget()?.account.capabilities.includes('sftp'); disconnect.disabled = !connection.active;
    for (const control of [listButton, statButton, mkdir]) control.disabled = !ready || busy;
    upload.disabled = !ready || busy || !uploadInput.files?.[0] || !destination.value || destination.value.includes('\0');
    uploadInput.disabled = destination.disabled = busy; cancel.disabled = !busy;
    const target = connection.active ? bound : getTarget();
    uploadTarget.textContent = target ? `上传目标：${target.asset.name} / ${target.account.username}；远程目录：${path.value}` : '没有授权目标。';
    uploadState.textContent = uploadOutcome || (!ready ? '请先点击“建立 SFTP 连接”。' : busy ? '操作正在进行；不会自动重试。' : !uploadInput.files?.[0] ? '请选择要上传的本地文件。' : !destination.value ? '请填写目标文件路径（包含文件名）。' : `准备上传 ${uploadInput.files[0].name} 到 ${destination.value}。`);
  }
  async function action(work: (signal: AbortSignal) => Promise<void>) {
    if (!ready || busy) return; busy = true; const controller = new AbortController(); transfer = controller; const request = generation; update(); result.textContent = '正在执行；无自动重试。';
    try { await work(AbortSignal.any([controller.signal, life.signal])); }
    catch (error) { if (!life.signal.aborted) { result.textContent = error instanceof ApiError && error.code === 'RESULT_UNKNOWN' ? '结果未知：请重新读取服务端状态，勿直接重复写入。' : '操作未完成。'; fail(error); } }
    finally { if (generation === request) busy = false; if (transfer === controller) transfer = null; update(); }
  }
  async function readList(signal: AbortSignal) {
    const requestedPath = path.value, reply = await api.files(connection.connectionId, requestedPath, signal); if (signal.aborted) return;
    if (!Array.isArray(reply?.items)) throw new ApiError('INVALID_RESPONSE', '目录响应不完整。');
    listing.replaceChildren(); result.textContent = reply.items.length ? `${reply.items.length} 条目录项。` : '目录为空。';
    for (const entry of reply.items) {
      if (entry.name === '.' || entry.name === '..') continue;
      if (typeof entry.name !== 'string' || !entry.metadata || !['file', 'directory', 'symlink', 'other'].includes(entry.metadata.kind)) throw new ApiError('INVALID_RESPONSE', '目录项无效。');
      const row = node('article', '', 'card'); row.dataset.path = fullPath(requestedPath, entry.name); row.append(node('h3', entry.name), node('p', `${entry.metadata.kind} · size: ${entry.metadata.size ?? '未知'} · permissions: ${entry.metadata.permissions ?? '未知'} · mtime: ${entry.metadata.mtime ?? '未知'}`, 'muted'));
      const rowActions = node('div', '', 'toolbar'); row.append(rowActions); listing.append(row);
      if (entry.metadata.kind === 'directory') button(rowActions, '进入目录', () => { path.value = fullPath(requestedPath, entry.name); suggestUploadDestination(); void list(); });
      if (entry.metadata.kind === 'file') { button(rowActions, '下载', () => { void download(fullPath(requestedPath, entry.name), entry); }); button(rowActions, '删除 regular file', () => operation('remove', fullPath(requestedPath, entry.name))); }
      button(rowActions, '无覆盖重命名', () => operation('rename', fullPath(requestedPath, entry.name)));
    }
  }
  function fullPath(directory: string, name: string) { if (!directory || name === '.' || name === '..' || name.includes('/') || name.includes('\0')) throw new Error('INVALID_DIRECTORY_ENTRY'); return `${directory.replace(/\/$/, '')}/${name}`; }
  async function list() { await action(readList); }
  function operation(operation: 'mkdir' | 'remove' | 'rename', initial = path.value) {
    if (!ready || busy) return;
    const dialog = node('dialog'), form = node('form'); form.append(node('h2', operation === 'mkdir' ? '创建远程目录' : operation === 'remove' ? '删除远程 regular file（不可撤回）' : '无覆盖重命名'));
    const source = input(form, '远程路径', initial), to = operation === 'rename' ? input(form, '完整目标路径') : null, issue = node('p', '', 'error'), controls = node('div', '', 'toolbar');
    const submit = node('button', '确认一次操作'); submit.type = 'submit'; controls.append(submit); button(controls, '取消', () => dialog.close()); form.append(issue, controls); dialog.append(form); document.body.append(dialog);
    dialog.onclose = () => { dialog.remove(); path.focus(); }; life.own(() => { dialog.close(); dialog.remove(); }); form.onsubmit = event => { event.preventDefault(); if (!source.value || to && !to.value) { issue.textContent = '路径不能为空。'; return; } dialog.close(); void action(async signal => { await api.fileOperation(connection.connectionId, { operation, path: source.value, ...(to ? { destination: to.value } : {}) }, signal); result.textContent = '服务端已确认文件操作。'; await readList(signal); }); }; dialog.showModal(); source.focus();
  }
  async function download(remote: string, entry: DirectoryEntry) {
    if (!ready || busy) return;
    const href = new URL(`/api/v1/connections/${encodeURIComponent(connection.connectionId)}/files/content`, location.origin);
    href.searchParams.set('path', remote);
    const anchor = document.createElement('a'); anchor.href = href.href; anchor.download = entry.name; anchor.rel = 'noreferrer'; anchor.textContent = `交给浏览器下载：${entry.name}`; anchor.className = 'download-link';
    parent.append(anchor); anchor.click(); status('已交给浏览器下载；浏览器不会向此页面报告服务端流是否完整。关闭文件连接可终止服务端绑定流。');
    life.own(() => anchor.remove());
  }
  if (info.features?.copy_jobs) mountCopyJobs(parent, api, life, getTarget, status, fail);
  else parent.append(node('p', '服务端未装配安全 copy job 能力；跨目标复制不可用。', 'muted'));
  life.own(() => { transfer?.abort(); uploadInput.value = ''; }); update(); return update;
}
function mountCopyJobs(parent: HTMLElement, api: ApiClient, life: RouteLifetime, getTarget: () => Target | null, status: (text: string) => void, fail: (error: unknown) => void) {
  const panel = node('section', '', 'card'); panel.append(node('h2', '跨授权目标单 regular file 复制'), node('p', '无覆盖、无续传、无自动重试。源为当前目标，目的必须是服务端授权的资产和账号。', 'muted'));
  const form = node('form'), source = input(form, '源完整路径'), asset = input(form, '目的资产 ID'), account = input(form, '目的账号 ID'), destination = input(form, '目的完整路径'), submit = node('button', '创建一次复制任务'); submit.type = 'submit'; form.append(submit); panel.append(form); parent.append(panel); const output = node('div'); panel.append(output); let busy = false;
  const refresh = async () => { try { const reply = await api.copyJobs({}, life.signal); if (life.signal.aborted) return; output.replaceChildren(); if (!reply.items.length) output.append(node('p', '没有复制任务。')); for (const job of reply.items) { const row = node('article', '', 'card'); row.append(node('pre', JSON.stringify(job, null, 2))); if (['queued', 'running'].includes(job.state)) button(row, '取消任务', () => { void api.cancelCopyJob(job.id, life.signal).then(refresh).catch(fail); }); output.append(row); } } catch (error) { if (!life.signal.aborted) fail(error); } };
  button(panel, '刷新任务状态', () => { void refresh(); });
  form.onsubmit = event => { event.preventDefault(); if (busy) return; const target = getTarget(); if (!target?.account.capabilities.includes('sftp')) return; if (![source.value, asset.value, account.value, destination.value].every(Boolean)) { fail(new Error('复制源和目的信息均不能为空。')); return; } busy = true; submit.disabled = true;
    void api.createCopyJob({ source_asset_id: target.asset.id, source_account_id: target.account.id, source_path: source.value, destination_asset_id: asset.value, destination_account_id: account.value, destination_path: destination.value }, life.signal).then(() => { status('复制任务已创建，以服务端状态为准。'); return refresh(); }).catch(fail).finally(() => { busy = false; submit.disabled = false; }); };
  void refresh();
}

export function mountReplay(parent: HTMLElement, api: ApiClient, life: RouteLifetime, status: (text: string) => void, fail: (error: unknown) => void, connectionId?: string) {
  parent.append(node('p', '只读 shell 录制回放。内容由服务端鉴权、解密及校验；不会下载 KEK/DEK，不包含终端输入或 exec/SFTP 输出。', 'muted'));
  const list = node('section'), controls = node('div', '', 'replay-controls'), selected = input(controls, '录制 ID'), speed = node('select'); speed.setAttribute('aria-label', '回放速度'); speed.replaceChildren(...['1', '0.5', '2', '4', '0'].map(value => new Option(value === '0' ? '即时（有界流式）' : `${value}×`, value))); controls.append(speed); parent.append(list, controls);
  const metadata = node('pre'), progress = node('p', '请选择录制。', 'muted'), viewport = node('div', '', 'terminal'); viewport.setAttribute('aria-label', '只读录制终端'); parent.append(metadata, progress, viewport);
  const term = new Terminal({ disableStdin: true, screenReaderMode: true, scrollback: 5000 }); const fit = new FitAddon(); term.loadAddon(fit); term.open(viewport); fit.fit();
  let playback: AbortController | null = null, paused = false, releasePause: (() => void) | null = null, next: string | null = null, listBusy = false;
  const play = button(controls, '开始回放（重新读取）', () => { void start(); }), pause = button(controls, '暂停', () => { paused = !paused; pause.textContent = paused ? '继续' : '暂停'; if (!paused) { releasePause?.(); releasePause = null; } }), stop = button(controls, '停止回放', () => { playback?.abort(); releasePause?.(); progress.textContent = '已停止；不宣称完整回放。'; }); pause.disabled = stop.disabled = true;
  const refresh = button(list, '刷新录制列表', () => { void load(false); }), more = button(list, '更多录制', () => { void load(true); }); more.hidden = true; const entries = node('div'); list.append(entries);
  const selectionButtons: HTMLButtonElement[] = [];
  function updateReplayControls() {
    play.disabled = !!playback || !selected.value;
    refresh.disabled = more.disabled = listBusy || !!playback;
    for (const selection of selectionButtons) selection.disabled = !!playback || selection.dataset.unsupported === 'true';
  }
  selected.oninput = updateReplayControls;
  async function load(append: boolean) {
    if (listBusy || playback) return; listBusy = true; updateReplayControls(); progress.textContent = '正在读取录制元数据…';
    try {
      const page = await api.recordings({ ...(connectionId ? { connection_id: connectionId } : {}), ...(append && next ? { cursor: next } : {}) }, life.signal);
      if (life.signal.aborted) return;
      if (!Array.isArray(page?.items)) throw new ApiError('INVALID_RESPONSE', '录制列表无效。');
      if (!append) { entries.replaceChildren(); selectionButtons.length = 0; }
      if (!page.items.length) entries.append(node('p', '没有可读取的录制。', 'muted'));
      for (const recording of page.items) {
        const row = node('article', '', 'card');
        row.append(node('h3', `录制 ${recording.id}`), node('p', `服务端状态: ${recording.state ?? recording.status ?? '未知'}；内容回放时仍需校验。`, 'muted'));
        const details = node('details'); details.append(node('summary', '查看录制元数据'), node('pre', JSON.stringify(recording, null, 2))); row.append(details);
        const selection = button(row, '选择回放', () => {
          if (playback) return;
          selected.value = recording.id; progress.textContent = `已选择 ${recording.id}，正在加载回放…`;
          controls.scrollIntoView({ behavior: 'smooth', block: 'start' });
          void start();
        });
        if (recording.format_version !== undefined && recording.format_version !== 1) {
          selection.dataset.unsupported = 'true'; selection.disabled = true;
          row.append(node('p', `无法回放：不支持录制格式 ${recording.format_version}。`, 'error'));
        }
        selectionButtons.push(selection); entries.append(row);
      }
      next = page.next_cursor; more.hidden = !next; progress.textContent = '点击任一“选择回放”即可开始；也可输入录制 ID 后点击开始。';
    }
    catch (error) { if (!life.signal.aborted) { progress.textContent = '录制列表读取失败，请查看错误信息。'; fail(error); } }
    finally { listBusy = false; updateReplayControls(); }
  }
  async function delay(milliseconds: number, signal: AbortSignal) { if (!milliseconds) return; await new Promise<void>((resolve, reject) => { const timer = setTimeout(() => { signal.removeEventListener('abort', aborted); resolve(); }, milliseconds); const aborted = () => { clearTimeout(timer); reject(abortError()); }; signal.addEventListener('abort', aborted, { once: true }); if (signal.aborted) aborted(); }); }
  async function waitPaused(signal: AbortSignal) { if (!paused) return; await new Promise<void>((resolve, reject) => { const aborted = () => reject(abortError()); releasePause = () => { signal.removeEventListener('abort', aborted); if (signal.aborted) reject(abortError()); else resolve(); }; signal.addEventListener('abort', aborted, { once: true }); if (signal.aborted) aborted(); }); }
  async function start() {
    if (playback) { progress.textContent = '已有回放进行中；请暂停或停止后选择另一条录制。'; return; }
    if (!selected.value) { progress.textContent = '请先选择录制或输入录制 ID。'; selected.focus(); return; }
    const recordingId = selected.value;
    const controller = new AbortController(); playback = controller; const signal = AbortSignal.any([controller.signal, life.signal]); selected.disabled = true; pause.disabled = stop.disabled = false; paused = false; pause.textContent = '暂停'; term.reset();
    updateReplayControls(); progress.textContent = `正在加载录制 ${recordingId}…`; status(`正在读取录制 ${recordingId}，回放为只读。`);
    try {
      const detail = await api.recording(selected.value, signal); if (signal.aborted) return; metadata.textContent = JSON.stringify(detail, null, 2);
      if (detail.format_version !== undefined && detail.format_version !== 1) throw new Error('UNSUPPORTED_RECORDING_FORMAT');
      const response = await api.recordingContent(selected.value, signal), sequence = new ReplaySequence(); let previous = 0;
      await readNDJSON(response, signal, async line => {
        const event = sequence.parse(line); await waitPaused(signal);
        let remaining = Number(speed.value) > 0 ? (event.elapsed_us - previous) / 1000 / Number(speed.value) : 0;
        while (remaining > 0) { await waitPaused(signal); const tick = Math.min(remaining, 100); await delay(tick, signal); remaining -= tick; }
        previous = event.elapsed_us; if (signal.aborted) throw abortError();
        if (event.type === 'meta' || event.type === 'resize') term.resize(event.cols!, event.rows!);
        if (event.type === 'output') await write(term, decodeBase64(event.data_base64!), signal);
        progress.textContent = `seq ${event.seq} · ${(event.elapsed_us / 1000000).toFixed(3)} s · ${event.type}${event.type === 'exit' ? ` ${event.exit_code ?? event.exit_signal}` : event.type === 'end' ? ` ${event.reason}` : ''}`;
      });
      sequence.finish();
      const state = String(detail.state ?? detail.status ?? 'unknown');
      if (state !== 'complete') { progress.textContent = `有效 end 已读取，但服务端录制状态为 ${state}；不宣称完整。`; }
      else { progress.textContent = `服务端确认录制 state=complete，且读取到有效 end；checksum/bytes 由服务端校验元数据负责。`; }
      status('只读回放流已结束。');
    } catch (error) { if (!signal.aborted) { progress.textContent = '回放失败或部分内容不可读；不宣称完整。'; fail(error); } }
    finally { if (playback === controller) playback = null; releasePause = null; selected.disabled = false; pause.disabled = stop.disabled = true; updateReplayControls(); }
  }
  life.own(() => { playback?.abort(); releasePause?.(); term.dispose(); }); updateReplayControls(); void load(false);
}
