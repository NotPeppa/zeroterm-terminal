import type { Info, Role } from './api';
export type RouteName = 'assets' | 'terminal' | 'files' | 'exec' | 'connections' | 'audit' | 'recordings' | 'profile' | 'users' | 'admin-assets' | 'grants';
export type Route = { name: RouteName | 'not-found'; id?: string };
export const routes: { name: RouteName; label: string; admin?: boolean; audit?: boolean; feature?: keyof NonNullable<Info['features']> }[] = [
  { name: 'assets', label: '授权资产' }, { name: 'terminal', label: '终端', feature: 'web_terminal' },
  { name: 'files', label: '文件', feature: 'web_sftp' }, { name: 'exec', label: '执行 / 工具', feature: 'web_exec' },
  { name: 'connections', label: '连接' }, { name: 'audit', label: '审计', audit: true },
  { name: 'recordings', label: '录制回放', feature: 'recording_replay' }, { name: 'profile', label: '个人设置' },
  { name: 'users', label: '用户管理', admin: true }, { name: 'admin-assets', label: '资产 / 账号 / 主机密钥', admin: true }, { name: 'grants', label: '授权管理', admin: true },
];
export function parseRoute(hash: string): Route {
  const match = /^#\/?([a-z-]+)(?:\/([^/?#]+))?$/.exec(hash);
  if (!hash || hash === '#' || hash === '#/') return { name: 'assets' };
  if (!match || !routes.some(route => route.name === match[1])) return { name: 'not-found' };
  try { return { name: match[1] as RouteName, ...(match[2] ? { id: decodeURIComponent(match[2]) } : {}) }; } catch { return { name: 'not-found' }; }
}
export function allowedRoute(name: Route['name'], role: Role, info: Info | null): boolean {
  const route = routes.find(route => route.name === name);
  return !!route && (!route.admin || role === 'admin') && (!route.audit || role === 'admin' || role === 'auditor') && (!(role === 'auditor' && ['assets', 'terminal', 'files', 'exec'].includes(name))) && (!route.feature || info?.features?.[route.feature] === true);
}
export function discoveryWarning(info: Info): string {
  const warnings: string[] = [];
  if (info.production_ready !== true || info.recording?.required === false) warnings.push('开发/候选版本，未通过生产发布验收');
  if (info.recording?.required === false) warnings.push('当前入口不提供 required 终端录制');
  return warnings.join(' · ');
}
export class RouteLifetime {
  controller = new AbortController();
  private cleanups: (() => void)[] = [];
  get signal() { return this.controller.signal; }
  own(cleanup: () => void) { if (this.signal.aborted) cleanup(); else this.cleanups.push(cleanup); }
  dispose() { if (this.signal.aborted) return; this.controller.abort(); for (const cleanup of this.cleanups.splice(0).reverse()) cleanup(); }
}
export function stateMessage(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = String(error.code);
    if (code === 'REVISION_CONFLICT') return '修订冲突：请刷新资源，重新核对修改；不会覆盖或自动重试。';
    if (code === 'RESULT_UNKNOWN') return '结果未知：操作可能已提交。请读取服务端状态，不要直接重复提交。';
    if ('status' in error && error.status === 403) return '禁止访问：当前身份没有此操作权限。';
  }
  return error instanceof Error ? error.message : '未知错误。';
}
