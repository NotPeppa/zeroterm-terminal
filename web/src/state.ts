import type { Info, Role } from './api';
export type RouteName = 'assets' | 'console' | 'connections' | 'audit' | 'recordings' | 'profile' | 'users' | 'admin-assets' | 'grants';
export type Route = { name: RouteName | 'not-found'; id?: string; sub?: string };
/** Live session state of the console viewport, surfaced by the session mounts to the popup shell. */
export type SessionState = 'idle' | 'connecting' | 'ready' | 'closed';
export const routes: { name: RouteName; label: string; group: string; admin?: boolean; audit?: boolean; feature?: keyof NonNullable<Info['features']> }[] = [
  { name: 'assets', label: '可用资产', group: '工作台' }, { name: 'console', label: '控制台', group: '工作台' },
  { name: 'connections', label: '会话连接', group: '日志审计' }, { name: 'recordings', label: '录制回放', group: '日志审计', feature: 'recording_replay' },
  { name: 'audit', label: '审计事件', group: '日志审计', audit: true },
  { name: 'users', label: '用户管理', group: '系统管理', admin: true }, { name: 'admin-assets', label: '资产管理', group: '系统管理', admin: true }, { name: 'grants', label: '资源授权', group: '系统管理', admin: true },
  { name: 'profile', label: '个人设置', group: '个人' },
];
const NAV: RouteName[] = ['assets', 'connections', 'recordings', 'audit', 'users', 'admin-assets', 'grants', 'profile'];
export function parseRoute(hash: string): Route {
  const match = /^#\/?([a-z-]+)(?:\/([^/?#]+))?(?:\/([^/?#]+))?$/.exec(hash);
  if (!hash || hash === '#' || hash === '#/') return { name: 'assets' };
  if (!match || !routes.some(route => route.name === match[1])) return { name: 'not-found' };
  try {
    const name = match[1] as RouteName;
    if (name === 'console') {
      if (!match[2] || !match[3]) return { name: 'not-found' };
      return { name, id: decodeURIComponent(match[2]), sub: decodeURIComponent(match[3]) };
    }
    if (match[3]) return { name: 'not-found' };
    return { name, ...(match[2] ? { id: decodeURIComponent(match[2]) } : {}) };
  } catch { return { name: 'not-found' }; }
}
export function allowedRoute(name: Route['name'], role: Role, info: Info | null): boolean {
  const route = routes.find(route => route.name === name);
  return !!route && (!route.admin || role === 'admin') && (!route.audit || role === 'admin' || role === 'auditor') && (!(role === 'auditor' && ['assets', 'console'].includes(name))) && (!route.feature || info?.features?.[route.feature] === true);
}
export function allowedInNavigation(name: RouteName, role: Role, info: Info | null): boolean {
  return NAV.includes(name) && allowedRoute(name, role, info);
}
export function discoveryWarning(info: Info): string {
  const warnings: string[] = [];
  if (!info.production_ready || info.recording?.required === false) warnings.push('开发/候选版本，未通过生产发布验收');
  if (info.recording?.required === false) warnings.push('当前入口不提供 required 会话录制');
  return warnings.join(' · ');
}
export class RouteLifetime {
  controller = new AbortController();
  private cleanups: (() => void)[] = [];
  get signal() { return this.controller.signal; }
  own(cleanup: () => void) { if (this.signal.aborted) cleanup(); else this.cleanups.push(cleanup); }
  dispose() { if (this.signal.aborted) return; for (const cleanup of this.cleanups.splice(0).reverse()) cleanup(); this.controller.abort(); }
}
export function stateMessage(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = String(error.code);
    if (code === 'TARGET_HOST_KEY_UNKNOWN') return '目标主机指纹尚未确认：请管理员首次连接时确认，或在资产管理中点击“确认主机指纹”，再重新连接。';
    if (code === 'TARGET_HOST_KEY_CHANGED') return '目标主机密钥已变化，连接已阻止。请管理员在资产管理中点击“重新核验主机指纹”，核实更换原因后再确认。';
    if (code === 'TARGET_ADDRESS_DENIED') return '目标地址被出站网络策略拒绝：请检查资产地址及服务端允许/拒绝网段；这不是账号权限不足。';
    if (code === 'REVISION_CONFLICT') return '修订冲突：请刷新资源，重新核对修改；不会覆盖或自动重试。';
    if (code === 'RESULT_UNKNOWN') return '结果未知：操作可能已提交。请读取服务端状态，不要直接重复提交。';
    if ('status' in error && error.status === 403) return '禁止访问：当前身份没有此操作权限。';
  }
  return error instanceof Error ? error.message : '未知错误。';
}
