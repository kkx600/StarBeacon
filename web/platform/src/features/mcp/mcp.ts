export const scopeNames = {
  'alerts:read': '告警与态势统计',
  'assets:read': '资产详情',
  'sensors:read': '探针状态',
  'traffic:read': '协议流量检索',
} as const;
export type Scope = keyof typeof scopeNames;
export interface Binding {
  id: string;
  name: string;
  issuer: string;
  subject: string;
  oauth_client_id: string;
  scopes: Scope[];
  enabled: boolean;
  expires_at: string;
  requests_per_minute: number;
  owner_id: string;
  revision: number;
  created_at: string;
  updated_at: string;
}
export interface BindingChange {
  id: string;
  expected_revision: number;
  name: string;
  subject: string;
  oauth_client_id: string;
  scopes: Scope[];
  enabled: boolean;
  expires_at: string;
  requests_per_minute: number;
}
export interface ToolInfo {
  name: string;
  title: string;
  scope: Scope;
  description: string;
}
export interface MCPInfo {
  enabled: boolean;
  resource: string;
  issuer: string;
  metadata_url: string;
  protocol_versions: string[];
  tools: ToolInfo[];
}
const bindingBadges = {
  disabled: { value: '停用', tone: 'neutral' },
  invalid: { value: '有效期异常', tone: 'warning' },
  expired: { value: '已到期', tone: 'neutral' },
  enabled: { value: '启用', tone: 'success' },
} as const;
export function bindingBadge(binding: Binding, now = Date.now()) {
  const expiry = Date.parse(binding.expires_at);
  if (!binding.enabled) return bindingBadges.disabled;
  if (!Number.isFinite(expiry)) return bindingBadges.invalid;
  return expiry <= now ? bindingBadges.expired : bindingBadges.enabled;
}
export function bindingState(binding: Binding, now = Date.now()) {
  return bindingBadge(binding, now).value;
}
