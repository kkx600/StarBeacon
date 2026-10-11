export const scopeNames={'alerts:read':'告警与态势统计','assets:read':'资产详情','sensors:read':'探针状态','traffic:read':'协议流量检索'} as const
export type Scope=keyof typeof scopeNames
export interface Binding {id:string;name:string;issuer:string;subject:string;oauth_client_id:string;scopes:Scope[];enabled:boolean;expires_at:string;requests_per_minute:number;owner_id:string;revision:number;created_at:string;updated_at:string}
export interface BindingChange {id:string;expected_revision:number;name:string;subject:string;oauth_client_id:string;scopes:Scope[];enabled:boolean;expires_at:string;requests_per_minute:number}
export interface ToolInfo {name:string;title:string;scope:Scope;description:string}
export interface MCPInfo {enabled:boolean;resource:string;issuer:string;metadata_url:string;protocol_versions:string[];tools:ToolInfo[]}
export function bindingState(binding:Binding,now=Date.now()){const expiry=Date.parse(binding.expires_at);return !binding.enabled?'停用':!Number.isFinite(expiry)?'有效期异常':expiry<=now?'已到期':'启用'}
