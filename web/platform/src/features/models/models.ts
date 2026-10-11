export type ProviderKind = 'openai_responses' | 'openai_chat'
export interface ModelUsage { input_tokens:number; output_tokens:number; total_tokens:number }
export interface ModelResult {state:string;code:string;returned_model?:string;usage:ModelUsage|null;http_status?:number;duration_ms?:number|null}
export interface ModelCheck {id:string;provider_revision:number;state:string;result:ModelResult;created_at:string;finished_at:string|null}
export interface ModelProvider {
  id:string;revision:number;name:string;kind:ProviderKind;base_url:string;model:string;enabled:boolean;allow_external:boolean
  max_output_tokens:number;timeout_seconds:number;daily_requests:number;has_key:boolean;updated_at:string;check:ModelCheck|null
}
export interface ModelChange {
  id:string;expected_revision:number;replace_key:boolean
  config:{name:string;kind:ProviderKind;base_url:string;model:string;api_key:string;enabled:boolean;allow_external:boolean;max_output_tokens:number;timeout_seconds:number;daily_requests:number}
}
export const providerNames:Record<ProviderKind,string>={openai_responses:'Responses API',openai_chat:'Chat Completions API'}
export const checkNames:Record<string,string>={running:'验证中',succeeded:'连接正常',failed:'验证失败',uncertain:'结果未知',refused:'提供方拒答',incomplete:'输出未完成'}
export const resultNames:Record<string,string>={completed:'生成接口已返回完整响应',invalid_config:'模型配置或请求参数无效',target_denied:'目标不在允许的网络范围内',response_too_large:'响应超过读取上限',provider_redirect:'提供方返回重定向，调用已停止',provider_rejected:'提供方拒绝请求',provider_rate_limited:'提供方限制请求频率',provider_result_unknown:'请求可能已执行，结果无法确认',request_cancelled:'请求在发送前取消',provider_unavailable:'提供方暂不可连接',invalid_response:'提供方响应不符合约定',invalid_usage:'提供方返回的用量不一致',empty_response:'提供方未返回文本',incomplete_output:'提供方未完成输出',provider_refused:'提供方拒绝生成内容',unexpected_tool_call:'响应包含未授权的工具调用'}
export function checkClass(state:string){return state==='succeeded'?'status-online':state==='running'?'status-unknown':state==='failed'?'status-high':state==='uncertain'||state==='incomplete'?'status-medium':'status-disabled'}
