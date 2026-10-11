export type ChannelKind = 'email'|'wecom'|'dingtalk'|'feishu'|'webhook'|'syslog_tls'|'syslog_tcp'
export type LogStream = 'alerts'|'operations'|'logins'
export type DeliveryState = 'queued'|'running'|'retry'|'accepted'|'transport_written'|'failed'|'uncertain'|'suppressed'|'cancelled'
export interface Channel {
  id:string;revision:number;name:string;kind:ChannelKind;enabled:boolean;severities:string[];streams?:LogStream[];target:string;has_secret:boolean;muted_until:string|null;updated_at:string
}
export interface ChannelChange {
  id:string;expected_revision:number;name:string;kind:ChannelKind;enabled:boolean;severities:string[];streams?:LogStream[];muted_until:string|null
  connection?:{endpoint?:string;secret?:string;token?:string;smtp_host?:string;smtp_port?:number;smtp_user?:string;smtp_password?:string;from?:string;recipients?:string[];implicit_tls?:boolean}
}
export interface Delivery {
  id:string;channel_id:string;channel_name:string;kind:ChannelKind;channel_revision:number;recipient:string;state:DeliveryState;version:number;attempts:number;alert_count:number;record_count?:number;stream?:LogStream|'test';created_at:string;updated_at:string
  receipt:{state?:string;code?:string;http_status?:number;provider_code?:number;duration_ms?:number;observed_at?:string;frames?:number;frames_written?:number}
}
export const channelNames:Record<ChannelKind,string>={email:'邮件',wecom:'企业微信',dingtalk:'钉钉',feishu:'飞书',webhook:'Webhook',syslog_tls:'Syslog TLS',syslog_tcp:'Syslog TCP'}
export const deliveryNames:Record<DeliveryState,string>={queued:'等待投递',running:'正在投递',retry:'等待重试',accepted:'渠道已受理',transport_written:'传输已写入',failed:'投递失败',uncertain:'结果待核实',suppressed:'已抑制',cancelled:'已取消'}
export const streamNames:Record<LogStream|'test',string>={alerts:'安全告警',operations:'操作日志',logins:'登录日志',test:'渠道测试'}
export const streamOptions=Object.entries(streamNames).filter(([value])=>value!=='test').map(([value,label])=>({value,label}))
export const severityOptions=[{value:'high',label:'高危'},{value:'medium',label:'中危'},{value:'low',label:'低危'},{value:'unknown',label:'未定级'}]
export const receiptNames:Record<string,string>={provider_accepted:'服务商确认受理消息',smtp_accepted:'邮件服务器确认受理消息',storage_acknowledgment_unavailable:'传输写入完成，未获取日志服务器落盘确认',provider_rejected:'服务商拒绝消息',provider_rate_limited:'服务商限流，按计划重试',connection_failed:'未建立连接，按计划重试',acknowledgment_lost:'发送后连接中断，需要核实渠道处理结果',provider_result_unknown:'服务商返回超时或故障，处理结果待核实',invalid_acknowledgment:'未获取有效业务回执，需要核实处理结果',smtp_result_unknown:'邮件内容提交结果待核实',smtp_setup_failed:'SMTP 建立会话、TLS 或认证失败',smtp_rejected:'SMTP 服务器拒绝投递',transport_result_unknown:'传输未完成，日志接收结果待核实',worker_interrupted:'投递执行中断，需要核实渠道处理结果',tls_verification_failed:'目标 TLS 身份校验失败',invalid_config:'渠道配置无效',target_denied:'目标不在允许范围内',message_too_large:'消息超过渠道容量限制',invalid_recipient:'接收人不在渠道配置范围内'}
export function deliveryClass(state:DeliveryState){return state==='accepted'||state==='transport_written'?'status-online':state==='failed'?'status-high':state==='uncertain'||state==='retry'?'status-medium':'status-unknown'}
