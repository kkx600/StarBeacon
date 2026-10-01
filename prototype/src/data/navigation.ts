import {pages} from './catalog.ts'

export interface WorkspaceSpec { id:string;title:string;group:string;pages:string[] }

// 主导航以工作任务组织；需求验收条目留在工作区页签与对象详情中。
export const workspaces:WorkspaceSpec[]=[
  {id:'overview',title:'态势总览',group:'overview',pages:['overview']},
  {id:'topology',title:'网络拓扑',group:'overview',pages:['topology']},
  {id:'response-metrics',title:'响应效能',group:'overview',pages:['response-metrics']},
  {id:'screens',title:'态势大屏',group:'overview',pages:['big-screen','screens']},
  {id:'alerts',title:'告警管理',group:'alerts',pages:['alerts','assessments']},
  {id:'search',title:'高级检索',group:'alerts',pages:['search','fields','exports']},
  {id:'investigation',title:'事件调查',group:'incidents',pages:['incidents','cases','timelines','case-sharing','reviews']},
  {id:'duty',title:'值班管理',group:'incidents',pages:['duty']},
  {id:'tickets',title:'处置工单',group:'incidents',pages:['tickets']},
  {id:'assets',title:'资产管理',group:'assets',pages:['assets','interfaces','address-history','nat','identities','services','asset-relations']},
  {id:'asset-groups',title:'资产组与网段',group:'assets',pages:['asset-groups']},
  {id:'asset-risk',title:'资产风险',group:'assets',pages:['asset-risk','vulnerabilities','scan-tasks','risk-priorities','remediations','baselines','external-exposure']},
  {id:'applications',title:'应用与行为',group:'traffic',pages:['applications','behaviors']},
  {id:'packets',title:'通信取证',group:'traffic',pages:['packets','packet-times','payloads','tls-visibility']},
  {id:'sessions',title:'会话与 PCAP',group:'traffic',pages:['sessions','session-integrity','pcap-tasks']},
  {id:'capture-policy',title:'流量采集',group:'traffic',pages:['capture-policy','capture-scope','inspection-depth','capture-quality','protocols']},
  {id:'pipeline-latency',title:'处理性能',group:'traffic',pages:['pipeline-latency','capacity']},
  {id:'rules',title:'检测规则',group:'detection',pages:['rules','correlation','sigma','application-rules','rule-samples','rule-tests']},
  {id:'hunts',title:'威胁狩猎',group:'detection',pages:['hunts','behavior-baselines']},
  {id:'threat-scenarios',title:'威胁场景',group:'detection',pages:['threat-scenarios','attack-coverage']},
  {id:'file-analysis',title:'文件分析',group:'detection',pages:['file-analysis','samples','static-analysis','sandbox','sample-access','analysis-pools','analysis-reports']},
  {id:'intelligence',title:'威胁情报',group:'detection',pages:['indicators','intel-sources','intel-lifecycle','intel-hits','intel-sharing']},
  {id:'watchlists',title:'保护与观察名单',group:'detection',pages:['watchlists']},
  {id:'decision-policies',title:'决策策略',group:'response',pages:['decision-policies']},
  {id:'devices',title:'联动设备',group:'response',pages:['devices','auth-plugins']},
  {id:'actions',title:'响应动作',group:'response',pages:['actions','emergency']},
  {id:'playbooks',title:'自动化编排',group:'response',pages:['playbooks','playbook-runs']},
  {id:'notifications',title:'通知管理',group:'notifications',pages:['channels','notification-routes','notification-templates','delivery-logs','syslog-output']},
  {id:'models',title:'模型与知识',group:'ai',pages:['models','knowledge']},
  {id:'chat',title:'智能对话',group:'ai',pages:['chat']},
  {id:'rule-studio',title:'规则生成',group:'ai',pages:['rule-studio']},
  {id:'mcp',title:'MCP 服务',group:'ai',pages:['mcp']},
  {id:'reports',title:'安全报告',group:'reports',pages:['reports','report-schedules']},
  {id:'sensors',title:'探针管理',group:'sensors',pages:['sensors']},
  {id:'releases',title:'版本发布',group:'sensors',pages:['releases']},
  {id:'data-sources',title:'数据接入',group:'system',pages:['data-sources','syslog-input','imports','flow-sources','parsers','data-quality','replays']},
  {id:'logs',title:'日志检索',group:'system',pages:['logs']},
  {id:'platform-health',title:'平台运维',group:'system',pages:['platform-health','backups','connectors','software-catalog']},
  {id:'users',title:'账号与权限',group:'system',pages:['users','authentication','roles','api-keys']},
  {id:'tenants',title:'租户管理',group:'system',pages:['tenants','quotas']},
  {id:'governance',title:'数据治理',group:'system',pages:['retention','data-security','governance']},
  {id:'audit',title:'审计日志',group:'system',pages:['audit','login-logs']},
]

export const workspaceById=new Map(workspaces.map(workspace=>[workspace.id,workspace]))
export const workspaceForPage=new Map(workspaces.flatMap(workspace=>workspace.pages.map(id=>[id,workspace] as const)))
export const legacyPages:Record<string,string>={'sensor-health':'sensors','pcap-downloads':'pcap-tasks','operation-logs':'audit'}
export const accountPages=pages.filter(page=>page.id==='my-account')

export function workspaceTitleForPage(id:string):string {
  return workspaceForPage.get(id)?.title??pages.find(page=>page.id===id)?.title??'页面目录'
}
