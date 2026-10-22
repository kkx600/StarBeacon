import type {LocationQuery, RouteLocationNormalized, RouteLocationRaw} from 'vue-router'

export type CollectorView = 'overview' | 'interfaces' | 'capture' | 'archives' | 'syslog' | 'identity' | 'samples' | 'tasks' | 'responses'
type CollectorWorkspace = 'overview' | 'network' | 'connection' | 'rules' | 'response'

export interface CollectorScreen {
  view: CollectorView
  workspace: CollectorWorkspace
  path: string
  title: string
  description: string
}

export const collectorScreens: readonly CollectorScreen[] = [
  {view:'overview',workspace:'overview',path:'/overview/status',title:'运行状态',description:'查看本机资源、待传队列、原包暂存及检测引擎的实际观测。'},
  {view:'interfaces',workspace:'network',path:'/network/interfaces',title:'网卡列表',description:'核对本机网卡、链路状态、MAC 和 IPv4／IPv6 地址；此页面不修改管理网络。'},
  {view:'capture',workspace:'network',path:'/network/capture',title:'采集配置',description:'选择采集网卡及捕获参数，保存后核对实际应用状态。'},
  {view:'archives',workspace:'network',path:'/network/archives',title:'原包归档',description:'查看本机原包目录、待确认制品和平台确认状态。'},
  {view:'syslog',workspace:'network',path:'/network/syslog',title:'Syslog 接收',description:'查看已登记来源的监听及接收观测；来源配置由部署管理员维护。'},
  {view:'identity',workspace:'connection',path:'/connection/identity',title:'平台通信身份',description:'核对本机注册和证书状态；平台地址、注册密钥及私钥不在此页面编辑或读取。'},
  {view:'samples',workspace:'rules',path:'/rules/samples',title:'重放样本',description:'导入 PCAP 或 HTTP Raw，指定规则执行隔离离线验证。'},
  {view:'tasks',workspace:'rules',path:'/rules/tasks',title:'任务记录',description:'查看本机执行任务、固定回执及仍需核对的未知结果。'},
  {view:'responses',workspace:'response',path:'/response/devices',title:'联动设备',description:'核对本机联动设备和运行配置；设备动作由主平台授权下发。'},
]

export const collectorWorkspaces = [
  {id:'overview',title:'运行状态',icon:'DashboardOutlined'},
  {id:'network',title:'网络与采集',icon:'ClusterOutlined'},
  {id:'connection',title:'平台接入',icon:'ApiOutlined'},
  {id:'rules',title:'规则与任务',icon:'FileProtectOutlined'},
  {id:'response',title:'联动设备',icon:'SafetyCertificateOutlined'},
] as const

export function collectorScreen(view: string | undefined): CollectorScreen | undefined {
  return collectorScreens.find(screen=>screen.view===view)
}

export function collectorMeta(view: CollectorView) {
  const screen=collectorScreen(view)!
  const related=collectorScreens.filter(item=>item.workspace===screen.workspace)
  return {
    title:screen.title,navWorkspace:screen.workspace,workspaceView:view,admin:true,
    allowedViews:related.map(item=>item.view),
    viewPaths:Object.fromEntries(collectorScreens.map(item=>[item.view,item.path])),
  }
}

export function collectorNavigation(admin: boolean) {
  return admin?collectorWorkspaces.map(workspace=>({...workspace,path:collectorScreens.find(screen=>screen.workspace===workspace.id)!.path})):[]
}

// view 是历史页面选择参数；业务条件与定位标记始终由原地址保留。
export function collectorLegacyDestination(to: {query: LocationQuery;hash: string}): RouteLocationRaw {
  const screen=typeof to.query.view==='string'?collectorScreen(to.query.view):undefined
  const {view:ignoredView,...query}=to.query
  return {path:screen?.path??'/network/interfaces',query,hash:to.hash}
}

export function collectorCanonicalDestination(to: Pick<RouteLocationNormalized,'path'|'query'|'hash'|'meta'>): RouteLocationRaw | undefined {
  if(typeof to.meta.workspaceView!=='string'||!Object.prototype.hasOwnProperty.call(to.query,'view'))return
  const selected=typeof to.query.view==='string'?collectorScreen(to.query.view):undefined
  const {view:ignoredView,...query}=to.query
  return {path:selected?.path??to.path,query,hash:to.hash,replace:true}
}

export function collectorDefaultDestination(to: {query: LocationQuery;hash: string},path: string): RouteLocationRaw {
  return {path,query:to.query,hash:to.hash}
}
