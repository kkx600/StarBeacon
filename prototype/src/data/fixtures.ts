import type { BusinessRecord, MetricSpec, PageSpec } from '../models'
import {statusesFor} from './statuses.ts'
import {examplePermissionCounts,expiryFromDuration} from '../composables/formValues.ts'

const owners = ['陈宁','林悦','值班分析组']
const names: Record<string,string[]> = {
  alert: ['HTTP 可疑管理路径访问','DNS 异常外连查询','疑似凭据暴力尝试','TLS 异常证书链','SMB 横向访问线索','HTTP 可疑命令参数','异常文件下载','新出现的外部目的地','可疑 RDP 连接','高频端口探测'],
  asset: ['业务 API 节点','订单数据库','研发构建节点','办公终端 A','文件服务节点','边界网关','身份服务','业务代理','办公终端 B','备份服务'],
  application: ['百度网盘','爱奇艺','企业微信','飞书','钉钉','Microsoft 365','腾讯会议','GitHub','通用 HTTPS','未识别应用'],
  rule: ['HTTP 管理路径探测','DNS 可疑域名访问','SMB 异常会话','TLS 证书异常','HTTP 可疑下载','RDP 暴力尝试','SSH 高频登录','Web 命令注入线索','异常代理请求','FTP 异常登录'],
  model: ['本地安全研判','通用总结服务','Jev 决策适配','Laya 决策适配','本地嵌入服务','备用分析路由'],
  sensor: ['总部核心探针','总部边界探针','研发核心探针','总部执行探针','分支采集探针','分支执行探针','研发边界探针','分支核心探针'],
  device: ['总部边界防火墙','总部终端 EDR','研发边界防火墙','分支边界防火墙'],
  channel: ['值班邮件','企业微信值班群','钉钉安全通知','飞书事件通知','工单 Webhook'],
  incident: ['业务管理入口异常访问','研发网络横向访问调查','办公终端异常外连','身份服务登录异常','文件下载事件','分支网络扫描线索'],
  case: ['管理入口访问调查','研发网横向访问调查','办公终端外连核对','身份异常登录核对','下载样本分析','分支扫描事件'],
  action: ['封禁可疑源 IP','隔离待核验终端','到期解除封禁','恢复终端连接','撤销重复租约','配置读回核验'],
  platform: ['业务 API','gRPC 接入','Elasticsearch','PostgreSQL','NATS JetStream','对象存储','Redis','分析 Worker','通知 Worker','执行调度器'],
  retention: ['全量 PCAP','告警数据','协议明细','操作日志','登录日志','通知记录','文件样本','安全报告','统计历史','导出记录'],
  protocol: ['HTTP/1.1','HTTP/2','HTTP/3 / QUIC','TLS','DNS','SMB','SSH','RDP','SMTP','Modbus/TCP'],
  field: ['ip.src','ip.dst','eth.src','eth.dst','http.request.method','http.request.uri','tcp.flags.syn','tcp.stream','frame.time','tls.handshake.extensions_server_name'],
  report: ['总部安全运营日报','研发安全运营周报','集团安全态势月报','分支安全运营日报','高危事件专项报告','文件分析周报'],
  vulnerability: ['应用组件远程执行风险','Web 服务访问控制风险','数据库版本维护风险','文件服务权限配置风险','代理组件解析风险','终端组件更新风险'],
  'intel-source': ['授权 IP 情报订阅','授权域名情报订阅','内部分析情报','文件哈希情报','社区公开安全情报'],
  indicator: ['198.51.100.24','example-risk.test','https://example-risk.test/download','203.0.113.18','sample-sha256-example'],
  integrity: ['完整 TCP 会话','捕获中途开始','仅观察单向流量','跨切片 TCP 会话','握手完整但载荷缺失','仍处于活动状态'],
  delivery: ['高危告警值班通知','事件分派通知','设备执行结果通知','规则发布结果通知','日报审核通知','沙箱分析结果通知'],
  audit: ['更新决策策略','审核事件结论','创建取证任务','调整留存期限','发布检测规则','访问授权证据','变更角色范围','撤销响应租约'],
  'login-log': ['陈宁','林悦','值班分析员','租户管理员','陈宁','服务审计员'],
  'api-key': ['内部分析 Agent','日报生成服务','只读审计集成','工单同步服务'],
  tenant: ['总部安全中心','研发事业部','华东分支','华南分支','集团审计组织'],
  network: ['核心业务','办公终端','研发服务','管理网络','分支业务','受限样本区'],
  syslog: ['总部日志存储','研发日志存储','隔离审计存储'],
  'data-source': ['总部防火墙日志','EDR 事件接口','身份认证日志','云审计数据','业务应用日志','总部网络探针'],
  sample: ['example-document.pdf','example-sample.bin','example-script.ps1','example-archive.zip','example-library.dll'],
  file: ['example-document.pdf','example-sample.bin','example-script.ps1','example-archive.zip','example-library.dll'],
  static: ['PDF 静态扫描','二进制静态扫描','脚本特征检查','压缩包有界检查','库文件静态扫描'],
  sandbox: ['二进制动态分析','PDF 动态分析','脚本动态分析','沙箱复核任务','离线样本分析'],
  'file-report': ['PDF 分析报告','二进制分析报告','脚本分析报告','样本复核报告','重复分析比较'],
  decision: ['Web 攻击审批策略','暴力尝试影子策略','高危外连自动策略','敏感资产人工策略','文件分析复核策略'],
  assessment: ['管理路径告警研判','DNS 外连线索研判','凭据尝试研判','TLS 元数据研判','文件样本研判'],
  latency: ['捕获 → 引擎检测','检测 → 持久接收','接收 → ES 可检索','告警 → 通知接受','审批 → 执行采集器','采集器 → 设备接受','设备接受 → 配置读回','配置读回 → 效果观察'],
  metric: ['Web 攻击场景','暴力登录场景','外连异常场景','文件异步分析场景','手动审批场景'],
}

export function createFixtures(page: PageSpec): BusinessRecord[] {
  const family = page.family
  const nameList = names[family] ?? [`总部${page.objectLabel}`,`研发${page.objectLabel}`,`分支${page.objectLabel}`,`核心业务${page.objectLabel}`,`办公网络${page.objectLabel}`,`受限范围${page.objectLabel}`]
  const statuses = statusesFor(page)
  return Array.from({length: Math.max(nameList.length,8)},(_,i) => {
    const name = nameList[i % nameList.length]!
    const record: BusinessRecord = {
      id: `${page.id.toUpperCase()}-${String(i+1).padStart(4,'0')}`,name,tenant:family==='tenant'?name:'总部安全中心（示例）',status:statuses[i % statuses.length]!,
      owner:owners[i % owners.length]!,actor:owners[i % owners.length]!,scope:['总部网络域','研发网络域','分支网络域'][i%3]!,
      time:`2026-09-30 ${String(9 - Math.floor(i/4)).padStart(2,'0')}:${String(42-i%4*6).padStart(2,'0')}:16`,updated:'2026-09-30 09:45:00',
      source:`198.51.100.${24+i}`,destination:`10.20.1.${15+i}`,ip:`10.20.1.${15+i}`,level:['高危','严重','中危','低危'][i%4]!,
      type:['服务器','终端','网络设备','云资源'][i%4]!,group:['核心业务','办公终端','研发服务'][i%3]!,
      protocol:['HTTP','DNS','TLS','SMB','TCP','UDP'][i%6]!,method:i%2?'POST':'GET',path:['/admin/login','/api/v1/status','/download/sample','/upload'][i%4]!,
      risk:[86,72,45,22,64,35,58,18][i%8]!,confidence:[0.97,0.89,0.76,0.62,0.91,0.83,0.95,0.68][i%8]!,quality:99.6-i%4*0.3,coverage:100-i%3*8,
      bytes:['8.4 MiB','42.8 MiB','512 KiB','1.2 GiB'][i%4]!,count:1248-i*73,progress:[100,35,78,0,56][i%5]!,
      asset:names.asset![i%names.asset!.length]!,assets:1+i%4,evidence:3+i%6,sessions:182+i*24,alerts:10+i*3,
      mac:`02:00:00:20:01:${(15+i).toString(16).padStart(2,'0')}`,zone:['总部网络域','研发网络域','分支网络域'][i%3]!,
      site:['总部','研发中心','分支机构'][i%3]!,role:i%4===3?'执行采集器':'采集与检测',version:'1.2.0',
      start:'2026-09-30 09:42:15',end:i%3===2?'尚未结束':'2026-09-30 09:42:19',expires:'2026-10-30 23:59:59',due:'2026-10-03 18:00',
      lastSeen:i===4?'2026-09-30 08:15:00':'2026-09-30 09:45:00',cpu:22+i*4,memory:35+i*3,disk:48+i*2,drop:i===5?'0.40%':'0.00%',
      bps:['482 Mbit/s','126 Mbit/s','68 Mbit/s','12 Mbit/s'][i%4]!,pps:'86.2 k/s',cps:'1.4 k/s',eps:'3.2 k/s',
      model:['本地安全模型','通用总结模型','Jev 适配器','Laya 适配器'][i%4]!,credential:'受控凭据引用',notes:'合成示例记录，用于呈现业务字段、状态和操作流程。',
      retention:180,codec:'Zstandard 独立块',estimate:['14.2 TB','8.6 GB','23.4 GB','180 MB'][i%4]!,storage:i===0?'S3 对象存储':'ES 数据流',held:i%4,
      p50:['4 ms','18 ms','240 ms','480 ms','36 ms','210 ms','630 ms','不可计算'][i%8]!,p95:['12 ms','48 ms','710 ms','1.2 s','92 ms','540 ms','1.3 s','不可计算'][i%8]!,p99:['28 ms','106 ms','1.1 s','2.4 s','180 ms','920 ms','2.0 s','不可计算'][i%8]!,missing:i===7?'无后续流量':'0',
      handshake:i%3===1?'缺少 SYN':'SYN / SYN-ACK / ACK',continuity:i%3===2?'存在字节缺口':'双向已核对',closure:i%3===2?'活动连接':'FIN / ACK',
      accepted:i===1?'尚未确认':'已接受',effective:i===1?'结果未知':'已读回',observed:i%2?'无后续流量':'已观察丢弃',
      format:['PCAPNG','CSV','JSON'][i%3]!,port:[443,80,53,445][i%4]!,window:'最近 24 小时',schedule:'每天 08:00（Asia/Shanghai）',
      entity:['source.ip','asset.id','user.id'][i%3]!,lateness:'60 秒',revision:1+i%3,sid:1000001+i,hits:142-i*11,mode:['审批','影子','自动'][i%3]!,
      target:i%2?'10.20.1.18':'198.51.100.24',sensor:['总部执行探针','分支执行探针'][i%2]!,address:`https://192.0.2.${20+i}`,capability:i%2?'终端隔离／恢复':'IP 封禁／解封',
      account:`analyst${i+1}@example.test`,department:['总部安全中心','研发中心'][i%2]!,mfa:i%3?'已验证':'需核验',
      provider:['本地服务','通用 API','Jev','Laya'][i%4]!,purpose:['研判＋结构化输出','报告总结','决策适配','决策适配'][i%4]!,residency:i%2?'授权云区域':'本地',
      conclusion:i%3===2?'无法判定':'疑似恶意',success:i%2?'无法判定':'未见成功证据',
      tasks:`${2+i%4} / ${4+i%4}`,sla:i%3===0?'剩余 18 分钟':i%3===1?'等待接单':'已暂停',sources:'探针＋设备日志',uncertainty:'±2 ms',
      operation:['移交','分享','拆分'][i%3]!,timezone:'Asia/Shanghai',response:'15 分钟',resolution:'4 小时',external:`TKT-DEMO-${100+i}`,connector:'授权示例连接器',direction:i%2?'双向同步':'入站＋出站',root:'访问控制与暴露',remaining:i%3,
      indexed:'keyword',recognition:'支持',transaction:i%3===0?'支持':'条件支持',rule:i%3===0?'支持':'部分支持',file:i%3===0?'支持':'不适用',native:'TShark',
      sni:'service.example.test',fingerprint:'仅元数据可见',visibility:i===2?'授权离线明文':'握手元数据',capture:'2026-09-30 09:42:16.128456789',ingress:'不可观测',egress:'不可观测',precision:'纳秒字段／±2 ms 校时误差',
      sampling:'1:1',domain:`domain-${i+1}`,templates:'已缓存／有效',binding:'客户端证书身份',transport:'TLS/TCP',backlog:i===4?'3,820 条':'0',
      ruleVersion:'rules-demo-20260930',sha256:'bcd824c93e7a0fe5ab8d0e1c753142706ca6c0bc2c81f6b4df85763e1b987a50',
      verdict:['待复核','未命中特征','证据不足','疑似恶意'][i%4]!,engine:i%2?'ClamAV':'YARA-X',rules:'example-20260930',profile:'隔离 Windows 环境',duration:['42 秒','3 分钟','未知'][i%3]!,
      sample:'example-sample.bin',concurrency:4,queue:12+i,timeout:'180 秒',permissions:28,members:8,cell:'cell-demo-01',parent:'星烽示例集团',sensors:12+i,
      used:['48%','32%','18%','72%'][i%4]!,limit:['10 TB','100 万／日','100 元／日','200 个'][i%4]!,period:'最近 30 天',
      license:'授权范围内使用',signature:'已核对',support:'社区／官方维护',redaction:'默认脱敏',verified:'2026-09-30 08:00',rate:'30 次／分钟',
      recipient:'值班分析组',delivered:i===2?'已送达':'不可观测',read:'不可观测',channels:'邮件＋企业微信',category:['文件传输','视频娱乐','协同办公','开发工具'][i%4]!,
      application:names.application![i%names.application!.length]!,layout:'安全态势',newActions:i%2?'停止调度':'运行中',leases:5+i,inflight:i%3,watermark:'待执行器回执',
      stream:'8 MiB',http:'4 MiB',fileDepth:'32 MiB',interface:`eth${i%2}`,vlans:'10, 20',duplicates:'0.00%',gap:'18 ms',
      current:'示例值',expected:'符合基线',actual:'需复核摘要',change:'出现新服务',exposure:i%2?'内网可达':'授权边界可达',
      cve:`CVE-EXAMPLE-${100+i}`,cvss:[9.1,8.2,7.5,6.4][i%4]!,epss:['3.2%','0.8%','12.6%','1.4%'][i%4]!,kev:i===0?'有外部利用信号':'未确认',
      score:86-i*5,phase:['初始访问','执行','横向移动','命令与控制'][i%4]!,technique:['T1190','T1110','T1021','T1071'][i%4]!,tactic:['初始访问','凭据访问','横向移动','命令与控制'][i%4]!,
      training:'最近 30 天',drift:'待监测',hypothesis:'存在非业务目的的异常访问',mapping:'ecs-example-01',supported:'支持清单内',
      refresh:'每 4 小时',indicator:'198.51.100.24',decay:'30 天有界衰减',reason:'业务授权与风险依据',
      rpo:'2026-09-30 02:00',validated:'隔离演练待验证',value:['跟随系统','邮件＋企业微信','30 分钟'][i%3]!,
      trigger:'高危告警＋证据完整',nodes:6,node:'等待人工审批',playbook:'高危访问响应',input:'HTTP Raw',product:names.application![i%names.application!.length]!,feature:'TLS SNI',priority:100-i*5,
      positive:'12 / 12',negative:'36 / 36',performance:'待压力验收',cursor:`batch-${i+1} / offset-${i*1000}`,missingFields:'0.2%',late:'0.8%',
      gateway:'总部边界网关',cidr:`10.${20+i}.0.0/16`,from:'业务 API 节点',to:'订单数据库',scanner:'授权扫描连接器',retest:i%3===0?'验证待完成':'待复测',vulnerabilities:2+i%4,encoding:'UTF-8（尝试）',session:`FLOW-DEMO-${page.id}-${i+1}`,packetSample:null,snapshot:`snapshot-${page.id}-${i+1}`,device:'总部边界防火墙',auth:'官方 API／签名认证插件',tools:'search_alerts / get_session',quota:'20 次／分钟',identity:`analyst${i+1}@example.test`,object:`${page.objectLabel} / demo-object-${i+1}`,
    }
    // 配置字段的可选值由所属业务对象约束，不能套用其他对象的通用分类。
    for(const field of page.fields){if(field.type==='select'&&field.options?.length&&!['name','status'].includes(field.key))record[field.key]=field.options[i%field.options.length]!}
    if(typeof record.validity==='string')record.expires=expiryFromDuration(record.validity,'2026-09-30T09:45:00Z')??record.expires
    if(family==='role')record.permissions=examplePermissionCounts[String(record.permissionTemplate)]??record.permissions
    if(page.id==='api-keys')record.used=record.time
    if(family==='platform')record.role=({'业务 API':'业务请求与授权','gRPC 接入':'探针接入与任务下发','Elasticsearch':'告警与证据检索','PostgreSQL':'配置与业务对象','NATS JetStream':'持久消息缓冲','对象存储':'PCAP、样本与报告','Redis':'运行缓存与限流','分析 Worker':'异步研判与任务','通知 Worker':'通知投递与重试','执行调度器':'执行路由与租约'} as Record<string,string>)[name]??'平台服务'
    const sources:Record<string,string[]>={interface:['ARP','NDP','DHCP','授权终端接口'],address:['DHCP','ARP','NDP'],identity:['OIDC','LDAP','AD'],service:['网络探针','授权扫描器'],exposure:['授权外部测绘','资产负责人申报','设备日志'],replay:['quarantine-parser','quarantine-events']}
    if(sources[family])record.source=sources[family]![i%sources[family]!.length]!
    if(page.id==='report-schedules')record.schedule=record.type==='日报'?'每天 08:00（Asia/Shanghai）':record.type==='周报'?'每周一 08:00（Asia/Shanghai）':'每月 1 日 08:00（Asia/Shanghai）'
    if (family==='pcap'){
      record.mode=i%3===1?'观测快照':'完整会话';record.format=i%2?'PCAP':'PCAPNG'
      if(record.status==='可下载'&&[record.handshake,record.continuity,record.closure].some(value=>/缺少|缺口|活动/.test(String(value))))record.status='完整性不足'
      record.expires=record.status==='权限已到期'?'2026-09-30 08:00:00':'2026-10-01 09:45:00'
      record.exportObject=null;record.digest=null
    }
    if (family==='channel') record.type=['邮件','企业微信','钉钉','飞书','Webhook'][i%5]!
    if (family==='sensor') {
      const prefix=name.startsWith('总部')?'总部':name.startsWith('研发')?'研发':'分支'
      record.site=prefix==='研发'?'研发中心':prefix==='分支'?'分支机构':'总部'
      record.scope=record.zone=`${prefix}网络域`
      record.role=name.includes('执行')?'执行采集器':'采集与检测'
      record.status=i===4?'离线':'在线';record.heartbeatAge=i===4?5400:0
      record.version='Suricata 8.0.7';record.agentVersion='Agent 示例构建'
      record.cpu=i===7?88:22+i*4;record.disk=i===6?92:48+i*2
      record.dropPercent=i===5?0.4:0;record.drop=i===5?'0.40%':'0.00%'
      record.bpsMbit=[482,126,68,0,54,0,82,36][i]!;record.bps=`${record.bpsMbit} Mbit/s`
      if(record.role==='执行采集器'){record.bps='不适用';record.bpsMbit=null;record.drop='不适用';record.dropPercent=null}
      record.interface=name.includes('执行')?'无捕获接口':'eth0';record.backlog=i===6?3820:0
      record.pps=name.includes('执行')?'不适用':`${Math.round(Number(record.bpsMbit)*80)} 包/秒`
      record.cps=name.includes('执行')?'不适用':`${Math.round(Number(record.bpsMbit)*3)} 会话/秒`
      record.eps=name.includes('执行')?'不适用':`${Math.round(Number(record.bpsMbit)*2)} 条/秒`
      record.snapshotAt='2026-09-30 09:45:00';record.certificate='有效（示例）';record.ruleVersion='rules-demo-20260930'
      if(i===4){for(const key of ['cpu','memory','disk','drop','dropPercent','bps','bpsMbit','pps','cps','eps','backlog'])record[key]=null}
      record.resources=i===4?'不可观测':`${record.cpu}% / ${record.memory}% / ${record.disk}%`
    }
    if (family==='device') {record.type=name.includes('EDR')?'EDR':'防火墙';record.scope=name.startsWith('研发')?'研发网络域':name.startsWith('分支')?'分支网络域':'总部网络域';record.zone=record.scope;record.sensor=name.startsWith('分支')?'分支执行探针':'总部执行探针'}
    if (family==='login-log') record.method='OIDC＋MFA'
    if (family==='data-security') record.egress='需授权'
    if (family==='inspection') record.file='32 MiB'
    if (family==='data-quality') record.missing='0.2%'
    if (family==='alert'||family==='rule') record.protocol=['HTTP','DNS','TCP','TLS','SMB','HTTP','HTTP','TLS','RDP','TCP'][i%10]!
    if (record.protocol!=='HTTP'&&family!=='login-log'){record.method=null;record.path=null}
    if (family==='latency'&&i===7){record.name='配置读回 → 效果观察';record.status='起点或结果不可观测'}
    if (family==='protocol') {record.protocol=name; record.version=name==='TLS'?'TLS 1.3':'协议配置'; record.file= i===0||i===5||i===8 ? '条件支持':'不适用'}
    if (family==='field') {record.type=i<4?'IP / MAC':i===6?'布尔':i===8?'时间':'字符串';record.source=i<4?'原始包／受控投影':'协议解析';record.status=i===7?'原生包模式':'支持';record.indexed=i===8?'date_nanos':'keyword'}

    if (family==='application') {record.category=({'百度网盘':'文件传输','爱奇艺':'视频娱乐','企业微信':'协同办公','飞书':'协同办公','钉钉':'协同办公','Microsoft 365':'协同办公','腾讯会议':'协同办公','GitHub':'开发工具','通用 HTTPS':'通用协议','未识别应用':'未知'} as Record<string,string>)[name]??'未知';record.source='域名／SNI 规则';record.evidence=i===9?'无可用特征':'匹配样例特征';record.status=i===9?'未知':i===8?'通用协议':'规则识别';record.bytes=['3.82 GiB','2.41 GiB','860 MiB','742 MiB','638 MiB','516 MiB','481 MiB','327 MiB','5.42 GiB','1.12 GiB'][i]!}
    if (family==='tls') {record.version=i%2?'TLS 1.3':'TLS 1.2';record.sni=i%3===1?'不可观测（ECH）':'service.example.test';record.fingerprint='未提供真实指纹';record.visibility=record.status==='授权明文'?'授权离线明文':'握手元数据';record.plaintextSource=record.status==='授权明文'?`授权离线样例 KEY-DEMO-${i+1}`:'未提供'}
    if (family==='report') {record.type=name.includes('日报')?'日报':name.includes('月报')?'月报':'周报';record.window=record.type==='日报'?'2026-09-29':record.type==='周报'?'2026-09-21 — 2026-09-27':'2026-09';record.status=['待审核','已审核','生成中','证据不足'][i%4]!}
    if (family==='retention') {record.status='继承默认';record.storage=({'全量 PCAP':'S3 对象存储','文件样本':'S3 对象存储＋PG 元数据','安全报告':'S3 正文＋PG 元数据','导出记录':'PG 任务＋S3 导出对象'} as Record<string,string>)[name]??'ES 数据流'}
    if (family==='decision') {record.mode=name.includes('影子')?'影子':name.includes('自动')?'自动':'审批';record.calibration='eval-web-202609';record.ttl=30}
    if (family==='action') {
      const waiting=record.status==='等待审批';const unknown=record.status==='结果未知';const revoked=record.status==='已撤销';const executing=record.status==='执行中'
      record.accepted=waiting?'未派发':unknown?'尚未确认':executing?'执行中':'已接受'
      record.effective=waiting?'未执行':unknown?'结果未知':revoked?'已撤销':executing?'未核验':'已读回'
      record.observed=waiting?'未执行':unknown||revoked||executing?'无法判定':'已观察丢弃'
      record.approvalStatus=waiting?'等待审批':'已审批';record.approval=waiting?'尚未批准':`APR-DEMO-${record.id}`;record.ttl=30
      record.operation=name.includes('隔离')?'隔离终端':name.includes('恢复')?'恢复终端':/解除|撤销/.test(name)?'解封 IP':'封禁 IP'
      record.target=i%2?record.destination:record.source
      record.sensor=i%3===2?'分支执行探针':'总部执行探针';record.device=/隔离|恢复/.test(String(record.operation))?'总部终端 EDR':'总部边界防火墙'
    }
    if ((family==='alert'||family==='session'||page.id==='packets')&&i===0) {record.packetSample='http-admin-demo';record.session='FLOW-20260930-0142';record.start='2026-09-30 09:42:16.100001';record.end='2026-09-30 09:42:16.142100';record.method='GET';record.path='/admin/login'}
    if (family==='integrity') {record.name=names.integrity![i%6]!;record.handshake=i%6===1?'缺少握手':i%6===2?'只见单向':'三次握手已核对';record.continuity=i%6===4?'存在字节缺口':i%6===2?'无法验证':'已核对';record.closure=i%6===5?'活动会话':'已观察 FIN / ACK'}
    return record
  })
}

export function metricsFor(page: PageSpec, empty = false): MetricSpec[] {
  const zero = empty ? '0' : undefined
  if (page.family==='alert') return [{label:'当前告警',value:zero??'1,248',note:'原始检测保留'},{label:'待研判',value:zero??'38',tone:'warning'},{label:'高危与严重',value:zero??'12',tone:'danger'},{label:'已关联事件',value:zero??'9'}]
  if (page.family==='action') return [{label:'活动租约',value:zero??'18'},{label:'等待审批',value:zero??'3',tone:'warning'},{label:'结果未知',value:zero??'1',tone:'warning'},{label:'已撤销',value:zero??'64'}]
  if (page.family==='application') return [{label:'观测流量',value:zero??'21.8',suffix:'GiB'},{label:'活跃会话',value:zero??'4,216'},{label:'规则识别覆盖',value:empty?'—':'74.6%',note:'当前可用特征'},{label:'未知应用',value:empty?'—':'25.4%',tone:'warning'}]
  if (page.family==='platform') return [{label:'在线服务',value:zero??'10'},{label:'异常组件',value:zero??'1',tone:'warning'},{label:'接入事件',value:zero??'3.2',suffix:'k EPS'},{label:'持久缓冲积压',value:zero??'3,820',note:'合成示例'}]
  return []
}

export type EvidenceFact = {title:string;value:string;status?:string}

export function hasPacketEvidence(record?:BusinessRecord):boolean{
  return !!record&&record.packetSample==='http-admin-demo'&&record.session==='FLOW-20260930-0142'&&record.source==='198.51.100.24'&&record.destination==='10.20.1.15'&&record.protocol==='HTTP'&&record.time==='2026-09-30 09:42:16'
}

// 回执、回读与流量效果各自使用当前对象的事实，缺失值不推定为成功。
export function responseFor(page:PageSpec,record?:BusinessRecord):{facts:EvidenceFact[];step:number}{
  if(page.family!=='action')return {step:0,facts:[
    {title:'任务与授权',value:'未关联响应任务；当前告警仅提供研判与处置建议',status:'需审批'},
    {title:'设备接受',value:'尚未向执行采集器派发设备动作',status:'未派发'},
    {title:'配置回读',value:'没有关联设备写入与配置回读结果',status:'未执行'},
    {title:'效果观察',value:'未提供独立的后续流量或终端结果',status:'无法判定'},
  ]}
  const accepted=String(record?.accepted??'未提供');const effective=String(record?.effective??'尚未核验');const observed=String(record?.observed??'无法判定')
  const known=observed==='已观察丢弃'
  return {step:known?5:effective==='已读回'||effective==='已撤销'?4:accepted==='已接受'?3:accepted==='未派发'?0:2,facts:[
    {title:'任务与授权',value:`${record?.id??'未提供任务'} · ${record?.approval??'授权依据未提供'} · TTL ${record?.ttl??'未提供'} 分钟`,status:String(record?.approvalStatus??(record?.status==='等待审批'?'等待审批':'未提供'))},
    {title:'设备接受',value:`${record?.sensor??'执行采集器未提供'} → ${record?.device??'目标设备未提供'} · ${record?.target??'目标未提供'}`,status:accepted},
    {title:'配置回读',value:`当前任务配置核对：${effective}`,status:effective},
    {title:'效果观察',value:known?`在 ${record?.scope??'当前网络域'} 的合成观测窗口内收到目标丢弃样例`:'没有足够的后续通信样本；不能从没有流量推定封禁效果',status:observed==='无后续流量'?'无法判定':observed},
  ]}
}

export function evidenceFor(page:PageSpec,record?:BusinessRecord):EvidenceFact[]{
  const common:EvidenceFact[]=[
    {title:'观测位置',value:`${record?.scope??record?.zone??'网络域未提供'} / 合成数据源`},
    {title:'证据快照',value:String(record?.snapshot??`snapshot-${record?.id??'未提供'}`)},
    {title:'来源与版本',value:`合成示例 · ${record?.time??record?.updated??'时间未提供'}`},
  ]
  const details:Record<string,EvidenceFact[]>={
    alert:[{title:'原始检测',value:`Suricata 示例 SID ${record?.sid??'未提供'} / rev ${record?.revision??'未提供'}`,status:'检测命中'},{title:'攻击是否成功',value:'未提供终端或应用执行证据',status:'无法判定'},{title:'处置权限',value:'需要审批；当前仅生成建议',status:'未执行'}],
    assessment:[{title:'校准置信度',value:record?.confidence===undefined?'未提供':`${Number(record.confidence).toFixed(2)} / ${record.calibration??'评测版本未提供'}`,status:record?.status},{title:'利用成功判断',value:String(record?.success??'未提供'),status:'无法判定'},{title:'自动资格',value:'缺少独立成功证据，不满足本策略自动条件',status:'需审批'}],
    action:responseFor(page,record).facts,
    model:[{title:'能力测试',value:record?.status==='未接入'?'当前适配器尚未接入真实服务':'结构化输出与引用校验样例',status:record?.status??'未提供'},{title:'领域评测',value:'实际标签集和校准版本待接入',status:'未验收'},{title:'数据外发',value:'仅授权脱敏字段',status:'受控'}],
    protocol:[{title:'元数据',value:'按引擎、配置和明文条件提供',status:'条件能力'},{title:'文件提取',value:'需解析器支持且达到提取完整性要求',status:'条件能力'},{title:'原生取证',value:'独立 TShark 按支持字段解析密文与明文边界',status:'已设计'}],
    retention:[{title:'当前期限',value:`${record?.retention??180} 天；租户与类别可单独配置`,status:record?.status??'未提供'},{title:'保全对象',value:'活动案件与授权保全排除自动清理',status:'受保护'},{title:'存储位置',value:String(record?.storage??'未提供')},{title:'压缩预算',value:'无压缩为容量基准，压缩率需实际测量',status:'待实测'}],
    rule:[{title:'规则状态',value:`SID ${record?.sid??'未提供'} / rev ${record?.revision??'未提供'}`,status:record?.status??'未提供'},{title:'目标引擎',value:'Suricata 8.0.7；真实引擎尚未接入',status:'合成示例'},{title:'生产生效',value:'当前仅有状态样例，真实签名发布与探针回执未接入',status:'未验收'}],
    pcap:[{title:'真实握手',value:String(record?.handshake??'未提供'),status:String(record?.handshake??'').includes('缺少')?'完整性不足':'合成完整性记录'},{title:'双向连续性',value:String(record?.continuity??'未提供'),status:String(record?.continuity??'').includes('缺口')?'完整性不足':'合成完整性记录'},{title:'连接结束',value:String(record?.closure??'未提供'),status:record?.status??'未提供'}],
    tls:[{title:'载荷可见性',value:String(record?.visibility??'未提供'),status:record?.status??'未提供'},{title:'元数据范围',value:`${record?.version??'版本未提供'} / SNI ${record?.sni??'不可观测'}；ECH 可能隐藏 SNI`,status:'条件能力'},{title:'明文来源',value:String(record?.plaintextSource??'未提供'),status:record?.status==='授权明文'?'授权样例':'未提供'}],
  }
  const family=page.family
  return [...(details[family]??[]),...common]
}

export const packetRows = [
  {id:'1',number:1,time:'09:42:16.100001',source:'198.51.100.24',destination:'10.20.1.15',protocol:'TCP',length:74,info:'51824 → 80 [SYN] Seq=0',flags:'SYN',payload:''},
  {id:'2',number:2,time:'09:42:16.100892',source:'10.20.1.15',destination:'198.51.100.24',protocol:'TCP',length:74,info:'80 → 51824 [SYN, ACK] Seq=0 Ack=1',flags:'SYN, ACK',payload:''},
  {id:'3',number:3,time:'09:42:16.101210',source:'198.51.100.24',destination:'10.20.1.15',protocol:'TCP',length:66,info:'51824 → 80 [ACK] Seq=1 Ack=1',flags:'ACK',payload:''},
  {id:'4',number:4,time:'09:42:16.128456',source:'198.51.100.24',destination:'10.20.1.15',protocol:'HTTP',length:184,info:'GET /admin/login HTTP/1.1',flags:'PSH, ACK',payload:'GET /admin/login HTTP/1.1\r\nHost: service.example.test\r\nUser-Agent: ExampleClient/1.0\r\nAccept: */*\r\n\r\n'},
  {id:'5',number:5,time:'09:42:16.133880',source:'10.20.1.15',destination:'198.51.100.24',protocol:'HTTP',length:160,info:'HTTP/1.1 403 Forbidden',flags:'PSH, ACK',payload:'HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"error":"forbidden","message":"访问受限"}'},
  {id:'6',number:6,time:'09:42:16.141000',source:'198.51.100.24',destination:'10.20.1.15',protocol:'TCP',length:66,info:'51824 → 80 [FIN, ACK]',flags:'FIN, ACK',payload:''},
  {id:'7',number:7,time:'09:42:16.141800',source:'10.20.1.15',destination:'198.51.100.24',protocol:'TCP',length:66,info:'80 → 51824 [FIN, ACK]',flags:'FIN, ACK',payload:''},
  {id:'8',number:8,time:'09:42:16.142100',source:'198.51.100.24',destination:'10.20.1.15',protocol:'TCP',length:66,info:'51824 → 80 [ACK]',flags:'ACK',payload:''},
]
export type PacketRecord = typeof packetRows[number]
export const exampleRule = 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"StarBeacon HTTP admin probe"; flow:to_server,established; http.method; content:"GET"; http.uri; content:"/admin/login"; startswith; classtype:web-application-attack; sid:1000001; rev:1;)'
