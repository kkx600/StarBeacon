export const collectorPages = [
  {id:'overview',title:'运行状态',description:'查看本机资源、采集链路、平台连接和待执行任务。',requirements:['SB-OPS-002'],primary:'服务维护'},
  {id:'network',title:'网络与采集',description:'配置管理网络、选择镜像网卡，并核对捕获参数与检测边界。',requirements:['SB-OPS-001','SB-NET-002','SB-NET-005','SB-NET-006'],primary:'配置管理网络'},
  {id:'connection',title:'平台接入',description:'管理主控平台地址、注册凭据、设备证书与数据上报。',requirements:['SB-OPS-001'],primary:'配置平台接入'},
  {id:'updates',title:'规则与升级',description:'核对目标与实际版本，跟踪规则同步、系统升级和回滚。',requirements:['SB-OPS-003'],primary:'同步规则'},
  {id:'maintenance',title:'系统维护',description:'管理时间、缓冲与服务，查看维护任务和本地操作日志。',requirements:['SB-OPS-002','SB-OPS-003','SB-NET-001'],primary:'配置时间与存储'},
] as const
export type CollectorPageId = typeof collectorPages[number]['id']
export type CollectorAction = 'network'|'capture'|'connection'|'enroll'|'certificate'|'rule-sync'|'sync-settings'|'upgrade'|'rollback'|'maintenance'|'service'|'diagnostic'
export interface CollectorInterface {
  id:string;name:string;role:'管理'|'镜像采集'|'未分配'|'系统';status:string;mac:string;speed:string;mtu:number
  ipv4:string;ipv6:string;driver:string;queues:number;gro:string;lro:string;rx:string;drop:string
}
export interface ManagementNetwork {interface:string;method:'静态地址'|'DHCP';ipv4:string;gateway:string;ipv6:string;gateway6:string;dns:string;mtu:number;rollbackSeconds:number}
export interface CaptureConfiguration {interfaces:string[];backend:string;homeNet:string;bpf:string;snaplen:number;threads:number;clusterBase:number;promisc:boolean;streamMiB:number;httpMiB:number;fileMiB:number}
export interface PlatformConnection {host:string;port:number;serverName:string;caRef:string;clientRef:string;artifactUrl:string;heartbeat:number;batch:number;retrySeconds:number}
export interface MaintenanceConfiguration {hostname:string;timezone:string;ntp:string;walGiB:number;pcapGiB:number;highWater:number;logDays:number}
export interface CollectorTask {id:string;name:string;type:string;source:string;target:string;status:string;time:string;summary:string;steps:{name:string;status:string}[]}
export const collectorDevice={id:'SENSORS-0001',name:'总部核心探针',site:'总部',zone:'总部网络域',tenant:'总部安全中心（示例）',snapshot:'2026-09-30 09:45:00'}
export function createCollectorFixtures(){
  return {
    interfaces:[
      {id:'eth0',name:'eth0',role:'镜像采集',status:'链路正常',mac:'02:00:00:20:00:10',speed:'10 Gbit/s',mtu:1500,ipv4:'未配置',ipv6:'未配置',driver:'i40e（示例）',queues:8,gro:'关闭',lro:'关闭',rx:'482 Mbit/s',drop:'0.00%'},
      {id:'eth1',name:'eth1',role:'管理',status:'链路正常',mac:'02:00:00:20:00:11',speed:'1 Gbit/s',mtu:1500,ipv4:'10.20.0.8/24',ipv6:'未配置',driver:'igb（示例）',queues:4,gro:'开启',lro:'关闭',rx:'8.2 Mbit/s',drop:'不适用'},
      {id:'eth2',name:'eth2',role:'未分配',status:'链路断开',mac:'02:00:00:20:00:12',speed:'不可观测',mtu:9000,ipv4:'未配置',ipv6:'未配置',driver:'i40e（示例）',queues:8,gro:'关闭',lro:'关闭',rx:'不可观测',drop:'不可观测'},
      {id:'lo',name:'lo',role:'系统',status:'本机回环',mac:'不适用',speed:'不适用',mtu:65536,ipv4:'127.0.0.1/8',ipv6:'::1/128',driver:'loopback',queues:1,gro:'不适用',lro:'不适用',rx:'不适用',drop:'不适用'},
    ] as CollectorInterface[],
    network:{interface:'eth1',method:'静态地址',ipv4:'10.20.0.8/24',gateway:'10.20.0.1',ipv6:'',gateway6:'',dns:'10.20.0.2, 10.20.0.3',mtu:1500,rollbackSeconds:90} as ManagementNetwork,
    capture:{interfaces:['eth0'],backend:'AF_PACKET',homeNet:'10.20.0.0/16',bpf:'',snaplen:262144,threads:8,clusterBase:99,promisc:true,streamMiB:8,httpMiB:4,fileMiB:32} as CaptureConfiguration,
    connection:{host:'platform.example.test',port:7443,serverName:'platform.example.test',caRef:'collector-ca-demo',clientRef:'collector-client-demo-01',artifactUrl:'https://platform.example.test/artifacts',heartbeat:30,batch:512,retrySeconds:5} as PlatformConnection,
    maintenance:{hostname:'sb-collector-hq-01',timezone:'Asia/Shanghai',ntp:'ntp.example.test',walGiB:20,pcapGiB:200,highWater:85,logDays:180} as MaintenanceConfiguration,
    services:[{id:'agent',name:'采集器代理',status:'运行中',version:'Agent 示例构建',description:'上报、控制、持久队列与任务回执'},{id:'suricata',name:'Suricata 检测引擎',status:'运行中',version:'8.0.7',description:'旁路检测，当前规则 rules-demo-20260930'},{id:'pcap',name:'原包捕获与归档',status:'运行中',version:'示例构建',description:'独立捕获、压缩切片与对象归档'},{id:'runner',name:'设备联动执行器',status:'未授权',version:'示例构建',description:'本机没有设备写权限，不能执行封禁'}],
    tasks:[{id:'LOCAL-0001',name:'规则包同步',type:'规则同步',source:'主控平台',target:'rules-demo-20260930',status:'已生效（示例）',time:'2026-09-30 09:30:00',summary:'历史合成回执：12840 条规则；目标包与引擎实际包一致。',steps:[{name:'制品签名与摘要',status:'通过（示例）'},{name:'引擎配置测试',status:'通过（示例）'},{name:'规则重载',status:'完成（示例）'},{name:'引擎版本回读',status:'一致（示例）'}]},{id:'LOCAL-0002',name:'规则包同步',type:'规则同步',source:'主控平台',target:'rules-demo-20261001',status:'待同步',time:'2026-09-30 09:43:00',summary:'待下载的签名规则包；尚未运行引擎测试或重载。',steps:[{name:'制品下载',status:'待执行'},{name:'签名与摘要校验',status:'待执行'},{name:'引擎测试与重载',status:'待执行'},{name:'实际版本回读',status:'待执行'}]}] as CollectorTask[],
    audits:[{id:'AUD-001',time:'2026-09-30 09:30:18',actor:'主控平台',action:'规则同步回执',object:'rules-demo-20260930',result:'已记录（示例）'},{id:'AUD-002',time:'2026-09-30 09:00:00',actor:'本地管理员（示例）',action:'登录本地控制台',object:'SENSORS-0001',result:'成功（示例）'},{id:'AUD-003',time:'2026-09-29 18:10:00',actor:'本地管理员（示例）',action:'保存管理网络草稿',object:'eth1',result:'已记录（示例）'}],
    ruleActive:'rules-demo-20260930',ruleDesired:'rules-demo-20261001',ruleRollback:'rules-demo-20260929',syncMode:'平台推送',syncMinutes:15,autoApply:true,agentActive:'Agent 示例构建',agentDesired:'Agent 示例目标构建',engineActive:'Suricata 8.0.7',certificate:'有效（示例）',certificateSerial:'demo-cert-0001',certificateExpiry:'2026-12-31 23:59:59',
  }
}

function ipv4(value:string){return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)&&value.split('.').every(part=>Number(part)<=255)}
function ipv6(value:string){if(!value.includes(':')||value.includes('%'))return false;try{return new URL(`http://[${value}]/`).hostname.startsWith('[')}catch{return false}}
function cidr(value:string,v6=false){const [address,prefix,...extra]=value.split('/');return extra.length===0&&!!address&&prefix!==undefined&&/^\d+$/.test(prefix)&&Number(prefix)<= (v6?128:32)&&(v6?ipv6(address):ipv4(address))}
function list(value:string){return value.split(/[,，\s]+/).filter(Boolean)}
function host(value:string){if(/^[\d.]+$/.test(value))return ipv4(value);return value==='localhost'||ipv6(value)||/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(value)}
export function validateManagement(values:ManagementNetwork,interfaces:CollectorInterface[],capture:string[]){
  const errors:string[]=[];const nic=interfaces.find(item=>item.id===values.interface)
  if(!nic||nic.role==='系统')errors.push('请选择可用的物理管理网卡。')
  if(capture.includes(values.interface))errors.push('管理网卡不能同时作为镜像采集网卡。')
  if(nic?.status==='链路断开')errors.push('所选网卡链路断开，不能提交管理网络变更。')
  if(values.method==='静态地址'&&!cidr(values.ipv4))errors.push('IPv4 地址必须包含有效前缀，例如 10.20.0.8/24。')
  if(values.method==='静态地址'&&values.gateway&&!ipv4(values.gateway))errors.push('IPv4 网关格式无效。')
  if(values.ipv6&&!cidr(values.ipv6,true))errors.push('IPv6 地址必须包含有效前缀。')
  if(values.gateway6&&(!ipv6(values.gateway6)||!values.ipv6))errors.push('IPv6 网关需要有效地址及已配置的 IPv6 网络。')
  if(list(values.dns).length>3||!list(values.dns).length||!list(values.dns).every(item=>ipv4(item)||ipv6(item)))errors.push('请配置 1–3 个有效 DNS 地址，以逗号分隔。')
  if(!Number.isInteger(values.mtu)||values.mtu<576||values.mtu>9000)errors.push('MTU 应为 576–9000 的整数。')
  if(!Number.isInteger(values.rollbackSeconds)||values.rollbackSeconds<60||values.rollbackSeconds>300)errors.push('回滚确认窗口应为 60–300 秒的整数。')
  return errors
}
export function validateCapture(values:CaptureConfiguration,interfaces:CollectorInterface[],management:string){
  const errors:string[]=[]
  if(!values.interfaces.length||new Set(values.interfaces).size!==values.interfaces.length)errors.push('请选择至少一张不重复的镜像采集网卡。')
  for(const id of values.interfaces){const nic=interfaces.find(item=>item.id===id);if(!nic||nic.role==='系统'||id===management)errors.push(`${id} 不能用作镜像采集网卡。`);else if(nic.status==='链路断开')errors.push(`${id} 链路断开，请先核对镜像连接。`)}
  if(!list(values.homeNet).length||!list(values.homeNet).every(item=>cidr(item)||cidr(item,true)))errors.push('HOME_NET 应为有效的 IPv4／IPv6 CIDR，以逗号分隔。')
  const maxMtu=Math.max(1500,...values.interfaces.map(id=>interfaces.find(item=>item.id===id)?.mtu??0))
  if(!Number.isInteger(values.snaplen)||values.snaplen<maxMtu+22||values.snaplen>262144)errors.push(`捕获长度须为 ${maxMtu+22}–262144 字节的整数；需覆盖 MTU 和链路封装。`)
  if(!Number.isInteger(values.threads)||values.threads<1||values.threads>32)errors.push('每接口线程数应为 1–32 的整数。')
  if(!Number.isInteger(values.clusterBase)||values.clusterBase<1||values.clusterBase+values.interfaces.length-1>65535)errors.push('AF_PACKET cluster-id 应在 1–65535 内，并为每张网卡分配不同值。')
  for(const key of ['streamMiB','httpMiB','fileMiB'] as const)if(!Number.isInteger(values[key])||values[key]<1||values[key]>1024)errors.push('检测深度应为 1–1024 MiB 的整数。')
  if(values.bpf.length>1024)errors.push('BPF 表达式不能超过 1024 字符。')
  return errors
}
export function validateConnection(values:PlatformConnection){
  const errors:string[]=[]
  if(!host(values.host))errors.push('请输入有效的平台主机名或 IP，不含路径、端口和用户名。')
  if(!Number.isInteger(values.port)||values.port<1||values.port>65535)errors.push('gRPC 端口应为 1–65535 的整数。')
  if(!host(values.serverName)||!values.caRef.trim()||!values.clientRef.trim())errors.push('请提供 TLS 服务名、受信 CA 引用及本机证书引用。')
  try{const url=new URL(values.artifactUrl);if(url.protocol!=='https:'||url.username||url.password)throw new Error()}catch{errors.push('制品地址须使用 HTTPS，且不能包含认证信息。')}
  if(!Number.isInteger(values.heartbeat)||values.heartbeat<15||values.heartbeat>300)errors.push('心跳周期应为 15–300 秒的整数。')
  if(!Number.isInteger(values.batch)||values.batch<1||values.batch>4096)errors.push('事件批次应为 1–4096 条的整数。')
  if(!Number.isInteger(values.retrySeconds)||values.retrySeconds<1||values.retrySeconds>60)errors.push('重试起始间隔应为 1–60 秒的整数。')
  return errors
}
export function validateMaintenance(values:MaintenanceConfiguration){
  const errors:string[]=[]
  if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(values.hostname))errors.push('主机名应为 1–63 位字母、数字或中划线。')
  if(!list(values.ntp).length||list(values.ntp).length>3||!list(values.ntp).every(host))errors.push('请提供 1–3 个有效 NTP 主机名或地址。')
  if(!['Asia/Shanghai','UTC'].includes(values.timezone))errors.push('请选择支持的显示时区。')
  if(!Number.isInteger(values.walGiB)||values.walGiB<1||values.walGiB>100)errors.push('WAL 配额应为 1–100 GiB 的整数。')
  if(!Number.isInteger(values.pcapGiB)||values.pcapGiB<10||values.pcapGiB>250)errors.push('本机 PCAP 缓冲配额应为 10–250 GiB 的整数。')
  if(values.walGiB+values.pcapGiB>300)errors.push('WAL 与 PCAP 配额总量不能超过本机示例可用容量 300 GiB。')
  if(!Number.isInteger(values.highWater)||values.highWater<50||values.highWater>95)errors.push('高水位应为 50–95% 的整数。')
  if(!Number.isInteger(values.logDays)||values.logDays<1||values.logDays>3650)errors.push('操作日志期限应为 1–3650 天的整数，默认 180 天。')
  return errors
}
