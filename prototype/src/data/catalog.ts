import type { ColumnSpec, FieldSpec, GroupSpec, PageSpec } from '../models'
import {statusesFor} from './statuses.ts'

export const groups: GroupSpec[] = [
  { id: 'overview', title: '态势总览', icon: 'DashboardOutlined' },
  { id: 'alerts', title: '告警中心', icon: 'AlertOutlined' },
  { id: 'incidents', title: '安全事件', icon: 'FileProtectOutlined' },
  { id: 'assets', title: '资产中心', icon: 'ClusterOutlined' },
  { id: 'traffic', title: '流量分析', icon: 'RadarChartOutlined' },
  { id: 'detection', title: '检测与情报', icon: 'SafetyCertificateOutlined' },
  { id: 'response', title: '响应中心', icon: 'ThunderboltOutlined' },
  { id: 'notifications', title: '通知中心', icon: 'BellOutlined' },
  { id: 'ai', title: '智能助手', icon: 'RobotOutlined' },
  { id: 'reports', title: '安全报告', icon: 'BarChartOutlined' },
  { id: 'sensors', title: '探针与版本', icon: 'ApiOutlined' },
  { id: 'system', title: '系统管理', icon: 'SettingOutlined' },
]

type Definition = [string, string, string, string, string, string, string, string?]
// 字段顺序：需求、路由、导航组、名称、对象类型、业务说明、列定义、主要操作。
const definitions: Definition[] = [
  ['SB-VIS-001','overview','overview','态势总览','overview','汇总当前风险、观测覆盖与安全运营进度。','name:风险对象|level:严重级别|status:处理状态|owner:责任人','筛选态势'],
  ['SB-VIS-002','topology','overview','风险拓扑','topology','按业务、网络域和资产关系定位风险传播路径。','name:资产|zone:网络域|risk:风险分|status:观测状态','筛选拓扑'],
  ['SB-VIS-005','response-metrics','overview','响应效能','metric','比较研判、审批、执行和验证耗时，区分观测窗口与未知起点。','name:场景|p50:P50|p95:P95|p99:P99|count:样本数|status:统计状态','导出统计'],
  ['SB-VIS-007','screens','overview','大屏管理','display','配置态势大屏的范围、时间窗口、轮播与访问期限。','name:大屏名称|scope:数据范围|layout:布局|status:状态|updated:更新时间','创建大屏'],
  ['SB-DET-001','alerts','alerts','告警列表','alert','筛选、分派和研判告警，保留原始检测与人工结论。','name:告警名称|level:严重级别|source:源 IP|destination:目的 IP|protocol:协议|status:处理状态|time:发生时间','批量研判'],
  ['SB-AI-002','assessments','alerts','研判任务','assessment','核对模型版本、证据快照、校准结果与人工复核。','name:研判对象|conclusion:恶意判断|success:利用成功判断|confidence:校准置信度|model:模型|status:任务状态','创建研判任务'],
  ['SB-SRH-001','search','alerts','高级检索','search','组合可视化条件和 Wireshark 风格表达式，明确字段支持范围。','name:记录|source:源 IP|destination:目的 IP|protocol:协议|time:时间|status:证据状态','保存查询'],
  ['SB-SRH-002','fields','alerts','字段目录','field','查看字段类型、多值语义、数据来源、索引方式与语法兼容性。','name:字段名|type:类型|source:数据来源|indexed:索引方式|status:支持状态','查看字段'],
  ['SB-SRH-008','exports','alerts','数据导出','export','以固定查询快照导出记录，跟踪权限校验与下载期限。','name:导出名称|format:格式|scope:范围|count:记录数|expires:下载到期|status:任务状态','创建导出'],
  ['SB-INC-001','incidents','incidents','事件列表','incident','创建、分派和分级安全事件，关联告警与调查证据。','name:事件名称|level:事件级别|assets:影响资产|owner:负责人|sla:SLA|status:事件状态','创建事件'],
  ['SB-INC-002','cases','incidents','案件工作台','case','集中管理任务、可观测对象、笔记和证据。','name:案件名称|owner:负责人|tasks:任务进度|evidence:证据数|scope:分享范围|status:案件状态','创建案件'],
  ['SB-INC-003','timelines','incidents','调查时间线','timeline','按事件时间串联观测事实，保留来源和时间不确定性。','name:调查对象|start:开始时间|end:结束时间|sources:数据源|uncertainty:时间误差|status:调查状态','创建调查'],
  ['SB-INC-004','case-sharing','incidents','案件协作','sharing','管理合并、拆分、移交和证据分享，保持租户与对象权限边界。','name:案件|operation:协作类型|scope:分享范围|owner:申请人|status:审核状态','创建协作申请'],
  ['SB-INC-005','duty','incidents','值班与 SLA','duty','配置值班、升级与工作日历，分别计量接单和解决时钟。','name:值班计划|owner:当班人员|timezone:时区|response:接单期限|resolution:解决期限|status:状态','创建值班计划'],
  ['SB-INC-006','tickets','incidents','工单同步','ticket','核对外部工单字段所有权、同步冲突与附件权限。','name:工单|external:外部编号|connector:连接器|direction:同步方向|status:同步状态|updated:最近同步','配置工单连接'],
  ['SB-INC-007','reviews','incidents','事件复盘','review','记录根因、影响、处置验证与遗留整改，沉淀可审核知识。','name:复盘名称|root:根因分类|owner:负责人|remaining:遗留任务|status:复盘状态|updated:更新时间','创建复盘'],
  ['SB-AST-001','assets','assets','资产列表','asset','认领资产、维护责任人并跟踪生命周期。','name:资产名称|ip:IP 地址|type:资产类型|group:资产组|owner:责任人|risk:风险分|status:生命周期','登记资产'],
  ['SB-AST-002','interfaces','assets','接口与地址','interface','按有效时间管理 IP、MAC 和网络接口，显示冲突与来源。','name:接口|asset:所属资产|ip:IP 地址|mac:MAC 地址|source:观测来源|status:归属状态','登记接口'],
  ['SB-AST-003','address-history','assets','地址归属历史','address','关联 DHCP、ARP、NDP 的时间窗口，不覆盖历史归属。','name:地址|mac:MAC 地址|asset:资产|source:来源协议|start:有效开始|end:有效结束|status:匹配状态','核对归属'],
  ['SB-AST-004','nat','assets','NAT 与代理映射','nat','区分真实客户端、代理声明与观测五元组。','name:映射名称|source:转换前地址|destination:转换后地址|gateway:网关|evidence:依据|status:状态','创建映射'],
  ['SB-AST-005','identities','assets','身份关联','identity','关联用户、终端、登录会话与目录来源，保留匹配强度。','name:身份|account:账号标识|asset:关联资产|source:目录来源|confidence:匹配强度|status:状态','建立关联'],
  ['SB-AST-006','asset-groups','assets','资产组与网段','network','划分业务资产组、CIDR 与网络域，处理范围冲突。','name:组名称|cidr:网段|zone:网络域|owner:责任人|count:资产数|status:状态','创建资产组'],
  ['SB-AST-007','services','assets','服务与暴露面','service','汇总已观测服务、指纹、端口和外部可达性依据。','name:服务|ip:资产 IP|port:端口|protocol:协议|exposure:暴露范围|source:数据来源|status:状态','登记服务'],
  ['SB-AST-008','asset-relations','assets','资产关系','relation','维护业务依赖、通信关系与身份连接，标明观察窗口。','name:关系|from:起点|to:终点|type:关系类型|window:观测窗口|status:依据状态','创建关系'],
  ['SB-EXP-001','vulnerabilities','assets','漏洞列表','vulnerability','导入扫描发现并按资产、服务和版本管理证据。','name:漏洞名称|cve:CVE|asset:影响资产|cvss:CVSS|epss:EPSS|kev:KEV|status:整改状态','导入扫描结果'],
  ['SB-EXP-002','scan-tasks','assets','扫描任务','scan','安排已授权扫描，控制目标范围、窗口和扫描器能力。','name:任务名称|scope:目标范围|scanner:扫描器|schedule:执行窗口|progress:进度|status:任务状态','创建扫描任务'],
  ['SB-EXP-003','risk-priorities','assets','风险优先级','priority','综合漏洞利用信号、业务重要性和证据来源排序。','name:风险对象|asset:资产|score:优先级|epss:EPSS|evidence:攻击依据|status:核对状态','配置排序策略'],
  ['SB-EXP-004','remediations','assets','整改与复测','remediation','分派整改、管理豁免期限并通过外部复测验证修复。','name:整改任务|asset:资产|owner:负责人|due:期限|retest:复测结果|status:整改状态','创建整改任务'],
  ['SB-EXP-005','baselines','assets','配置与弱口令风险','baseline','管理授权检查结果，保留策略版本并隔离敏感信息。','name:检查项|asset:资产|expected:期望值|actual:实际摘要|version:策略版本|status:整改状态','导入检查结果'],
  ['SB-EXP-006','external-exposure','assets','外部暴露与外连审批','exposure','认领公网资产、审核未知外连和暴露变更。','name:对象|type:类型|owner:责任人|change:变更|source:依据来源|status:审核状态','创建审批'],
  ['SB-EXP-007','asset-risk','assets','资产风险态势','risk','分别展示资产弱点与攻击尝试，保留关联方法和冲突。','name:资产|ip:IP 地址|vulnerabilities:弱点数|alerts:告警数|risk:风险分|status:处理状态','创建调查'],
  ['SB-VIS-003','applications','traffic','应用流量','application','按应用产品、资产和网络域比较流量，显示识别依据与置信度。','name:应用产品|category:类别|bytes:流量|sessions:会话数|confidence:识别置信度|evidence:识别依据|status:识别状态','创建识别规则'],
  ['SB-VIS-004','behaviors','traffic','行为与外连','behavior','分析应用访问、外部目的地、时间模式与异常基线。','name:行为|asset:资产|destination:目的地|application:应用|bytes:流量|status:核对状态','创建行为策略'],
  ['SB-SRH-003','packets','traffic','数据包工作台','search','浏览帧、协议层、MAC、VLAN 和隧道字段。','name:数据包|source:源地址|destination:目的地址|protocol:协议|bytes:长度|time:捕获时间|status:完整性','保存查询'],
  ['SB-SRH-004','packet-times','traffic','通信时间','packet-time','区分镜像捕获、设备接收与发送时间，标明精度和时钟误差。','name:会话|capture:捕获时间|ingress:入站时间|egress:出站时间|precision:时间精度|status:来源状态','导出时间记录'],
  ['SB-SRH-005','sessions','traffic','会话与事务','session','关联双向通信、HTTP 请求响应和跨切片原包。','name:会话|source:源 IP|destination:目的 IP|protocol:协议|method:请求方法|path:路径|status:会话状态','导出会话'],
  ['SB-SRH-006','payloads','traffic','载荷与编码','search','对原始字节进行 HEX、UTF-8 和协议解码，保持偏移可定位。','name:载荷|source:源 IP|destination:目的 IP|protocol:协议|encoding:解码方式|status:证据状态','保存查询'],
  ['SB-SRH-007','pcap-tasks','traffic','PCAP 取证任务','pcap','选择真实完整会话或观测快照，核对握手、连续性和结束证据。','name:取证任务|session:会话|format:格式|coverage:覆盖比例|handshake:握手证据|status:任务状态','创建取证任务'],
  ['SB-NET-001','capture-policy','traffic','捕获与归档策略','capture','配置全量捕获、分层存储与压缩；业务留存默认 180 天。','name:策略名称|scope:探针范围|retention:留存天数|codec:压缩方式|estimate:容量估算|status:状态','创建捕获策略'],
  ['SB-NET-002','capture-scope','traffic','镜像与捕获范围','capture-scope','登记 TAP／SPAN、方向、接口、VLAN 和镜像限制。','name:捕获点|sensor:探针|interface:接口|direction:方向|vlans:VLAN|status:观测状态','登记捕获点'],
  ['SB-NET-003','session-integrity','traffic','会话完整性','integrity','检查三次握手、双向字节连续性与 FIN／RST 结束证据。','name:会话|source:源 IP|destination:目的 IP|handshake:握手|continuity:连续性|closure:结束证据|status:判定','创建核验任务'],
  ['SB-NET-005','inspection-depth','traffic','检测深度与限制','inspection','管理重组、应用检查和文件深度，区分捕获与检测覆盖。','name:检测配置|scope:探针范围|stream:流重组深度|http:HTTP 检查深度|file:文件提取深度|status:生效状态','创建检测配置'],
  ['SB-NET-006','capture-quality','traffic','捕获质量','quality','比较镜像、NIC、内核和引擎计数，定位丢包和重复风险。','name:捕获点|bps:吞吐|pps:PPS|drop:丢包率|duplicates:重复率|gap:交付滞后|status:质量状态','创建质量检查'],
  ['SB-NET-007','tls-visibility','traffic','TLS 可见性','tls','区分加密元数据与授权明文来源，展示解密能力和证据缺口。','name:会话|version:TLS 版本|sni:SNI|fingerprint:指纹|visibility:可见范围|status:解密状态','创建授权分析'],
  ['SB-NET-008','protocols','traffic','协议能力','protocol','逐项核对识别、事务、规则、文件、原生取证与外部信号。','name:协议|recognition:识别|transaction:事务|rule:规则|file:文件|native:原生取证|status:当前条件','查看协议能力'],
  ['SB-NET-009','pipeline-latency','traffic','全链路时延','latency','按真实采样点分段计量采集、检测、写入、推送和阻断耗时。','name:链路阶段|p50:P50|p95:P95|p99:P99|count:样本数|missing:缺失起点|status:计量状态','导出时延统计'],
  ['SB-NET-010','capacity','traffic','容量与压力评估','capacity','同时检查 bps、PPS、CPS、EPS 和存储积压，保留试验条件。','name:测试场景|bps:吞吐|pps:PPS|cps:CPS|eps:EPS|status:验收状态','创建评估任务'],
  ['SB-DET-002','rules','detection','Suricata 规则','rule','管理 SID、版本、变量、测试报告、灰度发布与回滚。','name:规则名称|sid:SID|revision:修订|protocol:协议|hits:命中数|status:生命周期|updated:更新时间','创建规则'],
  ['SB-DET-003','correlation','detection','关联规则','correlation','配置窗口、实体键、迟到策略和抑制，回测后发布。','name:规则名称|window:时间窗口|entity:实体键|lateness:允许迟到|version:版本|status:状态','创建关联规则'],
  ['SB-DET-004','sigma','detection','日志规则','sigma','导入 Sigma 并核验字段映射和语义支持，阻止不完整转换。','name:规则名称|source:日志来源|mapping:映射版本|supported:语义支持|status:验证状态','导入 Sigma'],
  ['SB-DET-005','hunts','detection','威胁狩猎','hunt','围绕假设保存查询、定时运行并将线索转为案件。','name:狩猎名称|hypothesis:假设|source:数据范围|schedule:调度|hits:线索数|status:状态','创建狩猎'],
  ['SB-DET-006','behavior-baselines','detection','行为基线','behavior-model','查看训练窗口、漂移、例外和异常依据。','name:基线名称|entity:实体类型|window:学习窗口|drift:漂移|version:版本|status:状态','创建基线'],
  ['SB-DET-007','threat-scenarios','detection','威胁场景','scenario','组织攻击阶段与数据依赖，显示覆盖和验证结果。','name:场景名称|phase:攻击阶段|source:信号来源|coverage:覆盖率|version:版本|status:验证状态','创建场景'],
  ['SB-DET-008','attack-coverage','detection','ATT&CK 覆盖','attack','展示已映射技术、实际数据依赖与评估样本。','name:技术|technique:技术编号|tactic:战术|rules:规则数|evidence:评估依据|status:覆盖状态','创建评估'],
  ['SB-DET-009','file-analysis','detection','文件分析','file','从告警和会话关联样本、静态分析与动态沙箱结果。','name:样本名称|sha256:SHA-256|type:类型|bytes:体积|verdict:分析结论|status:完整性','提交分析'],
  ['SB-TI-001','intel-sources','detection','情报源','intel-source','注册情报订阅，核对来源、许可和数据更新。','name:情报源|type:接入类型|license:许可|refresh:更新频率|updated:最近更新|status:状态','接入情报源'],
  ['SB-TI-002','indicators','detection','威胁指标','indicator','管理 IP、域名、URL 和哈希的来源、上下文及可信度。','name:指标值|type:指标类型|source:来源|confidence:可信度|expires:有效期|status:状态','创建指标'],
  ['SB-TI-003','intel-lifecycle','detection','情报有效性','intel-life','设置有效期、衰减和复核，保留历史命中依据。','name:指标|source:来源|confidence:当前可信度|decay:衰减策略|expires:到期时间|status:复核状态','配置生命周期'],
  ['SB-TI-004','intel-hits','detection','情报命中与回溯','intel-hit','查看实时命中和历史回溯任务，冻结所用情报版本。','name:命中对象|indicator:指标|asset:资产|version:情报版本|mode:匹配模式|status:任务状态','创建回溯'],
  ['SB-TI-005','watchlists','detection','名单管理','watchlist','配置保护名单、例外与关注对象，并设置审批和到期。','name:名单对象|type:名单类型|scope:作用范围|reason:原因|expires:到期时间|status:状态','创建名单项'],
  ['SB-TI-006','intel-sharing','detection','情报共享','intel-share','审核可共享字段、脱敏、许可和接收范围。','name:共享任务|scope:接收范围|format:格式|redaction:脱敏策略|license:许可|status:审核状态','创建共享申请'],
  ['SB-FIL-001','samples','detection','文件样本','sample','记录提取来源、截断、哈希、完整性与受控样本访问。','name:样本名称|type:类型|bytes:体积|sha256:SHA-256|source:提取来源|status:完整性','导入授权样本'],
  ['SB-FIL-002','static-analysis','detection','静态检测','static','管理 YARA-X、ClamAV 的引擎版本、规则与报告。','name:分析任务|engine:引擎|version:引擎版本|rules:规则版本|verdict:结果|status:任务状态','创建静态检测'],
  ['SB-FIL-003','sandbox','detection','动态沙箱','sandbox','将样本提交授权沙箱，跟踪运行、取消和异步报告。','name:沙箱任务|profile:执行环境|connector:连接器|duration:耗时|verdict:结论|status:运行状态','提交沙箱任务'],
  ['SB-FIL-004','sample-access','detection','样本隔离与授权','sample-access','控制隔离样本的查看、导出和到期授权。','name:授权申请|sample:样本|owner:申请人|purpose:使用目的|expires:权限到期|status:审核状态','申请样本访问'],
  ['SB-FIL-005','analysis-pools','detection','文件分析资源','pool','配置资源池、租户配额、超时和排队上限。','name:资源池|type:引擎类型|concurrency:并发|queue:队列长度|timeout:超时|status:状态','创建资源池'],
  ['SB-FIL-006','analysis-reports','detection','文件分析报告','file-report','查看后到报告、复核和重新分析，分别关联响应依据。','name:报告|sample:样本|verdict:结论|revision:修订|owner:复核人|status:复核状态','创建重新分析'],
  ['SB-RSP-001','decision-policies','response','决策策略','decision','配置影子、审批和自动模式，绑定校准版本与动作资格。','name:策略名称|mode:运行模式|model:决策模型|confidence:置信度门槛|scope:作用范围|status:状态','创建决策策略'],
  ['SB-RSP-002','devices','response','联动设备','device','绑定执行采集器、网络域、凭据引用与设备能力。','name:设备名称|type:设备类型|address:管理地址|sensor:执行采集器|capability:动作能力|status:连接状态','接入设备'],
  ['SB-RSP-003','auth-plugins','response','认证插件','auth-plugin','管理控制台认证、会话缓存、续期与设备版本兼容性。','name:插件名称|device:设备|version:插件版本|auth:认证方式|expires:会话到期|status:认证状态','配置认证插件'],
  ['SB-RSP-004','actions','response','动作中心','action','跟踪封禁、解封、隔离与恢复，区分接受、生效和效果观察。','name:动作|target:目标|sensor:执行采集器|accepted:设备接受|effective:配置核验|observed:效果观察|status:动作状态','创建响应动作'],
  ['SB-RSP-005','playbooks','response','响应剧本','playbook','编排触发、条件、人工审批、受控动作和补偿路径。','name:剧本名称|trigger:触发器|nodes:节点数|version:版本|status:发布状态','创建剧本'],
  ['SB-RSP-006','playbook-runs','response','剧本实例','playbook-run','跟踪检查点、等待、结果未知、取消与补偿。','name:实例|playbook:剧本|node:当前节点|duration:耗时|owner:审批人|status:运行状态','创建演练实例'],
  ['SB-RSP-007','emergency','response','应急控制','emergency','停止新动作、撤销有效租约并核对在途任务和执行器隔离。','name:控制范围|newActions:调度状态|leases:活动租约|inflight:在途动作|watermark:撤销水位|status:控制状态','发起应急控制'],
  ['SB-OPS-005','channels','notifications','通知渠道','channel','配置邮件、企业微信、钉钉、飞书与 Webhook，验证投递能力。','name:渠道名称|type:渠道类型|scope:使用范围|rate:限流|verified:最近测试|status:状态','创建通知渠道'],
  ['SB-OPS-006','syslog-output','notifications','Syslog 转发','syslog','配置出站服务器、分帧、持久缓冲和失败重放。','name:转发目标|address:服务器|transport:传输|format:格式|backlog:缓冲积压|status:状态','创建转发目标'],
  ['SB-AI-001','models','ai','模型配置','model','配置通用大模型、Jev、Laya 的能力、路由、预算和数据驻留。','name:模型名称|provider:供应商|model:模型 ID|purpose:任务能力|residency:数据驻留|status:验证状态','接入模型'],
  ['SB-AI-003','chat','ai','智能对话','chat','围绕有权限的数据进行检索和分析，显示工具调用与证据引用。','name:对话|model:模型|scope:数据范围|updated:更新时间|status:状态','创建对话'],
  ['SB-AI-004','rule-studio','ai','AI 规则生成','rule-studio','通过自然语言、PCAP 或 HTTP Raw 生成候选规则，验证后进入发布流程。','name:生成任务|input:输入来源|model:模型|sid:SID|status:验证状态','生成候选规则'],
  ['SB-AI-005','knowledge','ai','知识与提示模板','knowledge','维护审核后的分析知识、提示版本与适用场景。','name:条目名称|type:条目类型|scope:适用场景|version:版本|owner:审核人|status:状态','创建知识条目'],
  ['SB-AI-006','mcp','ai','MCP 服务','mcp','向授权 Agent 提供查询工具，限制数据范围、输出和调用预算。','name:服务名称|transport:传输|tools:工具范围|scope:数据范围|quota:调用配额|status:状态','创建 MCP 客户端'],
  ['SB-VIS-006','reports','reports','日报周报月报','report','根据固定数据窗口生成日报、周报与月报，引用统计和研判依据。','name:报告名称|type:报告周期|window:统计窗口|model:总结模型|owner:审核人|status:报告状态','创建报告'],
  ['SB-OPS-001','sensors','sensors','探针列表','sensor','登记探针、站点、捕获域与执行角色，管理证书和连接状态。','name:探针名称|site:站点|role:角色|version:版本|lastSeen:最近心跳|status:连接状态','注册探针'],
  ['SB-OPS-003','releases','sensors','发布中心','release','灰度发布探针、引擎、规则与应用识别包，核对实际生效版本。','name:发布任务|type:内容类型|version:目标版本|scope:探针范围|progress:进度|status:发布状态','创建发布任务'],
  ['SB-DAT-001','data-sources','system','数据源','data-source','创建、验证、启停数据源，绑定认证租户与网络域。','name:数据源名称|type:来源类型|scope:所属网络域|eps:EPS|quality:解析成功率|status:连接状态','接入数据源'],
  ['SB-DAT-002','syslog-input','system','Syslog 接收','syslog-input','配置独立入站监听、来源绑定、传输与分帧。','name:监听器|address:监听地址|transport:传输|binding:来源绑定|format:格式|status:状态','创建监听器'],
  ['SB-DAT-003','imports','system','批次导入','import','通过 API、文件或对象导入数据，跟踪游标和断点续传。','name:导入任务|type:导入来源|cursor:接收游标|progress:进度|count:记录数|status:任务状态','创建导入任务'],
  ['SB-DAT-004','logs','system','日志工作台','log','检索主机、身份、云和应用日志，核对标准化字段。','name:事件摘要|source:数据源|asset:资产|identity:身份|time:事件时间|status:解析状态','保存日志查询'],
  ['SB-DAT-005','flow-sources','system','流量记录接入','flow-source','接入 NetFlow、IPFIX、sFlow，保持采样率与计量域。','name:导出器|protocol:协议|domain:观测域|sampling:采样率|templates:模板|status:连接状态','接入导出器'],
  ['SB-DAT-006','parsers','system','解析器','parser','测试样例映射、时间解析和脱敏，灰度发布后保留回放能力。','name:解析器名称|type:来源类型|version:版本|quality:测试通过率|scope:数据源范围|status:发布状态','创建解析器'],
  ['SB-DAT-007','data-quality','system','数据质量','data-quality','检查缺失、迟到、重复、乱序和字段漂移，保留受影响范围。','name:数据源|missing:必需字段缺失|late:迟到比例|duplicates:重复比例|quality:解析成功率|status:质量状态','创建质量检查'],
  ['SB-DAT-008','replays','system','隔离与重放','replay','从隔离队列创建有界重放任务，冻结解析和检测版本。','name:重放任务|source:来源队列|version:解析版本|count:事件数|progress:进度|status:任务状态','创建重放任务'],
  ['SB-OPS-004','platform-health','system','平台运行状态','platform','查看依赖健康、资源和数据影响，按业务链路定位故障。','name:组件|role:职责|cpu:CPU|memory:内存|backlog:积压|status:运行状态','配置监控阈值'],
  ['SB-OPS-007','backups','system','备份与恢复','backup','管理备份范围、恢复点与隔离演练，核对恢复验证。','name:备份任务|scope:范围|bytes:体积|rpo:恢复点|validated:验证时间|status:状态','创建备份任务'],
  ['SB-OPS-008','connectors','system','连接器与许可','connector','管理连接器签名、版本适配、权限、许可与维护责任。','name:连接器|type:类别|version:版本|license:许可|owner:维护方|status:适配状态','注册连接器'],
  ['SB-GOV-001','authentication','system','登录与会话','auth','配置 OIDC、MFA、会话期限与撤销，查看当前活动会话。','name:会话|account:账号|source:登录来源|mfa:MFA|expires:到期时间|status:状态','配置登录策略'],
  ['SB-GOV-002','roles','system','角色与权限','role','按操作、对象和字段范围授予权限，预览有效权限。','name:角色|scope:数据范围|permissions:权限数|members:成员数|owner:责任人|status:状态','创建角色'],
  ['SB-GOV-003','tenants','system','租户与组织','tenant','管理集团组织、租户委派与数据单元归属。','name:租户名称|parent:上级组织|cell:数据单元|sensors:探针数|owner:管理员|status:状态','创建租户'],
  ['SB-GOV-004','api-keys','system','服务身份与 API 密钥','api-key','为 API 与 MCP 签发有范围和期限的服务身份，支持轮换。','name:服务身份|scope:授权范围|tools:工具权限|expires:到期时间|used:最近使用|status:状态','创建服务身份'],
  ['SB-GOV-005','data-security','system','数据脱敏与外发','data-security','控制敏感字段、模型外发、样本导出和驻留范围。','name:策略名称|scope:数据范围|redaction:脱敏方式|egress:外发规则|owner:负责人|status:状态','创建数据策略'],
  ['SB-GOV-006','retention','system','留存与证据保全','retention','所有已启用业务数据默认保留 180 天，变更前预览影响与保全。','name:数据类别|retention:留存天数|storage:存储层|held:保全数量|estimate:预计占用|status:策略状态','调整留存策略'],
  ['SB-GOV-007','audit','system','审计日志','audit','追溯登录、操作、访问与导出，保留主体和对象快照。','name:操作摘要|actor:操作人|object:对象|source:来源 IP|time:时间|status:结果','导出审计记录'],
  ['SB-GOV-008','quotas','system','用量与配额','quota','按租户治理流量、索引、对象存储、模型和任务资源。','name:配额项|scope:租户|used:已使用|limit:限额|period:计费窗口|status:状态','调整配额'],
  ['SB-GOV-009','software-catalog','system','软件物料与供应链','software','查看 SBOM、签名、许可、支持版本与升级资格。','name:组件|version:版本|license:许可|signature:签名|support:维护状态|status:核验状态','导入物料清单'],
  ['SB-GOV-010','governance','system','治理检查','governance','通过检查项、依据与豁免跟踪配置和合规治理。','name:检查项|scope:适用范围|evidence:依据|owner:责任人|expires:豁免到期|status:检查结果','创建治理检查'],
]

const commonFields: FieldSpec[] = [
  { key: 'name', label: '名称', required: true, value: '' },
  { key: 'scope', label: '作用范围', type: 'select', required: true, options: ['总部网络域','研发网络域','分支网络域'], value: '总部网络域' },
  { key: 'owner', label: '责任人', type: 'select', required: true, options: ['陈宁','林悦','值班分析组'], value: '值班分析组' },
  { key: 'notes', label: '说明', type: 'textarea', hint: '记录业务目的、依据和适用边界。' },
]
function fieldsForColumns(columnText:string,family:string):FieldSpec[]{
  const types:Record<string,string[]>={field:['IP / MAC','字符串','布尔','时间'],relation:['业务依赖','通信关系','身份关联'],exposure:['公网资产','异常外连','暴露变更'],release:['探针','引擎','检测规则','应用识别包'],import:['JSON','CSV','Syslog'],parser:['JSON','Syslog','CSV'],connector:['设备联动','文件沙箱','漏洞扫描','工单'],delivery:['邮件','企业微信','钉钉','飞书','Webhook'],'intel-source':['IP','域名','URL','文件哈希'],indicator:['IP','域名','URL','文件哈希']}
  const options:Record<string,string[]|undefined>={protocol:['HTTP','TLS','DNS','TCP','UDP','SMB','RDP'],type:types[family],scope:['总部网络域','研发网络域','分支网络域'],owner:['陈宁','林悦','值班分析组'],transport:['TLS/TCP','TCP','UDP'],format:['JSON','CSV','PCAPNG'],entity:['source.ip','asset.id','user.id']}
  const excluded=new Set(['status','time','updated','quality','progress','count','hits','confidence','risk','bytes','duration','evidence','accepted','effective','observed'])
  const fields=columnText.split('|').map(part=>part.split(':')).filter(([key])=>!excluded.has(key!)).slice(0,5).map(([key,label]):FieldSpec=>({key:key!,label:label!,required:true,type:options[key!]?'select':['retention','concurrency','threshold','priority','ttl'].includes(key!)?'number':'text',options:options[key!],value:options[key!]?.[0]??(key==='name'?'':key==='version'?'1.0':key==='window'?'300 秒':key==='schedule'?'每天 08:00（Asia/Shanghai）':key==='cidr'?'10.20.0.0/16':key==='expires'?'2026-10-30':key==='refresh'?'每 4 小时':undefined)}))
  if(!fields.some(f=>f.key==='scope'))fields.push({...commonFields[1]!})
  if(!fields.some(f=>f.key==='owner'))fields.push({...commonFields[2]!})
  fields.push({...commonFields[3]!})
  return fields
}
const field = (key: string, label: string, type: FieldSpec['type'] = 'text', value?: FieldSpec['value'], options?: string[], hint?: string): FieldSpec => ({ key, label, type, value, options, hint, required: !['notes','reason'].includes(key) })
const policyFields: Record<string, FieldSpec[]> = {
  alert: [field('owner','分派给','select','值班分析组',['值班分析组','陈宁','林悦']),field('status','处理状态','select','研判中',['待研判','研判中','误报','已关联事件']),field('reason','研判依据','textarea')],
  assessment: [field('model','研判模型','select','本地安全模型',['本地安全模型','Jev 适配器','Laya 适配器','通用大模型']),field('task','判断任务','select','恶意行为',['恶意行为','利用成功','处置建议']),field('scope','证据范围','select','告警与会话',['告警与会话','授权终端信号','完整调查快照']),field('notes','补充依据','textarea')],
  asset: [field('name','资产名称'),field('ip','IP 地址','text','10.20.1.15'),field('type','资产类型','select','服务器',['服务器','终端','网络设备','云资源']),field('group','资产组','select','核心业务',['核心业务','办公终端','研发服务']),field('owner','责任人','select','陈宁',['陈宁','林悦','值班分析组'])],
  network: [field('name','资产组名称'),field('cidr','CIDR 网段','text','10.20.0.0/16'),field('zone','网络域','select','总部网络域',['总部网络域','研发网络域','分支网络域']),field('owner','责任人','select','陈宁',['陈宁','林悦']),field('reason','划分依据','textarea')],
  rule: [field('name','规则名称'),field('sid','SID','number',1000001,undefined,'平台分配本地 SID，提交前检查冲突。'),field('protocol','协议','select','HTTP',['HTTP','TLS','DNS','TCP','UDP','SMB','RDP']),field('rule','规则正文','textarea','alert http any any -> $HOME_NET any (msg:"SB HTTP suspicious request"; flow:to_server,established; http.uri; content:"/admin"; sid:1000001; rev:1;)'),field('notes','测试依据','textarea')],
  correlation: [field('name','规则名称'),field('entity','实体键','select','source.ip',['source.ip','destination.ip','asset.id','user.id']),field('window','窗口（秒）','number',300),field('threshold','触发阈值','number',20),field('lateness','允许迟到（秒）','number',60),field('notes','关联条件','textarea')],
  decision: [field('name','策略名称'),field('mode','运行模式','select','审批',['影子','审批','自动']),field('model','决策模型','select','本地安全模型',['本地安全模型','Jev 适配器','Laya 适配器','通用大模型']),field('confidence','校准置信度门槛','number',0.97,undefined,'取值 0–1；0.97 表示 97%。仅作为资格条件之一，不能替代证据、授权和保护名单检查。'),field('ttl','动作 TTL（分钟）','number',30),field('scope','授权网络域','select','总部网络域',['总部网络域','研发网络域','分支网络域']),field('calibration','校准与评测版本','text','eval-web-202609'),field('notes','人工复核要求','textarea')],
  device: [field('name','设备名称'),field('type','设备类型','select','防火墙',['防火墙','EDR','交换机']),field('address','管理地址','text','https://192.0.2.20'),field('sensor','执行采集器','select','总部执行探针',['总部执行探针','分支执行探针']),field('auth','访问模式','select','官方 API',['官方 API','认证插件']),field('credential','凭据引用','text','vault/device/hq-fw'),field('scope','授权网络域','select','总部网络域',['总部网络域','研发网络域','分支网络域'])],
  action: [field('target','目标 IP','text','198.51.100.24'),field('operation','动作类型','select','封禁 IP',['封禁 IP','解封 IP','隔离终端','恢复终端']),field('device','目标设备','select','总部边界防火墙',['总部边界防火墙','总部终端 EDR']),field('sensor','执行采集器','select','总部执行探针',['总部执行探针','分支执行探针']),field('ttl','有效期（分钟）','number',30),field('approval','授权依据','text','审批单 APR-20260930-001'),field('reason','处置原因','textarea')],
  emergency: [field('scope','控制范围','select','当前租户',['当前租户','总部网络域','总部边界防火墙']),field('operation','控制类型','select','停止新动作',['停止新动作','撤销有效动作','隔离故障执行器']),field('reason','执行原因','textarea'),field('confirm','输入确认文字','text','',undefined,'输入“确认控制”后才能提交。停止调度与撤销租约分别追踪。')],
  channel: [field('name','渠道名称'),field('type','渠道类型','select','邮件',['邮件','企业微信','钉钉','飞书','Webhook']),field('address','接收地址','text','security@example.test'),field('credential','凭据引用','text','vault/notification/mail'),field('rate','每分钟限额','number',30),field('notes','消息模板','textarea','[星烽] {{alert.severity}} · {{alert.name}} · {{alert.id}}')],
  syslog: [field('name','目标名称'),field('address','服务器地址','text','192.0.2.40:6514'),field('transport','传输方式','select','TLS/TCP',['TLS/TCP','TCP','UDP']),field('format','消息格式','select','RFC 5424',['RFC 5424','RFC 3164']),field('credential','TLS 凭据引用','text','vault/syslog/client'),field('notes','转发范围','textarea')],
  model: [field('name','配置名称'),field('provider','供应商／适配器','select','本地模型',['本地模型','通用 API','Jev','Laya']),field('endpoint','服务地址','text','https://model.example.test/v1'),field('model','精确模型 ID','text','security-small-example'),field('credential','API 密钥引用','text','vault/models/local'),field('residency','数据驻留','select','本地',['本地','授权云区域']),field('budget','每日预算（元）','number',100),field('notes','允许的任务','textarea')],
  report: [field('name','报告名称'),field('type','报告周期','select','日报',['日报','周报','月报']),field('window','统计窗口','text','2026-09-29 00:00 — 23:59'),field('model','总结模型','select','本地安全模型',['本地安全模型','通用大模型']),field('owner','审核人','select','陈宁',['陈宁','林悦']),field('schedule','自动生成','switch',false)],
  sensor: [field('name','探针名称'),field('site','站点','select','总部',['总部','研发中心','分支机构']),field('role','角色','select','采集与检测',['采集与检测','执行采集器','采集与执行']),field('zone','网络域','select','总部网络域',['总部网络域','研发网络域','分支网络域']),field('targetVersion','目标引擎版本','text','Suricata 8.0.7'),field('notes','镜像接入说明','textarea')],
  capture: [field('name','策略名称'),field('scope','探针范围','select','总部探针组',['总部探针组','分支探针组']),field('retention','留存（天）','number',180),field('codec','压缩方式','select','Zstandard 独立块',['Zstandard 独立块','LZ4 独立块','不压缩']),field('level','压缩级别','number',3),field('block','独立块目标（MiB）','number',16),field('notes','归档边界','textarea')],
  inspection: [field('name','配置名称'),field('scope','探针范围','select','总部探针组',['总部探针组','分支探针组']),field('stream','流重组深度（MiB）','number',8),field('http','HTTP 检查深度（MiB）','number',4),field('file','文件提取深度（MiB）','number',32),field('notes','性能验收依据','textarea')],
  retention: [field('category','数据类别','select','PCAP',['PCAP','告警','协议明细','操作日志','登录日志','通知记录','文件样本','报告']),field('retention','留存（天）','number',180),field('scope','租户范围','select','当前租户',['当前租户','指定组织']),field('reason','变更依据','textarea'),field('preview','已核对影响预览','switch',false)],
  mcp: [field('name','客户端名称'),field('scope','数据范围','select','总部网络域',['总部网络域','当前租户']),field('tools','工具权限','select','只读分析',['只读分析','查询与报告']),field('validity','有效期限','select','30 天',['7 天','30 天','90 天']),field('quota','每分钟调用限额','number',20),field('notes','用途说明','textarea')],
  pcap: [field('name','任务名称'),field('session','会话 ID','text','FLOW-20260930-0142'),field('mode','导出模式','select','完整会话',['完整会话','观测快照']),field('format','文件格式','select','PCAPNG',['PCAPNG','PCAP']),field('reason','取证用途','textarea')],
}

const notices: Record<string, string> = {
  alert: '检测命中表示观察到规则条件。利用成功和是否可封禁需要独立证据与处置授权。',
  assessment: '校准置信度、自报分数和处置资格分别记录；证据不足时保留“无法判定”。',
  application: '应用识别以规则、域名、SNI 等观测依据为准。共享域名、CDN、ECH 或加密载荷可能造成未知或冲突。',
  'packet-time': '旁路单臂镜像通常只有捕获时间；没有独立观测来源时，入站／出站时间显示“不可观测”。',
  pcap: '完整会话必须验证真实三次握手、双向连续性与结束证据；缺包时只能导出观测快照。',
  integrity: '握手完整不代表应用内容全部可见。TLS 密文、丢包、重组限制和单向镜像分别核对。',
  tls: '保存 TLS 密文不等于能够解密。没有授权密钥或明文来源时，仅提供可观测元数据。',
  inspection: '原包捕获与规则检查分开。超出检查深度、重组内存或解析范围时产生覆盖缺口，不推断为安全。',
  capture: '默认归档期限 180 天。压缩收益依赖实际载荷，容量预算采用无压缩基准；TLS 密文通常收益有限。',
  action: '主平台 → 执行采集器 → 设备。设备接受、配置存在和流量效果分别核验；无后续流量不代表效果已证实。',
  decision: '自动处置需同时满足校准资格、完整证据、保护名单、范围、TTL 与预算条件。',
  'auth-plugin': '凭据与 Cookie 仅保留受控引用。遇到验证码、MFA 或版本变化时暂停自动执行并请求人工接管。',
  sandbox: '动态检测在隔离环境异步执行，不阻塞实时告警；执行失败或样本不完整不等于无恶意。',
  static: '未命中静态规则不等于安全。保留引擎、规则版本、样本完整性与复核结果。',
  vulnerability: '漏洞存在与观察到利用尝试是独立事实；工单关闭不能直接证明漏洞已修复。',
  protocol: '识别、事务、规则、文件、原生取证与外部信号分别验收；条件不具备时不输出确定结论。',
  'flow-source': '采样流记录不等于全包流量；不同计量域不直接叠加，也不提供不存在的 PCAP。',
  retention: '业务数据默认 180 天。当前有效配置、活动案件与证据保全对象不会因创建时间自动删除。',
  latency: '所有数值为合成示例。生产计量依赖真实时间点，动态沙箱与模型耗时分别统计。',
  metric: '所有数值为合成示例；样本口径和缺失起点可见，不能据此声称性能验收通过。',
  model: '连接测试、能力测试和领域质量评测分别完成。Jev／Laya 以适配器契约与实际版本验收为准。',
  mcp: '客户端继承租户、对象和字段权限；读分析工具与具有副作用的处置动作分开授权。',
}

const readOnlyFamilies = new Set(['field','metric','latency','audit','protocol','packet-time','attack','data-quality','quality','platform','risk'])
const detailTabs: Record<string, string[]> = {
  alert: ['告警信息','通信证据','研判与响应','处理记录'],
  incident: ['事件信息','关联证据','任务与时间线','处理记录'],
  case: ['案件信息','关联证据','任务与时间线','处理记录'],
  action: ['动作信息','执行链路','回执与核验','处理记录'],
  sensor: ['基本信息','运行状态','采集与版本','运行记录'],
  report: ['报告信息','报告正文','统计依据','处理记录'],
  rule: ['规则信息','规则正文','测试与发布','处理记录'],
  model: ['模型信息','能力与评测','路由与预算','处理记录'],
}

function columnsFromText(text: string): ColumnSpec[] {
  return text.split('|').map((part, index) => {
    const [key = '', title = ''] = part.split(':')
    const kind = key === 'status' ? 'status' : key === 'level' ? 'level' : key === 'progress' ? 'progress' : ['confidence','quality','coverage','cpu','memory','disk'].includes(key) ? 'percent' : ['ip','source','destination','mac','sha256','sid','cve','technique','address'].includes(key) ? 'code' : 'text'
    return { key, title, width: index === 0 ? 225 : key==='level'?90:key==='protocol'?88:key==='status'?114:key === 'time' || key === 'updated' ? 178 : 132, kind }
  })
}

export const pages: PageSpec[] = definitions.map(([requirement,id,group,title,family,description,columnText,primary]) => ({
  id,title,group,family,description,requirement:[requirement],kind: ['overview','topology','search','chat','rule-studio','playbook','retention'].includes(family) ? family as PageSpec['kind'] : 'table',
  columns: columnsFromText(columnText), fields: policyFields[family] ?? fieldsForColumns(columnText,family),
  primary: primary ?? '创建记录', rowAction: readOnlyFamilies.has(family) ? '导出' : ['alert','assessment'].includes(family) ? '研判' : family === 'action' ? '撤销' : family === 'rule' ? '编辑' : family === 'report' ? '审核' : '操作',
  emptyTitle: `暂无${title.replace(/列表$/,'')}数据`,
  emptyDescription: `当前租户与筛选范围内没有${title.replace(/列表$/,'')}记录。请核对时间和网络域，或${(primary ?? '完成相关配置')}。`,
  objectLabel: title.replace(/列表$/,''), notice: notices[family], detailTabs: detailTabs[family] ?? ['基本信息'],
  readOnly: readOnlyFamilies.has(family), actionMode: readOnlyFamilies.has(family) ? 'export' : ['scan','assessment','pcap','import','replay','sandbox','static','export'].includes(family) ? 'task' : 'create',
  statusOptions: statusesFor({family,actionMode:['scan','assessment','pcap','import','replay','sandbox','static','export'].includes(family)?'task':'create'}),
}))

function supplemental(id: string, title: string, group: string, family: string, description: string, cols: string, primary: string): PageSpec {
  return { id,title,group,family,description,kind:'table',requirement:[],columns:columnsFromText(cols),fields:fieldsForColumns(cols,family),primary,rowAction:'操作',emptyTitle:`暂无${title}`,emptyDescription:'当前筛选范围内没有记录，请核对时间范围或完成相关配置。',objectLabel:title }
}
pages.push(
  { ...supplemental('big-screen','态势大屏','overview','screen','按网络域展示风险、流量与响应状态。','name:对象|status:状态','配置大屏'),kind:'screen',requirement:['SB-VIS-007'] },
  supplemental('notification-routes','通知规则','notifications','notification-rule','按严重级别、业务范围、值班与升级条件分派通知。','name:规则名称|level:告警级别|channels:通知渠道|owner:接收组|schedule:静默窗口|status:状态','创建通知规则'),
  supplemental('notification-templates','消息模板','notifications','template','维护邮件、机器人卡片和 Webhook 的字段、脱敏与版本。','name:模板名称|type:渠道类型|version:版本|redaction:脱敏策略|status:状态','创建模板'),
  { ...supplemental('delivery-logs','推送日志','notifications','delivery','查看发送尝试、供应商接受、送达和阅读回执，支持有界重试。','name:推送内容|type:渠道类型|recipient:接收对象|accepted:供应商接受|delivered:送达回执|read:阅读回执|status:投递状态','导出推送记录'),actionMode:'export',readOnly:true,requirement:['SB-OPS-005'],notice:'供应商接受、送达和阅读是不同状态；渠道不提供回执时显示“不可观测”。' },
  supplemental('application-rules','应用识别规则','detection','application-rule','管理产品特征、版本、域名、SNI 与冲突优先级。','name:规则名称|product:应用产品|feature:识别特征|priority:优先级|version:版本|status:状态','创建识别规则'),
  supplemental('rule-samples','重放样本','detection','replay-sample','导入 PCAP 与 PCAPNG 样本，选择目标探针与规则包进行离线验证。','name:样本名称|bytes:大小|format:格式|status:完整性','导入 PCAP'),
  { ...supplemental('rule-tests','重放任务','detection','rule-test','管理离线重放任务、执行探针与规则来源，核对包处理统计、命中和执行日志。','name:重放任务|version:规则版本|positive:正样本|negative:负样本|performance:性能验证|status:结果','创建重放测试'),requirement:['SB-DET-002','SB-AI-004'] },
  supplemental('report-schedules','报告计划','reports','report-schedule','配置日报、周报和月报的时间窗口、审核与授权发送。','name:计划名称|type:报告周期|schedule:生成时间|model:总结模型|owner:审核人|status:状态','创建报告计划'),
  { ...supplemental('login-logs','登录日志','system','login-log','查看登录、MFA、认证失败与会话撤销，支持范围内审计。','name:账号|method:认证方式|source:来源 IP|mfa:MFA|time:时间|status:登录结果','导出登录日志'),readOnly:true,actionMode:'export',requirement:['SB-GOV-007'] },
  supplemental('users','用户管理','system','user','维护组织用户、角色、状态和 MFA。','name:姓名|account:账号|department:组织|role:角色|mfa:MFA|status:状态','创建用户'),
  supplemental('my-account','个人设置','system','account','管理显示偏好、通知订阅与会话安全。','name:设置项|value:当前值|scope:作用范围|status:状态','保存个人设置'),
)

const customFields: Record<string, FieldSpec[]> = {
  'auth-plugins': [field('name','插件名称'),field('device','目标设备','select','总部边界防火墙',['总部边界防火墙']),field('plugin','签名插件','text','connector.example.auth'),field('version','兼容版本','text','1.2.0'),field('credential','凭据引用','text','vault/device/hq-fw'),field('scope','允许访问的管理域','text','https://192.0.2.20'),field('notes','会话续期说明','textarea')],
  'scan-tasks': [field('name','任务名称'),field('scanner','授权扫描器','select','内网扫描连接器',['内网扫描连接器','外部测绘连接器']),field('scope','目标 CIDR','text','10.20.0.0/24'),field('schedule','执行窗口','text','2026-10-01 01:00 — 03:00'),field('authorization','授权单号','text','AUTH-20260930-002'),field('notes','速率与范围约束','textarea')],
  'notification-routes': [field('name','规则名称'),field('level','严重级别','select','高危及以上',['严重','高危及以上','中危及以上','全部']),field('channels','通知渠道','select','邮件＋企业微信',['邮件＋企业微信','钉钉','飞书','Webhook']),field('owner','接收组','select','值班分析组',['值班分析组','陈宁']),field('schedule','静默窗口','text','00:00 — 07:00，严重告警除外'),field('escalation','升级等待（分钟）','number',15)],
  'notification-templates': [field('name','模板名称'),field('type','渠道类型','select','邮件',['邮件','企业微信','钉钉','飞书','Webhook']),field('title','标题模板','text','[星烽] {{alert.severity}} · {{alert.name}}'),field('body','正文模板','textarea','告警：{{alert.name}}\n证据：{{alert.id}}\n状态：{{alert.status}}'),field('redaction','脱敏策略','select','办公通知脱敏',['办公通知脱敏','内部授权详情'])],
  'application-rules': [field('name','规则名称'),field('product','应用产品','text','百度网盘'),field('feature','特征类型','select','TLS SNI',['TLS SNI','HTTP Host','DNS 域名','协议特征']),field('pattern','匹配表达式','text','*.pan.baidu.com'),field('priority','优先级','number',100),field('notes','正负样本依据','textarea')],
  'data-sources': [field('name','数据源名称'),field('type','来源类型','select','Syslog',['Syslog','API','文件','对象存储','主机事件']),field('scope','网络域','select','总部网络域',['总部网络域','研发网络域']),field('credential','认证身份引用','text','vault/source/device'),field('parser','解析器','select','RFC 5424 标准映射',['RFC 5424 标准映射','JSON 事件映射']),field('eps','EPS 限额','number',1000)],
  'syslog-input': [field('name','监听器名称'),field('address','监听地址','text','0.0.0.0:6514'),field('transport','传输方式','select','TLS/TCP',['TLS/TCP','TCP','UDP']),field('binding','来源身份绑定','text','client-cert/hq-device'),field('parser','解析器','select','RFC 5424 标准映射',['RFC 5424 标准映射','RFC 3164 标准映射']),field('notes','来源归属与限额','textarea')],
  'parsers': [field('name','解析器名称'),field('type','输入类型','select','JSON',['JSON','Syslog','CSV']),field('sample','授权样例','textarea','{"timestamp":"2026-09-30T09:42:16+08:00","src_ip":"10.20.1.15"}'),field('mapping','字段映射','textarea','src_ip → source.ip\ntimestamp → @timestamp'),field('timezone','默认时区','text','Asia/Shanghai'),field('notes','验证与灰度范围','textarea')],
  'roles': [field('name','角色名称'),field('scope','数据范围','select','总部网络域',['总部网络域','当前租户']),field('permissionTemplate','权限模板','select','安全分析员',['安全分析员','响应审批员','租户管理员','只读审计员']),field('redaction','字段可见性','select','默认脱敏',['默认脱敏','授权完整字段']),field('notes','授权依据','textarea')],
  'tenants': [field('name','租户名称'),field('parent','上级组织','select','星烽示例集团',['星烽示例集团','独立组织']),field('cell','数据单元','select','cell-demo-01',['cell-demo-01','cell-demo-02']),field('owner','管理员','select','陈宁',['陈宁','林悦']),field('quota','探针配额','number',200)],
  'users': [field('name','姓名'),field('account','账号','text','analyst@example.test'),field('department','组织','select','总部安全中心',['总部安全中心','研发中心']),field('role','角色','select','安全分析员',['安全分析员','响应审批员','租户管理员','只读审计员']),field('requireMfa','要求 MFA','switch',true)],
  'api-keys': [field('name','服务身份名称'),field('scope','数据范围','select','总部网络域',['总部网络域','当前租户']),field('tools','权限范围','select','查询与报告',['只读查询','查询与报告']),field('validity','有效期','select','30 天',['7 天','30 天','90 天']),field('notes','使用目的','textarea')],
  'authentication': [field('name','策略名称'),field('provider','认证方式','select','OIDC＋本地应急账号',['OIDC＋本地应急账号','本地账号']),field('issuer','OIDC Issuer','text','https://id.example.test'),field('requireMfa','强制 MFA','switch',true),field('timeout','会话期限（分钟）','number',60),field('notes','应急账号管理','textarea')],
  'samples': [field('name','样本名称'),field('source','样本来源','select','授权上传',['授权上传','会话提取']),field('file','示例文件','select','example-sample.bin',['example-sample.bin','example-document.pdf']),field('purpose','分析用途','textarea'),field('isolated','隔离访问','switch',true)],
  'sandbox': [field('name','任务名称'),field('sample','授权样本','select','example-sample.bin',['example-sample.bin','example-document.pdf']),field('profile','沙箱环境','select','隔离 Windows 环境',['隔离 Windows 环境','隔离 Linux 环境']),field('connector','连接器','select','沙箱示例连接器',['沙箱示例连接器']),field('timeout','超时（秒）','number',180),field('notes','授权与网络限制','textarea')],
  'report-schedules': [field('name','计划名称'),field('type','报告周期','select','日报',['日报','周报','月报']),field('schedule','生成时间','text','每天 08:00（Asia/Shanghai）'),field('model','总结模型','select','本地安全模型',['本地安全模型','通用大模型']),field('owner','审核人','select','陈宁',['陈宁','林悦']),field('notification','审核后通知','switch',false)],
  'screens': [field('name','大屏名称'),field('scope','数据范围','select','当前租户',['当前租户','总部网络域']),field('layout','展示模板','select','安全态势',['安全态势','运营效能','网络流量']),field('interval','刷新间隔（秒）','number',30),field('validity','访问有效期','select','1 小时',['1 小时','8 小时','1 天'])],
}
for (const page of pages) {
  page.statusOptions=[...new Set(statusesFor(page))]
  if(page.family==='decision')page.columns=page.columns.map(column=>column.key==='confidence'?{...column,title:'校准置信度门槛'}:column)
  if (customFields[page.id]) page.fields = customFields[page.id]!
  if(page.family==='alert'){page.emptyTitle='暂无告警';page.emptyDescription='当前租户与查询范围内没有告警。请核对时间范围、数据源接入与检测规则生效状态。'}
}
export const states = [
  { value: 'data', label: '有数据' }, { value: 'empty', label: '无数据' },
  { value: 'detail', label: '查看详情' }, { value: 'action', label: '操作表单' },
  { value: 'loading', label: '加载中' }, { value: 'error', label: '加载失败' },
] as const

const sensorPage=pages.find(page=>page.id==='sensors')!
sensorPage.title='探针管理'
sensorPage.description='统一查看探针连接、健康、资源与流量，管理接入配置和运行记录。'
sensorPage.requirement=['SB-OPS-001','SB-OPS-002']
sensorPage.objectLabel='探针'
sensorPage.rowAction='编辑'
sensorPage.emptyTitle='暂无探针'
sensorPage.emptyDescription='当前租户和网络域内没有探针。注册并连接探针后，可查看运行指标与采集质量。'
sensorPage.columns=[{key:'name',title:'探针',width:180},{key:'status',title:'连接',width:70,kind:'status'},{key:'health',title:'健康',width:110,kind:'status'},{key:'resources',title:'资源（CPU / 内存 / 磁盘）',width:178},{key:'bps',title:'镜像流量',width:105},{key:'drop',title:'丢包率',width:74},{key:'lastSeen',title:'最近心跳',width:145},{key:'version',title:'引擎版本',width:180}]

const auditPage=pages.find(page=>page.id==='audit')!
auditPage.title='操作日志'
auditPage.description='追溯操作、查询、导出和授权变更，核对主体、对象、范围与结果。'
auditPage.objectLabel='操作日志'
const pcapPage=pages.find(page=>page.id==='pcap-tasks')!
pcapPage.title='PCAP 取证'
pcapPage.description='从会话创建取证任务，统一核对完整性、导出结果与下载授权。'
pcapPage.requirement=['SB-SRH-007','SB-NET-004']
pcapPage.objectLabel='取证任务'
pcapPage.detailTabs=['任务信息','会话完整性','导出结果']
pcapPage.rowAction='编辑'
pcapPage.columns=[{key:'name',title:'取证任务',width:190},{key:'session',title:'会话',width:180},{key:'mode',title:'导出模式',width:110},{key:'format',title:'格式',width:90},{key:'status',title:'任务状态',width:115,kind:'status'},{key:'expires',title:'下载到期',width:170}]

auditPage.emptyTitle='暂无操作日志'
auditPage.emptyDescription='当前时间、主体和授权范围内没有操作记录。请调整检索条件；审计记录只能查询和导出。'
pcapPage.emptyTitle='暂无取证任务'
pcapPage.emptyDescription='选择授权会话创建取证任务后，可在同一列表跟踪完整性验证、导出与下载授权。'

export const pageById = new Map(pages.map(p => [p.id,p]))
