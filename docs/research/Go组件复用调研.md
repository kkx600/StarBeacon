# 星烽 StarBeacon Go 组件复用调研

核验日期：2026-09-30。目标是让业务代码集中处理租户、证据、研判和处置规则，基础协议、认证、解析、任务执行和更新验证优先复用官方或活跃社区实现。本文记录选定组件、必要的业务边界和待验收项，不代表这些库已经被引入工程或完成平台构建。

## 1. 选型与维护原则

1. 优先标准库，其次协议或产品官方 SDK，再选择有明确维护主体、正式 tag、版本迁移说明和许可证的社区库。
2. 核验 `go.mod` 的 `go`、实际传递依赖和维护仓库；不只看 GitHub 星数或 README 的一句支持声明。Go 目标为 1.26.x；本机默认 1.25.6 不达标，隔离 1.26.8 已验证代表性组合的模块图与校验和，编译尝试超时，验证范围见[实测记录](依赖版本核验.md#九go-工具链与统一依赖图复核)。
3. 基础库只解决其明确职责。AST parser 不提供 Wireshark 协议语义，OIDC 客户端不提供完整平台权限，任务队列不保证外部防火墙副作用只执行一次。
4. 复用采用小接口隔离；不要在所有业务包中散布厂商 SDK。不同用途使用不同可执行文件／构建依赖集合，探针不携带平台登录或报告浏览器的全部依赖。
5. 不为避免少量业务代码引入新的常驻数据库或服务。Go 模块、现有 PG、现有 NATS 与受限离线工具足够完成首期职责。

## 2. 最小复用矩阵

所有版本均为正式 tag 或已核实的固定模块版本。“最低 Go”是直接模块声明，不是完整图构建结果。来源链接指向固定源码／发布，维护状态在核验日读取官方仓库元数据。

| 职责 | 组件与锁点 | 最低 Go／许可 | 决定与边界 |
| --- | --- | --- | --- |
| IP、网段、MAC、HEX、基础协议 | Go 标准库：`net/netip`、`net.ParseMAC`、`encoding/hex`、`encoding/binary`、`time`、`net/http`、`crypto/tls` | 与选定 Go 补丁一致 | 不手写 CIDR、MAC 或 HEX 编码；时间精度来源另存，`time.Time` 不会创造原包不存在的纳秒精度 |
| OIDC RP | [coreos/go-oidc v3.21.0](https://github.com/coreos/go-oidc/blob/v3.21.0/go.mod) | 1.25.0／Apache-2.0 | OIDC Provider discovery、JWKS、ID Token 验签；平台自己持有 nonce/state/PKCE、会话和组织映射 |
| OAuth 授权码 | [x/oauth2 v0.36.0](https://github.com/golang/oauth2/blob/v0.36.0/go.mod) | 1.25.0／BSD-3-Clause | 复用官方流程库；OAuth access token 与 ID Token 不能互换 |
| JOSE 传递依赖 | [go-jose v4.1.5](https://github.com/go-jose/go-jose/blob/v4.1.5/go.mod) | 1.24.0／Apache-2.0 | OIDC 3.21.0 原要求 4.1.4，代表性 P1 图实际选择维护补丁 4.1.5，真实工程仍需构建验证；不另写 JWT 验签 |
| Passkey / WebAuthn | [go-webauthn v0.18.2](https://github.com/go-webauthn/webauthn/blob/v0.18.2/go.mod) | 1.26.0／BSD-3-Clause | 当前活跃维护；RP ID、Origin、challenge、用户验证和凭据记录由服务端配置 |
| TOTP | [pquerna/otp v1.5.0](https://github.com/pquerna/otp/releases/tag/v1.5.0) | 1.12／Apache-2.0 | 稳定小组件，发布频率较低；复用算法，不自行实现 HMAC 动态截断；独立复核维护与安全公告 |
| 查询 AST | [participle/v2 v2.1.4](https://github.com/alecthomas/participle/blob/v2.1.4/go.mod) | 1.18／MIT | 词法／语法与错误定位；字段类型、数组量词、授权及 ES 编译仍是产品契约 |
| 数据包结构 | [gopacket v1.7.2](https://github.com/gopacket/gopacket/blob/v1.7.2/go.mod) | 1.25.0／BSD-3-Clause | 使用持续维护的 `gopacket/gopacket`；复用 L2/L3/L4、PCAP/PCAPNG，完整协议树复用 TShark |
| 网络流协议接入 | [GoFlow2 v2.2.7](https://github.com/netsampler/goflow2/blob/v2.2.7/go.mod) | 1.23.0／BSD-3-Clause | 条件启用 `github.com/netsampler/goflow2/v2` 解码/模板组件；独立验证来源身份、采样与模板状态，不默认引入 Kafka 输出 |
| 主机健康 | [gopsutil/v4 v4.26.8](https://github.com/shirou/gopsutil/blob/v4.26.8/go.mod) | 1.24.0／BSD-3-Clause | CPU、内存、磁盘、进程、接口；容器与宿主机口径要分别注明 |
| Syslog | [leodido/go-syslog/v4 v4.6.0](https://github.com/leodido/go-syslog/blob/v4.6.0/README.md) | 1.22／MIT | 原 influxdata/go-syslog 的官方延续；5424 builder／parser、3164 parser、流帧解析 |
| 指标 | [client_golang v1.24.1](https://github.com/prometheus/client_golang/blob/v1.24.1/go.mod) | 1.25.0／Apache-2.0 | 官方客户端；独立 registry、有界 label，不在所有指标上挂完整 URL、event_id、IP |
| 追踪 | [OTel v1.46.0](https://github.com/open-telemetry/opentelemetry-go/releases/tag/v1.46.0) | 1.25.0／Apache-2.0 | 复用 trace context、采样、exporter；不承担告警可靠投递 |
| PG 通用任务 | [River v0.47.0](https://github.com/riverqueue/river/blob/v0.47.0/go.mod) | 1.26.0／MPL-2.0 | 官方维护活跃，复用 pgx v5；运行库及 riverpgxv5 driver 同版；不依赖 Pro |
| Cron 解析 | [robfig/cron/v3 v3.0.1](https://github.com/robfig/cron/blob/v3.0.1/go.mod) | 1.12／MIT | River 已依赖，作为成熟表达式库；不是持久化调度器，不再叠加另一套 gocron |
| JSON Schema | [google/jsonschema-go v0.4.3](https://github.com/google/jsonschema-go/blob/v0.4.3/go.mod) | 1.23.0／MIT | 官方 Go MCP SDK 已复用；业务仅使用经过验证的 schema 特性，避免第二套验证器造成接受范围不一致 |
| YAML | [go.yaml.in/yaml/v3 v3.0.5](https://github.com/yaml/go-yaml/blob/v3.0.5/README.md) | 1.16／Apache-2.0 | YAML 官方组织接管维护；新的直接引用不用已归档的 `go-yaml/yaml` 旧路径 |
| 边缘状态与 journal | [bbolt v1.5.0](https://github.com/etcd-io/bbolt/blob/v1.5.0/go.mod) | 1.25.0／MIT | 检查点／注册／本地撤销状态优先复用嵌入式事务存储；无需单独服务 |
| 更新信任元数据 | [go-tuf/v2 v2.4.2](https://github.com/theupdateframework/go-tuf/blob/v2.4.2/go.mod) | 1.25.0／Apache-2.0 | 复用 TUF 信任与更新验证，不重复实现根轮换、阈值和防回退协议 |

`go-jose 4.1.5` 在上述认证组合中作为受控补丁约束登记；它在代表性 P1 图中经 MVS 仍为该版本，实际应用继续以工程锁文件为准。当前阶段不把所有表行都声明成默认直接依赖：Passkey/TOTP 按认证方式启用，TUF 由更新模块持有，后台任务库不进入探针抓包进程。

## 3. 认证与授权实现边界

- OIDC 仅信任配置的 issuer，校验 audience、过期和签名；网络 discovery/JWKS 请求有出站策略与缓存。未知 `kid` 可以受限刷新，不能允许攻击者触发无限外部请求。回调 URL 精确匹配，state/nonce 单次消费，PKCE 用于授权码流程。
- OIDC ID Token 用于登录，不直接当作 MCP 资源 access token。MCP 对资源 audience、scope、issuer 和授权主体单独验证；未声明为 JWT 的 access token 按相应可信内省契约处理。不得仅因某段字符串可解码成 JSON 就接受。
- WebAuthn session/challenge 单次、短时、绑定用户及请求；服务器固定 RP ID/Origins，不能采纳浏览器传来的任意值。凭据 sign counter 的异常作为风险信号处理，兼容多设备同步 passkey 的计数语义。凭据删除、恢复和管理员重置需强认证与审计。
- TOTP secret 信封加密，已用 time step 在有效窗口中防重放；校验窗口可配置且有界。恢复码只存 hash、单次消费，与 MFA 关闭／重绑事件审计关联。仅调用 OTP 库不等于这些账户恢复边界已经解决。
- 授权继续以平台 RBAC、组织、资产范围和 PG RLS 为准；不因引入 OIDC 或另一套 ACL 库就产生第二个相互矛盾的权威权限来源。

WebAuthn 版本曾调整跨 Origin 默认行为，不能拷贝旧配置关闭验证。核对其固定版迁移说明并用指定 1.26.x 工具链编译，库内 `toolchain go1.27.1` 不应触发全局升级。[迁移说明](https://github.com/go-webauthn/webauthn/blob/v0.18.2/MIGRATION.md)、[Go 工具链规则](https://go.dev/doc/toolchain)

## 4. 持久任务执行复用

P1 的报告生成、规则回放、PCAP 深度分析、批量导出等使用 River 开源核心。任务入队必须与对应业务状态通过同一个 pgx 事务完成，业务回滚时不留下可执行作业；跨服务 HTTP 请求完成后再单独入队不能获得这一保证。NATS 仍负责大流量告警、网络上下文与计量消息，不能为了统一任务库将每条网络事件插入 PG。[事务入队](https://riverqueue.com/docs/transactional-enqueueing)

River `unique jobs` 只约束特定状态／周期／参数组合下的作业重复，不等于外部调用 exactly-once。StarBeacon 自己维护报告周期唯一键、投递唯一键、设备动作 ID 与状态；任务重领后先查业务幂等记录，再决定继续、核对未知结果或终止。[任务唯一性](https://riverqueue.com/docs/unique-jobs)

River 开源周期任务的调度状态在内存，选主和重启边界可能漏过一个周期；持久周期是 Pro 功能。平台必须在 PG 保存 `report_schedules`、`next_due_at`、时区与 `schedule_slots`，扫描到期范围并以周期唯一键原子入队，记录补偿游标。River 的定时触发只作为唤醒机制，不能取代持久业务日历。日／周／月周期按租户时区生成，处理 DST、月末及停机后的有界补偿，报告引用明确的起止窗口。[周期调度](https://riverqueue.com/docs/periodic-jobs)

开源基线不依赖 Pro 的 workflows、sequences、全局分区并发、持久周期、专用 dead-letter queue 或 encrypted jobs。失败业务记录与人工重试入口由平台状态提供；job 参数只放引用与必要元数据，秘密不进入普通 job JSON。每类作业池有并发与内存上限，跨租户配额及公平性在入队／领取前的业务调度层执行，设备动作租约仍由响应控制面约束。[功能划分](https://riverqueue.com/pro)

River 表放内部任务 schema，普通租户 API 不直接查询或写入；job args 中 `tenant_id` 必须从已认证业务上下文产生，Worker 读取目标后重新建立对应受限事务，不能从任意 job JSON 获得跨租户权限。平台不向租户暴露全局 River UI。River migrations 与业务 migrations 分开版本化并按兼容顺序执行；MPL 相关文件和修改的源码义务随发行清单登记。[River LICENSE](https://github.com/riverqueue/river/blob/v0.47.0/LICENSE)

## 5. 检索、日志与取证复用

Wireshark 相似检索分为有界 ES 编译子集和固定 TShark 原生离线作业。participle 只复用语法分析基础设施，类型检查和翻译必须符合平台的字段契约。原生 `matches`、切片、协议层级、多值量词或重组依赖不能因为 AST 能解析就宣称 ES 可准确执行。完整协议树、原生过滤由 TShark **4.6.9** 负责，固定 profile、关闭名称解析，以只读文件和限时管道操作；不给用户 shell 或任意 CLI 参数。[TShark 发行](https://www.wireshark.org/docs/relnotes/wireshark-4.6.9.html)、[participle](https://github.com/alecthomas/participle)

Syslog 使用 leodido 的结构化 builder / serializer 与 parser；其 builder 会忽略某些不符合语法的输入，业务必须先验证 facility/severity、时间戳、字段长度和 structured-data，再检查序列化错误，不能只调用 `Valid()` 就判发送内容完整。TLS、客户端证书、重连、队列持久化、批次水位、接收方应用确认由平台实现。RFC 3164 缺少年／时区时保留解析质量与原文，不猜测成确定时间。标准库 `log/syslog` 不作为 TLS + RFC 5424 完整方案。[固定版 builder 语义](https://github.com/leodido/go-syslog/blob/v4.6.0/README.md)

Go 的 `encoding/hex.Dump` 可用于 xxd 风格文本输出；页面 HEX 视图仍需字节偏移、原始长度、截断标志、选择范围与双向定位。UTF-8 使用 `unicode/utf8` 校验，替换字符展示不改写原字节；其他编码通过明确选择的 `x/text/encoding` 解码，并显示所用编码及失败位置。HTTP body、TCP 重组流和单帧字节有不同偏移域，不能共享一个虚构的“包偏移”。

## 6. 状态、签名和外部规则生态

bbolt 负责可靠的小型本地状态，可将源代次、检查点和本地执行 journal 纳入一致事务；不关闭同步落盘换取表面吞吐。高频顺序事件 WAL 是否直接存 KV 或采用分段文件必须由断电恢复和目标 EPS 评测决定：若使用分段文件，bbolt 中的检查点只能在段 fsync 后提交，回收段前必须确认全部引用与 ACK。bbolt 的单写者、长只读事务阻止页面回收、容量和备份要求进入运维检查。PCAP 保持独立环形文件与对象存储，不进入 KV。[bbolt 文档](https://github.com/etcd-io/bbolt/tree/v1.5.0)

短期设备命令可复用标准库 Ed25519 签名原语，但签名的规范编码、身份、期限与防重放属于平台契约。规则／插件／探针长期更新采用 TUF 元数据验证，记录 root 版本、threshold、targets 摘要、snapshot/timestamp 版本与到期时间，探针持久化已信任版本以抵御回退。离线部署可通过人工受控导入更新元数据，不能关闭过期／签名验证。TUF 不代替规则回放、灰度发布或发布审批，也不证明制品本身无恶意。[go-tuf](https://github.com/theupdateframework/go-tuf/tree/v2.4.2)

Sigma 与 STIX 没有必要为满足“Go 后端”而从头复刻成熟解析器。完整格式兼容作为可选隔离适配作业复用 [SigmaHQ pySigma 1.5.1](https://github.com/SigmaHQ/pySigma/releases/tag/v1.5.1) 与 [OASIS STIX2 Python 3.0.2](https://github.com/oasis-open/cti-python-stix2/releases/tag/v3.0.2)，Go 控制面只接收已校验的有界规范 JSON。版本锁定还要包含 Python、后端插件、wheel hash 与字段映射，当前尚未完成该可选镜像的统一锁定，不能列为已验收发行物。

Sigma 是日志检测规则生态，Suricata 是包／协议检测规则，不能无损互相转换。pySigma backend 产出的 ES 查询也必须通过平台授权字段、时间窗、索引范围和复杂度审查，不允许绕过 QueryService。STIX Pattern 包含复杂观察语义，首期只有明确支持的 IOC 类型可展开为匹配键，其他 pattern 保留原文并标 `unsupported`，不悄悄扁平化为一个域名/IP。STIX 导入内容按来源、版本、撤销、标记和有效期管理。

## 7. 交付验收

1. 本机与 CI 的 Go 1.26.x 指定补丁一致；`GOTOOLCHAIN=local`；真实主模块完成 `go mod tidy`、`go mod verify`、全图版本和漏洞检查，固定 `go.sum`。共享模块按 MVS 形成结果，禁止用 `replace` 强行降级掩盖约束。
2. 平台、探针、连接器、回放 Worker 按各自目标平台构建；Linux afpacket 不能用 macOS 编译成功替代验证；运行镜像只带需要的工具与权限。
3. 重点测试 OIDC 错 issuer/aud、未知 kid 刷新预算、MFA 重放、WebAuthn Origin、Syslog 非法结构数据、查询多值语义、任务崩溃重领、周期补偿、证据损坏、更新元数据回退／过期与根轮换。
4. 库升级先看迁移说明和最终共享依赖变化，再跑业务不变量；引入新库必须记录解决的业务需求、实际导入包、维护人、许可证和替换路径。
5. 已有官方源码与发布信息复核、隔离 Go 1.26.8 的两组代表性模块图／校验和成功记录；Linux ARM64 代表性编译均在 180 秒内未完成，不认定构建通过。GoFlow2 等条件组件未进入本次图。本机 TShark 4.4.7 的有限语义样本不能替代目标 4.6.9 验收；没有完整平台、真实设备动作或性能通过记录。正式发布必须另外提供实测记录。
