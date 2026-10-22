# MCP 服务接入

StarBeacon 使用官方 `github.com/modelcontextprotocol/go-sdk` 1.8.0 提供有界只读分析工具和元数据资源。接口与授权范围由部署配置和租户管理员登记决定，不能由调用参数扩大。[官方 SDK](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0)

## 部署与认证

公开资源为 `SB_ALLOWED_ORIGIN + /mcp`，仅支持 HTTPS 公开来源。平台后台仍监听回环地址，由 `deploy/nginx/platform.conf` 中的精确 MCP 路由代理；生产部署需在入口提供实际 TLS 证书。未配置授权方时，不注册 MCP 协议入口，管理页面明确显示服务未启用。

| 配置 | 含义 |
| --- | --- |
| `SB_ALLOWED_ORIGIN` | 无路径的 HTTPS 公开来源，例如 `https://soc.example.com` |
| `SB_MCP_ISSUER` | 受信 OAuth 授权方的精确 issuer，不通过请求指定 |
| `SB_MCP_INTROSPECTION_URL` | 授权方令牌内省 HTTPS 端点；来源必须与 issuer 一致 |
| `SB_MCP_CLIENT_ID` | StarBeacon 资源服务在授权方登记的内省客户端身份 |
| `SB_MCP_CLIENT_SECRET_FILE` | 内省客户端凭据文件；不能同时设置对应明文环境变量 |
| `SB_OUTBOUND_PRIVATE_NETWORKS` | 授权方在内网时，显式授权的目标网段 |
| `SB_OUTBOUND_CA` | 授权方使用私有 CA 时的受信根文件 |

内省凭据只用于访问受信授权方，不是其他 Agent 的访问令牌。每个请求单独内省，使用限定解析与直连目标的出站策略、有效 TLS 根、3 秒超时、64 KiB 响应上限，禁止重定向与宿主代理继承。故障时拒绝访问，不回退到未经验证的 JWT 解码。

授权方需返回 `active`、`iss`、`aud`、`sub`、`client_id`、`scope`、`exp`；`aud` 支持字符串或字符串数组，必须包含平台精确 MCP 资源。过期、未来生效、错误 issuer/audience、缺少有效期或剩余期限超过 24 小时的令牌拒绝。校验 `nbf` 和 `iat`，不放宽过期时间。令牌只接受 `Authorization: Bearer …`，不接受查询参数或浏览器会话；非空 Origin 必须匹配公开来源，拒绝跨站请求。[令牌内省标准](https://www.rfc-editor.org/rfc/rfc7662)

资源发现为 `GET /.well-known/oauth-protected-resource/mcp`，返回资源、授权方和只读 scope，不返回内省客户端凭据。该路径在 Nginx 中精确代理，不能落入通用隐藏文件拒绝或 SPA 回退。

## 服务身份

“模型配置 → MCP 服务”提供单一身份列表及登记／配置弹窗。“工具与资源”弹窗分别展示软件工具目录和元数据资源接入说明；资源说明可以复制 URI，但不代表已经使用某个服务身份完成发现或读取。每个身份登记授权方的 `sub` 和调用方 OAuth `client_id`，绑定当前租户和登记人的账号。其他应用即使使用同一 `sub` 也不会继承权限；三元身份不允许被其他租户重新认领。

权限取令牌 scope 与当前身份 scope 的交集，仅支持 `alerts:read`、`assets:read`、`sensors:read`、`traffic:read`。协议流量与告警分别授权，已有身份不会自动取得协议权限；授权方令牌与登记权限均需包含 `traffic:read` 才能调用协议工具。工具按只读角色执行，管理员登记不授予 Agent 管理员权限。有效期表单默认 180 天，可配置未来 3650 天内的到期时间；账号或租户停用、身份停用／删除／到期后拒绝后续调用。登记后的三元身份不可改绑，更新和删除按当前修订进行 CAS 校验。每个租户最多登记 100 个身份。

认证路由表只保存三元身份 SHA-256 和租户／身份路由，不保存令牌、业务数据或授权范围。授权信息表启用并强制执行租户 RLS；认证后每次工具执行、资源发现与读取都重新读取有效身份与所属账号。返回前再次核对修订、账号与令牌有效期，发生权限变更时丢弃途中取得的结果。

管理接口包括 `GET /api/v1/mcp`、`GET/POST /api/v1/mcp/bindings`、`DELETE /api/v1/mcp/bindings/{id}`，均需要管理员会话；写入还校验来源及 CSRF。身份登记、配置、删除，以及进入授权执行流程的工具和资源操作的开始／成功／失败／拒绝／输出超限写入操作日志，保留策略默认 180 天，可配置。未知 URI 或 SDK 参数校验阶段拒绝的请求不构造业务读取成功记录。

## 当前工具

| 工具 | 主要输入 | 输出与边界 | Scope |
| --- | --- | --- | --- |
| `alerts.search` | 必填 `start/end`；可选 `page/page_size`、IP、协议、方法、路径、严重度、关键字和过滤表达式 | 最多 31 天，默认 20／最多 100 条，页码最多 100；与平台告警检索共用校验，`total` 为十进制字符串 | `alerts:read` |
| `alerts.aggregate` | 必填 `start/end` | 最多 31 天的真实告警趋势／分布及登记资产、探针统计；共用窗口缓存和统计预算，不判断攻击成功 | `alerts:read` |
| `assets.get` | 必填 `id` | 当前租户登记资产详情；不存在和无权访问返回同一失败语义 | `assets:read` |
| `sensors.list` | 可选 `limit` | 默认 100／最多 200 个，超过返回上限标记 `truncated`，不返回探针注册标识 | `sensors:read` |
| `alerts.fields` | 空对象 | 告警数据集字段、别名、类型与运算符，带检索版本；不查询业务数据 | `alerts:read` |
| `alerts.filter.validate` | 必填 `filter` | 告警表达式有效性及错误行／列／原因；空字符串表示无附加条件，不执行查询 | `alerts:read` |
| `traffic.search` | 必填 `start/end`；可选 `page/page_size`、源／目的 IP、协议、HTTP 方法／路径、表达式、`event_kind`、`sensor_id`、`flow_id` | 与平台协议检索共用校验和租户索引；最多 31 天、默认 20／最多 100 条、页码最多 100；返回 TLS／DNS 可见元数据、MAC 和会话双向计数，`total` 与 64 位计数为十进制字符串 | `traffic:read` |
| `traffic.fields` | 空对象 | 协议数据集字段目录，与浏览器目录相同；不包含规则、严重级别或检测动作等告警专属字段 | `traffic:read` |
| `traffic.filter.validate` | 必填 `filter` | 按协议目录验证表达式，别名与括号内条件同样受限；无效表达式返回 `valid=false` 及位置，不执行查询 | `traffic:read` |

输入使用官方 SDK 生成并校验的受限 JSON Schema，不接受 `tenant_id`、任意 ES DSL、SQL 或命令参数。当前工具不返回原始 EVE、PCAP 或通信载荷，不调用模型、外部文件服务或设备接口。

Agent 可先调用所属数据集的 `fields`，使用返回的字段及运算符构造表达式，再调用 `filter.validate`。校验结果为 `valid=false` 时，根据 `error.line`、`error.column` 和 `error.message` 修正表达式；有效表达式仍需独立执行检索，校验通过不代表有命中或数据完整。表达式上限为 4096 字节、16 层括号、128 个条件、每个集合 64 个值；不返回编译后的 ES DSL。

协议检索默认覆盖所有支持的协议事件，可用 `event_kind` 选择会话摘要、HTTP、DNS、TLS 等记录。流标识必须是规范的 64 位无符号十进制字符串，不单独证明跨探针关联。`traffic.search` 不接受告警关键字、严重级别、探针注册标识、来源代次或租户参数；协议数据集使用告警专属表达式时拒绝查询。工具中的源 IP、目的 IP、MAC、客户端／服务端计数属于实际观测，不能直接视为资产网段入站／出站方向。EVE flow 为会话累计摘要，重复协议记录的字节不能相加冒充实时带宽。TLS SNI 与证书元数据不证明密文已解密。

`sensors.list` 保持有界探针摘要，不携带完整 `protocol_capabilities` 目录。CPU、内存、流量等原健康字段和精度保持原样；完整协议目录通过平台或采集器的专门入口核对。协议目录尚无独立 MCP 工具，不能据此扩展现有服务身份权限。

统一结果包含 `data`、`observed_at`、`request_id`、`limitations`、`truncated`。结构化结果最多 256 KiB，超限返回可读失败并要求缩小范围，不隐蔽丢弃内容。业务文本、名称和 URL 是不可信证据，不能作为执行指令；告警数量不代表利用成功、风险结论或已完成阻断。

每个身份每分钟 1–120 次授权执行，默认 60；每租户每分钟最多 300 次，平台每分钟最多 600 个协议 POST。工具调用、`resources/list`、`resources/templates/list` 和已登记资源的 `resources/read` 共用身份与租户预算，不单独获得元数据免费额度。Redis 原子计数在多实例共享；每次授权执行单独计数，批量协议请求不能绕过预算。预算存储不可用时拒绝访问。租户时间窗聚合还受原有统计服务预算约束。

## 元数据资源

资源读取使用 MCP 协议，不使用平台浏览器会话代替 Agent 令牌，也不通过 `GET /api/v1/mcp` 管理接口返回当前身份的资源清单。完成 MCP 初始化后，客户端先调用 `resources/list` 与 `resources/templates/list`，再将发现结果中的完整 URI 交给 `resources/read`。

| 资源 URI | 内容 | 所需有效权限 |
| --- | --- | --- |
| `starbeacon://catalog/alerts/fields` | 告警数据集的字段、别名、类型、运算符和检索版本，`dataset=alerts` | `alerts:read` |
| `starbeacon://catalog/context/fields` | 协议数据集的字段、别名、类型、运算符和检索版本，`dataset=context` | `traffic:read` |
| `starbeacon://catalog/capabilities` | 本次身份可发现的工具、数据集、资源、资源模板和实际限制 | 任一有效的只读权限 |

`resources/list` 只返回本次身份获授权的资源。只有资产或探针权限的身份可读取能力说明，但不会因此取得告警字段、协议字段或字段模板。字段模板为 `starbeacon://catalog/{dataset}/fields`，只在身份拥有告警或协议权限时出现在模板发现结果中；`dataset` 只接受 `alerts` 或 `context`，读取时仍需对应数据集权限。

示例请求发送到已完成初始化的 `/mcp`，使用 Agent 自身的 Bearer 令牌和协商的协议请求头：

```json
{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"starbeacon://catalog/capabilities"}}
```

资源结果在 `contents[]` 中返回完整 `uri`、`mimeType=application/json` 和 `text`。解析 `text` 后得到与工具一致的结果信封：`data`、`observed_at`、`request_id`、`limitations` 和 `truncated`。能力说明的 `data.schema_version` 为 `mcp-metadata.v1`，`scopes`、`tools`、`datasets`、`resources`、`resource_templates` 都按当前有效授权裁剪；`max_request_bytes=65536`、`max_content_bytes=262144`、`read_timeout_seconds=10`，`raw_payloads`、`pcap_downloads`、`device_actions` 均为 `false`。

URI 按登记值精确匹配，不把百分号编码或其他 URI 当作替代地址。未知资源、未登记的模板取值、`file:`、任意文件路径及网络地址不能转为文件或出站访问。资源目录不证明字段已经采集、数据已经索引、流量已经解密、攻击已经成功或生产客户端兼容性已验收。资源协议没有订阅、文件下载或设备执行能力；工具数仍为上表中的 9 个。

资源发现与读取复用工具的身份重核对、取消、超时、输出限制及审计链路。读取结束时身份修订变化、账号停用、授权撤回或令牌到期，均不释放途中取得的结果；元数据操作不会因内容不含业务记录而绕过授权。

## 协议与验收边界

传输为无持久会话的 HTTP POST，使用 JSON 响应，请求体上限 64 KiB、查询上限 10 秒；GET／DELETE 协议长连接返回 405。工具声明只读、无设备副作用，发现结果使用私有缓存 scope 与零有效期。[传输规范](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

本地测试覆盖官方 SDK 客户端发现与实际调用、越权输入、令牌声明、Origin、撤销、审计故障和输出预算；远程集成测试使用独立 PG／ES／Redis 与受控 TLS 授权方。该授权方验证协议与业务授权，不代表真实企业身份系统、客户 Agent 或生产 TLS 已接通。完整验收以对应源码快照的原始报告为准。

当前资源仅覆盖上述软件能力与检索字段元数据。事件／情报／规则／报告资源和扩展工具、原始证据或 PCAP 下载、带费用的分析任务及响应提议尚未发布。未来能力需要复用现有任务身份、幂等、费用配额和结果查询，不能因 MCP 接入绕过审批、输出范围或下游设备执行权限。
