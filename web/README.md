# 星烽 StarBeacon 前端工程

`platform` 为主控平台，`collector` 为采集器本地管理，两者是独立构建、独立登录和独立 API 命名空间。`packages/shared` 复用经确认的白灰背景、蓝色动作、4/8/12/16 px 间距和 Ant Design Vue 组件。交互原型继续位于仓库根目录 `prototype`，正式工程不加载合成数据或原型状态开关。

## 组件职责

| 组件／模块 | 单一职责与数据契约 |
| --- | --- |
| App / 路由视图 | 配置主题、布局及业务组件，不持有表单、表格或请求实现。 |
| AppShell | 接收菜单、用户名和当前路由，发出导航及退出事件；窄屏折叠导航。 |
| LoginForm | 接收提交状态和错误，校验并发出账号密码提交事件；不持有凭据存储。 |
| useSession / ApiClient | 管理 HttpOnly 会话查询与内存 CSRF Token，统一错误和取消信号。 |
| SensorsWorkspace / useSensors | 获取当前租户探针及健康快照，编排表格、详情和启用状态操作。 |
| SensorTable / SensorDetail | 接收真实探针数据，分别发出查看／状态操作事件和展示观测详情。 |
| AlertsWorkspace / useAlerts | 管理有界服务端检索、分页和请求取消；不使用本地全量筛选。 |
| AlertFilters / AlertTable / AlertDetail | 分别接收条件并发出查询、展示分页记录、展示当前记录及原始 EVE。 |
| CollectorWorkspace / useCollector | 获取本机健康、网卡和目标配置，编排配置保存，不调用操作系统网络变更。 |
| RulesWorkspace | 不可变规则包修订、选定探针原生装载检查；不提供正式发布假入口。 |
| RuleEditor / inspectRules | 共用 CodeMirror 6 编辑器，提供行号、高亮、撤销、换行和基础结构错误定位；关键词、变量与引擎兼容由原生 Suricata 检查。 |
| ReplayWorkspace / ReplayResult | 两端样本导入、规则选择、平台探针选择、真实离线结果及失败／截断边界。 |
| TaskWorkspace / TaskTable | 平台签名任务、独立本地任务、执行回执及有限刷新；不把未知结果显示为成功。 |
| HealthSummary / InterfaceTable / CaptureForm | 展示实测指标、网卡能力和采集目标；配置状态明确为待应用。 |

## 界面边界

平台 `/sensors` 通过「探针列表」与「任务记录」页签组织设备和任务，`view=devices`／`tasks`；`/rules` 通过「规则包」「重放样本」「重放任务」页签分别展示数据，`view=packages`／`samples`／`tasks`。采集器 `/network` 分为「网卡与状态」「采集配置」「重放样本」「任务记录」，`view=interfaces`／`capture`／`samples`／`tasks`。每个视图只展示所属业务数据集，详情描述表不作为另一份业务列表。

页面使用中文业务名称，加载、错误、无数据各自呈现真实请求状态；数据缺测使用“未获取”。探针在线状态以平台接收时间判定，离线后保留最后观测时间。CPU、内存、磁盘和网络计数标注宿主机口径，接口字节数不作为镜像捕获吞吐。

原始 EVE 属于事件 JSON，不标为原生通信报文，不构造 PCAP、握手、攻击成功或封禁成功。尚未连接的正式规则发布、升级、模型、持续 PCAP 捕获和设备阻断不提供可提交的假操作入口。

PCAP 重放不向真实网络发包，本地输入规则与平台规则包修订分开标识；检测结果首屏呈现结论和包数／命中数／耗时。读取失败保留错误和重试，展示旧任务状态时明确提示尚未更新。具体部署及样本边界见[PCAP 重放与规则验证](../docs/PCAP重放与规则验证.md)。

规则编辑器仅对受控 `alert` 规则做本地基础诊断：规则头、引号／转义、括号结构、末尾分号、SID 范围与重复、rev 和 900 KiB 文本上限。错误项可点击定位；基础检查通过不表示完整 Suricata 语法、语义或目标引擎兼容已经验证。正式 `rules.apply` 创建入口仍返回 409。

容量按 SI 的 B／KB／MB／GB／TB 等单位展示，速率按千进制 bit/s 系列展示；显式二进制值保留 KiB 等单位。累计整数字符串与 bigint 保留 64 位精度，缺测与零分开，带不同单位的数量按原始精度排序。

## 路由与部署

两端使用 `createWebHistory(import.meta.env.BASE_URL)`，保留 `#/` 旧地址迁移、同源安全回跳及登录前完整路径，未知路径进入 404。工作区页签由查询参数确定，支持刷新与浏览器历史恢复。

Go API 不提供前端静态页。Vite 开发服务分别把 `/api` 代理到 28080／28081，生产需同源静态入口。[平台 Nginx 示例](../deploy/nginx/platform.conf)与[采集器 Nginx 示例](../deploy/nginx/collector.conf)将 `/api/` 代理、`/assets/` 404 和 SPA `index.html` 回退分开，配置 100 MiB 上传和 360 秒代理期限。两个示例均为 `listen 80`、`server_name _`，应在各自部署位置配置实际主机名／监听入口及 HTTPS；不能原样作为同一监听入口的两份默认站点。Go 的 `SB_ALLOWED_ORIGIN` 须设为该端实际外部来源（无路径，生产为 HTTPS），代理保留浏览器原始 Origin。示例配置不代表生产 TLS 或代理部署已经验收。

## 启动

使用 Node 24.19.0、pnpm 12.6.0。在仓库根目录执行：

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web --filter @starbeacon/platform dev
pnpm --dir web --filter @starbeacon/collector dev
```

两条 dev 命令分别运行于不同终端，平台端口为 5174，采集器端口为 5175；Go 与开发依赖启动见[工程实现与开发](../docs/工程实现与开发.md)。检查与构建使用 `pnpm --dir web test`、`pnpm --dir web build`。

共享包直接锁定 CodeMirror view 6.43.13、state 6.7.6、language 6.12.4、lint 6.9.7、commands 6.11.1 及 Lezer highlight 1.2.5。`prototype/` 直接引用共享源，启动／构建原型前也必须先安装 `web` 依赖；这项源码复用不要求工程应用进程同时运行。
