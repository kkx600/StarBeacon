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
| ReplayWorkspace / ReplayResult | 两端样本导入、规则选择、平台探针选择、真实离线结果及失败／截断边界。 |
| TaskWorkspace / TaskTable | 平台签名任务、独立本地任务、执行回执及有限刷新；不把未知结果显示为成功。 |
| HealthSummary / InterfaceTable / CaptureForm | 展示实测指标、网卡能力和采集目标；配置状态明确为待应用。 |

## 界面边界

页面使用中文业务名称，加载、错误、无数据各自呈现真实请求状态；数据缺测使用“未获取”。探针在线状态以平台接收时间判定，离线后保留最后观测时间。CPU、内存、磁盘和网络计数标注宿主机口径，接口字节数不作为镜像捕获吞吐。

原始 EVE 属于事件 JSON，不标为原生通信报文，不构造 PCAP、握手、攻击成功或封禁成功。尚未连接的正式规则发布、升级、模型、持续 PCAP 捕获和设备阻断不提供可提交的假操作入口。

PCAP 重放不向真实网络发包，本地输入规则与平台规则包修订分开标识；检测结果首屏呈现结论和包数／命中数／耗时。读取失败保留错误和重试，展示旧任务状态时明确提示尚未更新。具体部署及样本边界见[PCAP 重放与规则验证](../docs/PCAP重放与规则验证.md)。

## 启动

使用 Node 24.19.0、pnpm 12.6.0。工程内执行 `pnpm install --frozen-lockfile`；平台 `pnpm --filter @starbeacon/platform dev`（5174），采集器 `pnpm --filter @starbeacon/collector dev`（5175）。两端 `/api` 由各自 Vite 服务代理到 28080／28081；生产同源反向代理保持相同契约。构建命令为 `pnpm build`。
