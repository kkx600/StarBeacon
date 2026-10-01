# 星烽 StarBeacon 态势感知系统

StarBeacon — stellar early-warning for security posture.

星烽 StarBeacon 面向单组织、集团与多租户安全运营，将网络检测、告警调查、流量证据和受控响应连接起来。本仓库提供产品设计、Vue 交互原型及可运行的 Go 与 Vue 工程。

## 当前工程

已实现身份会话、租户隔离、探针登记与心跳、持久事件上报、基础告警筛选、签名任务、规则装载检查和 PCAP 离线重放。真实事件链路为：

```text
Suricata EVE → bbolt WAL → mTLS gRPC → NATS JetStream → Elasticsearch → 平台检索
```

主控平台可管理探针、规则包、重放样本和任务；采集器可查看本机资源与网卡、保存待应用的采集目标，并独立导入样本执行重放。规则使用共享 CodeMirror 编辑器提供语法高亮和基础结构诊断，引擎兼容性由选定探针的原生 Suricata `-T` 检查确定。

离线重放使用 `suricata -r`，支持 PCAP／PCAPNG、本地执行及平台选择探针执行，结果保留包数、命中、摘要、日志和限制。本机已验证真实 Suricata 8.0.7 的命中、未命中及非法规则拒绝；重放不向网卡发包，也不发布线上告警或执行阻断。

完整高级检索、持续 PCAP 捕获与压缩、完整握手导出、AI／LLM、MCP、通知、设备阻断、操作系统配置应用和正式规则灰度发布属于后续工程范围。原型中的页面与交互不代表这些能力已经上线。Linux 原生隔离、S3 高可用、生产 TLS、容量和故障演练仍须单独验收，具体边界见[工程实现与开发](docs/工程实现与开发.md)和[PCAP 重放与规则验证](docs/PCAP重放与规则验证.md)。

## 开发启动

需要 Go **1.26.8**、Node.js **24.19.0**、pnpm **12.6.0**、Python 3、Docker 与 Compose plugin。Go 构建与检查由 Makefile 设置 `GOTOOLCHAIN=local`，并核对精确补丁版本；PATH 中的 `go` 必须为 1.26.8，或在相关命令后加 `GO=/绝对路径/go`。仅依赖 `go.mod` 的自动工具链选择不能满足 Makefile 检查。

在仓库根目录执行：

```sh
make dev-setup
pnpm --dir web install --frozen-lockfile
```

`dev-setup` 编译五个 Go 入口、启动 PostgreSQL／Redis／NATS／Elasticsearch 开发依赖、迁移和初始化身份，并生成开发证书与命令签名密钥。Compose 只包含上述依赖；Go 进程和前端分别启动。随机凭据保存在 Git 忽略的 `.local/`，重跑初始化保留已有身份。

分别在六个终端运行：

```sh
make platform
make ingest
make worker
make collector
make web
make collector-web
```

平台页面为 `http://127.0.0.1:5174/`，采集器页面为 `http://127.0.0.1:5175/`；两端使用独立登录。以上启动命令使用已经编译的二进制，不需要再次指定 Go 路径。`make sample` 追加带明确标记的工程验收 EVE，用于验证传递与索引，不代表真实抓包或攻击检测。

两端使用 History 路由。Go API 不提供静态页面；生产静态文件与 `/api/` 应经同源入口发布。[Nginx 平台示例](deploy/nginx/platform.conf)与[采集器示例](deploy/nginx/collector.conf)包含 SPA 回退及 API 代理，两份模板默认均为 `listen 80`、`server_name _`，须配置不同的主机名／监听入口及 TLS。Go 的 `SB_ALLOWED_ORIGIN` 须设为实际外部来源（不含路径，生产使用 HTTPS），代理保留请求的原始 `Origin`。完整端口、环境变量及镜像限制见[开发说明](docs/工程实现与开发.md)。

## 页面原型

原型提供 **42 个主导航工作区、116 个主控功能视图**（工作区内 115 个，个人设置 1 个）、**5 个采集器工作区**，映射 **107 项需求**。六种业务状态共 726 张，登录／访问边界 11 张，基础图 737 张；另有 43 张补充图，图库合计 **780 张**。

可直接打开[图片目录](prototype/public/screenshots/index.html)查看图库。原型全部使用合成数据，操作只改变浏览器内存，不调用模型、设备或后端。交互页面启动顺序为：

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir prototype install --frozen-lockfile
pnpm --dir prototype dev
```

打开 `http://127.0.0.1:4173/`。原型直接复用 `web/packages/shared` 的规则编辑器及工具源，因此需要先安装 `web` 依赖；原型运行本身无需启动 Go 服务或两个工程前端。详情见[原型说明](prototype/README.md)。

## 仓库目录

| 目录 | 内容 |
| --- | --- |
| `cmd/`、`internal/` | 五个 Go 入口及平台、采集、接入、索引和公共模块 |
| `api/`、`migrations/` | 当前 OpenAPI／Protobuf 契约与 SQL 迁移 |
| `web/` | 主控平台、采集器管理及共享组件 workspace |
| `prototype/` | 合成数据交互原型、页面清单和图库 |
| `deploy/`、`scripts/` | 开发依赖、Go 镜像、同源代理示例和开发脚本 |
| `tests/integration/` | 真实依赖与 mTLS 集成测试 |
| `docs/` | 产品目标、领域设计、工程记录及调研依据 |

## 构建与检查

```sh
make build test vet
make integration
pnpm --dir web test
pnpm --dir web build
pnpm --dir prototype check:coverage
pnpm --dir prototype check:workspaces
pnpm --dir prototype check:collector
pnpm --dir prototype check:theme
pnpm --dir prototype build
node prototype/scripts/check-screenshots.mjs
```

Go 命令沿用前述精确工具链要求；集成测试需先完成 `dev-setup` 并保持开发依赖运行。截图检查核对文件、来源和校验值；原型覆盖及静态对比度检查不代替完整无障碍、逐图人工视觉或生产验收。

## 文档导航

| 文档 | 用途 |
| --- | --- |
| [工程实现与开发](docs/工程实现与开发.md) | 实际能力、启动、数据链路、验证与后续工程范围 |
| [前端工程](web/README.md)、[服务模块](internal/README.md)、[当前接口](api/README.md) | 组件职责、模块边界与实际 API |
| [产品设计](docs/产品设计.md)、[功能覆盖与验收矩阵](docs/功能覆盖与验收矩阵.md) | 完整产品目标、107 项需求与验收责任 |
| [架构设计](docs/架构设计.md)、[依赖版本与部署清单](docs/依赖版本与部署清单.md) | 目标架构、固定选型及条件组件；MinIO AIStor、TShark、River 等须按启用范围另行落实 |
| [页面原型设计](docs/页面原型设计.md)、[界面设计规范](DESIGN.md) | 原型页面目录、交互与设计系统 |
| [PCAP 重放与规则验证](docs/PCAP重放与规则验证.md) | 已实现重放的入口、信任、资源、存储与部署限制 |
| [数据留存与生命周期设计](docs/数据留存与生命周期设计.md)、[实施与容量规划](docs/实施与容量规划.md) | 默认 180 天业务留存、策略与容量目标；全域清理和保全尚待实现 |

各领域详细设计与官方调研来源从上述文档继续进入。设计文档描述目标契约，当前接口以 `api/openapi/` 为准；版本核定基准为 2026-09-30，当前工程记录为 2026-10-02。
