# 星烽 StarBeacon 接口契约

当前 HTTP 接口使用 OpenAPI 3.1：

- [平台 API](openapi/platform.json)：身份、探针启停与心跳视图、告警检索、依赖／宿主健康、规则包、签名任务、重放样本、操作／登录审计游标。
- [采集器 API](openapi/collector.json)：独立本地身份、宿主机健康、实际网卡、采集目标保存、独立本地重放及任务回执。

两端使用各自的 HttpOnly Cookie。写请求及 `POST /alerts/search` 需要 `X-CSRF-Token`；登录由同源校验和限流保护。客户端只传业务筛选，不指定租户、ES 索引或任意 DSL。字符串长度限制在服务端按 UTF-8 字节校验。原始 EVE 仅向平台管理员返回；通信证据权限尚未细分。

`/healthz`、`/readyz`、`/metrics` 是运维接口，HTTP 只监听回环。外部同源入口仅放行该端对应的 `/api/` 路由，监控接口另由受控管理入口访问。就绪检查代表当前依赖可用，不证明 Suricata 捕获质量、队列无积压或生产容量合格。

[采集器 Protobuf](proto/starbeacon/sensor/v1/sensor.proto) 定义四种 RPC：`UploadEvents` 与 `GetRoute` 由接入进程提供，`Control` 与 `DownloadReplaySample` 由主平台提供。mTLS 证书唯一绑定租户、探针和注册代次；每个控制帧及样本流核验注册启用状态，不接受消息自报租户。

控制连接使用受限 `sensor.command.v1` JSON：租户、探针、注册代次、任务身份、种类、投递期限和固定业务载荷；不传 shell 命令。Ed25519 签名覆盖 `StarBeacon/sensor.command.v1\x00` 加原始 JSON，`payload_sha256` 是原始载荷的 32 字节 SHA-256。设备核对预置信任公钥和身份后同步保存接受状态，回执采用 `sensor.receipt.v1`，最多 64 KiB；平台 ACK 精确确认原始回执字节摘要。断线重传不重复执行，终态回执不可改写。签名密钥与 mTLS 私钥独立；设备不持有平台命令私钥。

任务已实现 `diagnostics`、`rules.validate` 和 `rules.replay`。`rules.apply` 尚无完整发布资格、灰度和原生回滚验收，HTTP 创建入口返回 409 `release_validation_required`。重复创建使用 `Idempotency-Key`；同键不同参数返回冲突。仅尚未投递的任务可取消。平台任务与本地 `localtask_` 任务分属不同信任来源，本地执行结果不进入平台待确认队列。

PCAP 上传接口在认证／CSRF 后接收 `application/octet-stream`、`Content-Length` 与 URL 编码的 `X-Filename`，24 字节至 100 MiB。下载 RPC 只能用于本设备有效且已投递／执行中的重放任务，每块最多 128 KiB，连续偏移，客户端核验签名中的最终长度和摘要；终态任务不能继续下载。没有通用对象存储凭据下发，也没有允许用户选择任意服务端文件路径的参数。完整限额与部署见[PCAP 重放与规则验证](../docs/PCAP重放与规则验证.md)。

审计默认最近 7 天，单次最多 31 天／100 行，使用时间与字符串 ID 的稳定游标；登录记录对应密码验证结果，不代表会话一定创建成功。平台健康返回 `host` 与 `services`，缺失资源不是推定为零。

生成器版本由 Makefile 固定。修改 `.proto` 后运行 `make generate GO=/绝对路径/go PROTOC=/绝对路径/protoc`；HTTP 变更同时维护本目录 OpenAPI。
