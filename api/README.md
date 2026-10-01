# 星烽 StarBeacon 接口契约

当前 HTTP 接口使用 OpenAPI 3.1：

- [平台 API](openapi/platform.json)：身份、探针启停与心跳视图、告警检索、依赖健康、操作日志。
- [采集器 API](openapi/collector.json)：独立本地身份、宿主机健康、实际网卡、采集目标保存。

两端使用各自的 HttpOnly Cookie。写请求及 `POST /alerts/search` 需要 `X-CSRF-Token`；登录由同源校验和限流保护。客户端只传业务筛选，不指定租户、ES 索引或任意 DSL。字符串长度限制在服务端按 UTF-8 字节校验。原始 EVE 仅向平台管理员返回；通信证据权限尚未细分。

`/healthz`、`/readyz`、`/metrics` 是运维接口，HTTP 只监听回环。外部同源入口仅放行该端对应的 `/api/` 路由，监控接口另由受控管理入口访问。就绪检查代表当前依赖可用，不证明 Suricata 捕获质量、队列无积压或生产容量合格。

[采集器 Protobuf](proto/starbeacon/sensor/v1/sensor.proto) 定义三种 RPC：`UploadEvents` 与 `GetRoute` 由接入进程提供，`Control` 由主平台提供。当前控制协议只接收健康心跳并确认，不包含规则发布、升级、封禁等执行指令。mTLS 证书唯一绑定租户、探针和注册代次；数据批次的消息身份必须与证书一致。

固定生成器为 protoc 36.2、protoc-gen-go 1.36.12、protoc-gen-go-grpc 1.6.2。生成源位于 `api/sensor/v1/`，通过 `make generate PROTOC=/绝对路径/protoc GO=/绝对路径/go` 更新；不要手工编辑。事件稳定 ID、规范批次摘要和精确 ACK 的语义由 `internal/contract/` 统一执行和测试。

规划中的完整契约见[接口与数据契约](../docs/接口与数据契约.md)。规划文档中的接口不能视为当前实现承诺；增加接口时需要同时实现授权、持久状态、错误路径和契约。
