import { ref } from 'vue';

// 系统级配置集中在“系统设置”里维护；业务页面只读取当前值，不在页面上修改。
// 原型里的取值只保存在浏览器内存中。

export type AutomationLevel = '人机协同' | '条件自动' | '全自动';
export const automationLevels: { value: AutomationLevel; note: string }[] = [
  { value: '人机协同', note: 'AI 研判并给出方案，由人确认后执行' },
  { value: '条件自动', note: '影响小的动作自动执行，其余等确认' },
  { value: '全自动', note: '策略授权范围内的动作都自动执行' },
];
export const automationLevel = ref<AutomationLevel>('人机协同');
// 全局级别是上限，示例场景都不高于默认的“人机协同”。
export const automationScenes = ref([
  {
    name: 'Web 攻击与漏洞利用',
    level: '人机协同',
    actions: '封禁源 IP、旁路阻断',
    judged: 412,
    executed: 38,
    revoked: 1,
  },
  {
    name: '暴力破解与口令喷洒',
    level: '人机协同',
    actions: '封禁源 IP（单一外部地址、不超过 2 小时）',
    judged: 236,
    executed: 51,
    revoked: 0,
  },
  {
    name: 'C2 外联与恶意域名',
    level: '人机协同',
    actions: '旁路阻断、封禁目的地址、隔离主机',
    judged: 87,
    executed: 9,
    revoked: 0,
  },
  {
    name: '扫描与探测',
    level: '人机协同',
    actions: '封禁源 IP（不超过 24 小时）',
    judged: 513,
    executed: 126,
    revoked: 2,
  },
]);

export type RetentionPolicy = '智能留存' | '完整保存' | '只存告警相关';
export const retentionPolicies: { value: RetentionPolicy; note: string }[] = [
  {
    value: '智能留存',
    note: '加密流保留握手和前 16 KB，大传输每方向保留前 1 MB，告警命中的会话完整保留，重复镜像包去重',
  },
  { value: '完整保存', note: '所有数据包完整保存，不截断。1 Gbit/s 存 180 天约需 1.9 PB' },
  { value: '只存告警相关', note: '只保留告警命中会话的原包，其余只保留会话元数据' },
];
export const retentionPolicy = ref<RetentionPolicy>('智能留存');
// 智能留存的参数；只有选中“智能留存”时生效。
export const retentionParams = ref({
  encryptedKB: 16,
  bulkMB: 1,
  sealMinutes: 5,
  days: 180,
  dedupe: true,
  alwaysFull: ['核心业务资产组', '保护与观察名单中的观察对象'],
});
export const fullRetentionScopes = ['核心业务资产组', '保护与观察名单中的观察对象', '管理网络'];
export const storageTiers = [
  { name: '热：采集器本地 NVMe', span: '最近 3 天', size: '1.8 TB', percent: 62 },
  { name: '温：对象存储', span: '3–30 天', size: '16.4 TB', percent: 41 },
  { name: '冷：对象存储（二次压缩）', span: '30–180 天', size: '71 TB', percent: 58 },
];

export const bypassEnabled = ref(true);
export const bypassInterface = 'eth2';
export const gatewayPerMinute = ref(10);
export const bypassPolicies = ref([
  {
    id: 'BYPASS-P-0001',
    name: 'C2 外联即时断开',
    trigger: 'AI 结论为真实攻击，且命中 C2 情报',
    scope: '研发网络域 → 外部',
    followUp: '已部署插件 · 告警目的 · 60 秒',
    owner: '陈宁',
    expires: '2026-12-31 23:59:59',
    status: '启用',
  },
  {
    id: 'BYPASS-P-0002',
    name: '高危漏洞利用断开',
    trigger: '严重级别为严重，规则族为漏洞利用',
    scope: '外部 → 核心业务资产组',
    followUp: '未预授权',
    owner: '林悦',
    expires: '2026-10-31 23:59:59',
    status: '启用',
  },
  {
    id: 'BYPASS-P-0003',
    name: '可疑 DNS 隧道',
    trigger: '关联规则：DNS 隧道特征',
    scope: '全部内部地址 → 外部 53/UDP',
    followUp: '未预授权',
    owner: '—',
    expires: '—',
    status: '待确认',
  },
]);
