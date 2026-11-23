<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { PlusOutlined, RobotOutlined, PlayCircleOutlined, SafetyCertificateOutlined } from '@ant-design/icons-vue';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import type { PageSpec, PreviewState } from '../models';
import PageHeader from '../components/PageHeader.vue';
import StatusTag from '../components/StatusTag.vue';
import StatePanel from '../components/StatePanel.vue';
import HelpNote from '../components/HelpNote.vue';

// 联动插件：由采集器访问内网的防火墙、EDR 等设备。简单设备填模板，复杂设备写脚本。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const message = useFeedback();

type Form = '模板' | '脚本';
interface Plugin {
  id: string;
  name: string;
  form: Form;
  device: string;
  abilities: string[];
  version: string;
  sensor: string;
  status: string;
  lastRun: string;
  source: string;
}

const templateSource = `# 模板插件：不写程序，按设备接口填写
id: fw-vendor-b
device: 防火墙 · 厂商 B v5
allow_hosts: [192.0.2.20]           # 只允许访问这些地址
auth:
  login: {method: POST, path: /api/login, body: {user: "{{secret.username}}", pass: "{{secret.password}}"}}
  token: "{{response.json.token}}"   # 过期后自动重新登录
  header: "Authorization: Bearer {{token}}"
actions:
  block:
    request: {method: POST, path: /api/blacklist, body: {ip: "{{target.ip}}", ttl: "{{duration_seconds}}", comment: "{{task_id}}"}}
    success: "{{response.status == 200 and response.json.code == 0}}"
    save: {rule_id: "{{response.json.id}}"}   # 随租约保存，解除和回读时用
  unblock:
    request: {method: DELETE, path: "/api/blacklist/{{lease.rule_id}}"}
    success: "{{response.status in [200, 404]}}"
  verify:
    request: {method: GET, path: "/api/blacklist/{{lease.rule_id}}"}
    present: "{{response.status == 200}}"
`;
const scriptSource = `# 脚本插件：语法类似 Python，只能调用平台提供的函数
def _headers(ctx):
    if state.get("token") == None:
        resp = http.post(ctx.base_url + "/login", json = {"user": secret.get("username"), "pwd": secret.get("password")})
        if resp.status != 200:
            fail("登录失败：%d" % resp.status)
        state.set("token", resp.json()["token"], ttl = 1500)
    return {"X-Auth-Token": state.get("token")}

def pull_alerts(ctx, since):
    resp = http.get(ctx.base_url + "/alerts", params = {"from": since, "limit": 200}, headers = _headers(ctx))
    levels = {"critical": "严重", "high": "高危", "medium": "中危"}
    return [{
        "id": item["uuid"],
        "time": item["occurred_at"],
        "severity": levels.get(item["level"], "低危"),
        "name": item["title"],
        "source_ip": item["src"],
        "destination_ip": item["dst"],
        "raw": item,
    } for item in resp.json()["items"]]

def block(ctx, target, duration):
    resp = http.post(ctx.base_url + "/blacklist", json = {"ip": target.ip, "expire": duration, "memo": ctx.task_id}, headers = _headers(ctx))
    if resp.status != 200:
        fail("设备拒绝：%d" % resp.status)
    return {"ok": resp.json()["code"] == 0, "rule_id": resp.json()["id"]}

def unblock(ctx, target, lease):
    resp = http.delete(ctx.base_url + "/blacklist/" + lease.rule_id, headers = _headers(ctx))
    return resp.status in [200, 404]

def verify(ctx, target, lease):
    resp = http.get(ctx.base_url + "/blacklist/" + lease.rule_id, headers = _headers(ctx))
    return resp.status == 200
`;

const plugins = ref<Plugin[]>([
  {
    id: 'PLUGIN-0001',
    name: '总部边界防火墙',
    form: '脚本',
    device: '防火墙 · 厂商 A v7.2',
    abilities: ['拉取告警', '封禁', '解封', '核验'],
    version: '1.3.0',
    sensor: '总部执行采集器',
    status: '启用',
    lastRun: '2026-09-30 09:40:02',
    source: scriptSource,
  },
  {
    id: 'PLUGIN-0002',
    name: '研发区防火墙',
    form: '模板',
    device: '防火墙 · 厂商 B v5',
    abilities: ['封禁', '解封', '核验'],
    version: '1.0.2',
    sensor: '研发执行采集器',
    status: '启用',
    lastRun: '2026-09-30 08:12:44',
    source: templateSource,
  },
  {
    id: 'PLUGIN-0003',
    name: '终端防护平台',
    form: '脚本',
    device: 'EDR · 厂商 C',
    abilities: ['拉取告警', '隔离主机', '解除隔离'],
    version: '0.9.0',
    sensor: '总部执行采集器',
    status: '验证失败',
    lastRun: '2026-09-30 07:55:10',
    source: scriptSource,
  },
  {
    id: 'PLUGIN-0004',
    name: 'WAF 黑名单',
    form: '模板',
    device: 'WAF · 厂商 D',
    abilities: ['封禁', '解封'],
    version: '0.1.0',
    sensor: '未下发',
    status: '草稿',
    lastRun: '—',
    source: templateSource,
  },
]);
const rows = computed(() => (props.state === 'empty' ? [] : plugins.value));
const columns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 116 },
  { title: '插件名称', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '形式', dataIndex: 'form', key: 'form', width: 64 },
  { title: '适配设备', dataIndex: 'device', key: 'device', width: 150, ellipsis: true },
  { title: '能力', dataIndex: 'abilities', key: 'abilities', width: 214 },
  { title: '运行采集器', dataIndex: 'sensor', key: 'sensor', width: 124, ellipsis: true },
  { title: '状态', dataIndex: 'status', key: 'status', width: 108 },
  { title: '最近执行', dataIndex: 'lastRun', key: 'lastRun', width: 158 },
  { title: '操作', key: 'actions', width: 132, fixed: 'right' as const },
];

const editing = ref<Plugin>();
const source = ref('');
const form = ref<Form>('脚本');
const tryAction = ref('block');
const tryTarget = ref('198.51.100.24');
const tryLog = ref<string[]>([]);
function open(plugin?: Plugin) {
  editing.value = plugin ?? {
    id: 'PLUGIN-草稿',
    name: '新插件',
    form: '脚本',
    device: '',
    abilities: [],
    version: '0.1.0',
    sensor: '未下发',
    status: '草稿',
    lastRun: '—',
    source: scriptSource,
  };
  source.value = editing.value.source;
  form.value = editing.value.form;
  tryLog.value = [];
}
function close() {
  editing.value = undefined;
  if (props.state === 'detail' || props.state === 'action') emit('state', 'data');
}
function tryRun() {
  tryLog.value = [
    `[沙箱] 载入${form.value}插件，动作 ${tryAction.value}，目标 ${tryTarget.value}`,
    '[沙箱] 仅允许访问登记的设备地址 https://192.0.2.20',
    '[请求] POST /auth/login → 200',
    `[请求] POST /api/v2/blocklist {"ip":"${tryTarget.value}","ttl":7200} → 200`,
    '[结果] ok(rule_id="demo-4821")，耗时 412 ms',
    '[说明] 合成输出：原型不连接任何设备。',
  ];
}
function publish() {
  message.success('已保存。原型不执行签名和下发；实际流程为“平台验签 → 下发到指定采集器 → 回执”。');
  close();
}

const aiOpen = ref(false);
const aiDoc = ref('');
const aiAbilities = ref<string[]>(['封禁', '解封', '核验']);
function generate() {
  aiOpen.value = false;
  open();
  message.success('已根据接口文档生成脚本草稿（合成示例），请在沙箱里试运行后再保存。');
}

watch(
  () => props.state,
  state => {
    if (state === 'detail') open(plugins.value[0]);
    else if (state === 'action') aiOpen.value = true;
    else {
      editing.value = undefined;
      aiOpen.value = false;
    }
  },
  { immediate: true },
);
</script>

<template>
  <PageHeader :title="page.title" :description="page.description">
    <a-space wrap>
      <a-button @click="aiOpen = true"><RobotOutlined />AI 生成插件</a-button>
      <a-button type="primary" @click="open()"><PlusOutlined />新建插件</a-button>
    </a-space>
  </PageHeader>
  <HelpNote
    message="插件运行在采集器上，只能访问登记的设备地址；凭据从密钥引用读取，不出现在插件内容里。保存后由平台验签并下发到指定采集器。"
  />
  <HelpNote message="本页为合成示例，不连接设备、不调用模型。" />

  <section class="panel table-panel">
    <div class="table-toolbar">
      <div><h2>插件</h2></div>
    </div>
    <StatePanel v-if="state === 'loading' || state === 'error'" :state="state" @action="emit('state', 'data')" />
    <StatePanel
      v-else-if="!rows.length"
      state="empty"
      title="还没有联动插件"
      description="为防火墙、EDR 等设备添加插件后，才能拉取它们的告警或执行封禁。"
      action="新建插件"
      @action="open()"
    />
    <a-table
      v-else
      :columns="columns"
      :data-source="rows"
      row-key="id"
      size="small"
      :scroll="{ x: 1170 }"
      :pagination="tablePagination()"
    >
      <template #bodyCell="{ column, record, text }">
        <span v-if="column.key === 'id'" class="mono">{{ text }}</span>
        <button v-else-if="column.key === 'name'" class="record-link" @click="open(record as Plugin)">
          {{ text }}
        </button>
        <span v-else-if="column.key === 'abilities'" class="plugin-abilities"
          ><a-tag v-for="ability in record.abilities" :key="ability">{{ ability }}</a-tag></span
        >
        <StatusTag
          v-else-if="column.key === 'status'"
          :value="text"
          :tone="text === '启用' ? 'success' : text === '验证失败' ? 'danger' : 'neutral'"
        />
        <span v-else-if="column.key === 'lastRun'" class="tabular">{{ text }}</span>
        <span v-else-if="column.key === 'actions'" class="row-actions">
          <a-button type="link" size="small" @click="open(record as Plugin)">编辑</a-button>
          <a-button
            type="link"
            size="small"
            @click="
              open(record as Plugin);
              tryRun();
            "
            >试运行</a-button
          >
          <a-button type="link" size="small" @click="message.success('本地示例：插件状态改为停用。')">停用</a-button>
        </span>
      </template>
    </a-table>
  </section>

  <a-modal :open="!!editing" :title="`${editing?.name ?? ''} · ${editing?.id ?? ''}`" :width="1120" @cancel="close">
    <div v-if="editing" class="plugin-editor">
      <div class="plugin-code">
        <div class="plugin-code-bar">
          <a-segmented
            v-model:value="form"
            :options="['模板', '脚本']"
            @change="source = form === '模板' ? templateSource : scriptSource"
          />
          <span class="muted">入口：pull_alerts、block、unblock、verify</span>
        </div>
        <textarea v-model="source" class="plugin-source" spellcheck="false" aria-label="插件内容"></textarea>
      </div>
      <div class="plugin-side">
        <a-form layout="vertical">
          <a-form-item label="插件名称"><a-input v-model:value="editing.name" /></a-form-item>
          <a-form-item label="设备地址"><a-input value="https://192.0.2.20" /></a-form-item>
          <a-form-item label="凭据引用"><a-input value="vault/device/hq-fw" /></a-form-item>
          <a-form-item label="运行采集器"
            ><a-select
              value="总部执行采集器"
              :options="['总部执行采集器', '研发执行采集器'].map(value => ({ value, label: value }))"
          /></a-form-item>
        </a-form>
        <div class="plugin-try">
          <h3>沙箱试运行</h3>
          <a-space wrap>
            <a-select
              v-model:value="tryAction"
              class="plugin-try-action"
              :options="['pull_alerts', 'block', 'unblock', 'verify'].map(value => ({ value, label: value }))"
            />
            <a-input v-model:value="tryTarget" class="plugin-try-target" aria-label="试运行目标" />
            <a-button @click="tryRun"><PlayCircleOutlined />运行</a-button>
          </a-space>
          <pre v-if="tryLog.length" class="plugin-log">{{ tryLog.join('\n') }}</pre>
          <p v-else class="muted plugin-hint">试运行在隔离环境里执行，只允许访问上面登记的设备地址。</p>
        </div>
      </div>
    </div>
    <template #footer>
      <a-button @click="close">取消</a-button>
      <a-button @click="message.success('草稿已保存在本地示例中。')">保存草稿</a-button>
      <a-button type="primary" @click="publish"><SafetyCertificateOutlined />签名并下发</a-button>
    </template>
  </a-modal>

  <a-modal
    :open="aiOpen"
    title="AI 生成插件"
    :width="720"
    ok-text="生成草稿"
    cancel-text="取消"
    @ok="generate"
    @cancel="
      aiOpen = false;
      close();
    "
  >
    <a-form layout="vertical">
      <a-form-item label="设备的接口文档" extra="粘贴厂商接口文档里与登录、黑名单、告警查询有关的部分。">
        <a-textarea
          v-model:value="aiDoc"
          :rows="8"
          placeholder="例如：POST /api/v2/blocklist 请求体 {ip, ttl}，返回 {id}…"
        />
      </a-form-item>
      <a-form-item label="需要的能力">
        <a-checkbox-group v-model:value="aiAbilities" :options="['拉取告警', '封禁', '解封', '核验', '隔离主机']" />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<style scoped>
.plugin-abilities {
  display: flex;
  flex-wrap: nowrap;
  gap: 4px;
}
.plugin-abilities :deep(.ant-tag) {
  margin: 0;
}
.plugin-editor {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) minmax(300px, 1fr);
  gap: var(--panel-inset);
}
.plugin-code {
  display: flex;
  flex-direction: column;
  gap: var(--related-gap);
  min-width: 0;
}
.plugin-code-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--related-gap);
  font-size: 12px;
}
.plugin-source {
  width: 100%;
  min-height: 460px;
  padding: 12px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--table-header);
  color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.65;
  resize: vertical;
  white-space: pre;
  overflow: auto;
}
.plugin-source:focus-visible {
  outline: 2px solid var(--primary);
  outline-offset: 2px;
}
.plugin-side {
  display: flex;
  flex-direction: column;
  gap: var(--section-gap);
  min-width: 0;
}
.plugin-try h3 {
  margin: 0 0 var(--related-gap);
  font-size: 14px;
  font-weight: 600;
}
.plugin-try-action {
  width: 130px;
}
.plugin-try-target {
  width: 150px;
}
.plugin-log {
  margin: var(--related-gap) 0 0;
  padding: 12px;
  border-radius: 6px;
  background: var(--table-header);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.plugin-hint {
  margin: var(--related-gap) 0 0;
  font-size: 12px;
}
</style>
