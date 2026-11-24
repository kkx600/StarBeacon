<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue';
import {
  ArrowDownOutlined,
  CheckOutlined,
  DeleteOutlined,
  PlayCircleOutlined,
  PlusOutlined,
  RobotOutlined,
  SaveOutlined,
} from '@ant-design/icons-vue';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import type { PageSpec, PreviewState } from '../models';
import PageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue';
import RecordForm from '../components/RecordForm.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import HelpNote from '../components/HelpNote.vue';

// 自动化编排：一条编排由若干步骤顺序组成，每种步骤有自己的配置项。
// 可以让 AI 按一句话描述生成草稿，也可以自己增删、调序和改配置。原型只在本地保存。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const message = useFeedback();

interface StepNode {
  id: string;
  type: string;
  name: string;
  note: string;
}
interface StepField {
  key: string;
  label: string;
  kind: 'select' | 'number' | 'switch' | 'multi';
  options?: string[];
  value: string | number | boolean | string[];
  suffix?: string;
}

// 每种步骤的配置项和默认值。
const stepFields: Record<string, StepField[]> = {
  触发器: [
    {
      key: 'source',
      label: '触发来源',
      kind: 'select',
      options: ['新告警', '安全事件升级', '人工发起'],
      value: '新告警',
    },
    { key: 'severity', label: '最低严重级别', kind: 'select', options: ['严重', '高危', '中危'], value: '高危' },
    {
      key: 'scope',
      label: '资产范围',
      kind: 'select',
      options: ['全部资产', '核心业务资产组', '研发网络域'],
      value: '核心业务资产组',
    },
  ],
  'AI 研判': [
    { key: 'threshold', label: '置信度门槛', kind: 'number', value: 90, suffix: '%' },
    {
      key: 'evidence',
      label: '研判依据',
      kind: 'multi',
      options: ['会话与原始包', '资产与漏洞', '威胁情报', '历史处置'],
      value: ['会话与原始包', '资产与漏洞', '威胁情报'],
    },
    {
      key: 'fallback',
      label: '低于门槛时',
      kind: 'select',
      options: ['转人工确认', '只记录不处置'],
      value: '转人工确认',
    },
  ],
  条件: [
    {
      key: 'rule',
      label: '判断条件',
      kind: 'select',
      options: ['来源与目标都不在保护名单内', '目标属于核心业务资产组', '来源是外部地址'],
      value: '来源与目标都不在保护名单内',
    },
    {
      key: 'otherwise',
      label: '不满足时',
      kind: 'select',
      options: ['结束流程并记录', '转人工确认'],
      value: '结束流程并记录',
    },
  ],
  人工确认: [
    {
      key: 'approver',
      label: '确认人',
      kind: 'select',
      options: ['当班值班组', '安全负责人', '资产负责人'],
      value: '当班值班组',
    },
    { key: 'deadline', label: '确认时限', kind: 'number', value: 15, suffix: '分钟' },
    {
      key: 'expired',
      label: '超时未确认',
      kind: 'select',
      options: ['不执行并通知', '升级给安全负责人'],
      value: '不执行并通知',
    },
  ],
  联动插件: [
    {
      key: 'plugin',
      label: '插件',
      kind: 'select',
      options: ['总部边界防火墙', '研发区防火墙', '终端防护平台', 'WAF 黑名单'],
      value: '总部边界防火墙',
    },
    {
      key: 'action',
      label: '动作',
      kind: 'select',
      options: ['封禁来源地址', '封禁目的地址', '隔离主机'],
      value: '封禁来源地址',
    },
    { key: 'hours', label: '生效时长', kind: 'number', value: 2, suffix: '小时' },
    { key: 'release', label: '到期自动解除', kind: 'switch', value: true },
  ],
  旁路阻断: [
    { key: 'method', label: '方式', kind: 'select', options: ['TCP RST 双向', 'ICMP 不可达'], value: 'TCP RST 双向' },
    {
      key: 'policy',
      label: '阻断策略',
      kind: 'select',
      options: ['C2 外联即时断开', '高危漏洞利用断开'],
      value: '高危漏洞利用断开',
    },
    { key: 'observe', label: '效果观察', kind: 'number', value: 5, suffix: '秒' },
  ],
  核验: [
    { key: 'readback', label: '回读设备配置', kind: 'switch', value: true },
    { key: 'observe', label: '观察时长', kind: 'number', value: 5, suffix: '分钟' },
    {
      key: 'still',
      label: '仍有流量时',
      kind: 'select',
      options: ['转人工处理', '重试一次后转人工'],
      value: '转人工处理',
    },
  ],
  通知: [
    {
      key: 'channel',
      label: '通知对象',
      kind: 'select',
      options: ['当班值班组', '资产负责人', '安全负责人'],
      value: '当班值班组',
    },
    { key: 'attach', label: '附带研判依据', kind: 'switch', value: true },
  ],
  补偿: [
    {
      key: 'undo',
      label: '撤销方式',
      kind: 'select',
      options: ['到期自动解除', '立即解除并回读'],
      value: '到期自动解除',
    },
    {
      key: 'unknown',
      label: '结果未知时',
      kind: 'select',
      options: ['先回读设备再决定', '转人工处理'],
      value: '先回读设备再决定',
    },
  ],
};
const stepTypes = Object.keys(stepFields).filter(type => type !== '触发器');
const sideEffect = (type: string) => type === '联动插件' || type === '旁路阻断';

const nodes = ref<StepNode[]>([
  { id: 'trigger', type: '触发器', name: '高危告警触发', note: '严重级别为高危或严重' },
  { id: 'triage', type: 'AI 研判', name: 'AI 研判', note: '置信度不低于 90% 才继续，否则转人工' },
  { id: 'protect', type: '条件', name: '核对保护名单', note: '来源与目标都不在保护名单内' },
  { id: 'approval', type: '人工确认', name: '值班员确认', note: '15 分钟内确认，超时不执行' },
  { id: 'action', type: '联动插件', name: '防火墙封禁来源', note: '总部边界防火墙，2 小时后自动解除' },
  { id: 'verify', type: '核验', name: '回读与效果观察', note: '回读设备配置，观察 5 分钟' },
  { id: 'compensate', type: '补偿', name: '到期解除', note: '结果未知时先回读设备' },
]);
const selected = ref('approval');
const status = ref('草稿');
const playbookTones = { 草稿: 'neutral', 校验通过: 'success' } as const;
const detail = ref(false);
const formOpen = ref(false);

// 每个步骤的配置值单独保存，第一次打开时取该类型的默认值。
const settings = reactive<Record<string, Record<string, StepField['value']>>>({});
function settingsOf(node: StepNode) {
  if (!settings[node.id]) {
    settings[node.id] = Object.fromEntries(
      (stepFields[node.type] ?? []).map(field => [
        field.key,
        Array.isArray(field.value) ? [...field.value] : field.value,
      ]),
    );
  }
  return settings[node.id];
}
const current = computed(() => nodes.value.find(node => node.id === selected.value));
const currentIndex = computed(() => nodes.value.findIndex(node => node.id === selected.value));
const currentFields = computed(() => (current.value ? (stepFields[current.value.type] ?? []) : []));
const currentSettings = computed(() => (current.value ? settingsOf(current.value) : {}));

function addStep(type: string) {
  const id = `step-${Date.now()}`;
  nodes.value.push({ id, type, name: `新的${type}步骤`, note: '在右侧填写这一步的配置' });
  selected.value = id;
}
function move(offset: number) {
  const from = currentIndex.value;
  const to = from + offset;
  // 触发器固定在第一步。
  if (from < 1 || to < 1 || to >= nodes.value.length) return;
  const list = [...nodes.value];
  [list[from], list[to]] = [list[to], list[from]];
  nodes.value = list;
}
function remove() {
  const index = currentIndex.value;
  if (index < 1) return;
  nodes.value = nodes.value.filter((_, position) => position !== index);
  selected.value = nodes.value[Math.min(index, nodes.value.length - 1)].id;
}
function validate() {
  status.value = '校验通过';
  message.success('步骤顺序、保护名单检查和设备动作的授权都满足要求。');
}

// AI 生成编排：描述场景后给出步骤草稿，采用后仍可逐步修改；原型里的草稿是固定的合成示例。
const aiOpen = ref(false);
const aiPrompt = ref('外部来源对核心业务发起高危 Web 攻击时，先断开连接，再封禁来源 2 小时，并通知值班组。');
const aiDraft: StepNode[] = [
  { id: 'trigger', type: '触发器', name: '高危 Web 攻击告警', note: '严重级别为高危或严重，目标属于核心业务资产组' },
  { id: 'triage', type: 'AI 研判', name: 'AI 研判', note: '结论为真实攻击且置信度不低于 90%，否则转人工' },
  { id: 'protect', type: '条件', name: '核对保护名单', note: '来源与目标都不在保护名单内' },
  { id: 'bypass', type: '旁路阻断', name: '旁路阻断当前连接', note: '向连接双方注入 TCP RST，观察 5 秒' },
  { id: 'action', type: '联动插件', name: '防火墙封禁来源 2 小时', note: '总部边界防火墙，到期自动解除' },
  { id: 'verify', type: '核验', name: '回读与效果观察', note: '回读设备配置，观察 5 分钟内是否仍有该来源流量' },
  { id: 'notify', type: '通知', name: '通知值班组', note: '附带研判依据与处置结果' },
];
function adoptDraft() {
  nodes.value = aiDraft.map(node => ({ ...node }));
  for (const key of Object.keys(settings)) delete settings[key];
  selected.value = 'triage';
  status.value = '草稿';
  aiOpen.value = false;
  message.success('已采用 AI 生成的编排草稿，可以继续逐步修改。');
}

function close() {
  detail.value = false;
  formOpen.value = false;
  if (['detail', 'action'].includes(props.state)) emit('state', 'data');
}
watch(
  () => props.state,
  state => {
    detail.value = state === 'detail';
    formOpen.value = state === 'action';
  },
  { immediate: true },
);
</script>

<template>
  <PageHeader :help-entries="helpEntries" :title="page.title" :description="page.description">
    <a-space>
      <a-button @click="aiOpen = true"><RobotOutlined />AI 生成编排</a-button>
      <a-button @click="validate"><CheckOutlined />校验</a-button>
      <a-button @click="message.success('编排已保存在本地示例中。')"><SaveOutlined />保存草稿</a-button>
      <a-button type="primary" @click="formOpen = true"><PlusOutlined />创建剧本</a-button>
    </a-space>
  </PageHeader>
  <HelpNote message="可以让 AI 按一句话描述生成步骤草稿，也可以自己添加、删除、调序并逐步配置。" />
  <HelpNote message="联动插件和旁路阻断会改变设备或网络，执行前都要核对保护名单；取消流程不等于设备动作已经回滚。" />

  <StatePanel
    v-if="state === 'loading' || state === 'error'"
    :loading="state === 'loading'"
    :error="state === 'error'"
    @retry="emit('state', 'data')"
  />
  <StatePanel
    v-else-if="state === 'empty'"
    empty
    title="尚未配置响应剧本"
    description="用 AI 生成一份草稿，或从空白开始添加步骤。"
    action="创建剧本"
    @action="formOpen = true"
  />
  <div v-else class="playbook-layout">
    <section class="panel playbook-canvas">
      <div class="panel-heading">
        <div>
          <h2>高危访问响应</h2>
          <small class="muted">PB-DEMO-001 · 版本 1 · 合成示例</small>
        </div>
        <StatusTag :value="status" :tone="statusTone(playbookTones, status)" />
      </div>
      <div class="workflow-flow">
        <template v-for="(node, index) in nodes" :key="node.id">
          <button
            type="button"
            class="workflow-node"
            :class="{ selected: selected === node.id, 'action-node': sideEffect(node.type) }"
            @click="selected = node.id"
          >
            <span class="node-index">{{ String(index + 1).padStart(2, '0') }}</span>
            <div>
              <small>{{ node.type }}</small>
              <b>{{ node.name }}</b>
              <p>{{ node.note }}</p>
            </div>
          </button>
          <ArrowDownOutlined class="workflow-arrow" />
        </template>
        <a-dropdown :trigger="['click']">
          <a-button type="dashed" class="playbook-add"><PlusOutlined />添加步骤</a-button>
          <template #overlay>
            <a-menu @click="({ key }: { key: string | number }) => addStep(String(key))">
              <a-menu-item v-for="type in stepTypes" :key="type">{{ type }}</a-menu-item>
            </a-menu>
          </template>
        </a-dropdown>
      </div>
    </section>

    <aside v-if="current" class="panel node-inspector">
      <div class="panel-heading">
        <h2>步骤配置</h2>
        <a-tag>{{ current.type }}</a-tag>
      </div>
      <a-form layout="vertical">
        <a-form-item label="步骤名称" required><a-input v-model:value="current.name" /></a-form-item>
        <a-form-item v-for="field in currentFields" :key="field.key" :label="field.label">
          <a-select
            v-if="field.kind === 'select'"
            v-model:value="currentSettings[field.key]"
            :options="(field.options ?? []).map(value => ({ value, label: value }))"
          />
          <a-checkbox-group
            v-else-if="field.kind === 'multi'"
            v-model:value="currentSettings[field.key]"
            :options="field.options"
          />
          <a-input-number
            v-else-if="field.kind === 'number'"
            v-model:value="currentSettings[field.key]"
            :min="1"
            :max="1440"
            :addon-after="field.suffix"
            class="playbook-number"
          />
          <a-switch v-else v-model:checked="currentSettings[field.key]" />
        </a-form-item>
        <a-form-item label="说明"><a-input v-model:value="current.note" /></a-form-item>
      </a-form>
      <div class="playbook-step-actions">
        <a-button :disabled="currentIndex <= 1" @click="move(-1)">上移</a-button>
        <a-button :disabled="currentIndex < 1 || currentIndex >= nodes.length - 1" @click="move(1)">下移</a-button>
        <a-button danger :disabled="currentIndex < 1" @click="remove"><DeleteOutlined />删除</a-button>
      </div>
      <a-button block class="playbook-rehearse" @click="detail = true"><PlayCircleOutlined />查看演练路径</a-button>
    </aside>
  </div>

  <a-modal :open="detail" title="演练路径" :width="720" :footer="null" @cancel="close">
    <a-steps
      direction="vertical"
      size="small"
      :current="2"
      :items="nodes.map(node => ({ title: node.name, description: node.note }))"
    />
    <p class="muted playbook-modal-note">演练只走流程，不执行任何设备动作。</p>
  </a-modal>

  <a-modal
    :open="aiOpen"
    title="AI 生成编排"
    :width="760"
    ok-text="采用草稿"
    cancel-text="取消"
    @ok="adoptDraft"
    @cancel="aiOpen = false"
  >
    <a-form layout="vertical">
      <a-form-item label="用一句话描述要处置的场景"><a-textarea v-model:value="aiPrompt" :rows="3" /></a-form-item>
    </a-form>
    <h3 class="playbook-draft-title">生成的步骤</h3>
    <ol class="playbook-draft">
      <li v-for="node in aiDraft" :key="node.id">
        <a-tag>{{ node.type }}</a-tag>
        <b>{{ node.name }}</b>
        <span class="muted">{{ node.note }}</span>
      </li>
    </ol>
  </a-modal>

  <RecordForm
    :open="formOpen"
    :page="{
      ...page,
      fields: [
        { key: 'name', label: '剧本名称', required: true },
        {
          key: 'trigger',
          label: '触发场景',
          type: 'select',
          required: true,
          value: '高危告警',
          options: ['高危告警', '异常外连', '人工发起'],
        },
        {
          key: 'mode',
          label: '自动化级别',
          type: 'select',
          required: true,
          value: '人机协同',
          options: ['人机协同', '条件自动', '全自动'],
        },
        { key: 'notes', label: '备注', type: 'textarea' },
      ],
    }"
    @close="close"
    @save="
      values => {
        status = '草稿';
        close();
        emit('state', 'data');
        message.success(`本地示例剧本 ${values.name} 已创建。`);
      }
    "
  />
</template>

<style scoped>
.playbook-layout {
  grid-template-columns: minmax(0, 1.5fr) minmax(320px, 1fr);
}
.workflow-flow {
  padding-block: var(--section-gap);
}
.workflow-node {
  width: min(100%, 520px);
  padding: 8px 12px;
  gap: 12px;
  cursor: pointer;
}
.workflow-node small {
  display: inline-block;
  margin: 0 8px 0 0;
  font-size: 12px;
}
.workflow-node p {
  margin-top: 2px;
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.workflow-arrow {
  margin: 4px 0;
  font-size: 12px;
}
.playbook-add {
  width: min(100%, 520px);
}
.playbook-number {
  width: 100%;
}
.playbook-step-actions {
  display: flex;
  gap: var(--related-gap);
}
.playbook-step-actions .ant-btn {
  flex: 1;
}
.playbook-rehearse {
  margin-top: var(--related-gap);
}
.playbook-modal-note {
  margin: 0;
  font-size: 12px;
}
.playbook-draft-title {
  margin: 0 0 var(--related-gap);
  font-size: 14px;
  font-weight: 600;
}
.playbook-draft {
  margin: 0;
  padding: 0;
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: var(--related-gap);
}
.playbook-draft li {
  display: grid;
  grid-template-columns: 92px minmax(140px, 0.8fr) minmax(0, 1.4fr);
  gap: var(--related-gap);
  align-items: baseline;
  font-size: 13px;
  line-height: 1.7;
}
.playbook-draft b {
  font-weight: 500;
}
</style>
