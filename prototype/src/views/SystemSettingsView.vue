<script setup lang="ts">
import ListTable from '../../../web/packages/shared/src/components/ListTable.vue';
import { computed, h, reactive, ref, watch, type Component } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  AppstoreOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  PlusOutlined,
  RobotOutlined,
  StopOutlined,
  TeamOutlined,
} from '@ant-design/icons-vue';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import FeatureDirectory from '../../../web/platform/src/features/settings/FeatureDirectory.vue';
import type { BusinessRecord, PageSpec, PreviewState } from '../models';
import { pageById } from '../data/catalog';
import { defaultSensorThresholds, type SensorThresholds } from '../data/sensorHealth';
import { useRecords } from '../composables/useRecords';
import { sensorThresholds } from '../composables/useSensorHealth';
import { expiryFromDuration } from '../composables/formValues';
import {
  automationLevel,
  automationLevels,
  automationScenes,
  bypassEnabled,
  bypassInjectLimit,
  bypassInterface,
  bypassPolicies,
  fullRetentionScopes,
  retentionParams,
  retentionPolicies,
  retentionPolicy,
  storageTiers,
} from '../composables/systemSettings';
import PageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';
import HelpNote from '../components/HelpNote.vue';
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTone } from '../../../web/packages/shared/src/statusTones';
import { configurationTones } from '../data/statuses';
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue';
import RecordForm from '../components/RecordForm.vue';

// 系统设置：所有对全员生效的配置集中在这里，业务页面只读显示当前值并链接回对应分类。
const props = defineProps<{ page: PageSpec; state: PreviewState }>();
const emit = defineEmits<{ state: [value: PreviewState] }>();
const route = useRoute();
const router = useRouter();
const message = useFeedback();

type SectionKey = 'users' | 'automation' | 'bypass' | 'traffic' | 'sensor-health' | 'features';
interface Section {
  key: SectionKey;
  title: string;
  icon: Component;
  help: string;
  // 只有整块都是参数的分类用页脚“保存”；旁路阻断的保存按钮跟在参数块下面。
  savable: boolean;
}
const sections: Section[] = [
  {
    key: 'users',
    title: '用户管理',
    icon: TeamOutlined,
    help: '账号名称创建后不能修改；变更角色或状态后，该用户需要重新登录。',
    savable: false,
  },
  {
    key: 'automation',
    title: '自动处置',
    icon: RobotOutlined,
    help: '保护名单、限时和可撤销在每一级自动化下都生效。',
    savable: true,
  },
  {
    key: 'bypass',
    title: '旁路阻断',
    icon: StopOutlined,
    help: '开关和注入上限点“保存”后生效；阻断策略逐条授权、启停立即生效，到期自动停用。',
    savable: false,
  },
  {
    key: 'traffic',
    title: '全流量存储',
    icon: DatabaseOutlined,
    help: '会话元数据全部保留；原包按留存策略保存，被截断的会话会明确标记。',
    savable: true,
  },
  {
    key: 'sensor-health',
    title: '探针健康',
    icon: DashboardOutlined,
    help: '资源或丢包达到阈值时标记为需关注；心跳超过期限时显示无数据。',
    savable: true,
  },
  {
    key: 'features',
    title: '功能目录',
    icon: AppstoreOutlined,
    help: '列出各功能的入口，以及当前版本是否提供。',
    savable: false,
  },
];
const menuItems = sections.map(item => ({ key: item.key, label: item.title, icon: () => h(item.icon) }));
const section = computed<SectionKey>(() => sections.find(item => item.key === route.query.section)?.key ?? 'users');
const current = computed(() => sections.find(item => item.key === section.value)!);
function selectSection(info: { key: string | number }) {
  void router.replace({ query: { ...route.query, section: String(info.key) } });
}

const busy = computed(() => props.state === 'loading' || props.state === 'error');
const empty = computed(() => props.state === 'empty');

// 用户管理：与“用户管理”页面共用同一份示例记录。
const usersPage = pageById.get('users')!;
const userFormPage: PageSpec = { ...usersPage, rowAction: '编辑' };
const { records: users, save: saveUser } = useRecords(usersPage);
const userRows = computed(() => (empty.value ? [] : users.value));
// 列宽合计约 920，1440 宽度下不出横向滚动；更窄时表格内横向滚动。
const userColumns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 124 },
  ...usersPage.columns.map(column => ({
    title: column.title,
    dataIndex: column.key,
    key: column.key,
    width:
      column.key === 'name'
        ? undefined
        : ['time', 'updated'].includes(column.key)
          ? 160
          : column.key === 'role'
            ? 96
            : 88,
    ellipsis: column.key !== 'status',
  })),
  { title: '操作', key: 'actions', width: 64, fixed: 'right' as const },
];
const userFormOpen = ref(false);
const editingUser = ref<BusinessRecord>();
function createUser() {
  editingUser.value = undefined;
  userFormOpen.value = true;
}
function editUser(record: BusinessRecord) {
  editingUser.value = record;
  userFormOpen.value = true;
}
function submitUser(values: Record<string, unknown>) {
  saveUser(values, editingUser.value?.id);
  closeDialogs();
  if (props.state !== 'data') emit('state', 'data');
  message.success('已保存在本地示例中。');
}

// 自动处置：全局级别是上限，场景级别只能等于或低于它。
const sceneLevels = ['仅观察', '人机协同', '条件自动', '全自动'];
const automationDraft = reactive({
  level: automationLevel.value,
  scenes: automationScenes.value.map(scene => ({ ...scene })),
});
const sceneOptions = computed(() =>
  sceneLevels.map(value => ({
    value,
    label: value,
    disabled: sceneLevels.indexOf(value) > sceneLevels.indexOf(automationDraft.level),
  })),
);
const sceneColumns = [
  { title: '场景', dataIndex: 'name', key: 'name', width: 180, ellipsis: true },
  { title: '级别', dataIndex: 'level', key: 'level', width: 148 },
  { title: '允许的动作', dataIndex: 'actions', key: 'actions', ellipsis: true },
  { title: '近 7 日研判', dataIndex: 'judged', key: 'judged', width: 100, align: 'right' as const },
  { title: '执行', dataIndex: 'executed', key: 'executed', width: 64, align: 'right' as const },
  { title: '撤销', dataIndex: 'revoked', key: 'revoked', width: 64, align: 'right' as const },
];

// 旁路阻断：开关和注入上限保存后生效；策略逐条授权，启停立即生效。
const bypassDraft = reactive({ enabled: bypassEnabled.value, limit: bypassInjectLimit.value });
const policyRows = computed(() => (empty.value ? [] : bypassPolicies.value));
// 触发条件和目标范围不定宽、放不下用省略号，列宽合计约 930，1440 宽度下不出横向滚动；
// 更窄时横向滚动，状态和启停固定在右侧仍能看到。
const policyColumns = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 112 },
  { title: '名称', dataIndex: 'name', key: 'name', width: 120, ellipsis: true },
  { title: '触发条件', dataIndex: 'trigger', key: 'trigger', ellipsis: true },
  { title: '目标范围', dataIndex: 'scope', key: 'scope', ellipsis: true },
  { title: '方式', dataIndex: 'method', key: 'method', width: 100 },
  { title: '授权人', dataIndex: 'owner', key: 'owner', width: 64 },
  { title: '有效期至', dataIndex: 'expires', key: 'expires', width: 156 },
  { title: '状态', dataIndex: 'status', key: 'status', width: 80, fixed: 'right' as const },
  { title: '操作', key: 'actions', width: 52, fixed: 'right' as const },
];
const policyTriggers = ['严重级别为严重', 'AI 结论为真实攻击', '命中指定规则族', '命中关联规则'];
const policyOpen = ref(false);
const blankPolicy = () => ({
  name: '',
  trigger: policyTriggers[0]!,
  scope: '',
  method: 'TCP RST 双向',
  days: 30,
  confirmed: false,
});
const policyDraft = ref(blankPolicy());
function createPolicy() {
  policyDraft.value = blankPolicy();
  policyOpen.value = true;
}
function savePolicy() {
  const draft = policyDraft.value;
  if (!draft.name.trim() || !draft.scope.trim()) {
    message.error('请填写策略名称和目标范围。');
    return;
  }
  const next = Math.max(0, ...bypassPolicies.value.map(item => Number(item.id.split('-').pop()) || 0)) + 1;
  bypassPolicies.value.unshift({
    id: `BYPASS-P-${String(next).padStart(4, '0')}`,
    name: draft.name.trim(),
    trigger: draft.trigger,
    scope: draft.scope.trim(),
    method: draft.method,
    owner: '陈宁',
    // 原型使用固定示例时钟，和其他示例记录的时间保持一致。
    expires: expiryFromDuration(`${draft.days} 天`, '2026-09-30T09:48:00Z') ?? '—',
    status: '启用',
  });
  closeDialogs();
  if (props.state !== 'data') emit('state', 'data');
  message.success('策略已保存在本地示例中，不会向采集器下发。');
}
function togglePolicy(record: { status: string; name: string }) {
  record.status = record.status === '启用' ? '停用' : '启用';
  message.success(`${record.name}：${record.status}。`);
}

// 全流量存储：参数只在“智能留存”下生效。
const trafficDraft = reactive({
  policy: retentionPolicy.value,
  params: { ...retentionParams.value, alwaysFull: [...retentionParams.value.alwaysFull] },
});

// 探针健康：与探针列表、详情和总览共用同一份阈值。
const thresholdFields: {
  key: keyof SensorThresholds;
  label: string;
  suffix: string;
  min: number;
  max: number;
  step: number;
}[] = [
  { key: 'cpu', label: 'CPU 使用率', suffix: '%', min: 1, max: 100, step: 1 },
  { key: 'memory', label: '内存使用率', suffix: '%', min: 1, max: 100, step: 1 },
  { key: 'disk', label: '磁盘使用率', suffix: '%', min: 1, max: 100, step: 1 },
  { key: 'drop', label: '丢包率', suffix: '%', min: 0.01, max: 100, step: 0.01 },
  { key: 'heartbeat', label: '心跳超时', suffix: '秒', min: 30, max: 3600, step: 30 },
];
const thresholdDraft = reactive<SensorThresholds>({ ...sensorThresholds });
function resetThresholds() {
  Object.assign(thresholdDraft, defaultSensorThresholds);
}

function save() {
  if (section.value === 'automation') {
    const tooHigh = automationDraft.scenes.find(
      scene => sceneLevels.indexOf(scene.level) > sceneLevels.indexOf(automationDraft.level),
    );
    if (tooHigh) {
      message.error(`“${tooHigh.name}”的级别高于全局级别，请先调低。`);
      return;
    }
    automationLevel.value = automationDraft.level;
    automationScenes.value = automationDraft.scenes.map(scene => ({ ...scene }));
  } else if (section.value === 'bypass') {
    bypassEnabled.value = bypassDraft.enabled;
    bypassInjectLimit.value = bypassDraft.limit;
  } else if (section.value === 'traffic') {
    retentionPolicy.value = trafficDraft.policy;
    retentionParams.value = { ...trafficDraft.params, alwaysFull: [...trafficDraft.params.alwaysFull] };
  } else if (section.value === 'sensor-health') {
    const invalid = thresholdFields.find(field => {
      const value = thresholdDraft[field.key];
      return typeof value !== 'number' || !Number.isFinite(value) || value < field.min || value > field.max;
    });
    if (invalid) {
      message.error(`${invalid.label}需为 ${invalid.min}–${invalid.max}${invalid.suffix}。`);
      return;
    }
    Object.assign(sensorThresholds, thresholdDraft);
  }
  message.success('已保存在本地示例中。');
}

function closeDialogs() {
  userFormOpen.value = false;
  policyOpen.value = false;
  if (props.state === 'action' || props.state === 'detail') emit('state', 'data');
}
// 原型“操作”状态打开当前分类的新建弹窗；其余分类没有弹窗。
watch(
  () => props.state,
  state => {
    if (state !== 'action') return;
    if (section.value === 'users') createUser();
    else if (section.value === 'bypass') createPolicy();
  },
  { immediate: true },
);
</script>

<template>
  <PageHeader :help-entries="helpEntries" :title="page.title" :description="page.description" />
  <HelpNote :message="current.help" />

  <div class="settings-layout">
    <nav class="panel settings-nav" aria-label="设置分类">
      <a-menu mode="inline" :selected-keys="[section]" :items="menuItems" @click="selectSection" />
    </nav>

    <section class="panel table-panel settings-content" :aria-label="current.title">
      <header class="settings-head">
        <h2>{{ current.title }}</h2>
        <a-space v-if="section === 'users' && !busy" :size="16">
          <router-link to="/page/users">打开完整的用户管理</router-link>
          <a-button type="primary" @click="createUser"><PlusOutlined />新建用户</a-button>
        </a-space>
        <router-link v-else-if="section === 'automation'" to="/page/decision-policies">管理决策策略</router-link>
      </header>

      <StatePanel
        v-if="busy"
        :loading="state === 'loading'"
        :error="state === 'error'"
        @retry="emit('state', 'data')"
      />

      <template v-else-if="section === 'users'">
        <StatePanel
          v-if="!userRows.length"
          empty
          title="还没有用户"
          description="新建用户后，账号会出现在这里。"
          action="新建用户"
          @action="createUser"
        />
        <ListTable
          v-else
          :columns="userColumns"
          :data-source="userRows"
          row-key="id"
          :scroll="{ x: 920 }"
          :pagination="tablePagination()"
        >
          <template #bodyCell="{ column, record, text }">
            <span v-if="column.key === 'id'" class="mono">{{ text }}</span>
            <span v-else-if="column.key === 'time' || column.key === 'updated'" class="tabular">{{ text }}</span>
            <StatusTag
              v-else-if="column.key === 'status'"
              :value="text"
              :tone="statusTone(configurationTones, record.status)"
            />
            <a-button
              v-else-if="column.key === 'actions'"
              type="link"
              size="small"
              @click="editUser(record as BusinessRecord)"
              >编辑</a-button
            >
          </template>
        </ListTable>
      </template>

      <div v-else-if="section === 'automation'" class="settings-body">
        <a-form layout="vertical" class="settings-form">
          <a-form-item label="全局自动化级别" extra="这是上限；每个场景可以设得更低，不能更高。">
            <a-radio-group v-model:value="automationDraft.level" class="settings-options">
              <a-radio v-for="item in automationLevels" :key="item.value" :value="item.value">
                {{ item.value }}<small>{{ item.note }}</small>
              </a-radio>
            </a-radio-group>
          </a-form-item>
        </a-form>
        <h3 class="settings-subhead">各场景的级别</h3>
        <ListTable
          :columns="sceneColumns"
          :data-source="automationDraft.scenes"
          row-key="name"
          :scroll="{ x: 760 }"
          :pagination="false"
        >
          <template #bodyCell="{ column, record, text }">
            <a-select
              v-if="column.key === 'level'"
              v-model:value="record.level"
              size="small"
              class="settings-scene-level"
              :aria-label="`${record.name}的级别`"
              :options="sceneOptions"
            />
            <span v-else-if="['judged', 'executed', 'revoked'].includes(String(column.key))" class="tabular">{{
              text
            }}</span>
          </template>
        </ListTable>
      </div>

      <template v-else-if="section === 'bypass'">
        <!-- 参数点“保存”才生效；策略按条目逐条生效，分成上下两块。 -->
        <div class="settings-block">
          <h3 class="settings-subhead">开关与注入</h3>
          <a-form layout="vertical" class="settings-grid">
            <a-form-item label="旁路阻断" extra="默认关闭。">
              <a-switch v-model:checked="bypassDraft.enabled" checked-children="开启" un-checked-children="关闭" />
            </a-form-item>
            <a-form-item label="注入网口">
              <span class="settings-readonly"
                ><span class="status-dot success"></span><span class="mono">{{ bypassInterface }}</span> ·
                链路正常</span
              >
            </a-form-item>
            <a-form-item label="每分钟注入上限">
              <a-input-number v-model:value="bypassDraft.limit" :min="1" :max="1000" class="settings-number">
                <template #addonAfter>次</template>
              </a-input-number>
            </a-form-item>
          </a-form>
          <a-button type="primary" @click="save">保存</a-button>
        </div>
        <div class="settings-block">
          <div class="settings-subhead">
            <h3>阻断策略</h3>
            <a-button size="small" @click="createPolicy"><PlusOutlined />新建策略</a-button>
          </div>
          <StatePanel
            v-if="!policyRows.length"
            empty
            title="还没有阻断策略"
            description="新建并启用策略后，命中的连接才会被阻断。"
            action="新建策略"
            @action="createPolicy"
          />
          <ListTable
            v-else
            :columns="policyColumns"
            :data-source="policyRows"
            row-key="id"
            :scroll="{ x: 930 }"
            :pagination="tablePagination()"
          >
            <template #bodyCell="{ column, record, text }">
              <span v-if="column.key === 'id'" class="mono">{{ text }}</span>
              <span v-else-if="column.key === 'expires'" class="tabular">{{ text }}</span>
              <StatusTag
                v-else-if="column.key === 'status'"
                :value="text"
                :tone="statusTone(configurationTones, record.status)"
              />
              <a-button
                v-else-if="column.key === 'actions'"
                type="link"
                size="small"
                @click="togglePolicy(record as { status: string; name: string })"
              >
                {{ record.status === '启用' ? '停用' : '启用' }}
              </a-button>
            </template>
          </ListTable>
        </div>
      </template>

      <div v-else-if="section === 'traffic'" class="settings-body">
        <a-form layout="vertical" class="settings-form">
          <a-form-item label="留存策略">
            <a-radio-group v-model:value="trafficDraft.policy" class="settings-options">
              <a-radio v-for="item in retentionPolicies" :key="item.value" :value="item.value">
                {{ item.value }}<small>{{ item.note }}</small>
              </a-radio>
            </a-radio-group>
          </a-form-item>
          <template v-if="trafficDraft.policy === '智能留存'">
            <div class="settings-grid">
              <a-form-item label="加密流握手后保留">
                <a-input-number
                  v-model:value="trafficDraft.params.encryptedKB"
                  :min="4"
                  :max="1024"
                  class="settings-number"
                >
                  <template #addonAfter>KB</template>
                </a-input-number>
              </a-form-item>
              <a-form-item label="大传输每方向保留">
                <a-input-number v-model:value="trafficDraft.params.bulkMB" :min="1" :max="1024" class="settings-number">
                  <template #addonAfter>MB</template>
                </a-input-number>
              </a-form-item>
              <a-form-item label="封段间隔">
                <a-input-number
                  v-model:value="trafficDraft.params.sealMinutes"
                  :min="1"
                  :max="30"
                  class="settings-number"
                >
                  <template #addonAfter>分钟</template>
                </a-input-number>
              </a-form-item>
              <a-form-item label="保留天数">
                <a-input-number v-model:value="trafficDraft.params.days" :min="1" :max="3650" class="settings-number">
                  <template #addonAfter>天</template>
                </a-input-number>
              </a-form-item>
              <a-form-item label="镜像去重" extra="多个镜像口的同一数据包只存一份。">
                <a-switch
                  v-model:checked="trafficDraft.params.dedupe"
                  checked-children="开启"
                  un-checked-children="关闭"
                />
              </a-form-item>
            </div>
            <a-form-item label="始终完整保留" extra="这些范围不受截断影响。">
              <a-select
                v-model:value="trafficDraft.params.alwaysFull"
                mode="multiple"
                :options="fullRetentionScopes.map(value => ({ value, label: value }))"
              />
            </a-form-item>
          </template>
        </a-form>
        <h3 class="settings-subhead">存储用量</h3>
        <div class="settings-tiers">
          <div v-for="tier in storageTiers" :key="tier.name">
            <span
              >{{ tier.name }}<small>{{ tier.span }} · {{ tier.size }}</small></span
            >
            <a-progress :percent="tier.percent" size="small" />
          </div>
        </div>
      </div>

      <div v-else-if="section === 'sensor-health'" class="settings-body">
        <a-form layout="vertical" class="settings-grid">
          <a-form-item v-for="field in thresholdFields" :key="field.key" :label="field.label">
            <a-input-number
              v-model:value="thresholdDraft[field.key]"
              :aria-label="field.label"
              :min="field.min"
              :max="field.max"
              :step="field.step"
              class="settings-number"
            >
              <template #addonAfter>{{ field.suffix }}</template>
            </a-input-number>
          </a-form-item>
        </a-form>
      </div>

      <div v-else class="settings-features">
        <FeatureDirectory embedded />
      </div>

      <footer v-if="current.savable && !busy" class="settings-footer">
        <a-button v-if="section === 'sensor-health'" type="link" @click="resetThresholds">恢复默认值</a-button>
        <a-button type="primary" @click="save">保存</a-button>
      </footer>
    </section>
  </div>

  <RecordForm
    :open="userFormOpen"
    :page="userFormPage"
    :record="editingUser"
    @close="closeDialogs"
    @save="submitUser"
  />

  <a-modal
    :open="policyOpen"
    title="新建阻断策略"
    :width="640"
    ok-text="保存并启用"
    cancel-text="取消"
    :ok-button-props="{ disabled: !policyDraft.confirmed }"
    @ok="savePolicy"
    @cancel="closeDialogs"
  >
    <a-form layout="vertical">
      <a-form-item label="策略名称" required>
        <a-input v-model:value="policyDraft.name" placeholder="例如：C2 外联即时断开" />
      </a-form-item>
      <a-form-item label="触发条件" required>
        <a-select
          v-model:value="policyDraft.trigger"
          :options="policyTriggers.map(value => ({ value, label: value }))"
        />
      </a-form-item>
      <a-form-item label="目标范围" required extra="保护名单里的地址不会被阻断。">
        <a-input v-model:value="policyDraft.scope" placeholder="例如：外部 → 核心业务资产组" />
      </a-form-item>
      <a-form-item label="方式">
        <a-radio-group v-model:value="policyDraft.method" :options="['TCP RST 双向', 'ICMP 不可达']" />
      </a-form-item>
      <a-form-item label="有效期">
        <a-input-number v-model:value="policyDraft.days" :min="1" :max="180" class="settings-number">
          <template #addonAfter>天</template>
        </a-input-number>
      </a-form-item>
      <a-checkbox v-model:checked="policyDraft.confirmed"
        >我了解旁路阻断不保证断开连接，也不能代替防火墙封禁。</a-checkbox
      >
    </a-form>
  </a-modal>
</template>

<style scoped>
.settings-layout {
  display: grid;
  grid-template-columns: 200px minmax(0, 1fr);
  gap: var(--section-gap);
  align-items: start;
}
.settings-nav {
  padding: var(--related-gap) 0;
}
.settings-nav :deep(.ant-menu.ant-menu-root) {
  border-inline-end: 0;
  background: transparent;
}
.settings-content {
  display: flex;
  flex-direction: column;
  min-height: 480px;
}
.settings-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--field-gap);
  min-height: 48px;
  padding: var(--related-gap) var(--panel-inset);
  border-bottom: 1px solid var(--line);
}
.settings-head h2 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}
.settings-head a {
  font-size: 13px;
}
.settings-body {
  flex: 1;
  padding: var(--panel-inset);
}
.settings-form {
  max-width: 720px;
}
.settings-block {
  padding: var(--panel-inset);
}
.settings-block + .settings-block {
  flex: 1;
  border-top: 1px solid var(--line);
}
.settings-block > .settings-subhead:first-child {
  margin-top: 0;
}
.settings-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 220px));
  gap: 0 var(--section-gap);
}
.settings-number {
  width: 100%;
}
.settings-options {
  display: flex;
  flex-direction: column;
  gap: var(--related-gap);
}
/* 选项带一行说明时，单选圈对齐选项名而不是两行的中线。 */
.settings-options :deep(.ant-radio) {
  align-self: flex-start;
  margin-top: 3px;
}
.settings-options small {
  display: block;
  margin-top: 2px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.6;
}
.settings-readonly {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 32px;
  font-size: 13px;
}
.settings-subhead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--field-gap);
  margin: var(--related-gap) 0;
  font-size: 14px;
  font-weight: 600;
}
.settings-subhead h3 {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
}
.settings-scene-level {
  width: 120px;
}
.settings-tiers {
  display: flex;
  flex-direction: column;
  gap: var(--related-gap);
  max-width: 720px;
}
.settings-tiers > div {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: var(--field-gap);
  align-items: center;
  font-size: 13px;
}
.settings-tiers small {
  display: block;
  color: var(--muted);
  font-size: 12px;
}
.settings-block :deep(.ant-table-wrapper .ant-table-pagination) {
  margin: var(--section-gap) 0 0;
}
.settings-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--related-gap);
  padding: var(--section-gap) var(--panel-inset);
  border-top: 1px solid var(--line);
}
.settings-features :deep(.panel) {
  margin: 0;
  border: 0;
  border-radius: 0;
}
.settings-features :deep(.filter-panel) {
  border-bottom: 1px solid var(--line);
}
@media (max-width: 1180px) {
  .settings-layout {
    grid-template-columns: 168px minmax(0, 1fr);
  }
  .settings-grid {
    grid-template-columns: repeat(2, minmax(0, 220px));
  }
}
</style>
