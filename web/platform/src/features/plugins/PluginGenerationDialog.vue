<script setup lang="ts">
import { computed, reactive, shallowRef } from 'vue';
import { Checkbox, Modal as AModal, Select as ASelect, Tabs, type TableColumnType } from 'ant-design-vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import {
  deviceTypes,
  generationAbilities,
  usePluginGeneration,
  type Ability,
  type DeviceType,
  type GeneratedPlugin,
  type GenerationJob,
} from './usePluginGeneration';

const emit = defineEmits<{ close: []; review: [GeneratedPlugin] }>();
const ACheckbox = Checkbox;
const ACheckboxGroup = Checkbox.Group;
const ATabs = Tabs;
const ATabPane = Tabs.TabPane;
const runtime = usePluginGeneration();
const {
  providers,
  page,
  cursors,
  pageSize,
  selected,
  available,
  optionsError,
  historyError,
  detailError,
  submitError,
  optionsLoading,
  historyLoading,
  detailLoading,
  posting,
  unresolved,
  loadProviders,
  loadHistory,
  move,
  resize,
  inspect,
  submit,
} = runtime;
const active = shallowRef('create');
const detailID = shallowRef('');
const form = reactive({
  provider: undefined as string | undefined,
  device: 'firewall' as DeviceType,
  abilities: ['health'] as Ability[],
  documentation: '',
  allow: false,
});
const formError = shallowRef('');
const modelOptions = computed(() => providers.value.map(p => ({ value: p.id, label: p.name + ' · ' + p.model })));
const deviceOptions = Object.entries(deviceTypes).map(([value, label]) => ({ value, label }));
const abilityOptions = Object.entries(generationAbilities).map(([value, label]) => ({ value, label }));
const status: Record<
  GenerationJob['state'],
  { text: string; tone: 'info' | 'success' | 'danger' | 'warning' | 'neutral' }
> = {
  queued: { text: '排队中', tone: 'info' },
  running: { text: '生成中', tone: 'info' },
  succeeded: { text: '待审阅', tone: 'success' },
  failed: { text: '生成失败', tone: 'danger' },
  refused: { text: '模型拒答', tone: 'warning' },
  incomplete: { text: '结果不完整', tone: 'warning' },
  uncertain: { text: '结果未知', tone: 'warning' },
  cancelled: { text: '已取消', tone: 'neutral' },
};
const feedback: Record<string, string> = {
  insufficient_documentation: '请补全所选能力的请求、响应和状态字段。',
  invalid_plugin_generation_output: '模型结果无法形成有效草稿和样例。',
  provider_revision_changed: '模型配置已更新，请重新选择后提交。',
  provider_result_unknown: '提供方可能已收到原请求，请核对本次记录。',
};
const columns: TableColumnType<GenerationJob>[] = [
  { title: '编号', key: 'id', width: 158, ellipsis: true },
  { title: '提交时间', key: 'created', width: 152 },
  { title: '模型', dataIndex: 'model', ellipsis: true },
  { title: '设备类型', key: 'device', width: 90 },
  { title: '状态', key: 'state', width: 102 },
  { title: '操作', key: 'actions', width: 88, fixed: 'right' },
];

void loadProviders();
void loadHistory();

function view(id: string) {
  detailID.value = id;
  void inspect(id);
}

async function generate(retry = false) {
  formError.value = '';
  if (retry) {
    if (!(await submit())) return;
  } else {
    const provider = providers.value.find(p => p.id === form.provider);
    const document = form.documentation.trim();
    if (
      !provider ||
      !form.abilities.length ||
      !form.allow ||
      document.length < 12 ||
      new TextEncoder().encode(document).length > 12 * 1024
    ) {
      formError.value = '请选择模型、设备能力并确认本次材料发送许可，接口文档限 12 KiB。';
      return;
    }
    if (
      !(await submit({
        provider_id: provider.id,
        provider_revision: provider.revision,
        device_type: form.device,
        abilities: form.abilities.slice(),
        documentation: document,
        allow_context: true,
      }))
    )
      return;
  }
  detailID.value = selected.value?.id ?? '';
  form.documentation = '';
  form.allow = false;
  active.value = 'history';
}
</script>

<template>
  <a-modal
    :open="true"
    title="AI 生成插件"
    :width="800"
    :footer="null"
    :closable="!posting"
    :keyboard="!posting"
    :mask-closable="false"
    @cancel="!posting && emit('close')"
  >
    <a-alert
      v-if="submitError"
      :type="unresolved ? 'warning' : 'error'"
      :message="submitError"
      show-icon
      class="section-gap"
    >
      <template v-if="unresolved" #action>
        <a-button size="small" :loading="posting" @click="generate(true)">核对原提交</a-button>
      </template>
    </a-alert>
    <a-tabs v-model:active-key="active">
      <a-tab-pane key="create" tab="生成草稿">
        <a-alert v-if="optionsError" type="error" :message="optionsError" class="section-gap">
          <template #action><a-button size="small" @click="loadProviders">重试</a-button></template>
        </a-alert>
        <a-alert
          v-else-if="!available && !optionsLoading && !historyLoading"
          type="warning"
          class="section-gap"
          message="暂无可用的生成模型或执行服务"
        />
        <a-alert v-if="formError" type="error" :message="formError" class="section-gap" />
        <a-form :model="form" layout="vertical" :disabled="posting || unresolved" @finish="generate()">
          <div class="generation-inputs">
            <a-form-item label="生成模型" required>
              <a-select
                v-model:value="form.provider"
                aria-label="生成模型"
                :options="modelOptions"
                :loading="optionsLoading"
                placeholder="选择模型"
                @change="form.allow = false"
              />
            </a-form-item>
            <a-form-item label="设备类型" required>
              <a-select v-model:value="form.device" aria-label="设备类型" :options="deviceOptions" />
            </a-form-item>
          </div>
          <a-form-item label="需要的能力" required
            ><a-checkbox-group v-model:value="form.abilities" :options="abilityOptions"
          /></a-form-item>
          <a-form-item
            label="设备接口文档"
            required
            extra="提供请求、响应与状态说明。用占位符替换令牌、密码及设备地址。"
          >
            <a-textarea
              v-model:value="form.documentation"
              aria-label="设备接口文档"
              :rows="7"
              placeholder="粘贴相关接口文档，最多 12 KiB"
            />
          </a-form-item>
          <a-form-item
            ><a-checkbox v-model:checked="form.allow">允许将本次接口文档发送至所选模型</a-checkbox></a-form-item
          >
          <div class="generation-actions">
            <a-button
              type="primary"
              html-type="submit"
              :disabled="!available || unresolved || !form.allow"
              :loading="posting"
              >生成草稿</a-button
            >
          </div>
        </a-form>
      </a-tab-pane>
      <a-tab-pane key="history" tab="生成记录">
        <div class="generation-actions">
          <a-button size="small" :loading="historyLoading" @click="loadHistory">刷新记录</a-button>
        </div>
        <a-alert v-if="historyError" type="error" :message="historyError" class="section-gap" />
        <ListTable :columns="columns" :data-source="page.items" :loading="historyLoading" :scroll="{ x: 688 }">
          <template #bodyCell="{ column, record }">
            <code v-if="column.key === 'id'" :title="record.id">{{ record.id }}</code>
            <template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
            <template v-else-if="column.key === 'device'">{{ deviceTypes[record.device_type as DeviceType] }}</template>
            <StatusTag
              v-else-if="column.key === 'state'"
              :value="status[record.state as GenerationJob['state']].text"
              :tone="status[record.state as GenerationJob['state']].tone"
            />
            <a-button v-else-if="column.key === 'actions'" size="small" type="link" @click="view(record.id)"
              >查看</a-button
            >
          </template>
          <template #emptyText>暂无生成记录</template>
        </ListTable>
        <ListPager
          mode="cursor"
          :page="cursors.length"
          :page-size="pageSize"
          :count="page.items.length"
          :has-previous="cursors.length > 1"
          :has-next="!!page.next_cursor"
          :disabled="historyLoading || !!historyError"
          @previous="move(false)"
          @next="move(true)"
          @change="resize"
        />
        <a-alert v-if="detailError" type="error" :message="detailError" class="section-gap">
          <template #action><a-button size="small" @click="view(detailID)">重试</a-button></template>
        </a-alert>
        <a-spin v-if="detailLoading && !selected" size="small" />
        <section v-if="selected" class="generation-detail" aria-label="生成结果">
          <div class="generation-heading">
            <strong>{{ selected.candidate?.name ?? selected.id }}</strong>
            <StatusTag :value="status[selected.state].text" :tone="status[selected.state].tone" />
            <span>{{ selected.model }} · 修订 {{ selected.provider_revision }}</span>
          </div>
          <p class="generation-document">
            文档 SHA-256 <code>{{ selected.documentation_sha256 }}</code>
          </p>
          <p v-if="!selected.candidate && feedback[selected.result.code]">{{ feedback[selected.result.code] }}</p>
          <div v-if="selected.candidate" class="generation-actions">
            <span
              >{{ selected.candidate.script ? 'Starlark 脚本' : '声明式模板' }} ·
              {{ selected.candidate.examples?.length ?? 0 }} 项样例</span
            >
            <a-button type="primary" @click="emit('review', selected.candidate)">在编辑器审阅</a-button>
          </div>
        </section>
      </a-tab-pane>
    </a-tabs>
  </a-modal>
</template>

<style scoped>
.generation-inputs {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(140px, 1fr);
  gap: var(--related-gap);
}
.generation-actions,
.generation-heading {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--related-gap);
}
.generation-actions {
  justify-content: flex-end;
  margin-block: var(--related-gap);
}
.generation-detail {
  margin-top: var(--related-gap);
  padding-top: var(--related-gap);
  border-top: 1px solid var(--line);
}
.generation-document {
  overflow-wrap: anywhere;
}
</style>
