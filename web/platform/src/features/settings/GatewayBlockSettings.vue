<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef } from 'vue';
import { RouterLink } from 'vue-router';
import { Alert as AAlert, Button as AButton, Table as ATable } from 'ant-design-vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import GatewayPolicyEditor from '../gateway/GatewayPolicyEditor.vue';
import {
  readGatewayPolicies,
  readGatewaySettings,
  saveGatewaySettings,
  type GatewayPolicy,
  type GatewaySettings,
} from '../gateway/gatewayBlocks';
import { useGatewayPage } from '../gateway/useGatewayPage';

const settings = shallowRef<GatewaySettings>();
const enabled = shallowRef(false);
const perMinute = shallowRef(10);
const settingsLoading = shallowRef(true);
const settingsError = shallowRef('');
const saving = shallowRef(false);
const saveError = shallowRef('');
const notice = shallowRef('');
let reader: AbortController | undefined;
let writer: AbortController | undefined;

function applySettings(value: GatewaySettings) {
  settings.value = value;
  enabled.value = value.enabled;
  perMinute.value = value.per_minute;
}
async function loadSettings() {
  reader?.abort();
  const current = new AbortController();
  reader = current;
  settingsLoading.value = true;
  settingsError.value = '';
  saveError.value = '';
  notice.value = '';
  try {
    const result = await readGatewaySettings(current.signal);
    if (!current.signal.aborted) applySettings(result);
  } catch (err) {
    if (!current.signal.aborted) settingsError.value = err instanceof Error ? err.message : '网关设置不可用。';
  } finally {
    if (reader === current) settingsLoading.value = false;
  }
}
const dirty = computed(
  () => settings.value && (settings.value.enabled !== enabled.value || settings.value.per_minute !== perMinute.value),
);
async function saveSettings() {
  const currentSettings = settings.value;
  if (!currentSettings || !dirty.value || saving.value) return;
  const limit = Number(perMinute.value);
  if (!Number.isInteger(limit) || limit < 1 || limit > 60) {
    saveError.value = '每分钟限额须为 1 至 60。';
    return;
  }
  const current = new AbortController();
  writer = current;
  saving.value = true;
  saveError.value = '';
  notice.value = '';
  try {
    const updated = await saveGatewaySettings(currentSettings.revision, enabled.value, limit, current.signal);
    if (!current.signal.aborted) {
      applySettings(updated);
      notice.value = '网关设置已保存。';
    }
  } catch (err) {
    if (!current.signal.aborted) saveError.value = err instanceof Error ? err.message : '保存失败，请刷新后核对。';
  } finally {
    if (!current.signal.aborted) saving.value = false;
  }
}
onMounted(loadSettings);
onScopeDispose(() => {
  reader?.abort();
  writer?.abort();
});

const { data, cursors, loading, error, pageSize, changePageSize, first, next, previous, reload } =
  useGatewayPage(readGatewayPolicies);
const items = computed(() => data.value?.items ?? []);
const editor = shallowRef<{ policy?: GatewayPolicy }>();
const columns = [
  { key: 'policy', title: '策略', width: 180 },
  { key: 'gateway', title: '采集器与规则', width: 170 },
  { key: 'deadline', title: '授权截止时间', width: 155 },
  { key: 'followUp', title: '联动封禁预授权', width: 180 },
  { key: 'edit', title: '操作', width: 72 },
];
function policySaved() {
  editor.value = undefined;
  first();
}
</script>

<template>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>网关阻断</h2>
      <RouterLink to="/response/gateway-blocks">查看阻断记录</RouterLink>
    </div>
    <StatePanel :loading="settingsLoading" :error="settingsError" @retry="loadSettings">
      <form v-if="settings" class="panel-body gateway-settings" @submit.prevent="saveSettings">
        <AAlert v-if="saveError" type="error" show-icon :message="saveError" />
        <AAlert v-if="notice" type="success" show-icon :message="notice" />
        <div class="gateway-settings-fields">
          <label><input v-model="enabled" type="checkbox" :disabled="saving" />启用平台网关阻断</label>
          <label>
            每分钟限额
            <input
              v-model.number="perMinute"
              class="ant-input limit-input"
              type="number"
              min="1"
              max="60"
              required
              :disabled="saving"
            />
          </label>
          <AButton type="primary" html-type="submit" :disabled="!dirty" :loading="saving">保存设置</AButton>
          <AButton :disabled="saving" @click="loadSettings">刷新设置</AButton>
        </div>
        <p>规则即时触发与研判后触发共用此限额。后续联动同时受响应动作的配额和设备租约约束。</p>
      </form>
    </StatePanel>
  </section>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>网关阻断策略</h2>
      <AButton type="primary" @click="editor = {}">新建策略</AButton>
    </div>
    <StatePanel
      :loading="loading"
      :error="error"
      :empty="!items.length"
      description="当前没有网关阻断策略。"
      @retry="reload"
    >
      <ATable
        :columns="columns"
        :data-source="items"
        row-key="id"
        :pagination="false"
        :scroll="{ x: 757 }"
        size="small"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'policy'">
            <div>{{ record.definition.name }}</div>
            <small class="mono">{{ record.id }} · v{{ record.revision }}</small>
          </template>
          <template v-else-if="column.key === 'gateway'">
            <div class="mono">{{ record.definition.sensor_id }}</div>
            <small
              >{{ record.definition.trigger === 'rule' ? '规则即时' : '研判后' }} · {{ record.definition.rule_id }}.{{
                record.definition.rule_revision
              }}</small
            >
          </template>
          <template v-else-if="column.key === 'deadline'">
            <StatusTag
              :value="record.definition.enabled ? '已启用' : '已停用'"
              :tone="record.definition.enabled ? 'success' : 'neutral'"
            />
            <div class="mono">{{ formatTime(record.definition.valid_until) }}</div>
          </template>
          <template v-else-if="column.key === 'followUp'">
            <div v-if="record.definition.follow_up">
              {{ record.definition.follow_up.plugin_id }} · 代次 {{ record.definition.follow_up.generation }}
              <div>
                {{ record.definition.follow_up.target_side === 'source' ? '告警源' : '告警目的' }} ·
                {{ record.definition.follow_up.ttl_seconds }} 秒
              </div>
            </div>
            <span v-else>未预授权</span>
          </template>
          <AButton
            v-else-if="column.key === 'edit'"
            type="link"
            size="small"
            @click="editor = { policy: record as GatewayPolicy }"
            >编辑</AButton
          >
        </template>
      </ATable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="items.length"
      :disabled="loading"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!data?.next_cursor"
      @update:page-size="changePageSize"
      @previous="previous"
      @next="next"
    />
  </section>
  <GatewayPolicyEditor v-if="editor" :policy="editor.policy" @close="editor = undefined" @saved="policySaved" />
</template>

<style scoped>
.gateway-settings {
  display: grid;
  gap: var(--related-gap);
}
.gateway-settings-fields,
.gateway-settings-fields label {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--related-gap);
}
.gateway-settings-fields {
  gap: var(--field-gap);
}
.limit-input {
  width: 72px;
}
.gateway-settings p {
  margin: 0;
  color: var(--muted);
}
</style>
