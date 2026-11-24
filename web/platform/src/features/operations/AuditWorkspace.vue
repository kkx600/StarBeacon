<script setup lang="ts">
import { reactive, shallowRef, toRef, watch } from 'vue';
import { Select as ASelect } from 'ant-design-vue';
import type { AuditRecord } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import TimeRangeField from '@starbeacon/shared/components/TimeRangeField.vue';
import AuditTable from './AuditTable.vue';
import AuditDetail from './AuditDetail.vue';
import { actionNames } from './audits';
import { useAudits, type AuditCategory } from './useAudits';
const props = defineProps<{ category: AuditCategory }>();
const { result, pending, error, cursors, pageSize, changePageSize, search, refresh, next, previous } = useAudits(
  toRef(props, 'category'),
);
const defaults = { username: '', action: '', success: '', hours: 168 },
  form = reactive({ ...defaults }),
  selected = shallowRef<AuditRecord | null>(null);
watch(
  () => props.category,
  () => {
    Object.assign(form, defaults);
    selected.value = null;
  },
);
const actions = [
  { label: '全部操作', value: '' },
  ...Object.entries(actionNames)
    .filter(([value]) => value !== 'auth.password_verification')
    .map(([value, label]) => ({ label, value })),
];
const timeOptions = [
  { label: '最近 24 小时', value: 24 },
  { label: '最近 7 天', value: 168 },
  { label: '最近 30 天', value: 720 },
];
</script>
<template>
  <a-form :model="form" layout="horizontal" @finish="search({ ...form })">
    <ListFilters :columns="3" label="审计日志筛选">
      <a-form-item label="账号" html-for="audit-username"
        ><a-input
          id="audit-username"
          v-model:value="form.username"
          :maxlength="64"
          placeholder="完整账号名称"
          allow-clear /></a-form-item
      ><a-form-item v-if="category === 'operations'" label="操作类型" html-for="audit-action"
        ><a-select id="audit-action" v-model:value="form.action" :options="actions" /></a-form-item
      ><a-form-item v-else label="凭据验证结果" html-for="audit-result"
        ><a-select
          id="audit-result"
          v-model:value="form.success"
          :options="[
            { label: '全部结果', value: '' },
            { label: '已验证', value: 'true' },
            { label: '验证失败', value: 'false' },
          ]"
      /></a-form-item>
      <TimeRangeField id-prefix="audit-hours" v-model:preset="form.hours" :preset-options="timeOptions" />
      <template #actions>
        <a-button html-type="submit" type="primary" :loading="pending">查询</a-button
        ><a-button
          :disabled="pending"
          @click="
            Object.assign(form, defaults);
            search({ ...form });
          "
          >重置</a-button
        ><a-button :disabled="pending" @click="refresh">刷新</a-button>
      </template>
    </ListFilters>
  </a-form>
  <section class="panel">
    <div class="panel-header">
      <h2>{{ category === 'operations' ? '操作日志' : '登录日志' }}</h2>
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="result.items.length === 0"
      description="当前条件下没有审计日志。"
      @retry="refresh"
      ><AuditTable :category="category" :records="result.items" @view="selected = $event"
    /></StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="error ? undefined : result.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!result.next_cursor"
      :disabled="pending"
      @previous="previous"
      @next="next"
      @update:page-size="changePageSize"
    />
  </section>
  <AuditDetail :record="selected" @close="selected = null" />
</template>
