<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue';
import { Modal as AModal } from 'ant-design-vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import { defaultPageSize, pageOf } from '@starbeacon/shared/pagination.ts';
import type { SearchField } from './filterCompletion';
const props = defineProps<{
  open: boolean;
  fields: SearchField[];
  error: string;
  loading: boolean;
  disabled: boolean;
  dataset: 'alerts' | 'context';
}>();
const emit = defineEmits<{ close: []; retry: []; insert: [name: string] }>();
const keyword = shallowRef('');
const page = shallowRef(1),
  pageSize = shallowRef(defaultPageSize);
const columns = [
  { title: '字段', dataIndex: 'name', width: 200 },
  { title: '业务含义', dataIndex: 'label', width: 160 },
  { title: '类型', dataIndex: 'type', width: 100 },
  { title: '别名', dataIndex: 'aliases', width: 180 },
  { title: '支持运算', dataIndex: 'operators', width: 200 },
];
const matches = computed(() =>
  props.fields.filter(field =>
    [field.name, field.label, ...field.aliases].join(' ').toLowerCase().includes(keyword.value.trim().toLowerCase()),
  ),
);
watch(
  () => props.dataset,
  () => {
    keyword.value = '';
  },
);
watch([keyword, () => props.dataset], () => (page.value = 1));
</script>
<template>
  <a-modal
    :title="dataset === 'context' ? '流量检索字段' : '告警检索字段'"
    :open="open"
    :width="960"
    :footer="null"
    @cancel="emit('close')"
  >
    <ListFilters label="字段检索" :columns="1">
      <a-input v-model:value="keyword" aria-label="查找检索字段" placeholder="字段、别名或业务含义" allow-clear />
    </ListFilters>
    <a-alert v-if="error" :message="error" type="error" show-icon class="section-gap"
      ><template #action
        ><a-button size="small" :loading="loading" @click="emit('retry')">重试</a-button></template
      ></a-alert
    >
    <ListTable
      :data-source="pageOf(matches, page, pageSize)"
      :columns="columns"
      :loading="loading"
      :scroll="{ x: 840 }"
      row-key="name"
    >
      <template #bodyCell="{ column, record }">
        <button
          v-if="column.dataIndex === 'name'"
          type="button"
          class="link-button technical"
          :disabled="disabled"
          @click="emit('insert', record.name)"
        >
          {{ record.name }}
        </button>
        <span v-else-if="column.dataIndex === 'aliases' || column.dataIndex === 'operators'" class="technical">{{
          record[column.dataIndex].join('、') || '—'
        }}</span>
      </template>
    </ListTable>
    <ListPager v-model:page="page" v-model:page-size="pageSize" :total="matches.length" :disabled="loading" />
  </a-modal>
</template>
