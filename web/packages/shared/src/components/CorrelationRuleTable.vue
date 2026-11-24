<script setup lang="ts">
import { computed } from 'vue';
import ListTable from './ListTable.vue';
import StatusTag from './StatusTag.vue';
import { correlationFields, type CorrelationRule } from '../correlation';
import { formatTime } from '../types';
const props = defineProps<{ items: readonly CorrelationRule[]; canEdit: boolean; disabled?: boolean }>();
const emit = defineEmits<{
  inspect: [rule: CorrelationRule];
  edit: [rule: CorrelationRule];
  backtest: [rule: CorrelationRule];
}>();
const rows = computed(() => [...props.items]);
const columns = [
  { title: '规则编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '规则名称', key: 'name', width: 170, ellipsis: true },
  { title: '分组字段', key: 'group', width: 120 },
  { title: '计量口径', key: 'metric', width: 142 },
  { title: '窗口 / 阈值', key: 'window', width: 150 },
  { title: '状态', key: 'active', width: 120 },
  { title: '修订', dataIndex: 'revision', width: 80 },
  { title: '保存时间', key: 'created', width: 180 },
  { title: '操作', key: 'actions', width: 220, fixed: 'right' as const },
];
</script>
<template>
  <ListTable :columns="columns" :data-source="rows" :scroll="{ x: 1322 }"
    ><template #bodyCell="{ column, record }"
      ><button
        v-if="column.key === 'name'"
        type="button"
        class="record-link"
        :title="record.name"
        @click="emit('inspect', record)"
      >
        {{ record.name }}</button
      ><template v-else-if="column.key === 'group'">{{ correlationFields[record.definition.group_by] }}</template>
      <template v-else-if="column.key === 'metric'">{{
        record.definition.metric === 'count'
          ? '唯一告警条数'
          : '不同' + correlationFields[record.definition.distinct_field] + '数量'
      }}</template><template v-else-if="column.key === 'window'"
        >{{ record.definition.window_seconds }} 秒 / {{ record.definition.threshold }}</template
      ><StatusTag
        v-else-if="column.key === 'active'"
        :tone="record.active ? 'success' : 'neutral'"
        :value="record.active ? '允许回测' : '停用'"
      />
      <template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
      <div v-else-if="column.key === 'actions'" class="table-row-actions">
        <a-button type="link" size="small" @click="emit('inspect', record)">查看</a-button
        ><a-button v-if="canEdit" type="link" size="small" :disabled="disabled" @click="emit('edit', record)"
          >编辑</a-button
        ><a-button
          v-if="canEdit"
          type="link"
          size="small"
          :disabled="disabled || !record.active"
          @click="emit('backtest', record)"
          >窗口回测</a-button
        >
      </div></template
    ></ListTable
  >
</template>
