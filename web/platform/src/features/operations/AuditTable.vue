<script setup lang="ts">
import { computed } from 'vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import type { AuditRecord } from '@starbeacon/shared/types.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { actionLabel } from './audits';
import type { AuditCategory } from './useAudits';
const props = defineProps<{ category: AuditCategory; records: AuditRecord[] }>();
const emit = defineEmits<{ view: [record: AuditRecord] }>();
const columns = computed(() => [
  { title: '日志编号', dataIndex: 'id', width: 146, className: 'technical', ellipsis: true },
  { title: '时间', key: 'time', width: 185 },
  { title: '账号', dataIndex: 'username', width: 150, ellipsis: true },
  ...(props.category === 'operations'
    ? [
        { title: '操作类型', key: 'action', width: 158, ellipsis: true },
        { title: '对象编号', dataIndex: 'object_id', width: 180, className: 'technical', ellipsis: true },
      ]
    : [{ title: '凭据验证结果', key: 'success', width: 140 }]),
  { title: '来源 IP', dataIndex: 'source_ip', width: 170, className: 'technical', ellipsis: true },
  { title: '操作', key: 'view', width: 68, fixed: 'right' as const },
]);
</script>
<template>
  <ListTable :columns="columns" :data-source="records" :scroll="{ x: category === 'operations' ? 1057 : 859 }"
    ><template #bodyCell="{ column, record }"
      ><span v-if="column.key === 'time'">{{ formatTime(record.created_at) }}</span
      ><span v-else-if="column.key === 'action'" :title="record.action">{{ actionLabel(record.action) }}</span
      ><StatusTag
        v-else-if="column.key === 'success'"
        :value="record.success === true ? '验证通过' : record.success === false ? '验证失败' : '未获取'"
        :tone="
          record.success === true
            ? statusTerms.已验证
            : record.success === false
              ? statusTerms.验证失败
              : statusTerms.无数据
        "
      /><button v-else-if="column.key === 'view'" class="link-button" @click="emit('view', record)">查看</button
      ><span
        v-else-if="
          column.dataIndex === 'source_ip' || column.dataIndex === 'object_id' || column.dataIndex === 'username'
        "
        >{{ record[column.dataIndex] || '未获取' }}</span
      ></template
    ></ListTable
  >
</template>
