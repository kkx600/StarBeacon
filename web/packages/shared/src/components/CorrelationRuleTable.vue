<script setup lang="ts">
import {computed} from 'vue'
import {Table as ATable,Tag as ATag} from 'ant-design-vue'
import {correlationFields,type CorrelationRule} from '../correlation'
import {formatTime} from '../types'
const props=defineProps<{items:readonly CorrelationRule[];canEdit:boolean;disabled?:boolean}>()
const emit=defineEmits<{inspect:[rule:CorrelationRule];edit:[rule:CorrelationRule];backtest:[rule:CorrelationRule]}>()
const rows=computed(()=>[...props.items])
const columns=[{title:'规则',key:'name',width:220},{title:'分组 / 计量',key:'group',width:220},{title:'窗口 / 阈值',key:'window',width:150},{title:'状态',key:'active',width:120},{title:'修订',dataIndex:'revision',width:80},{title:'保存时间',key:'created',width:180},{title:'操作',key:'actions',width:220,fixed:'right' as const}]
</script>
<template><div class="table-wrap"><a-table :columns="columns" :data-source="rows" row-key="id" size="small" :pagination="false" :scroll="{x:1290}"><template #bodyCell="{column,record}"><template v-if="column.key==='name'"><strong class="correlation-id">{{record.name}}</strong><div class="page-description technical correlation-id">{{record.id}}</div></template><template v-else-if="column.key==='group'">{{correlationFields[record.definition.group_by]}}<div class="page-description">{{record.definition.metric==='count'?'唯一告警条数':'不同'+correlationFields[record.definition.distinct_field]+'数量'}}</div></template><template v-else-if="column.key==='window'">{{record.definition.window_seconds}} 秒 / {{record.definition.threshold}}</template><a-tag v-else-if="column.key==='active'" :color="record.active?'success':undefined">{{record.active?'允许回测':'停用'}}</a-tag><template v-else-if="column.key==='created'">{{formatTime(record.created_at)}}</template><div v-else-if="column.key==='actions'" class="correlation-actions"><a-button type="link" size="small" @click="emit('inspect',record as CorrelationRule)">查看</a-button><a-button v-if="canEdit" type="link" size="small" :disabled="disabled" @click="emit('edit',record as CorrelationRule)">编辑</a-button><a-button v-if="canEdit" type="link" size="small" :disabled="disabled||!record.active" @click="emit('backtest',record as CorrelationRule)">窗口回测</a-button></div></template></a-table></div></template>
<style scoped>.correlation-actions{display:flex;gap:4px;flex-wrap:wrap}.correlation-id{overflow-wrap:anywhere}</style>
