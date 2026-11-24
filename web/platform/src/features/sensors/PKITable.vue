<script setup lang="ts">
import { computed } from 'vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import {
  enrollmentStates,
  certificateStates,
  pkiStateTones,
  revocationStates,
  type Enrollment,
  type ProbeCertificate,
} from './pki';
const props = defineProps<{
  paginate?: boolean;
  mode: 'enrollments' | 'certificates';
  enrollments: Enrollment[];
  certificates: ProbeCertificate[];
  locked: boolean;
}>();
const emit = defineEmits<{
  view: [record: Enrollment | ProbeCertificate];
  revoke: [record: Enrollment | ProbeCertificate];
  certificates: [sensor: string];
}>();
const columns = computed(() =>
  props.mode === 'enrollments'
    ? [
        { title: '凭据编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
        { title: '探针标识', dataIndex: 'sensor_id', width: 150, className: 'technical', ellipsis: true },
        { title: '注册身份', dataIndex: 'registration_id', width: 150, className: 'technical', ellipsis: true },
        { title: '注册状态', key: 'state', width: 140 },
        { title: '注册截止时间', dataIndex: 'expires_at', width: 180 },
        { title: '操作', key: 'action', width: 220, fixed: 'right' as const },
      ]
    : [
        { title: '证书编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
        { title: '证书指纹', dataIndex: 'fingerprint_sha256', width: 190, className: 'technical', ellipsis: true },
        { title: '注册身份', dataIndex: 'registration_id', width: 145, className: 'technical', ellipsis: true },
        { title: '签发状态', key: 'state', width: 140 },
        { title: '证书到期时间', dataIndex: 'not_after', width: 180 },
        { title: 'CA 吊销确认', dataIndex: 'ca_revocation', width: 140 },
        { title: '操作', key: 'action', width: 160, fixed: 'right' as const },
      ],
);
const rows = computed<(Enrollment | ProbeCertificate)[]>(() =>
  props.mode === 'enrollments' ? props.enrollments : props.certificates,
);
function action(kind: 'view' | 'revoke', id: string) {
  const item = (props.mode === 'enrollments' ? props.enrollments : props.certificates).find(v => v.id === id);
  if (item) {
    if (kind === 'view') emit('view', item);
    else emit('revoke', item);
  }
}
function canRevoke(id: string) {
  if (props.mode === 'enrollments') {
    const row = props.enrollments.find(v => v.id === id);
    return !!row && !row.revoked && Date.parse(row.expires_at) > Date.now();
  }
  const row = props.certificates.find(v => v.id === id);
  return !!row && row.state === 'issued' && (!row.revoked_at || row.ca_revocation !== 'confirmed');
}
</script>
<template>
  <ListTable
    :columns="columns"
    :data-source="rows"
    :scroll="{ x: mode === 'enrollments' ? 980 : 1095 }"
    :pagination="paginate ? tablePagination() : false"
  >
    <template #bodyCell="{ column, record }">
      <div v-if="column.key === 'action'" class="table-row-actions">
        <a-button type="link" size="small" @click="action('view', record.id)">查看</a-button
        ><a-button
          v-if="mode === 'enrollments'"
          type="link"
          size="small"
          :disabled="locked"
          @click="emit('certificates', record.sensor_id)"
          >查看证书</a-button
        ><a-button
          v-if="canRevoke(record.id)"
          type="link"
          danger
          size="small"
          :disabled="locked"
          @click="action('revoke', record.id)"
          >{{ 'revoked' in record ? '撤销令牌' : record.revoked_at ? '重试 CA 吊销' : '吊销' }}</a-button
        >
      </div>
      <StatusTag
        v-else-if="column.key === 'state' && 'revoked_at' in record && record.revoked_at"
        tone="danger"
        value="平台已吊销"
      />
      <StatusTag
        v-else-if="column.key === 'state'"
        :tone="statusTone(pkiStateTones, record.state)"
        :value="('revoked' in record ? enrollmentStates : certificateStates)[record.state]"
      />
      <template v-else-if="column.dataIndex === 'expires_at' && 'expires_at' in record">{{
        formatTime(record.expires_at)
      }}</template>
      <template v-else-if="column.dataIndex === 'not_after' && 'not_after' in record">{{
        record.state === 'issued' ? formatTime(record.not_after) : '—'
      }}</template>
      <template v-else-if="column.dataIndex === 'ca_revocation' && 'ca_revocation' in record">{{
        revocationStates[record.ca_revocation]
      }}</template>
      <span
        v-else-if="column.dataIndex === 'fingerprint_sha256' && 'fingerprint_sha256' in record"
        :title="record.fingerprint_sha256 || undefined"
        >{{ record.fingerprint_sha256 || '尚未取得签发回执' }}</span
      >
    </template>
  </ListTable>
</template>
