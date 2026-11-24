<script setup lang="ts">
import { Modal, Descriptions, DescriptionsItem, Popconfirm } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import { deliveryNames, deliveryTones, receiptNames, streamNames, type Delivery } from './notifications';
defineProps<{ record: Delivery | null; busy: boolean }>();
const emit = defineEmits<{ close: []; retry: [record: Delivery] }>();
</script>
<template>
  <Modal
    :open="!!record"
    :width="700"
    :footer="null"
    :closable="!busy"
    :keyboard="!busy"
    :mask-closable="false"
    @cancel="emit('close')"
  >
    <template #title>
      <span class="heading-with-help"
        >推送日志详情
        <PageHelp title="渠道回执">
          <p>渠道受理只说明渠道已接手消息。是否已读、传输后是否落盘，请向接收渠道分别核对。</p>
          <p>结果待核实时，人工重试前须先查看接收记录。</p>
        </PageHelp>
      </span>
    </template>
    <template v-if="record"
      ><Descriptions :column="1" bordered size="small"
        ><DescriptionsItem label="投递标识"
          ><span class="technical">{{ record.id }}</span></DescriptionsItem
        ><DescriptionsItem label="通知渠道"
          >{{ record.channel_name }} · 修订 {{ record.channel_revision }}</DescriptionsItem
        ><DescriptionsItem label="接收目标"
          ><span class="technical">{{ record.recipient || '渠道目标' }}</span></DescriptionsItem
        ><DescriptionsItem label="处理状态"
          ><StatusTag
            :tone="statusTone(deliveryTones, record.state)"
            :value="deliveryNames[record.state]" /></DescriptionsItem
        ><DescriptionsItem label="内容类别">{{ streamNames[record.stream ?? 'alerts'] }}</DescriptionsItem
        ><DescriptionsItem label="记录数量">{{ record.record_count ?? record.alert_count }}</DescriptionsItem
        ><DescriptionsItem label="尝试次数">{{ record.attempts }}</DescriptionsItem
        ><DescriptionsItem label="渠道回执">{{
          record.receipt.code ? (receiptNames[record.receipt.code] ?? '渠道返回其他处理状态') : '尚未获取渠道回执'
        }}</DescriptionsItem
        ><template v-if="record.kind === 'syslog_tls' || record.kind === 'syslog_tcp'"
          ><DescriptionsItem label="计划发送帧数">{{ record.receipt.frames ?? '未获取' }}</DescriptionsItem
          ><DescriptionsItem label="完整写入帧数">{{
            record.receipt.frames_written ?? '未获取'
          }}</DescriptionsItem></template
        ><template v-else
          ><DescriptionsItem label="HTTP 状态">{{ record.receipt.http_status ?? '未获取' }}</DescriptionsItem
          ><DescriptionsItem label="业务代码">{{
            record.receipt.provider_code ?? '未获取'
          }}</DescriptionsItem></template
        ><DescriptionsItem label="执行耗时">{{
          record.receipt.duration_ms == null ? '未获取' : record.receipt.duration_ms + ' ms'
        }}</DescriptionsItem
        ><DescriptionsItem label="创建时间">{{ formatTime(record.created_at) }}</DescriptionsItem
        ><DescriptionsItem label="更新时间">{{ formatTime(record.updated_at) }}</DescriptionsItem></Descriptions
      ><a-alert
        v-if="
          (record.kind === 'syslog_tls' || record.kind === 'syslog_tcp') &&
          record.receipt.frames != null &&
          record.receipt.frames_written != null &&
          record.receipt.frames_written < record.receipt.frames
        "
        type="warning"
        :message="`已完整写入 ${record.receipt.frames_written} / ${record.receipt.frames} 帧。请核对日志服务器接收记录，重试可能重复发送已写入的帧。`"
        show-icon
        class="detail-notice"
      />
      <div v-if="record.state === 'failed' || record.state === 'uncertain'" class="filter-actions">
        <Popconfirm
          title="确认人工重试该投递？"
          description="渠道可能已经处理原请求。重试可能重复通知，请先核对接收记录。"
          ok-text="确认重试"
          cancel-text="取消"
          :disabled="busy"
          @confirm="emit('retry', record)"
          ><a-button type="primary" :loading="busy">人工重试</a-button></Popconfirm
        >
      </div></template
    ></Modal
  >
</template>
<style scoped>
.detail-notice {
  margin: var(--section-gap) 0;
}
</style>
