<script setup lang="ts">
import { Modal as AModal, Select as ASelect, InputNumber as AInputNumber, Checkbox as ACheckbox } from 'ant-design-vue'
import type { useRuleRelease } from './useRuleRelease'
defineProps<{ release: ReturnType<typeof useRuleRelease> }>()
</script>
<template>
  <a-modal title="规则发布与回滚" :open="release.selected.value !== null" :width="760" :footer="null" :closable="!release.submitting.value" :mask-closable="!release.submitting.value" :keyboard="!release.submitting.value" @cancel="release.close">
    <template v-if="release.selected.value">
      <p class="page-description section-gap">{{ release.selected.value.name }} · 固定修订 · Suricata {{ release.selected.value.engine_version }}</p>
      <a-alert type="info" show-icon message="先选择单个探针验证生效，再对其他探针逐台推进。" class="section-gap"><template #description>需要一天内同一探针的装载、命中和未命中回执，样本摘要必须不同。平台重新核对配置与规则摘要；设备原生回读后才确认成功。选择经过验证的历史修订可执行回滚，离线样本不证明所有线上流量的检测效果。</template></a-alert>
      <a-alert v-if="release.error.value" type="error" show-icon :message="release.error.value" class="section-gap" />
      <a-alert v-if="release.taskID.value" type="success" show-icon message="发布任务已受理" class="section-gap"><template #description>任务 <span class="technical">{{ release.taskID.value }}</span>，<router-link to="/sensors?view=tasks">查看设备执行回执</router-link>。受理不等于规则已生效。</template></a-alert>
      <a-form layout="vertical" :disabled="release.submitting.value || !!release.taskID.value">
        <a-form-item label="目标探针" html-for="release-sensor" required><a-select id="release-sensor" v-model:value="release.form.sensorID" :options="release.options.value" :loading="release.pending.value" :disabled="release.submitting.value || !!release.taskID.value" placeholder="选择在线且允许规则部署的探针" @change="release.loadEvidence" /></a-form-item>
        <a-form-item label="规则修订" html-for="release-revision" required><a-input-number id="release-revision" v-model:value="release.form.revision" :min="1" :max="release.selected.value.revision" :precision="0" :disabled="release.pending.value || release.submitting.value || !!release.taskID.value" @change="release.loadEvidence" /><small class="record-id">修订 1–{{ release.selected.value.revision }}；历史修订需要提供该修订的有效验证回执。</small></a-form-item>
        <a-form-item label="登记规则文件摘要"><span class="technical" style="overflow-wrap:anywhere">{{ release.expectedSHA.value || '未观察到有效摘要' }}</span></a-form-item>
        <a-form-item label="装载检查回执" html-for="release-validation" required><a-select id="release-validation" v-model:value="release.form.validation" :options="release.validations.value" :loading="release.pending.value" :disabled="release.pending.value || release.submitting.value || !!release.taskID.value" placeholder="选择同一修订的成功装载检查" @change="release.changed" /></a-form-item>
        <a-form-item label="命中样本回执" html-for="release-positive" required><a-select id="release-positive" v-model:value="release.form.positive" :options="release.positives.value" :loading="release.pending.value" :disabled="release.pending.value || release.submitting.value || !!release.taskID.value" placeholder="选择完整执行且产生预期命中的样本" @change="release.changed" /></a-form-item>
        <a-form-item label="未命中样本回执" html-for="release-negative" required><a-select id="release-negative" v-model:value="release.form.negative" :options="release.negatives.value" :loading="release.pending.value" :disabled="release.pending.value || release.submitting.value || !!release.taskID.value" placeholder="选择完整执行且零命中的独立样本" @change="release.changed" /></a-form-item>
        <a-form-item><a-checkbox v-model:checked="release.form.confirmed">确认将选定修订部署至该探针，并核对两份样本的预期检测结果。</a-checkbox></a-form-item>
        <a-button type="primary" :loading="release.submitting.value" :disabled="release.pending.value || !!release.taskID.value" @click="release.submit">提交发布任务</a-button>
      </a-form>
    </template>
  </a-modal>
</template>
