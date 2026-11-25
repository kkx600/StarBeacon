<script setup lang="ts">
import { computed, reactive, shallowRef, watch } from 'vue';
import { Descriptions as ADescriptions, InputNumber as AInputNumber, Select as ASelect } from 'ant-design-vue';
const ADescriptionsItem = ADescriptions.Item;
import {
  retentionModes,
  retentionOrigins,
  validRetentionPolicy,
  type PacketRetentionChange,
  type PacketRetentionObservation,
  type RetentionMode,
} from '../packetRetention';

const props = defineProps<{
  observation: PacketRetentionObservation;
  saving?: boolean;
  disabled?: boolean;
  remote?: boolean;
}>();
const emit = defineEmits<{ save: [change: PacketRetentionChange] }>();
const base = shallowRef(props.observation);
const draft = reactive<{
  mode: RetentionMode;
  encrypted: number | undefined;
  plain: number | undefined;
  dedup: number | undefined;
  protect: string;
  observe: string;
}>({ mode: 'smart', encrypted: undefined, plain: undefined, dedup: undefined, protect: '', observe: '' });
const error = shallowRef('');
const options = Object.entries(retentionModes).map(([value, label]) => ({ value, label }));
const asList = (input: string) => input.trim().split(/\s+/).filter(Boolean);
const current = computed(() => props.observation.policy);
const changed = (source: PacketRetentionObservation) => {
  const policy = source.policy;
  return (
    draft.mode !== policy.mode ||
    draft.encrypted !== policy.encrypted_bytes ||
    draft.plain !== policy.plain_bytes ||
    draft.dedup !== policy.dedup_millis ||
    asList(draft.protect).join(' ') !== (policy.protect ?? []).join(' ') ||
    asList(draft.observe).join(' ') !== (policy.observe ?? []).join(' ')
  );
};
const stale = computed(() => base.value.sha256 !== props.observation.sha256);
const dirty = computed(() => changed(base.value));
const blocked = computed(
  () => props.saving || props.disabled || stale.value || current.value.revision >= Number.MAX_SAFE_INTEGER,
);

function reset() {
  base.value = props.observation;
  const policy = current.value;
  Object.assign(draft, {
    mode: policy.mode,
    encrypted: policy.encrypted_bytes,
    plain: policy.plain_bytes,
    dedup: policy.dedup_millis,
    protect: (policy.protect ?? []).join('\n'),
    observe: (policy.observe ?? []).join('\n'),
  });
  error.value = '';
}
reset();
watch(
  () => props.observation.sha256,
  () => {
    // 更新观测时保留尚未提交的草稿，除非观测内容与刚提交的配置一致。
    if (!dirty.value || !changed(props.observation)) reset();
  },
);

function save() {
  if (blocked.value || !dirty.value) return;
  const policy = {
    network_domain: base.value.policy.network_domain,
    revision: base.value.policy.revision + 1,
    mode: draft.mode,
    encrypted_bytes: draft.encrypted,
    plain_bytes: draft.plain,
    dedup_millis: draft.dedup,
    protect: asList(draft.protect),
    observe: asList(draft.observe),
  };
  if (!validRetentionPolicy(policy)) {
    error.value = '请核对字节预算、去重窗口和 CIDR 网段。每个名单最多 128 项，且不能重复。';
    return;
  }
  error.value = '';
  emit('save', { expected_revision: base.value.policy.revision, expected_sha256: base.value.sha256, policy });
}
</script>

<template>
  <ADescriptions :column="2" size="small" class="section-gap">
    <ADescriptionsItem label="网络域"
      ><span class="technical">{{ current.network_domain }}</span></ADescriptionsItem
    >
    <ADescriptionsItem label="当前修订"
      >{{ current.revision }} · {{ retentionOrigins[observation.origin] }}</ADescriptionsItem
    >
  </ADescriptions>
  <a-alert
    v-if="stale"
    type="warning"
    show-icon
    class="section-gap"
    message="采集器已有新修订，请载入当前配置后再修改。"
  >
    <template #action><a-button size="small" :disabled="saving" @click="reset">载入当前配置</a-button></template>
  </a-alert>
  <a-form layout="vertical" :model="draft" @finish="save">
    <div class="retention-fields">
      <a-form-item label="原包留存策略" html-for="retention-mode">
        <ASelect id="retention-mode" v-model:value="draft.mode" :options="options" :disabled="blocked" />
      </a-form-item>
      <a-form-item label="镜像去重窗口（毫秒）" html-for="retention-dedup" extra="0 为关闭，启用时填写 10–500。">
        <AInputNumber
          id="retention-dedup"
          :value="draft.dedup"
          @update:value="value => (draft.dedup = typeof value === 'number' ? value : undefined)"
          :min="0"
          :max="500"
          :precision="0"
          :disabled="blocked || draft.mode !== 'smart'"
        />
      </a-form-item>
      <a-form-item label="加密流每方向字节" html-for="retention-encrypted" extra="握手后保留 0–1 MiB。">
        <AInputNumber
          id="retention-encrypted"
          :value="draft.encrypted"
          @update:value="value => (draft.encrypted = typeof value === 'number' ? value : undefined)"
          :min="0"
          :max="1048576"
          :precision="0"
          :disabled="blocked || draft.mode !== 'smart'"
        />
      </a-form-item>
      <a-form-item label="明文大传输每方向字节" html-for="retention-plain" extra="保留 64 KiB–64 MiB。">
        <AInputNumber
          id="retention-plain"
          :value="draft.plain"
          @update:value="value => (draft.plain = typeof value === 'number' ? value : undefined)"
          :min="65536"
          :max="67108864"
          :precision="0"
          :disabled="blocked || draft.mode !== 'smart'"
        />
      </a-form-item>
      <a-form-item label="保护网段" html-for="retention-protect">
        <a-textarea
          id="retention-protect"
          v-model:value="draft.protect"
          :rows="2"
          :maxlength="6144"
          placeholder="每行一个 CIDR 网段"
          :disabled="blocked || draft.mode !== 'smart'"
        />
      </a-form-item>
      <a-form-item label="观察网段" html-for="retention-observe">
        <a-textarea
          id="retention-observe"
          v-model:value="draft.observe"
          :rows="2"
          :maxlength="6144"
          placeholder="每行一个 CIDR 网段"
          :disabled="blocked || draft.mode !== 'smart'"
        />
      </a-form-item>
    </div>
    <a-alert v-if="error" type="error" show-icon class="section-gap" :message="error" />
    <div class="filter-actions">
      <a-button type="primary" html-type="submit" :loading="saving" :disabled="blocked || !dirty">
        {{ remote ? '下发留存策略' : '保存留存策略' }}
      </a-button>
      <a-button :disabled="saving || !dirty" @click="reset">重置</a-button>
    </div>
  </a-form>
</template>

<style scoped>
.retention-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: var(--panel-inset);
}
.retention-fields :deep(.ant-input-number) {
  width: 100%;
}
</style>
