<script setup lang="ts">
import { onScopeDispose, reactive, shallowRef } from 'vue';
import { Checkbox, Modal as AModal, Radio } from 'ant-design-vue';
import {
  entryLabels,
  type PluginDraft,
  type PluginEntry,
  type PluginExample,
  type PluginKind,
  type PluginTemplate,
  type PluginVersion,
} from '@starbeacon/shared/responsePlugins.ts';
import { session } from '../../session';

const ACheckboxGroup = Checkbox.Group;
const ARadioGroup = Radio.Group;
const ARadioButton = Radio.Button;

const props = defineProps<{ version?: PluginVersion }>();
const emit = defineEmits<{ close: []; saved: [PluginVersion] }>();
const sampleTemplate = {
  schema_version: 'response.template.v1',
  health: { method: 'GET', path: '/health', accept: { status: [200], field: 'healthy', equals: true } },
};
const sampleScript = 'def health(ctx):\n    return http.get(ctx.base_url + "/health").json()["healthy"]\n';
const sampleExamples: PluginExample[] = [{ method: 'GET', path: '/health', status: 200, response: '{"healthy":true}' }];
const form = reactive({
  id: props.version?.id ?? '',
  name: props.version?.name ?? '',
  device: props.version?.device ?? '',
  kind: props.version?.kind ?? ('template' as PluginKind),
  template: JSON.stringify(props.version?.template ?? sampleTemplate, null, 2),
  source: props.version?.script?.source ?? sampleScript,
  entries: props.version?.script?.entries.slice() ?? (['health'] as PluginEntry[]),
  examples: JSON.stringify(props.version ? (props.version.examples ?? []) : sampleExamples, null, 2),
});
const entryOptions = Object.entries(entryLabels).map(([value, label]) => ({ value, label }));
const saving = shallowRef(false);
const error = shallowRef('');
let controller: AbortController | undefined;
let attempt: { body: string; key: string } | undefined;

function draft(): PluginDraft {
  const id = form.id.trim(),
    name = form.name.trim(),
    device = form.device.trim();
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) || !name || !device) throw new Error('请填写有效的编号、名称和适配设备。');
  const examples = JSON.parse(form.examples) as PluginExample[];
  if (!Array.isArray(examples)) throw new Error('设备样例须为 JSON 数组。');
  const body: PluginDraft = { id, name, device, expected_version: props.version?.version ?? 0, examples };
  if (form.kind === 'template') {
    const template = JSON.parse(form.template) as PluginTemplate;
    if (template?.schema_version !== 'response.template.v1') throw new Error('模板须使用 response.template.v1。');
    body.template = template;
  } else {
    if (!form.source.trim() || !form.entries.length) throw new Error('请填写 Starlark 源码并选择入口。');
    body.script = { source: form.source, entries: form.entries.slice() };
  }
  return body;
}

async function save() {
  if (saving.value) return;
  error.value = '';
  let body: PluginDraft;
  try {
    body = draft();
  } catch (cause) {
    error.value = cause instanceof SyntaxError ? '模板配置或样例的 JSON 格式无效。' : (cause as Error).message;
    return;
  }
  const fingerprint = JSON.stringify(body);
  if (attempt?.body !== fingerprint) attempt = { body: fingerprint, key: crypto.randomUUID() };
  const call = new AbortController();
  controller = call;
  saving.value = true;
  try {
    const version = await session.api.request<PluginVersion>('/response-plugins', {
      method: 'POST',
      body,
      headers: { 'Idempotency-Key': attempt.key },
      signal: call.signal,
    });
    if (!call.signal.aborted) emit('saved', version);
  } catch (cause) {
    if (!call.signal.aborted) error.value = cause instanceof Error ? cause.message : '插件草稿保存失败';
  } finally {
    if (controller === call) saving.value = false;
  }
}
onScopeDispose(() => controller?.abort());
</script>

<template>
  <a-modal
    :open="true"
    :title="version ? '编辑联动插件' : '新建联动插件'"
    :width="800"
    ok-text="保存草稿"
    cancel-text="取消"
    :confirm-loading="saving"
    :closable="!saving"
    :mask-closable="false"
    :keyboard="!saving"
    @ok="save"
    @cancel="!saving && emit('close')"
  >
    <a-alert v-if="error" :message="error" type="error" show-icon class="section-gap" />
    <a-form layout="vertical" :disabled="saving" @finish="save">
      <div class="plugin-fields">
        <a-form-item label="编号" required
          ><a-input v-model:value="form.id" aria-label="编号" :disabled="!!version" :maxlength="64"
        /></a-form-item>
        <a-form-item label="插件名称" required
          ><a-input v-model:value="form.name" aria-label="插件名称" :maxlength="128"
        /></a-form-item>
        <a-form-item label="适配设备" required
          ><a-input v-model:value="form.device" aria-label="适配设备" :maxlength="128"
        /></a-form-item>
      </div>
      <a-form-item label="形式">
        <a-radio-group v-model:value="form.kind">
          <a-radio-button value="template">模板</a-radio-button>
          <a-radio-button value="script">脚本</a-radio-button>
        </a-radio-group>
      </a-form-item>
      <a-form-item v-if="form.kind === 'template'" label="模板 JSON" required>
        <a-textarea
          v-model:value="form.template"
          aria-label="模板 JSON"
          class="technical"
          :rows="10"
          spellcheck="false"
        />
      </a-form-item>
      <template v-else>
        <a-form-item label="入口" required
          ><a-checkbox-group v-model:value="form.entries" :options="entryOptions"
        /></a-form-item>
        <a-form-item label="Starlark 源码" required>
          <a-textarea
            v-model:value="form.source"
            aria-label="Starlark 源码"
            class="technical"
            :rows="10"
            spellcheck="false"
          />
        </a-form-item>
      </template>
      <a-form-item label="模拟设备样例" extra="按请求发生顺序填写 JSON 数组。凭据只配置在采集器。" required>
        <a-textarea
          v-model:value="form.examples"
          aria-label="模拟设备样例"
          class="technical"
          :rows="6"
          spellcheck="false"
        />
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<style scoped>
.plugin-fields {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--related-gap);
}
@media (max-width: 600px) {
  .plugin-fields {
    grid-template-columns: 1fr;
    gap: 0;
  }
}
</style>
