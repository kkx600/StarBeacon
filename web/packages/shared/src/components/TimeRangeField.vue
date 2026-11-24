<script setup lang="ts" generic="Preset extends string | number = string">
import { computed, useId } from 'vue';
import { FormItem as AFormItem, Input as AInput, Select as ASelect } from 'ant-design-vue';

const props = withDefaults(
  defineProps<{
    label?: string;
    presets?: readonly string[];
    presetOptions?: readonly { label: string; value: Preset }[];
    idPrefix?: string;
    required?: boolean;
    startLabel?: string;
    endLabel?: string;
    endHint?: string;
    disabled?: boolean;
  }>(),
  { label: '时间范围', startLabel: '开始时间（本地时间）', endLabel: '结束时间（本地时间）' },
);
const preset = defineModel<Preset>('preset');
const start = defineModel<string>('start');
const end = defineModel<string>('end');
const id = useId();
const fieldId = computed(() => props.idPrefix ?? id);
const options = computed(() => props.presetOptions ?? props.presets?.map(value => ({ value, label: value })));
</script>

<template>
  <div v-if="options" class="filter-field">
    <label :for="fieldId">{{ label }}</label>
    <ASelect :id="fieldId" :aria-label="label" v-model:value="preset" :options="[...options]" :disabled="disabled" />
  </div>
  <template v-else>
    <AFormItem :label="startLabel" :html-for="`${fieldId}-start`" :required="required">
      <AInput :id="`${fieldId}-start`" v-model:value="start" type="datetime-local" step="1" :disabled="disabled" />
    </AFormItem>
    <AFormItem :label="endLabel" :html-for="`${fieldId}-end`" :required="required" :extra="endHint">
      <AInput :id="`${fieldId}-end`" v-model:value="end" type="datetime-local" step="1" :disabled="disabled" />
    </AFormItem>
  </template>
</template>
