<script setup lang="ts">
import { computed, useId } from 'vue';
import { FormItem as AFormItem, Input as AInput, Select as ASelect } from 'ant-design-vue';

const props = withDefaults(
  defineProps<{
    label?: string;
    presets?: readonly string[];
    idPrefix?: string;
    required?: boolean;
    endHint?: string;
  }>(),
  { label: '时间范围' },
);
const preset = defineModel<string>('preset');
const start = defineModel<string>('start');
const end = defineModel<string>('end');
const id = useId();
const fieldId = computed(() => props.idPrefix ?? id);
const options = computed(() => props.presets?.map(value => ({ value, label: value })));
</script>

<template>
  <div v-if="presets" class="filter-field">
    <label :for="fieldId">{{ label }}</label>
    <ASelect :id="fieldId" v-model:value="preset" :options="options" />
  </div>
  <template v-else>
    <AFormItem label="开始时间（本地时间）" :html-for="`${fieldId}-start`" :required="required">
      <AInput :id="`${fieldId}-start`" v-model:value="start" type="datetime-local" step="1" />
    </AFormItem>
    <AFormItem label="结束时间（本地时间）" :html-for="`${fieldId}-end`" :required="required" :extra="endHint">
      <AInput :id="`${fieldId}-end`" v-model:value="end" type="datetime-local" step="1" />
    </AFormItem>
  </template>
</template>
