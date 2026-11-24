<script setup lang="ts">
import { shallowRef, useId } from 'vue';
import { QuestionCircleOutlined } from '@ant-design/icons-vue';
import { Popover as APopover } from 'ant-design-vue';

defineProps<{ title: string }>();
const open = shallowRef(false);
const contentId = useId();
</script>

<template>
  <a-popover v-model:open="open" placement="bottomLeft" :trigger="['hover', 'click']">
    <template #content>
      <div :id="contentId" class="page-help"><slot /></div>
    </template>
    <button
      class="page-help-trigger"
      type="button"
      :aria-label="`${title}的说明`"
      :aria-expanded="open"
      :aria-controls="open ? contentId : undefined"
      @keydown.esc.stop="open = false"
    >
      <QuestionCircleOutlined aria-hidden="true" />
    </button>
  </a-popover>
</template>

<style scoped>
.page-help-trigger {
  display: inline-grid;
  place-items: center;
  flex: none;
  width: 24px;
  height: 24px;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: var(--muted);
  font-size: 16px;
  cursor: pointer;
}
.page-help-trigger:hover,
.page-help-trigger[aria-expanded='true'] {
  color: var(--link);
  background: var(--row-hover);
}
.page-help {
  display: flex;
  flex-direction: column;
  gap: var(--related-gap);
  max-width: 420px;
  color: var(--text);
  font-size: 13px;
  line-height: 1.7;
}
.page-help > :slotted(p) {
  margin: 0;
}
</style>
