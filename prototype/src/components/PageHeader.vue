<script setup lang="ts">
import {computed} from 'vue'
import {QuestionCircleOutlined} from '@ant-design/icons-vue'
import {helpEntries} from '../composables/pageHelp'

// 页面标题一行：标题、说明入口、页面动作。页面说明和静态提示只在“说明”里出现，不常驻。
const props = defineProps<{title: string; description?: string; notice?: string}>()
const hasHelp = computed(() => Boolean(props.description || props.notice || helpEntries.value.length))
</script>

<template>
  <div class="page-header">
    <div class="page-heading">
      <h1>{{ title }}</h1>
      <a-popover v-if="hasHelp" placement="bottomLeft" :trigger="['hover', 'click']">
        <template #content>
          <div class="page-help">
            <p v-if="description">{{ description }}</p>
            <p v-if="notice">{{ notice }}</p>
            <p v-for="entry in helpEntries" :key="entry.id">
              <b v-if="entry.description">{{ entry.message }}</b>
              <template v-if="entry.description"> {{ entry.description }}</template>
              <template v-else>{{ entry.message }}</template>
            </p>
          </div>
        </template>
        <button class="page-help-trigger" type="button" :aria-label="`${title}的说明`">
          <QuestionCircleOutlined />
        </button>
      </a-popover>
    </div>
    <div class="page-header-actions"><slot /></div>
  </div>
</template>
