<script setup lang="ts">
import { computed,watch } from 'vue'
import { useRoute } from 'vue-router'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import ConsoleLayout from './layouts/ConsoleLayout.vue'
import CollectorLayout from './layouts/CollectorLayout.vue'
import {appTheme} from './theme'

dayjs.locale('zh-cn')
const route=useRoute()
const standalone=computed(()=>route.path.startsWith('/auth/')||route.path.startsWith('/collector/auth/'))
const collector=computed(()=>route.path.startsWith('/collector/'))
// 导出截图时冻结过渡，避免捕获到弹窗的中间帧；不改变业务状态。
watch(()=>route.query.capture,value=>document.documentElement.classList.toggle('capture-mode',value==='1'),{immediate:true})
</script>

<template>
  <a-config-provider :locale="zhCN" :theme="appTheme">
    <a-app>
      <router-view v-if="standalone" />
      <CollectorLayout v-else-if="collector"><router-view /></CollectorLayout>
      <ConsoleLayout v-else><router-view /></ConsoleLayout>
    </a-app>
  </a-config-provider>
</template>
