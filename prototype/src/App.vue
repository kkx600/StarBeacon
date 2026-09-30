<script setup lang="ts">
import { computed,watch } from 'vue'
import { useRoute } from 'vue-router'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import dayjs from 'dayjs'
import 'dayjs/locale/zh-cn'
import ConsoleLayout from './layouts/ConsoleLayout.vue'

dayjs.locale('zh-cn')
const route=useRoute()
const standalone=computed(()=>route.path.startsWith('/auth/'))
// 导出截图时冻结过渡，避免捕获到弹窗的中间帧；不改变业务状态。
watch(()=>route.query.capture,value=>document.documentElement.classList.toggle('capture-mode',value==='1'),{immediate:true})
const theme={token:{colorPrimary:'#2563eb',colorInfo:'#2563eb',colorSuccess:'#15803d',colorWarning:'#b45309',colorError:'#b91c1c',colorText:'#1f2937',colorTextSecondary:'#596579',colorTextPlaceholder:'#65758b',borderRadius:6,fontFamily:'-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',fontSize:14,controlHeight:34},components:{Table:{headerBg:'#f8fafc',cellPaddingBlock:12,cellPaddingInline:14},Modal:{borderRadiusLG:8}}}
</script>

<template>
  <a-config-provider :locale="zhCN" :theme="theme">
    <a-app>
      <router-view v-if="standalone" />
      <ConsoleLayout v-else><router-view /></ConsoleLayout>
    </a-app>
  </a-config-provider>
</template>
