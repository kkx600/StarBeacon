import { createApp } from 'vue'
import { registerAnt } from '@starbeacon/shared/ant.ts'
import 'ant-design-vue/dist/reset.css'
import '@starbeacon/shared/styles.css'
import { applyPalette } from '@starbeacon/shared/theme.ts'
import App from './App.vue'
import { router } from './router'
applyPalette()
registerAnt(createApp(App)).use(router).mount('#app')
