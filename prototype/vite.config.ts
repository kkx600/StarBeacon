import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import {fileURLToPath} from 'node:url'

export default defineConfig({
  plugins: [vue()],
  base: '/',
  resolve: {dedupe:['vue','vue-router','ant-design-vue'],alias:{'@starbeacon/shared':fileURLToPath(new URL('../web/packages/shared/src',import.meta.url))}},
  server: { host: '127.0.0.1', port: 4173, strictPort: true, fs: { deny: ['.env', '.env.*', '**/.git/**', '**/.impeccable/**', '**/PRODUCT.md', '**/DESIGN.md'] } },
  build: { target: 'es2022', chunkSizeWarningLimit: 1600 },
})
