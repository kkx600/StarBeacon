import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: './',
  server: { host: '127.0.0.1', port: 4173, strictPort: true, fs: { deny: ['.env', '.env.*', '**/.git/**', '**/.impeccable/**', '**/PRODUCT.md', '**/DESIGN.md'] } },
  build: { target: 'es2022', chunkSizeWarningLimit: 1600 },
})
