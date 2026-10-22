import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import {fileURLToPath} from 'node:url'

export default defineConfig({
  plugins: [vue()],
  resolve: {dedupe: ['vue', 'vue-router', 'ant-design-vue'], alias: {'@ant-design/icons-vue':fileURLToPath(new URL('./packages/shared/node_modules/@ant-design/icons-vue',import.meta.url))}},
  test: {
    environment: 'jsdom',
    // DOM 与覆盖插桩共享计算资源；限制进程并发，避免负载争用影响真实超时断言。
    maxWorkers: 2,
    include: ['tests/**/*.test.ts'],
    setupFiles: ['tests/setup.ts'],
    restoreMocks: true,
    clearMocks: true,
    coverage: {
      provider: 'v8',
      include: ['platform/src/**/*.{ts,vue}', 'collector/src/**/*.{ts,vue}', 'packages/shared/src/**/*.{ts,mjs,vue}'],
      exclude: ['**/*.d.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      reportsDirectory: '../.local/acceptance/web-coverage',
      thresholds: { statements: 90, branches: 90, functions: 90, lines: 90 },
    },
  },
})
