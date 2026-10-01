import type { App } from 'vue'
import { Alert, Button, ConfigProvider, Drawer, Empty, Form, Input, Layout, Menu, Space, Spin } from 'ant-design-vue'

export function registerAnt(app: App) {
  for (const component of [Alert, Button, ConfigProvider, Drawer, Empty, Form, Input, Layout, Menu, Space, Spin]) app.use(component)
  return app
}
