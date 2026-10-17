import {App, message} from 'ant-design-vue'

// 应用内消息继承 ConfigProvider；独立挂载组件继续使用组件库默认消息。
export function useFeedback() {
  const api = App.useApp().message
  return typeof api.open === 'function' ? api : message
}
