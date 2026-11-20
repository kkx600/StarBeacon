<script setup lang="ts">
import {nextTick, ref} from 'vue'
import {useRouter} from 'vue-router'
import {SendOutlined} from '@ant-design/icons-vue'

// 全局 AI 助手：任何页面都能唤起，自动带入当前页面作为上下文。
// 原型里的回复是固定的合成示例，不调用模型。
const props = defineProps<{open: boolean; context: string}>()
const emit = defineEmits<{'update:open': [value: boolean]}>()
const router = useRouter()

interface Message {
  role: 'user' | 'assistant'
  text: string
  actions?: {label: string; path: string}[]
}
const messages = ref<Message[]>([{role: 'assistant', text: '我可以研判告警、给出处置方案、生成自动化编排和联动插件。当前上下文已带入。'}])
const input = ref('')
const body = ref<HTMLElement>()

const quick = [
  {label: '研判当前告警', reply: '研判 ALERTS-0001：来源 198.51.100.24 在 10 分钟内访问 14 个管理路径，命中 3 次规则，情报标记为扫描器；没有终端日志，无法判断是否利用成功。结论：真实攻击（94%）。建议：封禁来源 2 小时，并通知资产负责人。', actions: [{label: '去 AI 值守确认', path: '/page/ai-ops'}]},
  {label: '生成处置编排', reply: '已按“高危 Web 攻击”生成编排草稿：AI 研判 → 核对保护名单 → 旁路阻断当前连接 → 防火墙封禁 2 小时 → 回读核验 → 通知值班组 → 到期解除。', actions: [{label: '打开编排', path: '/page/playbooks'}]},
  {label: '生成联动插件', reply: '请把设备接口文档里登录、黑名单和告警查询的部分贴给我，或直接在联动插件页使用“AI 生成插件”。生成后先在沙箱试运行，再签名下发到采集器。', actions: [{label: '打开联动插件', path: '/page/auth-plugins'}]},
  {label: '解释本页数据', reply: '本页的数字来自当前租户和所选时间范围。带“—”的表示没有观测数据，不代表数值为零。'},
]

async function push(question: string, reply: string, actions?: Message['actions']) {
  messages.value.push({role: 'user', text: question}, {role: 'assistant', text: reply, actions})
  await nextTick()
  body.value?.scrollTo({top: body.value.scrollHeight})
}
function send() {
  const text = input.value.trim()
  if (!text) return
  input.value = ''
  void push(text, '这是合成示例回复。实际环境里我会先检索你有权限的数据，再给出带证据引用的回答；涉及设备的动作都要经过授权。')
}
function go(path: string) {
  emit('update:open', false)
  void router.push(path)
}
</script>

<template>
  <a-drawer :open="props.open" title="AI 助手" placement="right" :width="420" @close="emit('update:open', false)">
    <div class="copilot">
      <div class="copilot-context">当前页面：<b>{{ context }}</b></div>
      <div class="copilot-quick">
        <button v-for="item in quick" :key="item.label" type="button" @click="push(item.label, item.reply, item.actions)">{{ item.label }}</button>
      </div>
      <div ref="body" class="copilot-body">
        <div v-for="(item, index) in messages" :key="index" class="copilot-message" :class="item.role">
          <p>{{ item.text }}</p>
          <a-space v-if="item.actions" wrap>
            <a-button v-for="action in item.actions" :key="action.path" size="small" @click="go(action.path)">{{ action.label }}</a-button>
          </a-space>
        </div>
      </div>
      <div class="copilot-input">
        <a-textarea v-model:value="input" :auto-size="{minRows: 2, maxRows: 5}" placeholder="问我关于当前页面或任何告警的问题" @press-enter.prevent="send" />
        <a-button type="primary" aria-label="发送" @click="send"><SendOutlined /></a-button>
      </div>
    </div>
  </a-drawer>
</template>

<style scoped>
.copilot {
  display: flex;
  flex-direction: column;
  gap: var(--section-gap);
  height: 100%;
}
.copilot-context {
  color: var(--muted);
  font-size: 12px;
}
.copilot-context b {
  color: var(--text);
  font-weight: 500;
}
.copilot-quick {
  display: flex;
  flex-wrap: wrap;
  gap: var(--related-gap);
}
.copilot-quick button {
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text);
  padding: 4px 10px;
  font-size: 12px;
  line-height: 20px;
}
.copilot-quick button:hover {
  border-color: var(--primary);
  color: var(--link);
}
.copilot-body {
  flex: 1;
  min-height: 0;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: var(--section-gap);
}
.copilot-message {
  max-width: 92%;
  padding: 8px 12px;
  border-radius: 8px;
  background: var(--table-header);
  font-size: 13px;
  line-height: 1.7;
}
.copilot-message.user {
  align-self: flex-end;
  background: var(--selection-surface);
}
.copilot-message p {
  margin: 0 0 6px;
}
.copilot-message p:last-child {
  margin: 0;
}
.copilot-input {
  display: flex;
  gap: var(--related-gap);
  align-items: flex-end;
}
</style>
