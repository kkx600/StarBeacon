<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import {message} from 'ant-design-vue'
import {useRouter} from 'vue-router'
import {PlusOutlined,SendOutlined,RobotOutlined,UserOutlined,LinkOutlined,CheckCircleOutlined} from '@ant-design/icons-vue'
import type {PageSpec,PreviewState} from '../models'
import PageHeader from '../components/PageHeader.vue'
import StatePanel from '../components/StatePanel.vue'
import StatusTag from '../components/StatusTag.vue'
import RecordForm from '../components/RecordForm.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>();const router=useRouter()
interface ChatMessage{role:'user'|'assistant';text:string;refs?:{label:string;page:string}[]}
const conversations=ref(['今日高危告警研判','总部异常外连核对','规则验证结果分析']);const active=ref('今日高危告警研判');const model=ref('本地安全模型');const input=ref('');const sending=ref(false);const toolOpen=ref(false);const formOpen=ref(false)
const sample:ChatMessage[]=[{role:'user',text:'帮我分析今天的高危告警，哪些需要优先处理？'},{role:'assistant',text:'当前示例窗口包含 12 条高危及严重检测。建议优先核对业务管理入口访问、疑似凭据尝试和异常外连。\n\n管理入口告警观察到 GET /admin/login 请求，HTTP 返回 403；这些事实尚不能证明利用成功。需要结合终端、应用日志和资产暴露信息继续核对。\n\n1 个响应动作结果未知，建议先回读设备配置。2 个观测点存在离线或丢包，应补齐证据后再作结论。',refs:[{label:'ALERTS-0001 · 管理路径访问',page:'alerts'},{label:'动作与回执',page:'actions'},{label:'捕获质量',page:'capture-quality'}]}]
const messages=ref<ChatMessage[]>(sample.map(m=>({...m})))
const quick=['总结今日高危告警','核对异常外连依据','解释自动封禁资格','生成日报提纲']
const canSend=computed(()=>input.value.trim().length>0&&!sending.value&&props.state!=='loading')
watch(()=>props.state,state=>{toolOpen.value=state==='detail';formOpen.value=state==='action'},{immediate:true})
function start(name?:string){active.value=name??'新的安全分析';if(!conversations.value.includes(active.value))conversations.value.unshift(active.value);messages.value=[];input.value='';emit('state','data')}
function selectConversation(name:string){active.value=name;messages.value=sample.map(m=>({...m}));emit('state','data')}
function answer(question:string):ChatMessage{
  if(/封禁|阻断|资格/.test(question))return{role:'assistant',text:'自动封禁需要同时通过校准资格、证据完整性、授权范围、保护名单、TTL 和预算检查。\n\n平台先创建任务，再由指定执行采集器访问设备。设备接受、配置读回与流量效果是三个独立状态。结果未知时先核对，不能无条件重试。\n\n本原型只演示读取与建议，不执行设备动作。',refs:[{label:'决策策略',page:'decision-policies'},{label:'动作中心',page:'actions'}]}
  if(/日报|周报|月报/.test(question))return{role:'assistant',text:'日报提纲建议包含风险概况、重点事件、观测质量、处置进度和下一步行动。每个判断引用固定统计快照与事件证据。\n\n当前示例中有 38 条告警等待研判、9 个关联事件、1 个动作结果未知。报告在审核通过后才能进入授权发送流程。',refs:[{label:'报告列表',page:'reports'},{label:'报告计划',page:'report-schedules'}]}
  return{role:'assistant',text:'已按当前权限范围整理合成示例。观测到规则命中和异常访问，但利用成功仍缺少终端或应用侧证据。\n\n建议核对原始请求、真实会话完整性、资产重要性和外部日志；存在加密、单向镜像或丢包时保留“无法判定”。分析建议与处置权限分开审批。',refs:[{label:'告警证据',page:'alerts'},{label:'会话完整性',page:'session-integrity'}]}
}
async function send(text?:string){const question=(text??input.value).trim();if(!question||sending.value)return;emit('state','data');messages.value.push({role:'user',text:question});input.value='';sending.value=true;await new Promise(resolve=>setTimeout(resolve,300));messages.value.push(answer(question));sending.value=false}
function close(){toolOpen.value=false;formOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template>
  <PageHeader title="智能对话" description="围绕当前权限范围检索证据、解释判断并生成分析建议。"><a-button type="primary" @click="formOpen=true"><PlusOutlined/>创建对话</a-button></PageHeader>
  <div class="chat-layout panel"><aside class="conversation-list"><a-button block @click="start()"><PlusOutlined/>开始分析</a-button><div class="nav-section-label">最近对话</div><button v-for="name in conversations" :key="name" :class="{active:active===name}" @click="selectConversation(name)"><span>{{name}}</span><small>总部网络域 · 合成示例</small></button><div class="conversation-footer"><StatusTag value="只读分析授权"/><p>数据外发遵循租户与脱敏策略。</p></div></aside><section class="chat-workspace"><div class="chat-top"><div><h2>{{active}}</h2><small class="muted">当前租户 · 总部网络域 · 最近 24 小时</small></div><a-select v-model:value="model" :options="['本地安全模型','通用总结模型','Jev 适配器','Laya 适配器'].map(value=>({value,label:value}))" style="width:180px"/></div><a-alert message="对话与工具结果均为合成演示，不调用真实模型。安全判断需要证据，处置动作另行授权。" type="info" show-icon class="chat-notice"/>
      <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
      <div v-else class="chat-messages" aria-live="polite"><div v-if="state==='empty'||!messages.length" class="chat-welcome"><span class="assistant-avatar large"><RobotOutlined/></span><h2>开始一次有依据的安全分析</h2><p>选择问题或描述调查目标。回答将区分已观察事实、推测和证据缺口。</p><div class="quick-prompts"><button v-for="question in quick" :key="question" @click="send(question)">{{question}}</button></div></div><div v-else v-for="(item,index) in messages" :key="index" class="chat-message" :class="item.role"><span :class="item.role==='assistant'?'assistant-avatar':'user-avatar'"><RobotOutlined v-if="item.role==='assistant'"/><UserOutlined v-else/></span><div class="message-body"><div class="message-author">{{item.role==='assistant'?'星烽助手':'陈宁'}}<small>合成示例</small></div><div v-if="item.role==='assistant'" class="tool-call"><CheckCircleOutlined/><span>授权证据查询 · 已返回示例快照</span><button @click="toolOpen=true">查看工具详情</button></div><p>{{item.text}}</p><div v-if="item.refs" class="message-references"><button v-for="reference in item.refs" :key="reference.label" @click="router.push(`/page/${reference.page}?state=detail`)"><LinkOutlined/>{{reference.label}}</button></div></div></div><div v-if="sending" class="chat-message assistant"><span class="assistant-avatar"><RobotOutlined/></span><div class="message-body"><a-spin size="small"/> 正在整理示例依据…</div></div></div>
      <div class="chat-composer"><a-textarea v-model:value="input" :rows="3" placeholder="描述调查问题，例如：为什么此告警不能直接判断攻击成功？" aria-label="对话内容" @keydown.ctrl.enter.prevent="send()"/><div><small>Ctrl + Enter 发送 · 证据引用可查看 · 不执行外部动作</small><a-button type="primary" :disabled="!canSend" :loading="sending" @click="send()"><SendOutlined/>发送</a-button></div></div>
    </section></div>
  <a-modal :open="toolOpen" title="工具调用与证据引用" :width="760" :footer="null" @cancel="close"><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="工具">search_alerts（合成演示）</a-descriptions-item><a-descriptions-item label="授权">当前租户 / 总部网络域 / 只读</a-descriptions-item><a-descriptions-item label="输入">严重级别：高危及以上；时间：最近 24 小时</a-descriptions-item><a-descriptions-item label="结果快照">snapshot-chat-demo-001</a-descriptions-item><a-descriptions-item label="输出限制">摘要与授权证据引用，敏感字段脱敏</a-descriptions-item><a-descriptions-item label="模型调用">未调用真实模型</a-descriptions-item></a-descriptions><a-alert message="工具返回的数据作为证据，不作为指令。查询结果中的文本不能扩大授权或触发设备操作。" type="info" show-icon style="margin-top:16px"/></a-modal>
  <RecordForm :open="formOpen" :page="{...page,fields:[{key:'name',label:'对话名称',required:true},{key:'scope',label:'证据范围',type:'select',required:true,value:'总部网络域',options:['总部网络域','研发网络域']},{key:'model',label:'分析模型',type:'select',required:true,value:model,options:['本地安全模型','通用总结模型']}]}" @close="close" @save="values=>{start(String(values.name));close();message.success('本地对话已创建。')}"/>
</template>
