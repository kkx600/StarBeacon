<script setup lang="ts">
import {computed,reactive,ref} from 'vue'
const states={empty:'无研判记录',queued:'等待研判',running:'研判中',succeeded:'建议已生成',uncertain:'结果未知',cancelled:'已取消'}
const selected=ref<keyof typeof states>('empty'),form=reactive({model:undefined as string|undefined,note:'',consent:false}),error=ref('')
const working=computed(()=>selected.value==='queued'||selected.value==='running')
function submit(){error.value='';if(!form.model||!form.consent){error.value='请选择可用模型并确认本次数据使用许可';return}selected.value='queued'}
</script>
<template>
 <a-alert type="info" message="合成示例。模型建议需要复核，自评分未经校准，不能证明攻击成功或单独授权封禁。示例操作不会调用外部模型。" show-icon/>
 <div class="triage-select"><a-select v-model:value="selected" aria-label="模型研判示例状态" :options="Object.entries(states).map(([value,label])=>({value,label}))"/><a-button @click="selected='empty'">刷新记录</a-button></div>
 <p v-if="selected==='empty'" class="muted">暂无模型研判记录，提交后可查看材料、判断依据和执行状态。</p>
 <a-form :model="form" layout="vertical" @finish="submit">
  <a-form-item label="研判模型" required><a-select v-model:value="form.model" placeholder="选择已配置凭据的模型" :options="[{value:'owned-model',label:'内部研判模型 · 修订 2'}]"/></a-form-item>
  <a-form-item label="研判说明" extra="可说明业务背景或调查问题，最多 2000 字符。说明会发送给选定模型，请勿填写密码或访问令牌。"><a-textarea v-model:value="form.note" :rows="2" :maxlength="2000" show-count/></a-form-item>
  <a-checkbox v-model:checked="form.consent">允许本次向选定模型发送告警索引字段与研判说明，不含原始载荷</a-checkbox>
  <a-alert v-if="error" type="error" :message="error" show-icon class="triage-gap"/>
  <div class="triage-gap"><a-button type="primary" html-type="submit">提交模型研判</a-button></div>
 </a-form>
 <template v-if="selected!=='empty'">
  <div class="triage-heading"><h3>研判结果</h3><a-button v-if="working" @click="selected='cancelled'">取消研判</a-button></div>
  <a-descriptions bordered :column="{xs:1,sm:2}" size="small"><a-descriptions-item label="作业状态">{{states[selected]}}</a-descriptions-item><a-descriptions-item label="模型修订">内部研判模型 · 2</a-descriptions-item><a-descriptions-item label="作业标识" :span="2"><span class="mono">triage_example_20261003</span></a-descriptions-item><a-descriptions-item label="模型调用耗时">{{selected==='succeeded'?'120 ms（合成示例）':'未获得实际调用耗时'}}</a-descriptions-item><a-descriptions-item label="调用用量">{{selected==='succeeded'?'输入 240 / 输出 180 Token（示例）':'提供方未返回用量'}}</a-descriptions-item></a-descriptions>
  <a-alert v-if="selected==='uncertain'" type="warning" message="提供方是否完成调用无法确认，费用可能已产生。平台不会自动重试本次调用，请先核对提供方记录。" show-icon class="triage-gap"/>
  <template v-if="selected==='succeeded'"><div class="triage-heading"><strong>待核实</strong><span>攻击结果尚未确认</span><a-tag color="blue">模型自评分 72.0% · 未经校准</a-tag></div><p>可见请求与规则条件相关，尚缺少终端执行与业务结果证据，建议继续调查。</p><h3>事实引用</h3><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="请求路径"><span class="mono">/admin/login</span></a-descriptions-item><a-descriptions-item label="命中规则标识">1000999</a-descriptions-item></a-descriptions><h3>反证与待补充信息</h3><p>授权测试也可能命中此规则。请核对业务日志、终端执行信息与完整会话。</p><p>处置建议：继续调查，须人工复核及独立授权。</p></template>
  <details class="triage-gap"><summary>查看冻结材料与证据限制</summary><ul><li>材料仅含告警索引字段，未包含原始载荷或完整会话。</li><li>未关联独立终端执行与业务结果证据，未进行 TLS 解密。</li><li>镜像丢包与采集完整度尚未核验。</li><li>规则命中不能单独证明误报、攻击成功或阻断生效。</li></ul><p>模板：alert-triage/1 · 默认保留 180 天</p></details>
 </template>
</template>
<style scoped>.triage-select,.triage-heading{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0}.triage-select .ant-select{flex:1;min-width:180px}.triage-heading h3{margin:0 auto 0 0}.triage-gap{margin-top:12px}summary{cursor:pointer;font-weight:600}p,li,.mono{overflow-wrap:anywhere}</style>
