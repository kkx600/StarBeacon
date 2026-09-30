<script setup lang="ts">
import {ref,watch} from 'vue'
import {message} from 'ant-design-vue'
import {PlusOutlined,CheckOutlined,SaveOutlined,PlayCircleOutlined,ArrowDownOutlined,SettingOutlined} from '@ant-design/icons-vue'
import type {PageSpec,PreviewState} from '../models'
import PageHeader from '../components/PageHeader.vue'
import StatePanel from '../components/StatePanel.vue'
import RecordForm from '../components/RecordForm.vue'
import StatusTag from '../components/StatusTag.vue'
const props=defineProps<{page:PageSpec;state:PreviewState}>();const emit=defineEmits<{state:[value:PreviewState]}>()
const nodes=ref([{id:'trigger',name:'高危告警触发',type:'触发器',note:'严重级别、租户与场景匹配'},{id:'evidence',name:'证据与资格检查',type:'条件',note:'完整性、校准版本与保护名单'},{id:'approval',name:'人工审批',type:'人工节点',note:'绑定证据快照与目标范围'},{id:'action',name:'采集器执行动作',type:'动作',note:'有界 TTL、幂等键与凭据引用'},{id:'verify',name:'回读与效果观察',type:'核验',note:'接受、配置和效果分别记录'},{id:'compensate',name:'到期撤销与补偿',type:'补偿',note:'租约到期、结果未知与回读'}])
const selected=ref('approval');const nodeName=ref('人工审批');const timeout=ref(900);const errorPath=ref('暂停并通知值班组');const mode=ref('审批');const status=ref('草稿');const detail=ref(false);const formOpen=ref(false)
watch(selected,id=>{nodeName.value=nodes.value.find(n=>n.id===id)?.name??''})
watch(()=>props.state,state=>{detail.value=state==='detail';formOpen.value=state==='action'},{immediate:true})
function applyNode(){const node=nodes.value.find(n=>n.id===selected.value);if(node&&nodeName.value.trim()){node.name=nodeName.value.trim();message.success('节点配置已保存在本地示例中。')}}
function close(){detail.value=false;formOpen.value=false;if(['detail','action'].includes(props.state))emit('state','data')}
</script>
<template>
  <PageHeader title="响应剧本" description="将调查、审批、受控动作与补偿连接为有界流程。"><a-space><a-button @click="status='示例验证通过';message.success('合成流程满足无环、节点上限与动作门控示例。')"><CheckOutlined/>校验</a-button><a-button @click="message.success('剧本已保存在本地示例中。')"><SaveOutlined/>保存草稿</a-button><a-button type="primary" @click="formOpen=true"><PlusOutlined/>创建剧本</a-button></a-space></PageHeader>
  <a-alert message="所有副作用节点经过统一授权；取消流程不等于设备动作已经回滚。结果未知时先核对配置，再决定重试或补偿。" type="info" show-icon class="page-notice"/>
  <StatePanel v-if="state==='loading'||state==='error'" :state="state" @action="emit('state','data')"/>
  <StatePanel v-else-if="state==='empty'" state="empty" title="尚未配置响应剧本" description="从授权场景创建流程，明确条件、人工节点、动作范围和撤销路径。" action="创建剧本" @action="formOpen=true"/>
  <div v-else class="playbook-layout"><section class="panel playbook-canvas"><div class="panel-heading"><div><h2>高危访问响应</h2><small class="muted">PB-DEMO-001 · 版本 1 · 合成示例</small></div><StatusTag :value="status"/></div><div class="workflow-flow"><template v-for="(node,index) in nodes" :key="node.id"><button class="workflow-node" :class="{selected:selected===node.id,'action-node':node.id==='action'}" @click="selected=node.id"><span class="node-index">{{String(index+1).padStart(2,'0')}}</span><div><small>{{node.type}}</small><b>{{node.name}}</b><p>{{node.note}}</p></div><SettingOutlined/></button><ArrowDownOutlined v-if="index<nodes.length-1" class="workflow-arrow"/></template></div><div class="workflow-legend"><a-tag>最大节点数 32</a-tag><a-tag>动作统一授权</a-tag><a-tag>冻结发布版本</a-tag></div></section><aside class="panel node-inspector"><div class="panel-heading"><h2>节点配置</h2><span class="muted">{{selected}}</span></div><a-form layout="vertical"><a-form-item label="节点名称" required><a-input v-model:value="nodeName"/></a-form-item><a-form-item label="运行模式"><a-select v-model:value="mode" :options="['影子','审批','自动'].map(value=>({value,label:value}))"/></a-form-item><a-form-item label="超时（秒）"><a-input-number v-model:value="timeout" :min="1" :max="3600" style="width:100%"/></a-form-item><a-form-item label="异常路径"><a-select v-model:value="errorPath" :options="['暂停并通知值班组','先核对结果，再人工决定','执行受控补偿'].map(value=>({value,label:value}))"/></a-form-item><a-form-item label="证据绑定"><a-input value="snapshot-demo-001" readonly/></a-form-item><a-form-item label="目标网络域"><a-input value="总部网络域" readonly/></a-form-item></a-form><a-alert message="审批绑定证据和动作摘要；范围变化后需要重新审批。" type="warning" show-icon/><a-button type="primary" block style="margin-top:16px" @click="applyNode">保存节点配置</a-button><a-button block style="margin-top:8px" @click="detail=true"><PlayCircleOutlined/>查看演练路径</a-button></aside></div>
  <a-modal :open="detail" title="剧本演练与执行门控" :width="820" :footer="null" @cancel="close"><a-steps direction="vertical" :current="2" :items="nodes.map(node=>({title:node.name,description:node.note}))"/><a-alert message="此演练不执行设备动作。生产需要实际连接器能力、幂等 journal、回读、租约撤销与故障隔离验收。" type="info" show-icon/></a-modal>
  <RecordForm :open="formOpen" :page="{...page,fields:[{key:'name',label:'剧本名称',required:true},{key:'trigger',label:'触发场景',type:'select',required:true,value:'高危告警',options:['高危告警','异常外连','人工发起']},{key:'mode',label:'运行模式',type:'select',required:true,value:'审批',options:['影子','审批','自动']},{key:'notes',label:'授权与补偿说明',type:'textarea'}]}" @close="close" @save="values=>{status='草稿';close();emit('state','data');message.success(`本地示例剧本 ${values.name} 已创建。`)}"/>
</template>
