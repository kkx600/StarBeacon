<script setup lang="ts">
import {computed,ref,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import {useRouter} from 'vue-router'
import CorrelationRuleForm from '../../../web/packages/shared/src/components/CorrelationRuleForm.vue'
import CorrelationRuleTable from '../../../web/packages/shared/src/components/CorrelationRuleTable.vue'
import CorrelationRuleDetail from '../../../web/packages/shared/src/components/CorrelationRuleDetail.vue'
import CorrelationScopeForm from '../../../web/packages/shared/src/components/CorrelationScopeForm.vue'
import CorrelationResultTable from '../../../web/packages/shared/src/components/CorrelationResultTable.vue'
import {correlationChangeError,definitionShape,type CorrelationChange,type CorrelationRule,type CorrelationRequest} from '../../../web/packages/shared/src/correlation'
import {goJSONDigest} from '../../../web/packages/shared/src/utils/goJSONDigest'
import {correlationRule,correlationQuery,correlationResult,correlationEmpty} from '../data/correlation'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
const props=defineProps<{state:PreviewState;backtest:boolean}>(),emit=defineEmits<{state:[value:PreviewState]}>(),router=useRouter()
const records=shallowRef<CorrelationRule[]>([structuredClone(correlationRule)]),keyword=ref(''),active=ref(''),editing=ref(false),editRecord=shallowRef<CorrelationRule|null>(null),detail=shallowRef<CorrelationRule|null>(null),error=ref(''),busy=ref(false),revision=ref(1),notice=ref(''),showResult=ref(true),showEvidence=ref(false),scopeEpoch=ref(0)
const history=new Map([[correlationRule.id,new Map([[1,correlationRule]])]])
const items=computed(()=>props.state==='empty'?[]:records.value.filter(r=>(!keyword.value||r.name.includes(keyword.value))&&(!active.value||r.active===(active.value==='true'))))
function create(record:CorrelationRule|null=null){detail.value=null;editRecord.value=record;error.value='';editing.value=true}
function inspect(record:CorrelationRule){editing.value=false;detail.value=record;revision.value=record.revision;error.value=''}
function read(value:number){const found=detail.value&&history.get(detail.value.id)?.get(value);if(found){detail.value=found;revision.value=value;error.value=''}else error.value='该修订没有当前原型页面内的合成记录。'}
function close(){editing.value=false;detail.value=null;if(props.state==='detail'||props.state==='action')emit('state','data')}
async function save(input:CorrelationChange){
 if(busy.value)return
 error.value=correlationChangeError(input);if(error.value)return
 const current=records.value.find(r=>r.id===input.id)
 if((current?.revision??0)!==input.expected_revision){error.value='当前示例修订已变化，请重新选择。';return}
 busy.value=true
 try{const record:CorrelationRule={...input,tenant_id:correlationRule.tenant_id,revision:input.expected_revision+1,definition:definitionShape(input.definition),definition_sha256:await goJSONDigest(definitionShape(input.definition)),created_by:correlationRule.created_by,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString()};const revisions=history.get(record.id)??new Map<number,CorrelationRule>();revisions.set(record.revision,record);history.set(record.id,revisions);records.value=[...records.value.filter(r=>r.id!==record.id),record].sort((a,b)=>a.id.localeCompare(b.id));close();emit('state','data')}
 catch(cause){error.value=cause instanceof Error?cause.message:'合成规则无法保存。'}finally{busy.value=false}
}
function run(q:CorrelationRequest){notice.value='';showEvidence.value=false;if(Date.parse(q.start)===Date.parse(correlationQuery.start)&&Date.parse(q.end)===Date.parse(correlationQuery.end)){showResult.value=true;emit('state','data')}else{showResult.value=false;notice.value='此时间范围没有合成快照材料，未调用工程服务。可恢复示例范围查看固定结果。'}}
function applyState(){editing.value=false;detail.value=null;error.value='';notice.value='';showResult.value=props.state!=='action';showEvidence.value=props.backtest&&props.state==='detail';if(!props.backtest&&props.state==='action')create();if(!props.backtest&&props.state==='detail')inspect(records.value[0]??correlationRule)}
watch(()=>[props.state,props.backtest],applyState,{immediate:true})
</script>
<template>
 <PageHeader :title="backtest?'窗口回测':'关联规则'" :description="backtest?'核对固定告警快照中的窗口计量、分组边界与证据。':'维护告警窗口计量条件及不可变修订。'"><a-button v-if="!backtest" type="primary" @click="create()">创建关联规则</a-button><a-button v-else @click="router.push('/detection/correlation/rules')">返回规则目录</a-button></PageHeader>
 <a-alert type="info" show-icon message="全部为合成示例；不调用工程 API。窗口回测只描述已进入快照的告警，来源覆盖未经证明；不启用实时关联，不生成告警或设备动作。" class="page-notice"/>
 <section v-if="!backtest" class="panel"><form class="table-toolbar" @submit.prevent><h2>规则目录</h2><a-input v-model:value="keyword" aria-label="筛选关联规则名称" placeholder="规则名称" style="width:220px"/><a-select v-model:value="active" aria-label="筛选回测状态" :options="[{value:'',label:'全部状态'},{value:'true',label:'允许回测'},{value:'false',label:'停用'}]" style="width:150px"/></form><StatePanel v-if="state==='loading'||state==='error'||!items.length" :state="state==='loading'?'loading':state==='error'?'error':'empty'" :description="state==='error'?'示例读取失败状态，工程服务未被调用。':'当前条件下没有关联规则。'" @action="emit('state','data')"/><CorrelationRuleTable v-else :items="items" :can-edit="true" @inspect="inspect" @edit="create" @backtest="router.push('/detection/correlation/backtest')"/></section>
 <template v-else><section class="panel panel-body section-gap"><strong>{{correlationRule.name}}</strong><p class="page-description">固定修订 1 · 60 秒窗口 · 阈值 2；最多一小时、5000 条告警、512 个窗口分组。</p></section><CorrelationScopeForm :key="state+'/'+scopeEpoch" :revision="1" :window-seconds="60" :initial="correlationQuery" :pending="state==='loading'" @run="run" @change="showResult=false;showEvidence=false" @cancel="emit('state','data')"/><a-alert v-if="notice" type="info" show-icon :message="notice" class="section-gap"/><section class="panel correlation-preview-result"><div class="panel-header"><h2>回测结果</h2><a-button size="small" @click="scopeEpoch++;emit('state','data');showResult=true">恢复示例范围</a-button></div><StatePanel v-if="state==='loading'||state==='error'||!showResult" :state="state==='loading'?'loading':state==='error'?'error':'empty'" description="当前没有可交付的回测结果，失败不展示部分事实。" @action="emit('state','data')"/><CorrelationResultTable v-else :result="state==='empty'?correlationEmpty:correlationResult" :definition="correlationRule.definition" :detail-id="showEvidence?correlationResult.windows[0]?.detection_id:undefined" @close="showEvidence=false;if(state==='detail')emit('state','data')"/></section></template>
 <CorrelationRuleForm v-if="editing" :record="editRecord" :busy="busy" :unconfirmed="false" :error="error" @save="save" @confirm="error='当前原型没有未确认的工程请求。'" @close="close"/>
 <CorrelationRuleDetail v-else-if="detail" :record="detail" :revision="revision" :maximum="records.find(r=>r.id===detail?.id)?.revision??1" :error="error" @read="read" @close="close"/>
</template>
<style scoped>.correlation-preview-result{margin-top:12px}.correlation-preview-result .panel-header{display:flex;gap:8px;justify-content:space-between;align-items:center}</style>
