<script setup lang="ts">
import {computed,onMounted,ref,shallowRef,watch} from 'vue'
import {message} from 'ant-design-vue'
import type {ApiClient} from '../../../web/packages/shared/src/api'
import {applicationCategories,appDigest,orderedDefinition,orderedObservation,changeError,type AppChange,type AppCondition,type AppDefinition,type AppObservation,type AppResult,type AppRule} from '../../../web/platform/src/features/applications/applicationRules'
import ApplicationRuleForm from '../../../web/platform/src/features/applications/ApplicationRuleForm.vue'
import ApplicationRuleTest from '../../../web/platform/src/features/applications/ApplicationRuleTest.vue'
import type {PreviewState} from '../models'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>()
const records=shallowRef<AppRule[]>([]),ready=ref(false),loadError=ref(''),keyword=ref(''),active=ref('')
const editing=ref(false),editRecord=shallowRef<AppRule|null>(null),busy=ref(false),error=ref(''),detail=shallowRef<AppRule|null>(null),testing=ref(false),testRecord=shallowRef<AppRule|null>(null),revision=ref<number|string>(1)
const history=new Map<string,Map<number,AppRule>>()
const columns=[{title:'规则名称',key:'name',width:225},{title:'应用产品 / 类别',key:'product',width:200},{title:'协议范围',key:'protocols',width:150},{title:'修订',dataIndex:'revision',width:70},{title:'状态',key:'active',width:90},{title:'操作',key:'action',width:180}]
const items=computed(()=>props.state==='empty'?[]:records.value.filter(row=>(!keyword.value||row.name.includes(keyword.value))&&(active.value===''||row.active===(active.value==='true'))))
function clear(){editing.value=false;editRecord.value=null;detail.value=null;testing.value=false;testRecord.value=null;error.value=''}
function close(){clear();if(props.state==='action'||props.state==='detail')emit('state','data')}
function create(record:AppRule|null=null){clear();editRecord.value=record;editing.value=true}
function inspect(record:AppRule){clear();detail.value=record;revision.value=record.revision}
function test(record:AppRule|null=null){clear();testRecord.value=record;testing.value=true}
function emptyAction(){if(keyword.value||active.value){keyword.value='';active.value=''}else create()}
function selectRevision(){const current=detail.value;if(!current)return;const raw=String(revision.value);const selected=/^[1-9][0-9]*$/.test(raw)?history.get(current.id)?.get(Number(raw)):undefined;if(!selected){error.value='该修订没有本地示例记录。';return}error.value='';detail.value=selected}
async function save(input:AppChange){
 if(busy.value)return
 error.value=changeError(input);if(error.value)return
 const current=records.value.find(row=>row.id===input.id)
 if((current?.revision??0)!==input.expected_revision){error.value='本地示例修订已变化，请重新打开规则。';return}
 if(!current&&records.value.length>=128){error.value='示例规则目录已达到 128 条上限。';return}
 busy.value=true
 try{const now=new Date(),record:AppRule={tenant_id:'prototype_tenant',id:input.id,revision:input.expected_revision+1,name:input.name,description:input.description,active:input.active,definition:structuredClone(orderedDefinition(input.definition)),definition_sha256:await appDigest(orderedDefinition(input.definition)),created_by:'prototype_user',created_at:now.toISOString(),expires_at:new Date(now.getTime()+180*86400000).toISOString()};const revisions=history.get(input.id)??new Map<number,AppRule>();revisions.set(record.revision,record);history.set(record.id,revisions);records.value=[...records.value.filter(row=>row.id!==record.id),record].sort((a,b)=>a.id.localeCompare(b.id));close();emit('state','data');message.success('规则保存在当前原型页面内存中。')}
 catch(e){error.value=e instanceof Error?e.message:'示例规则无法保存。'}finally{busy.value=false}
}
// 此适配器只比较合成材料，不接触网络、工程 API 或真实流量。
function names(o:AppObservation,field:AppCondition['field']):string[]{
 if(field.startsWith('http.')&&o.protocol!=='http'||field.startsWith('tls.')&&!['tls','quic'].includes(o.protocol)||field==='dns.name'&&o.protocol!=='dns')return []
 const values=field==='http.host'?[o.http_host]:field==='tls.sni'?[o.tls_sni]:field==='dns.name'?o.dns_names:field==='http.method'?[o.http_method]:field==='http.path'?[o.http_path]:field==='http.user_agent'?[o.http_user_agent]:o.tls_alpn
 if(!['http.host','tls.sni','dns.name'].includes(field))return values.filter(Boolean)
 return values.filter(Boolean).map(value=>{try{return new URL('https://'+value).hostname.toLowerCase().replace(/\.$/,'')}catch{return ''}}).filter(Boolean)
}
function matches(o:AppObservation,c:AppCondition){return names(o,c.field).some(value=>c.op==='eq'?value===c.value:c.op==='domain_suffix'?value===c.value||value.endsWith('.'+c.value):c.op==='prefix'?value.startsWith(c.value):value.includes(c.value))}
const previewAPI:Pick<ApiClient,'request'>={async request<T>(path:string,options:NonNullable<Parameters<ApiClient['request']>[1]>={}){
 if(options.signal?.aborted)throw new DOMException('已取消','AbortError')
 if(!['/application-rules/test','/application-rules/preview'].includes(path)||options.method!=='POST')throw new Error('原型不提供该接口。')
 const body=options.body as {definition?:AppDefinition;observation:AppObservation},o=body.observation
 const snapshots=body.definition?[{id:'candidate_rule',revision:1,definition:orderedDefinition(body.definition)}]:records.value.filter(row=>row.active).map(row=>({id:row.id,revision:row.revision,definition:orderedDefinition(row.definition)})).sort((a,b)=>a.id.localeCompare(b.id))
 const found:AppResult['matches']=[]
 for(const row of snapshots){const d=row.definition;if(!d.protocols.includes(o.protocol)||!d.any.some(c=>matches(o,c))||!d.all.every(c=>matches(o,c))||d.exclude.some(c=>matches(o,c)))continue;const evidence=[...d.any.filter(c=>matches(o,c)),...d.all].map(c=>({field:c.field,op:c.op,pattern:c.value}));found.push({rule_id:row.id,revision:row.revision,product_id:d.product_id,product_name:d.product_name,category_id:d.category_id,evidence:evidence.slice(0,8),evidence_limited:evidence.length>8})}
 const products=new Set(found.map(row=>row.product_id)),status=products.size>1?'conflict':products.size===1?'candidate':'unknown'
 const available=o.protocol==='http'?!!o.http_host:o.protocol==='dns'?o.dns_names.length>0:!!o.tls_sni
 const result:AppResult={schema_version:'application-test.v1',origin:'user_supplied_metadata',protocol:o.protocol,status,reason:status==='conflict'?'multiple_products':status==='candidate'?'visible_name_rule':available?'no_matching_rule':'metadata_unavailable',evaluated_at:new Date().toISOString(),observation_sha256:await appDigest(orderedObservation(o)),rules_sha256:await appDigest(snapshots),rule_count:snapshots.length,matched_rule_count:found.length,matches:found.slice(0,16),limited:found.length>16}
 if(options.signal?.aborted)throw new DOMException('已取消','AbortError')
 return result as T
}}
function applyState(){clear();if(props.state==='action')create();if(props.state==='detail'&&records.value[0])inspect(records.value[0])}
watch(()=>props.state,applyState)
onMounted(async()=>{try{const examples=[['files','业务文件服务（示例）','cloud_storage'],['video','视频服务（示例）','video'],['office','协作服务（示例）','office']] as const;for(const [id,name,category]of examples){const definition:AppDefinition={schema_version:'application-rule.v1',product_id:id+'_demo',product_name:name,category_id:category,protocols:['http','tls'],any:[{field:'http.host',op:'domain_suffix',value:id+'.example'},{field:'tls.sni',op:'domain_suffix',value:id+'.example'}],all:[],exclude:[]};const row:AppRule={tenant_id:'prototype_tenant',id:'app_demo_'+id,revision:1,name:name+'名称规则',description:'合成 .example 名称；不用于真实产品识别。',active:true,definition,definition_sha256:await appDigest(orderedDefinition(definition)),created_by:'prototype_user',created_at:'2026-10-10T00:00:00Z',expires_at:'2027-04-08T00:00:00Z'};history.set(row.id,new Map([[1,row]]));records.value=[...records.value,row]}applyState()}catch(e){loadError.value=e instanceof Error?e.message:'示例数据无法加载。'}finally{ready.value=true}})
</script>
<template>
 <PageHeader title="应用识别规则" description="维护产品名称条件、不可变修订与可见元数据输入验证。"><a-button :disabled="!ready||busy" @click="test()">验证启用规则</a-button><a-button type="primary" :disabled="!ready||busy" @click="create()">创建规则</a-button></PageHeader>
 <a-alert type="info" show-icon message="全部为合成示例；操作只保存在当前原型页面内存中。名称规则形成产品候选或冲突，不表示真实流量归因、探针分发或应用计量已完成。" class="page-notice"/>
 <section class="panel table-panel"><form class="table-toolbar" @submit.prevent><h2>应用识别规则</h2><a-input v-model:value="keyword" placeholder="规则名称" aria-label="应用识别规则名称" style="width:220px"/><a-select v-model:value="active" aria-label="应用识别规则状态" :options="[{value:'',label:'全部状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]" style="width:130px"/><span class="muted">当前筛选 {{items.length}} 条</span></form>
  <StatePanel v-if="!ready||state==='loading'" state="loading"/>
  <StatePanel v-else-if="loadError||state==='error'" state="error" :description="loadError||'示例错误状态；工程服务没有被调用。'" @action="emit('state','data')"/>
  <StatePanel v-else-if="!items.length" state="empty" :title="keyword||active?'没有符合筛选条件的规则':'暂无应用识别规则'" :description="keyword||active?'请调整条件后重新检索。':'配置规则后可验证产品名称条件与排除依据。'" :action="keyword||active?'重置筛选':'创建规则'" @action="emptyAction"/>
  <a-table v-else :data-source="items" :columns="columns" row-key="id" :pagination="{pageSize:8,showSizeChanger:false}" :scroll="{x:1015}" size="small"><template #bodyCell="{column,record}"><template v-if="column.key==='name'"><b>{{record.name}}</b><small class="row-id">{{record.id}}</small></template><template v-else-if="column.key==='product'">{{record.definition.product_name}}<small class="row-id">{{applicationCategories[record.definition.category_id as keyof typeof applicationCategories]}}</small></template><template v-else-if="column.key==='protocols'"><a-tag v-for="protocol in record.definition.protocols" :key="protocol" color="blue">{{protocol.toUpperCase()}}</a-tag></template><a-tag v-else-if="column.key==='active'" :color="record.active?'green':'default'">{{record.active?'启用':'停用'}}</a-tag><div v-else-if="column.key==='action'" class="application-preview-actions"><a-button type="link" size="small" @click="inspect(record as AppRule)">查看</a-button><a-button type="link" size="small" @click="create(record as AppRule)">编辑</a-button><a-button type="link" size="small" @click="test(record as AppRule)">验证</a-button></div></template></a-table>
 </section>
 <ApplicationRuleForm v-if="editing" :record="editRecord" :busy="busy" :unconfirmed="false" :error="error" @save="save" @confirm="error='当前原型没有未确认的工程请求。'" @close="close"/>
 <ApplicationRuleTest v-else-if="testing" :definition="testRecord?.definition" :name="testRecord?.name" :revision="testRecord?.revision" :api="previewAPI" @close="close"/>
 <a-modal v-else-if="detail" :open="true" title="应用识别规则详情" :width="800" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="close"><a-alert type="info" show-icon message="此修订与摘要属于合成示例，不来自工程平台。" class="modal-notice"/><a-alert v-if="error" type="error" show-icon :message="error" class="modal-notice"/><form class="application-preview-revision" @submit.prevent="selectRevision"><label for="prototype-application-revision">读取修订</label><a-input-number id="prototype-application-revision" v-model:value="revision" :min="1" :max="records.find(row=>row.id===detail?.id)?.revision??1"/><a-button html-type="submit">读取</a-button></form><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="规则 / 修订">{{detail.name}} / {{detail.revision}}</a-descriptions-item><a-descriptions-item label="状态">{{detail.active?'启用':'停用'}}</a-descriptions-item><a-descriptions-item label="定义 SHA-256"><span class="technical">{{detail.definition_sha256}}</span></a-descriptions-item><a-descriptions-item label="维护说明">{{detail.description||'未填写'}}</a-descriptions-item></a-descriptions><pre class="application-preview-definition">{{JSON.stringify(detail.definition,null,2)}}</pre></a-modal>
</template>
<style scoped>.application-preview-actions,.application-preview-revision{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.application-preview-revision{margin-bottom:12px}.application-preview-definition{padding:12px;background:var(--bg-soft,#f8f9fa);border:1px solid var(--border,#e5e7eb);border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere}.technical{overflow-wrap:anywhere}</style>
