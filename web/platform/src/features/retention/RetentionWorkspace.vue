<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {computed,ref,watch} from 'vue'
import {Checkbox,InputNumber,Modal,Table} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {scopeNames,type RetentionPolicy} from './retention'
import {useRetention} from './useRetention'
const message=useFeedback()
const state=useRetention(),{data,pending,error,actionError,busy,checking,preview,unconfirmed}=state
const selected=ref<RetentionPolicy|null>(null),days=ref<number|undefined>(180),confirmed=ref(false),open=ref(false)
const rows=computed(()=>data.value?.items.map(policy=>({...policy,...data.value!.catalog.find(category=>category.id===policy.category)}))??[])
const validDays=computed(()=>Number.isInteger(days.value)&&Number(days.value)>=1&&Number(days.value)<=3650)
const label=computed(()=>data.value?.catalog.find(c=>c.id===selected.value?.category)?.name??'留存策略')
const columns=[{title:'数据类别',dataIndex:'name',width:160},{title:'保留期',key:'days',width:110},{title:'生效范围',key:'scope',width:160},{title:'策略修订',dataIndex:'revision',width:100},{title:'业务边界',dataIndex:'boundary',width:380},{title:'操作',key:'action',width:100,fixed:'right' as const}]
function choose(category:string){const policy=data.value?.items.find(item=>item.category===category);if(!policy)return;if(unconfirmed.value){open.value=true;return};state.invalidate();selected.value=policy;days.value=policy.days;confirmed.value=false;open.value=true}
function changed(){confirmed.value=false;state.invalidate()}
watch(data,page=>{if(!selected.value||busy.value||unconfirmed.value)return;const current=page?.items.find(p=>p.category===selected.value!.category);if(current&&current.revision!==selected.value.revision){selected.value=current;changed()}})
async function inspect(){if(selected.value&&validDays.value)await state.inspect({category:selected.value.category,days:Number(days.value),expected_revision:selected.value.revision,apply_mode:'future'})}
async function publish(){const policy=await state.save();if(policy){open.value=false;selected.value=null;confirmed.value=false;message.success('留存策略已发布')}}
</script>
<template>
 <header class="page-header"><div><h1>数据留存</h1><p class="page-description">默认保留 180 天，按数据类别设置未来对象的保留期并复核生效范围。</p></div><div class="filter-actions"><a-button v-if="unconfirmed&&!open" @click="open=true">确认原提交</a-button><a-button :loading="pending" @click="state.refresh">刷新</a-button></div></header>
 <a-alert type="info" show-icon message="策略发布不改变存量对象的期限" description="延长不能恢复已删除的数据；当前未开放存量重算、全域保全或备份销毁。活动配置与传输缓存使用独立生命周期。" class="section-gap"/>
 <a-alert v-if="actionError&&!open" type="warning" :message="actionError" class="section-gap"/>
 <section class="panel section-gap"><div class="panel-header"><h2>分类保留策略</h2><span class="muted">{{data?data.items.length:'—'}} 类</span></div><StatePanel :loading="pending&&!data" :error="error" :empty="!!data&&!rows.length" description="暂无分类留存策略。" @retry="state.refresh"><div class="table-wrap"><Table :data-source="rows" :columns="columns" row-key="category" :pagination="false" :scroll="{x:1060}"><template #bodyCell="{column,record}"><template v-if="column.key==='days'">{{record.days}} 天</template><template v-else-if="column.key==='scope'"><span :class="record.scope==='pending_pipeline'?'status-unknown':'muted'">{{scopeNames[record.scope as keyof typeof scopeNames]}}</span></template><a-button v-else-if="column.key==='action'" type="link" size="small" :disabled="busy||unconfirmed" @click="choose(record.category)">配置</a-button></template></Table></div></StatePanel></section>
 <Modal :open="open" :title="label" :width="600" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="open=false"><template v-if="selected"><a-alert v-if="actionError" type="error" :message="actionError" class="section-gap"/><p class="muted">当前策略：{{selected.days}} 天 · 修订 {{selected.revision}}</p><a-form layout="vertical"><a-form-item label="未来对象保留期" required help="1–3650 天，0 不表示永久保留。"><InputNumber v-model:value="days" aria-label="未来对象保留期" :min="1" :max="3650" :precision="0" :disabled="busy||unconfirmed" addon-after="天" class="retention-days" @change="changed"/></a-form-item></a-form><a-button :loading="checking" :disabled="!validDays||busy||unconfirmed" @click="inspect">计算影响预览</a-button><section v-if="preview" class="retention-preview section-gap"><h3>影响预览</h3><p>{{preview.current_days}} 天 → {{preview.candidate.days}} 天</p><p>生效范围：{{scopeNames[preview.scope]}}</p><p>{{preview.boundary}}</p><p>既有对象期限保持原值；不承诺立即释放存储空间。未来成本需要结合实测数据量核算。</p><p class="muted">预览有效至 {{formatTime(preview.expires_at)}}</p><Checkbox v-model:checked="confirmed" :disabled="busy||unconfirmed">已核对未来数据的保留期与生效范围</Checkbox></section><div class="filter-actions section-gap"><a-button :disabled="busy" @click="open=false">关闭</a-button><a-button type="primary" :loading="busy" :disabled="!unconfirmed&&(!preview||!confirmed)" @click="publish">{{unconfirmed?'确认原提交':'发布策略'}}</a-button></div></template></Modal>
</template>
<style scoped>
.retention-days{width:100%}.retention-preview{padding:12px;background:var(--workspace);border:1px solid var(--line);border-radius:8px;overflow-wrap:anywhere}.retention-preview h3{margin-top:0}.retention-preview p{line-height:1.6}
</style>
