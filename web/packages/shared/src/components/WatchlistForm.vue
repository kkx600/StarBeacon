<script setup lang="ts">
import {computed,nextTick,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,DatePicker as ADatePicker} from 'ant-design-vue'
import {watchlistKinds,watchlistMatchTypes,watchlistChangeError,watchlistDefinitionError,watchlistDefinitionShape,watchlistScopeKey,emptyWatchlistDefinition,type WatchlistChange,type WatchlistRecord,type WatchlistSensor,type WatchlistPreviewRequest,type WatchlistPreviewResult} from '../watchlists'
import WatchlistPreviewResultView from './WatchlistPreviewResult.vue'
const props=defineProps<{record:WatchlistRecord|null;draft?:WatchlistChange;busy:boolean;unconfirmed:boolean;error:string;sensors:readonly WatchlistSensor[];sensorsPending?:boolean;sensorsError?:string;preview?:WatchlistPreviewResult|null;previewPending?:boolean;previewError?:string}>()
const emit=defineEmits<{save:[input:WatchlistChange];preview:[input:WatchlistPreviewRequest];change:[];confirm:[];refreshSensors:[];close:[]}>()
const source=props.draft??props.record,definition=watchlistDefinitionShape(source?.definition??emptyWatchlistDefinition()),identifier=source?.id??'watch_'+crypto.randomUUID().replaceAll('-',''),expected=props.draft?.expected_revision??props.record?.revision??0
const form=reactive({name:source?.name??'',description:source?.description??'',active:source?.active??false,kind:definition.kind,matchType:definition.match_type,values:definition.values.join('\n'),scopes:definition.sensors.map(watchlistScopeKey),validFrom:definition.valid_from.slice(0,19),validUntil:definition.valid_until.slice(0,19)})
const localError=shallowRef(''),errorPanel=shallowRef<HTMLDivElement|null>(null),locked=computed(()=>props.busy||props.unconfirmed)
const sensorMap=computed(()=>new Map([...definition.sensors.map(s=>({...s,name:s.sensor_id,available:false})),...props.sensors].map(s=>[watchlistScopeKey(s),s])))
const options=computed(()=>[...sensorMap.value].map(([value,s])=>({value,label:`${s.name} · ${s.sensor_id}${s.available===false?'（当前注册不可用）':''}`,disabled:s.available===false})))
const unavailable=computed(()=>form.scopes.some(k=>!props.sensors.some(s=>watchlistScopeKey(s)===k)))
const kinds=Object.entries(watchlistKinds).map(([value,label])=>({value,label})),matchTypes=Object.entries(watchlistMatchTypes).map(([value,label])=>({value,label}))
function shape(){return {schema_version:'watchlist.v1' as const,kind:form.kind,match_type:form.matchType,values:form.values.split('\n').map(s=>s.trim()).filter(Boolean),sensors:form.scopes.map(k=>sensorMap.value.get(k)).filter((v):v is WatchlistSensor=>!!v).map(s=>({sensor_id:s.sensor_id,registration_id:s.registration_id})),valid_from:form.validFrom+'Z',valid_until:form.validUntil+'Z'}}
const request=computed<WatchlistPreviewRequest>(()=>({definition:shape(),active:form.active,targets:[]}))
function scopes(value:unknown){if(locked.value||!Array.isArray(value)||value.some(v=>typeof v!=='string'||!sensorMap.value.has(v)))return;form.scopes=value as string[]}
async function fail(message:string){localError.value=message;await nextTick();errorPanel.value?.focus()}
async function runPreview(){if(locked.value||props.previewPending)return;const invalid=watchlistDefinitionError(request.value.definition);if(invalid){await fail(invalid);return}localError.value='';emit('preview',structuredClone(request.value))}
async function submit(){
 if(locked.value||props.sensorsPending||props.sensorsError)return
 const input:WatchlistChange={id:identifier,expected_revision:expected,name:form.name.trim(),description:form.description.trim(),active:form.active,definition:shape()}
 const invalid=watchlistChangeError(input);if(invalid){await fail(invalid);return}
 if(form.active&&!props.preview?.admissible){await fail('启用前请执行范围核验，确认当前探针、匹配值及有效期。');return}
 localError.value='';emit('save',input)
}
watch(request,()=>{localError.value='';emit('change')},{deep:true})
watch(()=>[form.name,form.description],()=>{localError.value=''})
</script>
<template>
 <a-modal :open="true" :title="expected?'编辑名单':'创建名单'" :width="820" :body-style="{maxHeight:'calc(100vh - 240px)',overflowY:'auto'}" :mask-closable="false" :closable="!busy" :keyboard="!busy&&!unconfirmed" @cancel="emit('close')">
  <a-alert type="info" show-icon message="名单保留告警事实。保护与观察的用途分开，任何设备动作仍须独立授权。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="提交结果尚未确认，输入已锁定；请核对原提交。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" role="region" aria-label="名单输入或提交错误" tabindex="-1" class="section-gap"><a-alert type="error" show-icon :message="localError||error"/></div>
  <a-form :model="form" layout="vertical" :disabled="locked" @finish="submit">
   <div class="watchlist-form-grid"><a-form-item label="名单名称" html-for="watchlist-name" required><a-input id="watchlist-name" v-model:value="form.name" :maxlength="128" placeholder="填写名单用途"/></a-form-item><a-form-item label="启用状态" html-for="watchlist-active" required><a-select @keydown.esc.stop id="watchlist-active" :value="form.active?'true':'false'" @update:value="(value:unknown)=>form.active=value==='true'" :options="[{value:'false',label:'停用'},{value:'true',label:'启用'}]"/></a-form-item><a-form-item label="名单类型" html-for="watchlist-kind" required><a-select @keydown.esc.stop id="watchlist-kind" v-model:value="form.kind" :options="kinds"/></a-form-item><a-form-item label="匹配方式" html-for="watchlist-match-type" required><a-select @keydown.esc.stop id="watchlist-match-type" v-model:value="form.matchType" :options="matchTypes"/></a-form-item></div>
   <a-form-item label="匹配值" html-for="watchlist-values" required :extra="form.matchType==='domain'?'精确小写 ASCII 域名；不接受通配符、URL 或后缀匹配。':form.matchType==='cidr'?'每行一个规范网段。IPv4 小于 /24、IPv6 小于 /120 只能停用保存。':'每行一个规范 IPv4 或 IPv6；不接受映射地址、接口区域、未指定或多播地址。'"><a-textarea id="watchlist-values" v-model:value="form.values" :maxlength="16320" :auto-size="{minRows:3,maxRows:6}" placeholder="每行一项，最多 64 项" class="technical"/></a-form-item>
   <a-form-item label="探针范围" html-for="watchlist-sensors" required extra="最多 32 个探针，固定当前注册代次；探针重新注册后须重新核对。"><a-select @keydown.esc.stop id="watchlist-sensors" :value="form.scopes" :options="options" mode="multiple" show-search option-filter-prop="label" :loading="sensorsPending" :disabled="locked||sensorsPending" :max-tag-count="3" placeholder="选择指定探针" @update:value="scopes"/><div class="watchlist-sensor-actions"><span v-if="unavailable" class="page-description">所选范围含不可用注册，请刷新并重新选择。</span><span v-else-if="!sensorsPending&&!sensors.length" class="page-description">没有可选择的启用探针。</span><a-button size="small" :loading="sensorsPending" :disabled="locked" @click="emit('refreshSensors')">刷新探针</a-button></div><a-alert v-if="sensorsError" type="error" show-icon :message="sensorsError"/></a-form-item>
   <div class="watchlist-form-grid"><a-form-item label="业务生效时间（UTC）" html-for="watchlist-valid-from" required><a-date-picker @keydown.esc.stop id="watchlist-valid-from" v-model:value="form.validFrom" value-format="YYYY-MM-DDTHH:mm:ss" format="YYYY-MM-DD HH:mm:ss" :show-time="{format:'HH:mm:ss'}" :allow-clear="false" class="watchlist-date"/></a-form-item><a-form-item label="业务到期时间（UTC）" html-for="watchlist-valid-until" required><a-date-picker @keydown.esc.stop id="watchlist-valid-until" v-model:value="form.validUntil" value-format="YYYY-MM-DDTHH:mm:ss" format="YYYY-MM-DD HH:mm:ss" :show-time="{format:'HH:mm:ss'}" :allow-clear="false" class="watchlist-date"/></a-form-item></div>
   <a-form-item label="配置依据" html-for="watchlist-description" required extra="简述保护或观察原因、适用范围和期限依据；单段文本，最多 1000 字。"><a-input id="watchlist-description" v-model:value="form.description" :maxlength="1000" placeholder="填写可核对的配置依据"/></a-form-item>
   <a-button html-type="submit" class="watchlist-native-submit" tabindex="-1" aria-hidden="true">保存名单</a-button>
  </a-form>
  <a-alert v-if="previewError" type="error" show-icon :message="previewError" class="section-gap"/>
  <WatchlistPreviewResultView v-if="preview" :result="preview"/>
  <p class="page-description section-gap">业务到期决定名单是否参与后续判断；历史修订默认保留 180 天，两者独立。范围核验不表示设备已经执行或流量已经阻断。</p>
  <template #footer><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><template v-else><a-button :loading="previewPending" :disabled="locked||sensorsPending||!!sensorsError" @click="runPreview">范围核验</a-button><a-button type="primary" :loading="busy" :disabled="locked||previewPending||sensorsPending||!!sensorsError" @click="submit">保存名单</a-button></template></template>
 </a-modal>
</template>
<style scoped>.watchlist-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:12px}.watchlist-date{width:100%}.watchlist-sensor-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin:8px 0}.watchlist-sensor-actions>.page-description{flex:1}.watchlist-native-submit{display:none}@media(max-width:700px){.watchlist-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
