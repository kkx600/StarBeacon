<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import type {ApiClient} from '../../../../packages/shared/src/api'
import {session} from '../../session'
import {applicationCategories,applicationFields,applicationOperators,appStatuses,emptyObservation,validTestResult,type AppDefinition,type AppObservation,type AppResult} from './applicationRules'
const props=defineProps<{definition?:AppDefinition;name?:string;revision?:number;api?:Pick<ApiClient,'request'>}>(),emit=defineEmits<{close:[]}>()
const form=reactive({protocol:props.definition?.protocols[0]??'http',name:'',method:'',path:'',userAgent:'',alpn:'',dns:''}),pending=shallowRef(false),error=shallowRef(''),result=shallowRef<AppResult|null>(null)
let request:AbortController|undefined,stopped=false
const protocolOptions=computed(()=>(props.definition?.protocols??['http','tls','quic','dns']).map(value=>({value,label:value.toUpperCase()})))
const nameLabel=computed(()=>form.protocol==='http'?'HTTP Host':'可见 SNI')
function invalidate(){request?.abort();request=undefined;pending.value=false;result.value=null;error.value=''}
watch(()=>JSON.stringify(form),invalidate,{flush:'sync'})
watch(()=>[session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role].join('/'),()=>{invalidate();emit('close')})
async function test(){
 if(pending.value||stopped)return
 const o:AppObservation=emptyObservation(form.protocol)
 if(form.protocol==='http'){o.http_host=form.name.trim();o.http_method=form.method.trim();o.http_path=form.path.trim();o.http_user_agent=form.userAgent.trim()}
 else if(form.protocol==='dns')o.dns_names=form.dns.split(/\r?\n/).map(v=>v.trim()).filter(Boolean)
 else{o.tls_sni=form.name.trim();o.tls_alpn=form.alpn.split(',').map(v=>v.trim()).filter(Boolean)}
 if(new TextEncoder().encode(JSON.stringify(o)).length>16384||o.dns_names.length>32||o.tls_alpn.length>8){error.value='材料超过验证上限：最多 32 个 DNS 名称、8 个 ALPN、16 KiB 元数据。';return}
 const controller=new AbortController();request=controller;pending.value=true;error.value='';result.value=null
 const timer=setTimeout(()=>controller.abort(),30000)
 try{const value=await (props.api??session.api).request<unknown>(props.definition?'/application-rules/preview':'/application-rules/test',{method:'POST',body:props.definition?{definition:props.definition,observation:o}:{observation:o},signal:controller.signal});if(controller.signal.aborted)return;if(!await validTestResult(value,o,props.definition))throw new Error('规则验证回执与材料或规则快照不一致，请重试。');if(!controller.signal.aborted)result.value=value as AppResult}
 catch(e){if(!stopped&&request===controller)error.value=controller.signal.aborted?'规则验证未完成，请重试。':e instanceof Error?e.message:'规则验证失败。'}
 finally{clearTimeout(timer);if(request===controller){if(controller.signal.aborted&&!error.value)error.value='规则验证未完成，请重试。';pending.value=false}}
}
function close(){invalidate();emit('close')}
onScopeDispose(()=>{stopped=true;request?.abort()})
</script>
<template>
 <a-modal :open="true" title="应用规则输入验证" :width="820" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" :mask-closable="false" @cancel="close">
  <a-alert type="info" show-icon :message="definition?`验证 ${name||'所选规则'} 的修订 ${revision??1} 定义副本。输入为测试材料，不确认真实会话产品，不授予发布或阻断资格。`:'按当前租户全部启用规则验证输入材料。结果不写入流量归因，不修改事件，也不执行网络动作。'" class="section-gap"/>
  <a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/>
  <a-form :model="form" layout="vertical" @finish="test">
   <a-form-item label="材料协议" html-for="application-test-protocol"><a-select id="application-test-protocol" v-model:value="form.protocol" :options="protocolOptions" @keydown.esc.stop/></a-form-item>
   <a-form-item v-if="form.protocol!=='dns'" :label="nameLabel" html-for="application-test-name"><a-input id="application-test-name" v-model:value="form.name" :maxlength="1024" placeholder="未观测到可留空，不能填写推断值"/></a-form-item>
   <template v-if="form.protocol==='http'">
    <div class="application-test-grid"><a-form-item label="请求方法" html-for="application-test-method"><a-select id="application-test-method" v-model:value="form.method" :options="['','GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','CONNECT','TRACE'].map(value=>({value,label:value||'未观测到'}))" @keydown.esc.stop/></a-form-item><a-form-item label="可见路径" html-for="application-test-path"><a-input id="application-test-path" v-model:value="form.path" :maxlength="4096" placeholder="例如 /documents/"/></a-form-item></div>
    <a-form-item label="可见 User-Agent" html-for="application-test-agent"><a-input id="application-test-agent" v-model:value="form.userAgent" :maxlength="1024"/></a-form-item>
   </template>
   <a-form-item v-else-if="form.protocol==='dns'" label="DNS 查询名称" html-for="application-test-dns"><a-textarea id="application-test-dns" v-model:value="form.dns" :rows="4" :maxlength="16384" placeholder="每行一个名称，最多 32 个；不用于给其他连接关联产品"/></a-form-item>
   <a-form-item v-else label="可见 ALPN" html-for="application-test-alpn"><a-input id="application-test-alpn" v-model:value="form.alpn" :maxlength="1024" placeholder="逗号分隔，最多 8 个；未观测到可留空"/></a-form-item>
   <div class="application-test-actions"><a-button @click="close">关闭</a-button><a-button type="primary" html-type="submit" :loading="pending" :disabled="pending">验证材料</a-button></div>
  </a-form>
  <section v-if="result" class="application-test-result" aria-label="应用规则验证结果">
   <a-alert :type="result.status==='conflict'?'warning':result.status==='candidate'?'success':'info'" show-icon :message="`${appStatuses[result.status]} · ${result.matched_rule_count} 条规则命中 / ${result.rule_count} 条参与验证`"/>
   <p class="page-description">{{result.reason==='metadata_unavailable'?'没有可用的可见元数据；保留未知。':'域名规则候选不能作为产品准确率、攻击结果或自动执行授权。'}}</p>
   <a-alert v-if="result.limited" type="warning" show-icon message="展示前 16 条命中；冲突判断已纳入所有命中规则。" class="section-gap"/>
   <dl v-for="match in result.matches" :key="match.rule_id" class="application-match"><dt>{{match.product_name}} · {{applicationCategories[match.category_id]}}</dt><dd><span class="technical">{{match.rule_id}}</span> · 修订 {{match.revision}}</dd><dd v-for="(e,index) in match.evidence" :key="index">{{applicationFields[e.field]}} · {{applicationOperators[e.op]}} · <span class="technical">{{e.pattern}}</span></dd><dd v-if="match.evidence_limited" class="page-description">该规则仅展示前 8 条匹配依据。</dd></dl>
   <dl class="application-receipt"><dt>验证材料 SHA-256</dt><dd class="technical">{{result.observation_sha256}}</dd><dt>规则快照 SHA-256</dt><dd class="technical">{{result.rules_sha256}}</dd></dl>
  </section>
 </a-modal>
</template>
<style scoped>.application-test-grid{display:grid;grid-template-columns:160px minmax(0,1fr);gap:12px}.application-test-actions{display:flex;justify-content:flex-end;gap:8px}.application-test-result{margin-top:14px}.application-match{border:1px solid var(--line);border-radius:8px;padding:10px;margin:10px 0}.application-match dt{font-weight:600}.application-match dd,.application-receipt dd{margin:4px 0;overflow-wrap:anywhere}.application-receipt{font-size:12px}.technical{overflow-wrap:anywhere}@media(max-width:600px){.application-test-grid{grid-template-columns:minmax(0,1fr)}}</style>
