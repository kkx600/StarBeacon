import {computed,onMounted,onScopeDispose,shallowRef,watch} from 'vue'
import type {RulePackage,Sensor} from '@starbeacon/shared/types.ts'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import {session} from '../../session'
import {syncInputError,syncPlanValid,type RuleSyncChange,type RuleSyncPage,type RuleSyncPlan} from './sync'

export function useRuleSync(){
 const page=shallowRef<RuleSyncPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const sensors=shallowRef<Sensor[]>([]),packages=shallowRef<RulePackage[]>([]),choicesPending=shallowRef(false),choicesError=shallowRef('')
 const editing=shallowRef<RuleSyncPlan|null|undefined>(),saving=shallowRef(false),formError=shallowRef(''),unconfirmed=shallowRef<RuleSyncChange>()
 const canEdit=computed(()=>session.current.value?.role==='admin'),currentCursor=computed(()=>cursors.value.at(-1)??'')
 let stopped=false,read:AbortController|undefined,choices:AbortController|undefined,write:AbortController|undefined
 async function refresh(){if(stopped||!canEdit.value)return;read?.abort();const call=new AbortController();read=call;pending.value=true;error.value=''
  try{const p=await session.api.request<RuleSyncPage>('/rule-sync-plans'+(currentCursor.value?'?cursor='+encodeURIComponent(currentCursor.value):''),{signal:call.signal});if(call.signal.aborted)return
   if(!p||!Array.isArray(p.items)||p.items.length>20||!p.items.every(syncPlanValid)||new Set(p.items.map(v=>v.id)).size!==p.items.length||p.items.some(v=>v.id<=currentCursor.value)||typeof p.next_cursor!=='string'||p.next_cursor!==''&&p.next_cursor!==p.items.at(-1)?.id)throw new Error('规则同步目录未完整返回，请重试')
   page.value=p
  }catch(e){if(!call.signal.aborted)error.value=e instanceof Error?e.message:'规则同步计划读取失败'}finally{if(read===call)pending.value=false}
 }
 function next(){if(pending.value||!page.value.next_cursor)return;cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}
 function previous(){if(pending.value||cursors.value.length<2)return;cursors.value=cursors.value.slice(0,-1);void refresh()}
 async function open(plan:RuleSyncPlan|null){if(stopped||saving.value||!canEdit.value||unconfirmed.value)return;editing.value=plan;formError.value='';choicesError.value='';sensors.value=[];packages.value=[];choices?.abort();const call=new AbortController();choices=call;choicesPending.value=true
  try{const [s,p]=await Promise.all([readSensorDirectory(session.api,call.signal),session.api.request<{items:RulePackage[]}>('/rule-packages',{signal:call.signal})]);if(call.signal.aborted)return;if(!p||!Array.isArray(p.items)||p.items.length>200||p.items.some(v=>!v||typeof v.id!=='string'||typeof v.name!=='string'||!Number.isSafeInteger(v.revision)||v.revision<1))throw new Error('规则包目录未完整返回，请重试');sensors.value=s;packages.value=p.items
  }catch(e){if(!call.signal.aborted)choicesError.value=e instanceof Error?e.message:'可用探针与规则包读取失败'}finally{if(choices===call)choicesPending.value=false}
 }
 function close(){if(saving.value)return;choices?.abort();editing.value=undefined;formError.value=''}
 async function save(input:RuleSyncChange){if(stopped||saving.value||!canEdit.value)return
  const problem=syncInputError(input);if(problem){formError.value=problem;return}
  if(unconfirmed.value&&JSON.stringify(input)!==JSON.stringify(unconfirmed.value)){formError.value='上次提交结果尚未确认，请先核对原提交';return}
  const frozen=structuredClone(input);unconfirmed.value=frozen;saving.value=true;formError.value='';write?.abort();const call=new AbortController();write=call
  try{const result=await session.api.request<RuleSyncPlan>('/rule-sync-plans',{method:'POST',body:frozen,signal:call.signal});if(call.signal.aborted)return
   if(!syncPlanValid(result)||result.id!==frozen.id||result.revision!==frozen.expected_revision+1||!Object.keys(frozen.spec).every(k=>result.spec[k as keyof typeof frozen.spec]===frozen.spec[k as keyof typeof frozen.spec]))throw new Error('保存结果未准确绑定原提交，请核对原提交')
   unconfirmed.value=undefined;editing.value=undefined;await refresh()
  }catch(e){if(!call.signal.aborted){formError.value=e instanceof Error?e.message:'规则同步计划保存失败';if(e&&typeof e==='object'&&'status' in e&&([400,403,404,409,429].includes(Number(e.status))||Number(e.status)===503&&'code' in e&&e.code==='rule_sync_unavailable'))unconfirmed.value=undefined}}
  finally{if(write===call)saving.value=false}
 }
 function confirm(){if(unconfirmed.value)void save(unconfirmed.value)}
 watch(()=>session.current.value?.tenant_id+'/'+session.current.value?.id+'/'+session.current.value?.role,()=>{read?.abort();choices?.abort();write?.abort();unconfirmed.value=undefined;editing.value=undefined;page.value={items:[],next_cursor:''};cursors.value=[''];void refresh()})
 onMounted(refresh);onScopeDispose(()=>{stopped=true;read?.abort();choices?.abort();write?.abort()})
 return {page,pending,error,cursors,sensors,packages,choicesPending,choicesError,editing,saving,formError,unconfirmed,refresh,next,previous,open,close,save,confirm}
}
