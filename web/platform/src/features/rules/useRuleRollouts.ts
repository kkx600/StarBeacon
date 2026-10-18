import {computed,onMounted,onScopeDispose,shallowRef,watch} from 'vue'
import {session} from '../../session'
import {syncPlanValid,type RuleSyncPage,type RuleSyncPlan} from './sync'
import {rolloutInputError,validRollout,sameRolloutSpec,stopReasonError,type RolloutCreate,type RolloutPage,type RuleRollout} from './rollout'

type Submission={kind:'create';input:RolloutCreate}|{kind:'stop';id:string;reason:string}
export function useRuleRollouts(){
 const page=shallowRef<RolloutPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const detail=shallowRef<RuleRollout>(),detailID=shallowRef(''),detailPending=shallowRef(false),detailError=shallowRef('')
 const creating=shallowRef(false),stopping=shallowRef(false),saving=shallowRef(false),formError=shallowRef(''),unconfirmed=shallowRef<Submission>()
 const draftEpoch=shallowRef(0)
 const plans=shallowRef<RuleSyncPlan[]>([]),plansCursor=shallowRef(''),plansPending=shallowRef(false),plansError=shallowRef('')
 const allowed=computed(()=>session.current.value?.role==='admin')
 let disposed=false,listCall:AbortController|undefined,detailCall:AbortController|undefined,plansCall:AbortController|undefined,writeCall:AbortController|undefined
 async function refresh(){if(disposed||!allowed.value)return;listCall?.abort();const call=new AbortController();listCall=call;pending.value=true;error.value='';const cursor=cursors.value.at(-1)??''
  try{const p=await session.api.request<RolloutPage>('/rule-rollouts'+(cursor?'?cursor='+encodeURIComponent(cursor):''),{signal:call.signal});if(call.signal.aborted)return
   if(!p||!Array.isArray(p.items)||p.items.length>20||!p.items.every(r=>validRollout(r))||p.items.some(r=>r.id<=cursor)||new Set(p.items.map(r=>r.id)).size!==p.items.length||typeof p.next_cursor!=='string'||p.next_cursor!==''&&p.next_cursor!==p.items.at(-1)?.id)throw new Error('分批发布目录未完整返回，请重试');page.value=p
  }catch(e){if(!call.signal.aborted)error.value=e instanceof Error?e.message:'分批发布目录读取失败'}finally{if(listCall===call)pending.value=false}
 }
 function next(){if(pending.value||!page.value.next_cursor)return;cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}
 function previous(){if(pending.value||cursors.value.length<2)return;cursors.value=cursors.value.slice(0,-1);void refresh()}
 function remember(r:RuleRollout){page.value={...page.value,items:page.value.items.map(item=>item.id===r.id?{...r,targets:undefined}:item)}}
 async function show(id:string){if(disposed||!allowed.value)return;detailCall?.abort();const call=new AbortController();detailCall=call;detailID.value=id;detail.value=undefined;detailError.value='';detailPending.value=true
   try{const r=await session.api.request<RuleRollout>('/rule-rollouts/'+encodeURIComponent(id),{signal:call.signal});if(call.signal.aborted)return;if(!validRollout(r,true)||r.id!==id)throw new Error('发布详情与目标快照未完整返回，请重试');detail.value=r;remember(r)}
  catch(e){if(!call.signal.aborted)detailError.value=e instanceof Error?e.message:'分批发布详情读取失败'}finally{if(detailCall===call)detailPending.value=false}
 }
 function back(){detailCall?.abort();detailID.value='';detail.value=undefined;detailError.value=''}
 async function loadPlans(more=false){if(disposed||!allowed.value||plansPending.value)return;plansCall?.abort();const call=new AbortController();plansCall=call;plansPending.value=true;plansError.value='';const cursor=more?plansCursor.value:''
  if(!more){plans.value=[];plansCursor.value=''}
  try{const p=await session.api.request<RuleSyncPage>('/rule-sync-plans'+(cursor?'?cursor='+encodeURIComponent(cursor):''),{signal:call.signal});if(call.signal.aborted)return
   if(!p||!Array.isArray(p.items)||p.items.length>20||!p.items.every(syncPlanValid)||p.items.some(v=>v.id<=cursor)||typeof p.next_cursor!=='string'||p.next_cursor!==''&&p.next_cursor!==p.items.at(-1)?.id||new Set([...plans.value,...p.items].map(v=>v.id)).size!==plans.value.length+p.items.length)throw new Error('同步计划目录未完整返回，请重试')
   plans.value=[...plans.value,...p.items];plansCursor.value=p.next_cursor
  }catch(e){if(!call.signal.aborted)plansError.value=e instanceof Error?e.message:'同步计划目录读取失败'}finally{if(plansCall===call)plansPending.value=false}
 }
 function open(){if(disposed||saving.value||unconfirmed.value||!allowed.value)return;creating.value=true;formError.value='';void loadPlans()}
 function close(){if(saving.value)return;plansCall?.abort();plansPending.value=false;creating.value=false;stopping.value=false;formError.value=''}
 function openStop(){if(!detail.value||saving.value||unconfirmed.value)return;stopping.value=true;formError.value=''}
 function rejected(e:unknown):boolean{return !!(e&&typeof e==='object'&&'status'in e&&([400,403,404,409,429].includes(Number(e.status))||Number(e.status)===503&&'code'in e&&e.code==='rule_rollout_unavailable'))}
 async function submit(s:Submission){if(disposed||saving.value||!allowed.value)return
  const problem=s.kind==='create'?rolloutInputError(s.input):stopReasonError(s.reason);if(problem){formError.value=problem;return}
  if(unconfirmed.value&&JSON.stringify(s)!==JSON.stringify(unconfirmed.value)){formError.value='上次操作结果尚未确认，请先核对原提交';return}
  const frozen=structuredClone(s);unconfirmed.value=frozen;saving.value=true;formError.value='';writeCall?.abort();const call=new AbortController();writeCall=call
  try{const r=await session.api.request<RuleRollout>(frozen.kind==='create'?'/rule-rollouts':'/rule-rollouts/'+encodeURIComponent(frozen.id)+'/stop',{method:'POST',body:frozen.kind==='create'?frozen.input:{reason:frozen.reason},signal:call.signal});if(call.signal.aborted)return
   if(!validRollout(r,true)||(frozen.kind==='create'?(r.id!==frozen.input.id||r.created_by!==session.current.value?.id||!sameRolloutSpec(r.spec,frozen.input.spec)):(r.id!==frozen.id||r.stop_reason!==frozen.reason||r.stopped_by!==session.current.value?.id||!['stopping','stopped','blocked'].includes(r.state))))throw new Error('操作回执未准确绑定原提交，请核对原提交')
   if(frozen.kind==='create')draftEpoch.value++
   unconfirmed.value=undefined;creating.value=false;stopping.value=false;detailID.value=r.id;detail.value=r;detailError.value='';remember(r);await refresh()
  }catch(e){if(!call.signal.aborted){formError.value=e instanceof Error?e.message:'分批发布操作失败';if(rejected(e))unconfirmed.value=undefined}}
  finally{if(writeCall===call)saving.value=false}
 }
 function create(input:RolloutCreate){return submit({kind:'create',input})}
 function stop(reason:string){if(detailID.value)return submit({kind:'stop',id:detailID.value,reason})}
 function confirm(){if(unconfirmed.value)void submit(unconfirmed.value)}
 watch(()=>session.current.value?.tenant_id+'/'+session.current.value?.id+'/'+session.current.value?.role+'/'+session.current.value?.csrf_token,()=>{listCall?.abort();detailCall?.abort();plansCall?.abort();writeCall?.abort();draftEpoch.value++;page.value={items:[],next_cursor:''};cursors.value=[''];detailID.value='';detail.value=undefined;plans.value=[];creating.value=false;stopping.value=false;unconfirmed.value=undefined;formError.value='';saving.value=false;plansPending.value=false;void refresh()})
 onMounted(refresh);onScopeDispose(()=>{disposed=true;listCall?.abort();detailCall?.abort();plansCall?.abort();writeCall?.abort();unconfirmed.value=undefined})
 return{page,pending,error,cursors,detail,detailID,detailPending,detailError,creating,stopping,saving,formError,unconfirmed,draftEpoch,plans,plansCursor,plansPending,plansError,refresh,next,previous,show,back,loadPlans,open,close,openStop,create,stop,confirm}
}
