import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {session} from '../../session'
import {policyID,policyStatuses} from './decisionPolicies'
import {validEvaluationPage,type EvaluationFilter,type EvaluationPage} from './decisionEvaluations'
const empty=():EvaluationFilter=>({policy_id:'',triage_id:'',status:''})
export function useDecisionEvaluations(){
 const page=shallowRef<EvaluationPage>({items:[],next_cursor:''}),filter=shallowRef(empty()),cursors=shallowRef(['']),pending=shallowRef(false),error=shallowRef('')
 let stopped=false,read:AbortController|undefined
 async function refresh(){
  if(stopped)return
  read?.abort();const controller=new AbortController();read=controller;pending.value=true;error.value='';page.value={items:[],next_cursor:''}
  const frozen={...filter.value},tenant=session.current.value?.tenant_id??'',owner=session.current.value?.id??''
  try{const value=await session.api.request<unknown>('/decision-evaluations?'+new URLSearchParams({...frozen,limit:'20',cursor:cursors.value.at(-1)??''}),{signal:controller.signal});if(controller.signal.aborted)return;if(!await validEvaluationPage(value,tenant,owner,frozen))throw new Error('评估记录目录与账号、筛选或摘要不一致，请重试。');if(!controller.signal.aborted)page.value=value as EvaluationPage}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'评估记录读取失败。'}finally{if(read===controller)pending.value=false}
 }
 function search(value:EvaluationFilter){const q={policy_id:value.policy_id.trim(),triage_id:value.triage_id.trim(),status:value.status};if(q.policy_id&&!policyID(q.policy_id)||q.triage_id&&!policyID(q.triage_id)||q.status&&!Object.hasOwn(policyStatuses,q.status)){error.value='请核对策略、研判作业标识与判断状态。';return}filter.value=q;cursors.value=[''];void refresh()}
 function next(){if(pending.value||error.value||!page.value.next_cursor)return;cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}
 function previous(){if(pending.value||cursors.value.length<2)return;cursors.value=cursors.value.slice(0,-1);void refresh()}
 function reset(){read?.abort();filter.value=empty();cursors.value=[''];page.value={items:[],next_cursor:''};void refresh()}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),reset)
 onScopeDispose(()=>{stopped=true;read?.abort()})
 void refresh()
 return {page:shallowReadonly(page),filter:shallowReadonly(filter),cursors:shallowReadonly(cursors),pending:shallowReadonly(pending),error:shallowReadonly(error),refresh,search,next,previous}
}
