import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {canEditSaved,changeError,copyDefinition,parserVersion,validSavedPage,validSavedReceipt,validSavedResolution,type Dataset,type SavedChange,type SavedListFilter,type SavedPage,type SavedQuery} from './savedSearch'

export function useSavedSearches(dataset:()=>Dataset){
 const page=shallowRef<SavedPage>({items:[],next_cursor:''}),filter=shallowRef<SavedListFilter>({keyword:'',visibility:'',active:'true'}),cursors=shallowRef([''])
 const loading=shallowRef(false),busy=shallowRef(false),resolving=shallowRef(false),error=shallowRef(''),mutationError=shallowRef(''),unconfirmed=shallowRef(false)
 let stopped=false,reader:AbortController|undefined,mutation:AbortController|undefined,resolver:AbortController|undefined,attempt:{input:SavedChange;key:string}|undefined
 async function load(){
  const principal=session.current.value
  if(stopped||!principal)return
  reader?.abort();const controller=new AbortController();reader=controller;loading.value=true;error.value=''
  const requested={...filter.value},cursor=cursors.value.at(-1)!,currentDataset=dataset()
  const parameters=new URLSearchParams({...requested,dataset:currentDataset,cursor,limit:'20'})
  try{const value=await session.api.request<unknown>('/saved-searches?'+parameters,{signal:controller.signal});if(controller.signal.aborted||stopped)return;if(!validSavedPage(value,principal,currentDataset,requested,cursor))throw new Error('查询目录未能完整返回，请刷新后重试。');page.value=value}
  catch(e){if(!controller.signal.aborted&&!stopped)error.value=e instanceof Error?e.message:'查询目录读取失败。'}
  finally{if(reader===controller){reader=undefined;loading.value=false}}
 }
 function search(value:SavedListFilter){filter.value={...value,keyword:value.keyword.trim()};cursors.value=[''];return load()}
 function next(){if(loading.value||error.value||!page.value.next_cursor)return; cursors.value=[...cursors.value,page.value.next_cursor];return load()}
 function previous(){if(loading.value||cursors.value.length<2)return;cursors.value=cursors.value.slice(0,-1);return load()}
 async function save(input:SavedChange){
  const principal=session.current.value
  if(stopped||busy.value||!principal)return undefined
  if(attempt&&JSON.stringify(attempt.input)!==JSON.stringify(input)){mutationError.value='上次提交结果尚未确认，请先核对原提交。';return undefined}
  const invalid=changeError(input)
  if(invalid){mutationError.value=invalid;return undefined}
  if(input.definition.dataset!==dataset()||input.visibility==='team'&&principal.role!=='admin'){mutationError.value='查询数据集或共享权限与当前页面不一致。';return undefined}
  if(!attempt)attempt={input:{...input,definition:copyDefinition(input.definition)},key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;mutationError.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const value=await session.api.request<unknown>('/saved-searches',{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted)throw new Error('提交结果尚未确认，请核对原提交。')
   if(!validSavedReceipt(value,frozen.input,principal))throw new Error('保存回执不完整或与原输入不一致，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;return value
  }catch(e){if(!stopped&&mutation===controller){mutationError.value=controller.signal.aborted?'提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'提交结果尚未确认。';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timer);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function confirm(){return attempt?save(attempt.input):Promise.resolve(undefined)}
 function pendingInput(){return attempt?structuredClone(attempt.input):undefined}
 function clearError(){if(!attempt)mutationError.value=''}
 async function resolve(record:SavedQuery){
  const principal=session.current.value
  if(stopped||resolving.value||!principal)return undefined
  if(record.definition.dataset!==dataset()||!record.active||record.definition.parser_version!==parserVersion){error.value='查询已停用、数据集不一致或解析器不兼容，请刷新后核对。';return undefined}
  resolver?.abort();const controller=new AbortController();resolver=controller;resolving.value=true;error.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{const value=await session.api.request<unknown>('/saved-searches/'+encodeURIComponent(record.id)+'/resolve',{method:'POST',body:{expected_revision:record.revision,expected_generation_id:record.generation_id,dataset:record.definition.dataset,parser_version:record.definition.parser_version},signal:controller.signal});if(controller.signal.aborted||stopped||resolver!==controller)return undefined;if(!validSavedResolution(value,record,principal))throw new Error('查询解析结果与所选条件不一致，请刷新后核对。');return value}
  catch(e){if(!stopped&&resolver===controller)error.value=controller.signal.aborted?'查询解析超时，请重试。':e instanceof Error?e.message:'查询解析失败。';return undefined}
  finally{clearTimeout(timer);if(resolver===controller){resolver=undefined;resolving.value=false}}
 }
 function reset(){reader?.abort();mutation?.abort();resolver?.abort();reader=mutation=resolver=undefined;attempt=undefined;page.value={items:[],next_cursor:''};cursors.value=[''];filter.value={keyword:'',visibility:'',active:'true'};loading.value=busy.value=resolving.value=unconfirmed.value=false;error.value=mutationError.value=''}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,dataset()].join('/'),reset)
 onScopeDispose(()=>{stopped=true;reset()})
 return {page:shallowReadonly(page),filter:shallowReadonly(filter),cursors:shallowReadonly(cursors),loading:shallowReadonly(loading),busy:shallowReadonly(busy),resolving:shallowReadonly(resolving),error:shallowReadonly(error),mutationError:shallowReadonly(mutationError),unconfirmed:shallowReadonly(unconfirmed),load,search,next,previous,save,confirm,pendingInput,clearError,resolve,canEdit:(record:SavedQuery)=>!!session.current.value&&canEditSaved(record,session.current.value)}
}
