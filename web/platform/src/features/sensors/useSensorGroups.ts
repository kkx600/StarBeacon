import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {session} from '../../session'
import {validGroupPage,type GroupPage,type SensorGroup} from './management'

export function useSensorGroups(){
 const page=shallowRef<GroupPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const choices=shallowRef<SensorGroup[]>([]),choicesPending=shallowRef(false),choicesError=shallowRef('')
 let stopped=false,keyword='',active='',epoch=0,choiceEpoch=0,reader:AbortController|undefined,choiceReader:AbortController|undefined
 async function refresh(){
  if(stopped)return
  const version=++epoch;reader?.abort();const controller=new AbortController();reader=controller;pending.value=true;error.value=''
  try{const value=await session.api.request<unknown>('/sensor-groups?'+new URLSearchParams({cursor:cursors.value.at(-1)??'',keyword,active,limit:'20'}),{signal:controller.signal});if(stopped||version!==epoch||controller.signal.aborted)return;if(!validGroupPage(value))throw new Error('探针分组列表未能完整返回');page.value=value}
  catch(e){if(!stopped&&version===epoch&&!controller.signal.aborted)error.value=e instanceof Error?e.message:'探针分组读取失败'}finally{if(!stopped&&version===epoch)pending.value=false}
 }
 async function loadChoices(){
  if(stopped)return
  const version=++choiceEpoch;choiceReader?.abort();const controller=new AbortController();choiceReader=controller;choicesPending.value=true;choicesError.value=''
  const collected:SensorGroup[]=[],seen=new Set<string>();let cursor=''
  try{
   for(let round=0;round<6;round++){
    const value=await session.api.request<unknown>('/sensor-groups?'+new URLSearchParams({cursor,active:'true',limit:'100'}),{signal:controller.signal});if(stopped||version!==choiceEpoch||controller.signal.aborted)return
    if(!validGroupPage(value)||value.items.some(g=>!g.active||seen.has(g.id)))throw new Error('可用探针分组未能完整返回')
    for(const group of value.items){seen.add(group.id);collected.push(group)}
    if(collected.length>512)throw new Error('可用探针分组数量超过管理上限')
    if(!value.next_cursor){choices.value=collected;return}
    if(value.next_cursor<=cursor)throw new Error('可用探针分组分页异常')
    cursor=value.next_cursor
   }
   throw new Error('可用探针分组分页未结束')
  }catch(e){if(!stopped&&version===choiceEpoch&&!controller.signal.aborted){choices.value=[];choicesError.value=e instanceof Error?e.message:'可用探针分组读取失败'}}finally{if(!stopped&&version===choiceEpoch)choicesPending.value=false}
 }
 function search(k:string,a:string){keyword=k.trim();active=a;cursors.value=[''];void refresh()}
 function next(){if(!pending.value&&page.value.next_cursor){cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}}
 function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
 onScopeDispose(()=>{stopped=true;epoch++;choiceEpoch++;reader?.abort();choiceReader?.abort()})
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),()=>{epoch++;choiceEpoch++;reader?.abort();choiceReader?.abort();page.value={items:[],next_cursor:''};choices.value=[];cursors.value=[''];keyword='';active='';error.value='';choicesError.value='';pending.value=false;choicesPending.value=false;if(session.current.value){void refresh();void loadChoices()}})
 void refresh();void loadChoices()
 return {page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),choices:shallowReadonly(choices),choicesPending:shallowReadonly(choicesPending),choicesError:shallowReadonly(choicesError),refresh,loadChoices,search,next,previous}
}
