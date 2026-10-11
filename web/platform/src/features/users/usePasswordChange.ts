import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validUserRecord,type UserRecord} from './user'

export interface PasswordInput{expected_revision:number;current_password:string;new_password:string}
export function passwordInputError(input:PasswordInput){
 if(!Number.isSafeInteger(input.expected_revision)||input.expected_revision<1||input.expected_revision>=1000000)return '当前账号修订不可修改，请刷新后核对。'
 const bytes=new TextEncoder()
 if(!input.current_password||bytes.encode(input.current_password).length>72||/\p{Cc}/u.test(input.current_password))return '请输入当前登录账号的密码，最多 72 个 UTF-8 字节。'
 if(bytes.encode(input.new_password).length<12||bytes.encode(input.new_password).length>72||/\p{Cc}/u.test(input.new_password))return '新密码须为 12～72 个 UTF-8 字节，不能包含控制字符。'
 if(input.new_password===input.current_password)return '新密码不能与当前登录账号的密码相同。'
 return ''
}

export function usePasswordChange(initial:UserRecord|null,own:boolean){
 const record=shallowRef<UserRecord|null>(initial),pending=shallowRef(false),error=shallowRef(''),busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
 const identity=[session.current.value?.tenant_id,session.current.value?.id].join('/'),id=own?session.current.value?.id??'':initial?.id??''
 let stopped=false,epoch=0,read:AbortController|undefined,mutation:AbortController|undefined,attempt:{input:PasswordInput;key:string}|undefined
 async function reload(){
  if(stopped||busy.value||unconfirmed.value)return
  const generation=++epoch,controller=new AbortController();read?.abort();read=controller;record.value=null;pending.value=true;error.value=''
  try{const result=await session.api.request<unknown>(own?'/auth/account':'/users/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||generation!==epoch)return;if(!validUserRecord(result)||result.id!==id)throw new Error('账号信息未能完整返回');record.value=result}
  catch(e){if(!stopped&&generation===epoch&&!controller.signal.aborted)error.value=e instanceof Error?e.message:'账号信息读取失败'}
  finally{if(!stopped&&generation===epoch)pending.value=false}
 }
 async function save(input:PasswordInput){
  if(stopped||busy.value||!record.value)return undefined
  if(attempt&&JSON.stringify(attempt.input)!==JSON.stringify(input)){actionError.value='上次操作结果尚未确认，请先核对原提交。';return undefined}
  if(!attempt){const reason=passwordInputError(input);if(reason){actionError.value=reason;return undefined}attempt={input:structuredClone(input),key:crypto.randomUUID()}}
  const frozen=attempt,before=record.value,controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const result=await session.api.request<unknown>(own?'/auth/password':'/users/'+encodeURIComponent(id)+'/password',{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted)throw new Error('提交结果尚未确认，请核对原提交。')
   if(!validUserRecord(result)||result.id!==id||result.username!==before.username||result.role!==before.role||result.active!==before.active||result.revision!==frozen.input.expected_revision+1)throw new Error('密码操作回执不完整，请核对原提交。')
   record.value=result;attempt=undefined;unconfirmed.value=false;return result
  }catch(e){if(!stopped&&mutation===controller){actionError.value=controller.signal.aborted?'提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'密码操作结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timer);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function clear(){epoch++;read?.abort();mutation?.abort();read=undefined;mutation=undefined;attempt=undefined;record.value=null;busy.value=false;pending.value=false;unconfirmed.value=false;actionError.value=''}
 onScopeDispose(()=>{stopped=true;clear()})
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),value=>{if(value!==identity){stopped=true;clear()}})
 if(!initial)void reload()
 return{record:shallowReadonly(record),pending:shallowReadonly(pending),error:shallowReadonly(error),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),reload,save,confirm:()=>attempt?save(attempt.input):Promise.resolve(undefined)}
}
