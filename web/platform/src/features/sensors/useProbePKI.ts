import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {session} from '../../session'
import {validEnrollmentPage,validCertificatePage,pkiID,type EnrollmentPage,type CertificatePage} from './pki'

export function useProbePKI(){
 const mode=shallowRef<'enrollments'|'certificates'>('enrollments'),sensor=shallowRef('')
 const enrollments=shallowRef<EnrollmentPage>({items:[],next_cursor:'',ca_configured:false}),certificates=shallowRef<CertificatePage>({items:[],next_cursor:''})
 const pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 let stopped=false,controller:AbortController|undefined
 function clear(){enrollments.value={items:[],next_cursor:'',ca_configured:false};certificates.value={items:[],next_cursor:''}}
 async function load(cursor=cursors.value.at(-1)??'',replace?:string[]){
  if(stopped||session.current.value?.role!=='admin')return
  controller?.abort();const current=new AbortController();controller=current;error.value=''
  if(mode.value==='certificates'&&!pkiID(sensor.value)){clear();pending.value=false;error.value='请填写完整的探针标识。';return}
  const selected=mode.value,target=sensor.value
  pending.value=true;clear()
  const timer=setTimeout(()=>current.abort(),10000)
  try{
   const raw=await session.api.request<unknown>((selected==='enrollments'?'/sensor-enrollments':'/sensors/'+encodeURIComponent(target)+'/certificates')+(cursor?'?cursor='+encodeURIComponent(cursor):''),{signal:current.signal})
   if(stopped||controller!==current)return
   if(current.signal.aborted)throw new Error('目录读取超时，请重试。')
   if(selected==='enrollments'){if(!validEnrollmentPage(raw))throw new Error('注册目录回执不完整，请重试。');enrollments.value=raw}
   else {if(!validCertificatePage(raw,target))throw new Error('证书目录与当前探针不一致，请重试。');certificates.value=raw}
   if(replace)cursors.value=replace
  }catch(e){if(!stopped&&controller===current){clear();error.value=current.signal.aborted?'目录读取超时，请重试。':e instanceof Error?e.message:'目录读取失败，请重试。'}}
  finally{clearTimeout(timer);if(controller===current){controller=undefined;pending.value=false}}
 }
 function select(value:'enrollments'|'certificates',target=sensor.value){controller?.abort();controller=undefined;pending.value=false;mode.value=value;sensor.value=target;cursors.value=[''];clear();error.value='';if(value==='enrollments'||pkiID(target))void load()}
 function search(target:string){sensor.value=target.trim();cursors.value=[''];void load()}
 function next(){const cursor=(mode.value==='enrollments'?enrollments.value:certificates.value).next_cursor;if(cursor&&!pending.value)return load(cursor,[...cursors.value,cursor])}
 function previous(){if(cursors.value.length>1&&!pending.value){const prior=cursors.value.slice(0,-1);return load(prior.at(-1)??'',prior)}}
 const reset=()=>{controller?.abort();controller=undefined;clear();error.value='';pending.value=false;cursors.value=['']}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),reset)
 onScopeDispose(()=>{stopped=true;reset()})
 return {mode:shallowReadonly(mode),sensor:shallowReadonly(sensor),enrollments:shallowReadonly(enrollments),certificates:shallowReadonly(certificates),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),load,select,search,next,previous}
}
