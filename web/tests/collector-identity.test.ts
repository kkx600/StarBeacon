import {beforeEach,describe,expect,it,vi} from 'vitest'
import {flushPromises,mount} from '@vue/test-utils'
import {defineComponent,h,type ShallowRef} from 'vue'
import {registerAnt} from '../packages/shared/src/ant'
import {validProbeIdentity} from '../packages/shared/src/utils/probeIdentity'
import type {Principal} from '../packages/shared/src/types'
import {session} from '../collector/src/session'
import {useProbeIdentity} from '../collector/src/features/network/useProbeIdentity'
import CollectorIdentity from '../collector/src/features/network/CollectorIdentity.vue'
import {principal,deferred,click} from './fixtures'
const {request}=vi.hoisted(()=>({request:vi.fn()}))
vi.mock('../collector/src/session',async()=>({session:{api:{request},current:(await import('vue')).shallowRef(null)}}))
const user=session.current as ShallowRef<Principal|null>
const identity={mode:'managed',sensor_id:'probe_a',registration_id:'reg_a',fingerprint_sha256:'a'.repeat(64),not_before:'2026-10-17T00:00:00Z',renew_after:'2026-10-17T02:00:00Z',not_after:'2026-10-17T03:00:00Z'}
beforeEach(()=>{user.value=principal;request.mockReset();request.mockResolvedValue(identity)})
function host(){let state!:ReturnType<typeof useProbeIdentity>;const wrapper=mount(defineComponent({setup(){state=useProbeIdentity();return()=>h('div')}}));return{state,wrapper}}
describe('采集器本机身份状态',()=>{
 it('验证身份、用途状态和时间顺序，拒绝私钥及令牌字段',()=>{
  expect(validProbeIdentity(identity)).toBe(true);expect(validProbeIdentity({...identity,mode:'static',fingerprint_sha256:''})).toBe(true)
  for(const bad of [null,{}, {...identity,mode:'unknown'}, {...identity,sensor_id:'foreign/probe'},{...identity,registration_id:''},{...identity,fingerprint_sha256:'bad'},{...identity,renew_after:identity.not_after},{...identity,not_after:'bad'},...['token','key_pem','chain_pem','csr_pem','private_key'].map(key=>({...identity,[key]:'excluded'}))])expect(validProbeIdentity(bad)).toBe(false)
 })
 it('迟到回执不能覆盖新请求，权限变化和卸载清除状态',async()=>{
  const {state,wrapper}=host();await flushPromises();expect(state.identity.value?.fingerprint_sha256).toBe(identity.fingerprint_sha256)
  const wait=deferred<unknown>();request.mockReturnValueOnce(wait.promise);const old=state.refresh();const signal=request.mock.lastCall?.[1].signal as AbortSignal
  request.mockResolvedValueOnce({...identity,fingerprint_sha256:'b'.repeat(64)});await state.refresh();wait.resolve(identity);await old;expect(signal.aborted).toBe(true);expect(state.identity.value?.fingerprint_sha256).toBe('b'.repeat(64))
  user.value={...principal,role:'viewer'};await flushPromises();expect(state.identity.value).toBeNull();const count=request.mock.calls.length;await state.refresh();expect(request).toHaveBeenCalledTimes(count)
  user.value=principal;await flushPromises();expect(state.identity.value).not.toBeNull();wrapper.unmount();expect(state.identity.value).toBeNull();await state.refresh()
 })
 it('错误回执和网络异常不会显示为有效证书，允许显式重试',async()=>{
  request.mockResolvedValueOnce({mode:'managed'});const wrapper=mount(CollectorIdentity,{global:{plugins:[registerAnt]},attachTo:document.body});await flushPromises();expect(wrapper.text()).toContain('回执不完整')
  request.mockRejectedValueOnce(new Error('服务不可用'));await click('刷新证书状态');expect(wrapper.text()).toContain('服务不可用')
  await click('刷新证书状态');expect(wrapper.text()).toContain(identity.fingerprint_sha256);expect(wrapper.text()).toContain('本机证书状态不代表平台当前允许通信')
 })
})
