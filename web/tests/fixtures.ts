import {flushPromises} from '@vue/test-utils'
import type {BaseWrapper} from '@vue/test-utils'
import {expect,vi} from 'vitest'
import {EditorView} from '@codemirror/view'
import type {Principal,ReplaySample,RulePackage,Sensor,SensorTask} from '../packages/shared/src/types'
export const principal:Principal={id:'u_admin',tenant_id:'t_office',username:'admin',role:'admin',csrf_token:'test-csrf'}
export const rules='alert http any any -> any any (msg:"HTTP API access"; http.uri; content:"/api"; sid:9900001; rev:1;)'
export const rulePackage:RulePackage={id:'pkg_test',name:'HTTP 检测',revision:4,engine_version:'8.0.7',sha256:'a'.repeat(64),created_at:'2026-10-01T00:00:00Z',text:rules}
export const sample:ReplaySample={id:'sample_1',name:'http-handshake.pcap',format:'pcap',size:1024,sha256:'b'.repeat(64),created_at:'2026-10-01T00:00:00Z',expires_at:'2027-03-30T00:00:00Z'}
export const sensor:Sensor={id:'probe_1',name:'办公区探针',registration_id:'register_1',active:true,status:'online',created_at:'2026-10-01T00:00:00Z',last_seen:'2026-10-02T00:00:00Z',health:{hostname:'lab',cpu_percent:10,memory_percent:null,disk_percent:20,rx_bytes:'18446744073709551615',tx_bytes:'12000',wal_pending:10,errors:[],task_capabilities:['diagnostics','rules.replay','rules.validate'],registered_rules_available:true}}
export const task:SensorTask={id:'task_1',sensor_id:sensor.id,kind:'rules.replay',state:'queued',created_by:principal.id,created_at:'2026-10-01T00:00:00Z',expires_at:'2026-10-02T00:00:00Z',updated_at:'2026-10-01T00:00:00Z',delivery_count:0,receipt:{}}
export function button(label:string,root:ParentNode=document.body){const matches=Array.from(root.querySelectorAll<HTMLButtonElement>('button')).filter(element=>element.textContent?.replace(/\s/g,'')===label);expect(matches.length,`页面应提供 ${label}`).toBeGreaterThan(0);return matches[0]!}
export async function click(label:string,root:ParentNode=document.body){let target:HTMLElement|undefined;await vi.waitFor(()=>{target=Array.from(root.querySelectorAll<HTMLElement>('button,[role=tab],label.ant-radio-button-wrapper')).find(element=>element.textContent?.replace(/\s/g,'')===label);expect(target,`页面应提供 ${label}`).toBeDefined()});target!.click();await flushPromises()}
export async function writeRule(wrapper:Pick<BaseWrapper<Node>, 'get'>,text:string){const element=wrapper.get('.cm-editor').element as HTMLElement,view=EditorView.findFromDOM(element);expect(view).not.toBeNull();view!.dispatch({changes:{from:0,to:view!.state.doc.length,insert:text}});await flushPromises();return view!}
export function closedMessage(){const promise=Promise.resolve();return Object.assign(()=>{}, {then:promise.then.bind(promise)})}
export function deferred<T>(){let resolve!:(value:T)=>void,reject!:(value:unknown)=>void;const promise=new Promise<T>((yes,no)=>{resolve=yes;reject=no});return{promise,resolve,reject}}
