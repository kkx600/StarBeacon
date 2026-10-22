import {webcrypto,randomUUID} from 'node:crypto'
import {beforeEach,describe,expect,it,vi} from 'vitest'
import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {emptyWatchlistDefinition,emptyWatchlistQuery,readWatchlist,readWatchlistPage,readWatchlistPreview,readWatchlistReceipt,watchlistBroad,watchlistChangeError,watchlistDefinitionError,watchlistDefinitionShape,watchlistPreviewError,watchlistState,watchlistTargetMatched,watchlistValueValid,type WatchlistDefinition,type WatchlistPreviewRequest} from '../packages/shared/src/watchlists'
import {watchlistDefinition,watchlistInput,watchlistPreview,watchlistRecord} from './watchlistFixtures'
import {principal} from './fixtures'

beforeEach(()=>vi.stubGlobal('crypto',{subtle:webcrypto.subtle,randomUUID}))
const query=emptyWatchlistQuery()
const target={sensor_id:'probe_1',registration_id:'register_1',type:'ip' as const,value:'192.0.2.10'}
const previewRequest=():WatchlistPreviewRequest=>({definition:watchlistDefinitionShape(watchlistDefinition),active:false,targets:[target]})
async function cursor(after:string,q=query,tenant=principal.tenant_id){return btoa(JSON.stringify({after,scope:await goJSONDigest({tenant,query:{...q,cursor:''}})})).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}

describe('名单输入与业务时间',()=>{
 it('地址格式使用浏览器规范地址并核对网段主机位，不接受隐式转换',()=>{
  for(const value of ['192.0.2.10','2001:db8::1','::1'])expect(watchlistValueValid('ip',value)).toBe(true)
  for(const value of ['192.000.2.10','192.0.2.256','0.0.0.0','224.0.0.1','::','ff02::1','::ffff:192.0.2.10','fe80::1%eth0','2001:0db8::1','2001:::1','<script>'])expect(watchlistValueValid('ip',value)).toBe(false)
  for(const value of ['192.0.2.0/24','192.0.2.10/32','0.0.0.0/0','2001:db8::/32','2001:db8::/120','::/0','1:2:3:4:5:6:7:8/128'])expect(watchlistValueValid('cidr',value)).toBe(true)
  for(const value of ['192.0.2.1/24','192.0.2.0/33','192.0.2.0/024','2001:db8::1/120','2001:db8::/129','::ffff:c000:200/120','192.0.2.0/24/2'])expect(watchlistValueValid('cidr',value)).toBe(false)
  expect(watchlistValueValid('domain','api.example.com')).toBe(true)
  for(const value of ['API.EXAMPLE.COM','*.example.com','https://example.com','example.com.','localhost','192.0.2.10','bad..example.com','-bad.example.com'])expect(watchlistValueValid('domain',value)).toBe(false)
  expect(watchlistValueValid('suffix','example.com')).toBe(false)
 })
 it('默认业务期限为180天且不填造探针和匹配值',()=>{const d=emptyWatchlistDefinition(Date.parse('2026-10-22T00:00:00.123Z'));expect(d.valid_from).toBe('2026-10-22T00:00:00Z');expect(Date.parse(d.valid_until)-Date.parse(d.valid_from)).toBe(180*86400000);expect(d.values).toEqual([]);expect(d.sensors).toEqual([]);expect(emptyWatchlistQuery()).toEqual(query)})
 it('复制定义时保留协议字段顺序并隔离输入数组',()=>{const d=watchlistDefinitionShape(watchlistDefinition);d.values.push('192.0.2.11');d.sensors[0]!.registration_id='new';expect(watchlistDefinition.values).toHaveLength(1);expect(watchlistDefinition.sensors[0]!.registration_id).toBe('register_1');expect(Object.keys(d)).toEqual(['schema_version','kind','match_type','values','sensors','valid_from','valid_until'])})
 it('拒绝不支持的结构、缺少范围、重复身份和不规范时间',()=>{
  for(const d of [null,{...watchlistDefinition,schema_version:'unknown'},{...watchlistDefinition,kind:'allow'},{...watchlistDefinition,match_type:'suffix'},{...watchlistDefinition,extra:true},{...watchlistDefinition,values:[]},{...watchlistDefinition,values:['192.0.2.10','192.0.2.10']},{...watchlistDefinition,values:['x\n']},{...watchlistDefinition,values:Array.from({length:65},(_,i)=>String(i))},{...watchlistDefinition,sensors:[]},{...watchlistDefinition,sensors:[target]},{...watchlistDefinition,sensors:[watchlistDefinition.sensors[0],{sensor_id:'probe_1',registration_id:'other'}]},{...watchlistDefinition,sensors:[{sensor_id:'A',registration_id:'r'}]},{...watchlistDefinition,valid_from:'2026-10-01T00:00:00.000Z'},{...watchlistDefinition,valid_from:'1999-01-01T00:00:00Z'},{...watchlistDefinition,valid_until:watchlistDefinition.valid_from},{...watchlistDefinition,valid_until:'2040-01-01T00:00:00Z'}])expect(watchlistDefinitionError(d)).not.toBe('')
  expect(watchlistDefinitionError(watchlistDefinition)).toBe('')
 })
 it('保存要求依据，过期不能启用，过宽前缀只允许停用',()=>{
  expect(watchlistChangeError(watchlistInput())).toBe('')
  for(const x of [{id:'BAD'},{expected_revision:1000000},{name:''},{description:''},{active:undefined},{name:' x'}])expect(watchlistChangeError({...watchlistInput(),...x} as ReturnType<typeof watchlistInput>)).not.toBe('')
  expect(watchlistChangeError({...watchlistInput(),active:true,definition:{...watchlistDefinition,valid_until:'2026-10-02T00:00:00Z'}},Date.parse('2026-10-22T00:00:00Z'))).toContain('已到期')
  const d:WatchlistDefinition={...watchlistDefinition,match_type:'cidr',values:['192.0.0.0/16']};expect(watchlistChangeError({...watchlistInput(),definition:d})).toBe('');expect(watchlistChangeError({...watchlistInput(),definition:d,active:true})).toContain('超过启用限制')
  expect(watchlistBroad({...d,values:['192.0.2.0/24']})).toBe(false);expect(watchlistBroad({...d,values:['2001:db8::/119']})).toBe(true);expect(watchlistBroad({...d,values:['2001:db8::/120']})).toBe(false);expect(watchlistBroad({...d,values:['bad']})).toBe(true)
 })
 it('停用、待生效、到期与有效分别显示，历史期限不控制业务状态',()=>{
  const row={active:true,definition:watchlistDefinition};expect(watchlistState(row,Date.parse('2026-10-22T00:00:00Z'))).toBe('effective');expect(watchlistState({...row,active:false})).toBe('disabled');expect(watchlistState(row,Date.parse('2026-09-01T00:00:00Z'))).toBe('scheduled');expect(watchlistState(row,Date.parse('2030-10-01T00:00:00Z'))).toBe('expired')
 })
})

describe('名单目录与不可变修订回执',()=>{
 it('核对租户、定义摘要、保存者、修订和历史时间',async()=>{
  const row=await watchlistRecord();expect(await readWatchlist(row,principal.tenant_id)).toEqual(row);expect(await readWatchlistReceipt(row,principal.tenant_id,watchlistInput(),principal.id)).toEqual(row)
  for(const extra of [{tenant_id:'other'},{id:'BAD'},{created_by:''},{revision:0},{name:''},{description:''},{active:null},{definition:{}},{definition_sha256:'a'.repeat(64)},{created_at:'bad'},{expires_at:row.created_at}])await expect(readWatchlist({...row,...extra},principal.tenant_id)).rejects.toThrow('不一致')
  for(const extra of [{created_by:'other'},{id:'watch_other'},{revision:2},{name:'其他名称'},{description:'其他依据'},{active:true},{definition:{...row.definition,kind:'observe'}}])await expect(readWatchlistReceipt({...row,...extra},principal.tenant_id,watchlistInput(),principal.id)).rejects.toThrow('不一致')
 })
 it('允许历史已过业务期，拒绝启用的过宽定义',async()=>{
  const expired=watchlistInput();expired.definition.valid_until='2026-10-02T00:00:00Z';expired.active=true;expect((await readWatchlist(await watchlistRecord(expired),principal.tenant_id)).active).toBe(true)
  const broad=watchlistInput();broad.active=true;broad.definition.match_type='cidr';broad.definition.values=['192.0.0.0/16'];await expect(readWatchlist(await watchlistRecord(broad),principal.tenant_id)).rejects.toThrow()
 })
 it('分页只接受同一查询及租户的严格游标，不交付错条件的记录',async()=>{
  const row=await watchlistRecord(),q={...query,limit:1},next=await cursor(row.id,q)
  expect((await readWatchlistPage({items:[row],next_cursor:next},q,principal.tenant_id)).next_cursor).toBe(next)
  expect((await readWatchlistPage({items:[],next_cursor:''},{...q,cursor:next},principal.tenant_id)).items).toEqual([])
  const values=[{items:null,next_cursor:''},{items:[row,row],next_cursor:''},{items:[row],next_cursor:1},{items:[],next_cursor:next},{items:[row],next_cursor:'bad!'}, {items:[row],next_cursor:await cursor('watch_z',q)}]
  for(const v of values)await expect(readWatchlistPage(v,q,principal.tenant_id)).rejects.toThrow()
  await expect(readWatchlistPage({items:[row],next_cursor:''},{...q,cursor:next},principal.tenant_id)).rejects.toThrow()
  await expect(readWatchlistPage({items:[row],next_cursor:''},{...q,active:'true'},principal.tenant_id)).rejects.toThrow()
  await expect(readWatchlistPage({items:[row],next_cursor:''},{...q,kind:'observe'},principal.tenant_id)).rejects.toThrow()
  for(const token of ['bad',btoa('{}').replaceAll('=',''),await cursor(row.id,{...q,keyword:'other'}),await cursor(row.id,q,'other')])await expect(readWatchlistPage({items:[],next_cursor:''},{...q,cursor:token},principal.tenant_id)).rejects.toThrow()
 })
})

describe('名单范围预览的真实含义',()=>{
 it('材料匹配按探针注册和地址族隔离，精确域名不作后缀命中',()=>{
  expect(watchlistTargetMatched(watchlistDefinition,target)).toBe(true);expect(watchlistTargetMatched(watchlistDefinition,{...target,registration_id:'other'})).toBe(false);expect(watchlistTargetMatched(watchlistDefinition,{...target,value:'192.0.2.11'})).toBe(false)
  const cidr:WatchlistDefinition={...watchlistDefinition,match_type:'cidr',values:['192.0.2.0/24','2001:db8::/120']}
  expect(watchlistTargetMatched(cidr,target)).toBe(true);expect(watchlistTargetMatched(cidr,{...target,value:'2001:db8::ff'})).toBe(true);expect(watchlistTargetMatched(cidr,{...target,value:'2001:db8::100'})).toBe(false)
  const domain:WatchlistDefinition={...watchlistDefinition,match_type:'domain',values:['example.test']}
  expect(watchlistTargetMatched(domain,{...target,type:'domain',value:'example.test'})).toBe(true);expect(watchlistTargetMatched(domain,{...target,type:'domain',value:'api.example.test'})).toBe(false);expect(watchlistTargetMatched(domain,target)).toBe(false);expect(watchlistTargetMatched(cidr,{...target,type:'domain',value:'example.test'})).toBe(false);expect(watchlistTargetMatched({...cidr,values:[]},target)).toBe(false)
 })
 it('预览材料匹配可以为真，但停用名单仍不生效，也不授权动作或删除',async()=>{
  const request=previewRequest(),result=await watchlistPreview(request);expect(result.matches[0]!.matched).toBe(true);expect(result.effective).toBe(false);expect(await readWatchlistPreview(result,request)).toEqual(result)
  expect(watchlistPreviewError(request)).toBe('');for(const v of [{...request,active:null},{...request,targets:[{...target,sensor_id:'BAD'}]},{...request,targets:[{...target,type:'cidr'}]},{...request,targets:Array.from({length:129},()=>target)}])expect(watchlistPreviewError(v as WatchlistPreviewRequest)).not.toBe('')
 })
 it('严格核对时间、范围、原因、结果索引和不可执行声明',async()=>{
  const request=previewRequest(),result=await watchlistPreview(request)
  for(const extra of [{schema_version:'other'},{definition_sha256:'a'.repeat(64)},{active:true},{admissible:false},{effective:true},{checked_at:'bad'},{scope_sensor_count:2},{value_count:2},{reasons:[]},{matches:[]},{matches:[{index:1,matched:true}]},{matches:[{index:0,matched:'true'}]},{matches:[{index:0,matched:false}]},{execution_authorized:true},{fact_deletion_allowed:true}])await expect(readWatchlistPreview({...result,...extra},request)).rejects.toThrow()
  const future={...request,active:true,definition:{...request.definition,valid_from:'2027-01-01T00:00:00Z'}};expect((await readWatchlistPreview(await watchlistPreview(future),future)).reasons).toEqual(['not_yet_valid'])
  const expired={...request,definition:{...request.definition,valid_until:'2026-10-02T00:00:00Z'}};expect((await readWatchlistPreview(await watchlistPreview(expired),expired)).admissible).toBe(false)
  const broad={...request,definition:{...request.definition,match_type:'cidr' as const,values:['192.0.0.0/16']}};expect((await readWatchlistPreview(await watchlistPreview(broad),broad)).reasons).toContain('scope_too_broad')
 })
})
