import {goJSONDigest} from '../../../web/packages/shared/src/utils/goJSONDigest'
import {instant} from '../../../web/packages/shared/src/utils/instant'
import {readWatchlist,readWatchlistPreview,watchlistBroad,watchlistDefinitionShape,watchlistPreviewError,watchlistTargetMatched,type WatchlistDefinition,type WatchlistRecord,type WatchlistPreviewRequest,type WatchlistPreviewResult,type WatchlistSensor} from '../../../web/packages/shared/src/watchlists'

export const watchlistExampleTime='2026-10-22T01:00:00Z'
export const watchlistExampleClock=Date.parse(watchlistExampleTime)
export const watchlistExampleSensors:WatchlistSensor[]=[{sensor_id:'probe_hq_example',registration_id:'reg_hq_example',name:'总部探针（示例）',available:true},{sensor_id:'probe_branch_example',registration_id:'reg_branch_example',name:'分支探针（示例）',available:true}]
export async function watchlistExamples():Promise<WatchlistRecord[]> {
 const base:WatchlistDefinition={schema_version:'watchlist.v1',kind:'protect',match_type:'ip',values:['192.0.2.10'],sensors:[{sensor_id:'probe_hq_example',registration_id:'reg_hq_example'}],valid_from:'2026-10-01T00:00:00Z',valid_until:'2027-04-20T00:00:00Z'}
 const examples=[
  {id:'watch_protect_example',name:'管理地址保护（示例）',description:'核对管理地址保护范围；该示例不接入设备执行。',active:true,definition:base},
  {id:'watch_observe_example',name:'业务域名观察（示例）',description:'保留相关检测事实，展示材料匹配与名单状态。',active:true,definition:{...base,kind:'observe' as const,match_type:'domain' as const,values:['example.test']}},
  {id:'watch_expired_example',name:'到期临时保护（示例）',description:'期限结束后不参与后续判断，历史记录保留。',active:true,definition:{...base,values:['198.51.100.20'],valid_until:'2026-10-21T00:00:00Z'}},
  {id:'watch_disabled_example',name:'宽范围待核对（示例）',description:'宽网段仅允许停用保存，不能直接启用。',active:false,definition:{...base,match_type:'cidr' as const,values:['192.0.0.0/16']}},
 ]
 return Promise.all(examples.map(async row=>readWatchlist({...row,tenant_id:'tenant_example',revision:2,definition_sha256:await goJSONDigest(watchlistDefinitionShape(row.definition)),created_by:'admin_example',created_at:'2026-10-18T01:00:00Z',expires_at:'2027-04-16T01:00:00Z'},'tenant_example')))
}

// 复用工程字段和材料匹配校验，仅计算内存示例；不核验生产探针权限或执行设备动作。
export async function previewWatchlistExample(input:WatchlistPreviewRequest):Promise<WatchlistPreviewResult> {
 const invalid=watchlistPreviewError(input)
 if(invalid)throw new Error(invalid)
 const broad=watchlistBroad(input.definition),now=instant(watchlistExampleTime)!,expired=now>=instant(input.definition.valid_until)!,future=now<instant(input.definition.valid_from)!
 const result:WatchlistPreviewResult={schema_version:'watchlist-preview.v1',definition_sha256:await goJSONDigest(watchlistDefinitionShape(input.definition)),active:input.active,admissible:!broad&&!expired,effective:input.active&&!broad&&!expired&&!future,checked_at:watchlistExampleTime,scope_sensor_count:input.definition.sensors.length,value_count:input.definition.values.length,reasons:[...(broad?['scope_too_broad']:[]),...(expired?['expired']:future?['not_yet_valid']:[]),...(!input.active?['inactive']:[])],matches:input.targets.map((target,index)=>({index,matched:watchlistTargetMatched(input.definition,target)})),execution_authorized:false,fact_deletion_allowed:false}
 return readWatchlistPreview(result,input)
}
