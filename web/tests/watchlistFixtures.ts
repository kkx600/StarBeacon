import {goJSONDigest} from '../packages/shared/src/utils/goJSONDigest'
import {watchlistBroad,watchlistDefinitionShape,watchlistTargetMatched,type WatchlistChange,type WatchlistDefinition,type WatchlistPreviewRequest,type WatchlistPreviewResult,type WatchlistRecord} from '../packages/shared/src/watchlists'
import {principal} from './fixtures'

export const watchlistDefinition:WatchlistDefinition={schema_version:'watchlist.v1',kind:'protect',match_type:'ip',values:['192.0.2.10'],sensors:[{sensor_id:'probe_1',registration_id:'register_1'}],valid_from:'2026-10-01T00:00:00Z',valid_until:'2030-10-01T00:00:00Z'}
export const watchlistInput=():WatchlistChange=>({id:'watch_office',expected_revision:0,name:'办公区管理地址',description:'保护办公区管理链路，保持告警事实。',active:false,definition:watchlistDefinitionShape(watchlistDefinition)})
export async function watchlistRecord(input=watchlistInput()):Promise<WatchlistRecord>{
 return {tenant_id:principal.tenant_id,id:input.id,revision:input.expected_revision+1,name:input.name,description:input.description,active:input.active,definition:watchlistDefinitionShape(input.definition),definition_sha256:await goJSONDigest(watchlistDefinitionShape(input.definition)),created_by:principal.id,created_at:'2026-10-22T00:00:00Z',expires_at:'2027-04-20T00:00:00Z'}
}
export async function watchlistPreview(input:WatchlistPreviewRequest,checkedAt='2026-10-22T00:00:00Z'):Promise<WatchlistPreviewResult>{
 const broad=watchlistBroad(input.definition),expired=Date.parse(checkedAt)>=Date.parse(input.definition.valid_until),future=Date.parse(checkedAt)<Date.parse(input.definition.valid_from)
 return {schema_version:'watchlist-preview.v1',definition_sha256:await goJSONDigest(watchlistDefinitionShape(input.definition)),active:input.active,admissible:!broad&&!expired,effective:input.active&&!broad&&!expired&&!future,checked_at:checkedAt,scope_sensor_count:input.definition.sensors.length,value_count:input.definition.values.length,reasons:[...(broad?['scope_too_broad']:[]),...(expired?['expired']:future?['not_yet_valid']:[]),...(!input.active?['inactive']:[])],matches:input.targets.map((t,index)=>({index,matched:watchlistTargetMatched(input.definition,t)})),execution_authorized:false,fact_deletion_allowed:false}
}
