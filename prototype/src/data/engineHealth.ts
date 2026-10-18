import type {EngineHealth} from '../../../web/packages/shared/src/engineHealth'
export function engineHealthExample(value:unknown=true):EngineHealth {
 const state=value===false?'unavailable':typeof value==='string'&&['pending','unconfigured','unavailable'].includes(value)?value:'observed'
 const codes:Record<string,string>={pending:'engine_observation_pending',unconfigured:'engine_observation_not_configured',unavailable:'engine_process_unverified'}
 return {schema_version:'1',state,source:state==='observed'?'managed_process':'unavailable',observed_at:'2026-10-18T08:30:00Z',...(state==='observed'?{pid:125,started_at:'2026-10-18T08:00:00Z',config_sha256:'a'.repeat(64),rules_sha256:'b'.repeat(64),file_rule_count:1250,rules_loaded:1250}:{code:codes[state]}),rules_failed:0}
}
