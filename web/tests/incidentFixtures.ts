import type {IncidentCreate,IncidentRecord,IncidentChange,IncidentClosure} from '../platform/src/features/incidents/incident'
import {principal} from './fixtures'
export const incidentRef={event_id:'event_owned',raw_sha256:'a'.repeat(64)}
export const incidentInput:IncidentCreate={spec:{title:'办公网检测调查',category:'network_intrusion',severity:'high',status:'open',summary:'核对检测事实与业务影响。',owner_id:principal.id,closure:null},alerts:[incidentRef]}
export const incidentRecord:IncidentRecord={id:'incident_owned',revision:1,spec:incidentInput.spec,owner_name:principal.username,alerts:[{...incidentRef,sensor_id:'probe_owned',observed_at:'2026-10-01T00:00:00Z',event_time:'2026-10-01T00:00:00Z'}],note:'登记检测事实。',actor_id:principal.id,actor_name:principal.username,created_at:'2026-10-01T00:00:00Z',recorded_at:'2026-10-01T00:00:00Z',expires_at:'2027-03-30T00:00:00Z'}
export const incidentClosure:IncidentClosure={reason:'resolved',root_cause:'授权测试命中。',impact:'隔离测试环境。',remediation:'检查规则和范围。',verification:'核对真实复测记录。',evidence:['owned:replay-result']}
export const incidentChange:IncidentChange={expected_revision:1,spec:{...incidentInput.spec,status:'investigating'},note:'责任人核对检测事实。',add_alerts:[]}
export const incidentChanged:IncidentRecord={...incidentRecord,revision:2,spec:incidentChange.spec,note:incidentChange.note,recorded_at:'2026-10-01T00:01:00Z',expires_at:'2027-03-30T00:01:00Z'}
export const incidentClosed:IncidentRecord={...incidentChanged,revision:3,spec:{...incidentChanged.spec,status:'closed',closure:incidentClosure}}
export const incidentOwners={items:[{id:principal.id,name:principal.username}]}
export const incidentPage={items:[incidentRecord],next_cursor:''}
