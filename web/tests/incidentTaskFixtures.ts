import type {IncidentTaskCreate,IncidentTaskRecord,IncidentTaskChange} from '../platform/src/features/incidents/incidentTask'
import {incidentRecord} from './incidentFixtures'
import {principal} from './fixtures'

export const incidentTaskCreate:IncidentTaskCreate={incident_revision:incidentRecord.revision,spec:{title:'核对请求与返回',description:'检查实际原包与保留材料，记录核对结果。',status:'open',priority:'high',assignee_id:principal.id,due_at:'2026-10-18T10:30:15.123456789Z',resolution:''}}
export const incidentTask:IncidentTaskRecord={id:'case_task_owned',incident_id:incidentRecord.id,incident_revision:incidentRecord.revision,revision:1,spec:incidentTaskCreate.spec,assignee_name:principal.username,note:'建立协作任务',actor_id:principal.id,actor_name:principal.username,created_at:'2026-10-18T01:00:00Z',recorded_at:'2026-10-18T01:00:00Z',expires_at:'2027-04-16T01:00:00Z'}
export const incidentTaskChange:IncidentTaskChange={incident_revision:1,expected_revision:1,spec:{...incidentTask.spec,status:'completed',resolution:'已核对隔离样本的实际请求与响应。'},note:'完成材料核对。'}
export const incidentTaskDone:IncidentTaskRecord={...incidentTask,revision:2,spec:incidentTaskChange.spec,note:incidentTaskChange.note,recorded_at:'2026-10-18T01:05:00Z',expires_at:'2027-04-16T01:05:00Z'}
export const incidentTaskPage={items:[incidentTask],next_cursor:''}
