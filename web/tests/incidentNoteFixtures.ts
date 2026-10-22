import type {IncidentNoteCreate,IncidentNoteChange,IncidentNoteRecord} from '../platform/src/features/incidents/incidentNote'
import {incidentRecord} from './incidentFixtures'
import {principal} from './fixtures'
export const incidentNoteCreate:IncidentNoteCreate={incident_revision:1,spec:{title:'核对原始材料',body:'观察到检测请求。\n<script>记录作为纯文本</script>\n攻击结果尚未确认。',status:'active',withdrawal_reason:''}}
export const incidentNote:IncidentNoteRecord={id:'case_note_owned',incident_id:incidentRecord.id,incident_revision:1,revision:1,spec:incidentNoteCreate.spec,author_id:principal.id,author_name:principal.username,reason:'建立调查笔记',actor_id:principal.id,actor_name:principal.username,created_at:'2026-10-01T00:02:00.000000001Z',recorded_at:'2026-10-01T00:02:00.000000001Z',expires_at:'2027-03-30T00:02:00Z'}
export const incidentNoteChange:IncidentNoteChange={incident_revision:1,expected_revision:1,spec:{...incidentNote.spec,status:'withdrawn',withdrawal_reason:'引用标识需要重新核对，原文保留。'},reason:'撤回待核实材料'}
export const incidentNoteWithdrawn:IncidentNoteRecord={...incidentNote,revision:2,spec:incidentNoteChange.spec,reason:incidentNoteChange.reason,recorded_at:'2026-10-01T00:03:00.000000001Z'}
export const incidentNotePage={items:[incidentNote],next_cursor:''}
