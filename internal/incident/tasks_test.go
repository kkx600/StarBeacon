package incident

import (
	"strings"
	"testing"
	"time"
)

func taskSpec() TaskSpec {
	return TaskSpec{Title: "核对业务影响", Description: "根据实际材料记录受影响范围。", Status: "open", Priority: "medium"}
}

func taskRecord() TaskRecord {
	now := time.Now().UTC()
	return TaskRecord{ID: "case_task_owned", IncidentID: "incident_owned", IncidentRevision: 1, Revision: 1, Spec: taskSpec(), Note: "建立协作任务", ActorID: "user_owned", ActorName: "调查员", CreatedAt: now, RecordedAt: now, ExpiresAt: now.AddDate(0, 0, 180)}
}

func TestIncidentTaskStateRequiresAssignmentAndTerminalReason(t *testing.T) {
	valid := taskSpec()
	date := time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)
	valid.DueAt = &date
	if valid.Validate() != nil {
		t.Fatal("有效任务被拒绝")
	}
	for _, state := range []string{"in_progress", "completed", "cancelled"} {
		s := valid
		s.Status, s.AssigneeID = state, "user_owned"
		if state != "in_progress" {
			s.Resolution = "记录已完成的核对或取消原因。"
		}
		if s.Validate() != nil {
			t.Fatal("有效任务状态被拒绝", state)
		}
	}
	for name, change := range map[string]func(*TaskSpec){
		"标题缺失": func(s *TaskSpec) { s.Title = "" }, "标题超限": func(s *TaskSpec) { s.Title = strings.Repeat("字", 121) },
		"描述缺失": func(s *TaskSpec) { s.Description = "" }, "控制字符": func(s *TaskSpec) { s.Description = "说明\x00" },
		"状态伪造": func(s *TaskSpec) { s.Status = "blocked" }, "优先级伪造": func(s *TaskSpec) { s.Priority = "urgent" },
		"负责人越界": func(s *TaskSpec) { s.AssigneeID = "../other" }, "未分派即处理": func(s *TaskSpec) { s.Status = "in_progress" },
		"缺少完成依据": func(s *TaskSpec) { s.Status, s.AssigneeID = "completed", "user_owned" },
		"缺少取消依据": func(s *TaskSpec) { s.Status = "cancelled" }, "开放任务含结论": func(s *TaskSpec) { s.Resolution = "已完成" },
		"结论控制字符": func(s *TaskSpec) { s.Status, s.Resolution = "cancelled", "原因\r" },
		"零截止时间":  func(s *TaskSpec) { v := time.Time{}; s.DueAt = &v },
		"越界截止时间": func(s *TaskSpec) { v := time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC); s.DueAt = &v },
	} {
		t.Run(name, func(t *testing.T) {
			s := taskSpec()
			change(&s)
			if s.Validate() == nil {
				t.Fatal("无效任务被接受")
			}
		})
	}
}

func TestIncidentTaskFrozenRecordAndRequestBoundaries(t *testing.T) {
	r := taskRecord()
	if r.Validate() != nil || (TaskCreate{IncidentRevision: 1, Spec: r.Spec}).Validate() != nil || (TaskChange{IncidentRevision: 1, ExpectedRevision: 1, Spec: r.Spec, Note: "核对计划"}).Validate() != nil {
		t.Fatal("有效记录或请求被拒绝")
	}
	for name, change := range map[string]func(*TaskRecord){
		"任务身份": func(r *TaskRecord) { r.ID = "bad/id" }, "事件身份": func(r *TaskRecord) { r.IncidentID = "bad/id" },
		"事件修订": func(r *TaskRecord) { r.IncidentRevision = 0 }, "任务修订": func(r *TaskRecord) { r.Revision = MaxRevision + 1 },
		"实际操作人": func(r *TaskRecord) { r.ActorID = "" }, "操作人姓名": func(r *TaskRecord) { r.ActorName = "" },
		"操作说明": func(r *TaskRecord) { r.Note = "" }, "建立时间": func(r *TaskRecord) { r.CreatedAt = time.Time{} },
		"时间倒退": func(r *TaskRecord) { r.RecordedAt = r.CreatedAt.Add(-time.Second) }, "期限倒退": func(r *TaskRecord) { r.ExpiresAt = r.RecordedAt },
		"无分派有姓名": func(r *TaskRecord) { r.AssigneeName = "其他人" },
		"有分派无姓名": func(r *TaskRecord) { r.Spec.AssigneeID = "user_owned" },
		"任务材料":   func(r *TaskRecord) { r.Spec.Description = "" },
	} {
		t.Run(name, func(t *testing.T) {
			value := clone(r)
			change(&value)
			if value.Validate() == nil {
				t.Fatal("不完整任务记录被接受")
			}
		})
	}
	for _, request := range []TaskCreate{{Spec: r.Spec}, {IncidentRevision: MaxRevision + 1, Spec: r.Spec}, {IncidentRevision: 1, Spec: TaskSpec{}}, {IncidentRevision: 1, Spec: TaskSpec{Title: "任务", Description: "说明", Priority: "high", Status: "cancelled", Resolution: "取消"}}} {
		if request.Validate() == nil {
			t.Fatal("错误创建请求被接受")
		}
	}
	for _, request := range []TaskChange{{IncidentRevision: 1, ExpectedRevision: 1, Spec: r.Spec}, {IncidentRevision: 0, ExpectedRevision: 1, Spec: r.Spec, Note: "说明"}, {IncidentRevision: 1, ExpectedRevision: 0, Spec: r.Spec, Note: "说明"}, {IncidentRevision: 1, ExpectedRevision: MaxRevision + 1, Spec: r.Spec, Note: "说明"}} {
		if request.Validate() == nil {
			t.Fatal("错误变更请求被接受")
		}
	}
	for _, q := range []TaskQuery{{Status: "unknown"}, {Before: "../other"}} {
		if q.Validate() == nil {
			t.Fatal("无效任务查询被接受")
		}
	}
	if (TaskQuery{}).Validate() != nil || (TaskQuery{Status: "completed", Before: "case_task_owned"}).Validate() != nil {
		t.Fatal("有界任务查询被拒绝")
	}
}
