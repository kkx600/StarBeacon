package incident

import (
	"strings"
	"testing"
	"time"
)

func ownedNoteSpec() NoteSpec {
	return NoteSpec{Title: "原始证据核对", Body: "仅记录已观察材料。\n保留未知。", Status: "active"}
}

func TestIncidentNoteInputAndLifecycleBoundaries(t *testing.T) {
	s := ownedNoteSpec()
	if s.Validate() != nil || (NoteCreate{IncidentRevision: 1, Spec: s}).Validate() != nil || (NoteChange{IncidentRevision: 1, ExpectedRevision: 1, Spec: s, Reason: "补充来源"}).Validate() != nil {
		t.Fatal("有效笔记被拒绝")
	}
	for _, mutate := range []func(*NoteSpec){
		func(s *NoteSpec) { s.Title = "" }, func(s *NoteSpec) { s.Title = " leading" }, func(s *NoteSpec) { s.Title = strings.Repeat("中", 121) },
		func(s *NoteSpec) { s.Title = "line\nnext" }, func(s *NoteSpec) { s.Body = "" }, func(s *NoteSpec) { s.Body = strings.Repeat("中", 8193) },
		func(s *NoteSpec) { s.Body = "bad\rvalue" }, func(s *NoteSpec) { s.Body = string([]byte{0xff}) }, func(s *NoteSpec) { s.Status = "deleted" },
		func(s *NoteSpec) { s.WithdrawalReason = "活动笔记不能保留撤回原因" }, func(s *NoteSpec) { s.Status = "withdrawn" },
		func(s *NoteSpec) { s.Status = "withdrawn"; s.WithdrawalReason = strings.Repeat("中", 2049) },
	} {
		value := s
		mutate(&value)
		if value.Validate() == nil {
			t.Fatal("非法材料被接受", value.Status)
		}
	}
	s.Status, s.WithdrawalReason = "withdrawn", "引用有误，保留旧记录供复核"
	if s.Validate() != nil || (NoteCreate{IncidentRevision: 1, Spec: s}).Validate() == nil {
		t.Fatal("撤回状态与新建边界不正确")
	}
	for _, revision := range []int64{0, 1001} {
		if (NoteCreate{IncidentRevision: revision, Spec: ownedNoteSpec()}).Validate() == nil || (NoteChange{IncidentRevision: revision, ExpectedRevision: 1, Spec: s, Reason: "核对"}).Validate() == nil || (NoteChange{IncidentRevision: 1, ExpectedRevision: revision, Spec: s, Reason: "核对"}).Validate() == nil {
			t.Fatal("无效修订被接受")
		}
	}
	if (NoteChange{IncidentRevision: 1, ExpectedRevision: 1, Spec: s}).Validate() == nil || (NoteChange{IncidentRevision: 1, ExpectedRevision: 1, Spec: s, Reason: strings.Repeat("中", 2049)}).Validate() == nil {
		t.Fatal("缺少或超长变更说明被接受")
	}
	if (NoteQuery{Status: "active"}).Validate() != nil || (NoteQuery{Status: "withdrawn", Before: "case_note_owned"}).Validate() != nil || (NoteQuery{Status: "deleted"}).Validate() == nil || (NoteQuery{Before: "invalid/id"}).Validate() == nil {
		t.Fatal("笔记筛选边界不正确")
	}
}

func TestIncidentNoteRecordRequiresFixedAuthorAndActualTimes(t *testing.T) {
	now := time.Now().UTC()
	r := NoteRecord{ID: "case_note_owned", IncidentID: "case_owned", IncidentRevision: 1, Revision: 1, Spec: ownedNoteSpec(), AuthorID: "user_owned", AuthorName: "核对员", ActorID: "user_owned", ActorName: "核对员", Reason: "建立调查笔记", CreatedAt: now, RecordedAt: now, ExpiresAt: now.Add(180 * 24 * time.Hour)}
	if r.Validate() != nil {
		t.Fatal("有效回执无效")
	}
	for _, mutate := range []func(*NoteRecord){
		func(r *NoteRecord) { r.ID = "invalid/id" }, func(r *NoteRecord) { r.IncidentID = "" }, func(r *NoteRecord) { r.IncidentRevision = 0 }, func(r *NoteRecord) { r.Revision = 1001 },
		func(r *NoteRecord) { r.Spec.Body = "" }, func(r *NoteRecord) { r.AuthorID = "" }, func(r *NoteRecord) { r.AuthorName = "" }, func(r *NoteRecord) { r.ActorID = "user_other" },
		func(r *NoteRecord) { r.ActorName = "" }, func(r *NoteRecord) { r.Reason = "" }, func(r *NoteRecord) { r.CreatedAt = time.Time{} }, func(r *NoteRecord) { r.RecordedAt = now.Add(-time.Second) }, func(r *NoteRecord) { r.ExpiresAt = now },
	} {
		value := r
		mutate(&value)
		if value.Validate() == nil {
			t.Fatal("不完整或伪造笔记回执被接受")
		}
	}
}
