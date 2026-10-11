package assessment

import (
	"strings"
	"testing"
)

func TestAssessmentRequiresExplicitBasisAndConsistentConclusion(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if ValidDigest(value) {
			t.Fatal("无效原始摘要被接受")
		}
	}
	if !ValidDigest(strings.Repeat("a", 64)) {
		t.Fatal("原始摘要校验错误")
	}
	s := Default()
	s.Note = "已登记调查范围，等待会话及终端证据。"
	if s.Validate() != nil {
		t.Fatal("有说明的初始记录无效")
	}
	for _, mutate := range []func(*Spec){func(s *Spec) { s.Status = "invented" }, func(s *Spec) { s.Verdict = "invented" }, func(s *Spec) { s.Outcome = "invented" }, func(s *Spec) { s.Note = "" }, func(s *Spec) { s.Note = " 前后空格 " }, func(s *Spec) { s.Note = "正文\x00" }, func(s *Spec) { s.Note = strings.Repeat("证", 2049) }, func(s *Spec) { s.Evidence = nil }, func(s *Spec) { s.Evidence = make([]string, 9) }, func(s *Spec) { s.Evidence = []string{""} }, func(s *Spec) { s.Evidence = []string{"证据\n引用"} }, func(s *Spec) { s.Evidence = []string{"ref", "ref"} }, func(s *Spec) { s.Evidence = []string{strings.Repeat("r", 257)} }, func(s *Spec) { s.Status = "closed" }, func(s *Spec) { s.Outcome = "success" }, func(s *Spec) { s.Verdict, s.Outcome = "confirmed", "success" }} {
		v := s
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("不一致或无依据的结论被接受", v)
		}
	}
	for _, verdict := range []string{"unreviewed", "suspicious", "false_positive", "confirmed"} {
		for _, status := range []string{"open", "investigating", "closed"} {
			for _, outcome := range []string{"unknown", "attempt", "success", "prevented"} {
				v := Spec{Status: status, Verdict: verdict, Outcome: outcome, Note: "人工复核\n已检查\t来源。", Evidence: []string{"case:owned/evidence:1"}}
				valid := (status != "closed" || verdict == "false_positive" || verdict == "confirmed") && (verdict == "confirmed" || outcome == "unknown")
				if (v.Validate() == nil) != valid {
					t.Fatal("结论组合验证错误", v)
				}
			}
		}
	}
	for _, revision := range []int64{-1, (1 << 53) - 1} {
		if (Change{ExpectedRevision: revision, Spec: s}).Validate() == nil {
			t.Fatal("不可准确表达的修订被接受")
		}
	}
	if (Change{ExpectedRevision: 0, Spec: s}).Validate() != nil {
		t.Fatal("初次研判修订无效")
	}
}
