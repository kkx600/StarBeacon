// Package rulerollout 定义固定同步计划修订的分批发布；停止不撤销已执行的规则。
package rulerollout

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/rulesync"
)

var ErrInput = errors.New("分批发布参数无效，请核对计划修订、批次和观察时间")
var ErrQuota = errors.New("分批发布数量或操作频率已达到上限")

type Selection struct {
	PlanID   string `json:"plan_id"`
	Revision int64  `json:"revision"`
}

type Spec struct {
	Name               string      `json:"name"`
	Plans              []Selection `json:"plans"`
	CanaryCount        int         `json:"canary_count"`
	BatchSize          int         `json:"batch_size"`
	ObservationSeconds int         `json:"observation_seconds"`
	TimeoutSeconds     int         `json:"timeout_seconds"`
}

func (s Spec) Validate() error {
	if !utf8.ValidString(s.Name) || s.Name != strings.TrimSpace(s.Name) || utf8.RuneCountInString(s.Name) < 1 || utf8.RuneCountInString(s.Name) > 128 || strings.ContainsFunc(s.Name, unicode.IsControl) || len(s.Plans) < 2 || len(s.Plans) > 200 || s.CanaryCount < 1 || s.CanaryCount > 20 || s.CanaryCount >= len(s.Plans) || s.BatchSize < 1 || s.BatchSize > 20 || s.ObservationSeconds < 30 || s.ObservationSeconds > 3600 || s.TimeoutSeconds < 300 || s.TimeoutSeconds > 86400 || s.TimeoutSeconds <= s.ObservationSeconds {
		return ErrInput
	}
	seen := map[string]bool{}
	for _, p := range s.Plans {
		if !contract.ValidID(p.PlanID) || p.Revision < 1 || p.Revision >= rulesync.MaxRevision-1 || seen[p.PlanID] {
			return ErrInput
		}
		seen[p.PlanID] = true
	}
	return nil
}

// 请求顺序决定目标批次；不按在线状态或后来的分组成员扩展范围。
func (s Spec) Batch(index int) int {
	if index < 0 || index >= len(s.Plans) || s.BatchSize < 1 {
		return -1
	}
	if index < s.CanaryCount {
		return 0
	}
	return 1 + (index-s.CanaryCount)/s.BatchSize
}

type Create struct {
	ID   string `json:"id"`
	Spec Spec   `json:"spec"`
}

func (c Create) Validate() error {
	if !contract.ValidID(c.ID) {
		return ErrInput
	}
	return c.Spec.Validate()
}

type Target struct {
	Ordinal            int           `json:"ordinal"`
	Batch              int           `json:"batch"`
	PlanID             string        `json:"plan_id"`
	AuthorizedRevision int64         `json:"authorized_revision"`
	ExecutionRevision  int64         `json:"execution_revision"`
	Spec               rulesync.Spec `json:"spec"`
	State              string        `json:"state"`
	Code               string        `json:"code"`
	Run                *rulesync.Run `json:"run,omitempty"`
}

type Rollout struct {
	ID                   string     `json:"id"`
	Spec                 Spec       `json:"spec"`
	CreatedBy            string     `json:"created_by"`
	State                string     `json:"state"`
	Code                 string     `json:"code"`
	CurrentBatch         int        `json:"current_batch"`
	PackageSHA256        string     `json:"package_sha256"`
	CreatedAt            time.Time  `json:"created_at"`
	Deadline             time.Time  `json:"deadline"`
	NextAt               time.Time  `json:"next_at"`
	ObservationStartedAt *time.Time `json:"observation_started_at,omitempty"`
	FinishedAt           *time.Time `json:"finished_at,omitempty"`
	ExpiresAt            time.Time  `json:"expires_at"`
	StopReason           string     `json:"stop_reason"`
	StoppedBy            string     `json:"stopped_by"`
	Targets              []Target   `json:"targets,omitempty"`
}

type Stop struct {
	Reason string `json:"reason"`
}

func (s Stop) Validate() error {
	if !utf8.ValidString(s.Reason) || s.Reason != strings.TrimSpace(s.Reason) || utf8.RuneCountInString(s.Reason) < 1 || utf8.RuneCountInString(s.Reason) > 512 || strings.ContainsFunc(s.Reason, unicode.IsControl) {
		return ErrInput
	}
	return nil
}

func Terminal(state string) bool {
	return state == "succeeded" || state == "stopped" || state == "blocked"
}

// 成功终态不能显示等待原因；历史阶段码按终态解释，不改写设备回执。
func RecordCode(state, code string) string {
	if state == "succeeded" && code == "observing" {
		return "observed"
	}
	return code
}

// 固定规则和样本必须一致；设备身份和各自核对周期仍取各计划快照。
func SameRelease(a, b rulesync.Spec) bool {
	return a.PackageID == b.PackageID && a.PackageRevision == b.PackageRevision && a.PositiveSampleID == b.PositiveSampleID && a.NegativeSampleID == b.NegativeSampleID
}
