// Package retention 定义分类保留期与策略发布边界，不以缓存 TTL 代替业务留存。
package retention

import (
	"fmt"
	"time"
)

const DefaultDays = 180

type Category struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Scope    string `json:"scope"`
	Boundary string `json:"boundary"`
}

var categories = []Category{
	{"security_logs", "安全日志", "new_indices", "UTC 日期分区在首次创建时固化保留期；既有分区不重算。"},
	{"alerts", "告警数据", "new_indices", "UTC 日期分区在首次创建时固化保留期；既有分区不重算。"},
	{"pcap", "PCAP 数据", "new_samples", "作用于重放样本和连续原包切片；首次归档时固化期限，既有对象不重算。"},
	{"network", "网络事件", "new_indices", "UTC 日期分区在首次创建时固化保留期；既有分区不重算。"},
	{"operations", "操作与任务记录", "new_records", "作用于操作日志与受控任务历史；活动配置不按此期限删除。"},
	{"logins", "登录记录", "new_records", "作用于首次提交的登录验证记录；会话使用独立安全有效期。"},
	{"notifications", "推送记录", "new_records", "作用于推送批次、投递记录和配置历史；运行缓冲另行治理。"},
	{"reports", "安全报告", "new_records", "作用于首次生成的报告作业和统计证据，不重算既有报告。"},
	{"files", "文件与样本", "pending_pipeline", "保留策略已登记；文件提取与分析存储尚未接入。"},
	{"asset_history", "资产历史", "new_records", "作用于资产、资产组与网段的历史修订；当前登记独立保存。"},
	{"models", "模型分析记录", "new_records", "作用于连接验证、对话作业和模型配置历史；活动配置独立保存。"},
	{"incidents", "安全事件", "new_records", "每份调查修订首次提交时固化期限；未关闭事件及其历史受保护，关闭后仅回收到期记录。"},
}

func Catalog() []Category { return append([]Category(nil), categories...) }
func Lookup(id string) (Category, bool) {
	for _, category := range categories {
		if category.ID == id {
			return category, true
		}
	}
	return Category{}, false
}

type Policy struct {
	Category  string    `json:"category"`
	Days      int       `json:"days"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Candidate struct {
	Category         string `json:"category"`
	Days             int    `json:"days"`
	ExpectedRevision int64  `json:"expected_revision"`
	ApplyMode        string `json:"apply_mode"`
}

func (c Candidate) Validate() error {
	if _, ok := Lookup(c.Category); !ok {
		return fmt.Errorf("留存类别无效")
	}
	if c.Days < 1 || c.Days > 3650 || c.ExpectedRevision < 1 {
		return fmt.Errorf("保留期必须为 1–3650 天，并提供当前策略修订")
	}
	if c.ApplyMode != "future" {
		return fmt.Errorf("当前策略发布仅支持未来对象，存量期限重算尚未开放")
	}
	return nil
}

type Preview struct {
	ID                 string    `json:"id"`
	Candidate          Candidate `json:"candidate"`
	CurrentDays        int       `json:"current_days"`
	Scope              string    `json:"scope"`
	Boundary           string    `json:"boundary"`
	ExistingUnmodified bool      `json:"existing_unmodified"`
	ExpiresAt          time.Time `json:"expires_at"`
}
type Change struct {
	PreviewID string    `json:"preview_id"`
	Candidate Candidate `json:"candidate"`
}
