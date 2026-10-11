package assistant

import (
	"bytes"
	"html/template"
)

var reportTemplate = template.Must(template.New("report").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>星烽 StarBeacon 安全{{.Kind}} · {{.Job.Request.Period}}</title><style>body{font:14px/1.6 system-ui,sans-serif;color:#182230;background:#f7f7f7;margin:0}main{max-width:1000px;margin:24px auto;padding:24px;background:white}h1{font-size:24px}h2{font-size:18px;margin-top:24px}p,td{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}th,td{border:1px solid #dfe3e8;text-align:left;padding:8px}th{background:#fafafa}.muted{color:#526173}.notice{padding:12px;border-left:3px solid #cd7100;background:#fff9ed}@media print{body{background:white}main{margin:0;padding:0}tr{break-inside:avoid}thead{display:table-header-group}}</style></head><body><main><h1>星烽 StarBeacon 安全{{.Kind}} · {{.Job.Request.Period}}</h1><p class="muted">报告修订 {{.Job.Revision}} · 时区 {{.Job.Request.Timezone}} · 模板 {{.Job.Template}}</p><p class="notice">本报告为统计与调查参考。告警命中不代表攻击成功；资产与在线探针数量为生成时登记状态。未采集数据、历史处置和检测覆盖不作推断。统计快照不包含完整接入水位证明，迟到事件可能改变后续修订。</p><h2>统计来源</h2><table><thead><tr><th>来源标识</th><th>指标</th><th>数值或范围</th></tr></thead><tbody>{{range .Facts}}<tr><td>{{.ID}}</td><td>{{.Label}}</td><td>{{.Value}}</td></tr>{{end}}</tbody></table>{{if .Job.Answer}}<h2>模型概述</h2><p>{{.Job.Answer.Summary}}</p><h2>统计观察</h2>{{range .Job.Answer.Observations}}<p>{{.Text}}<br><span class="muted">来源：{{range .Sources}}{{.}} {{end}}</span></p>{{end}}<h2>调查建议</h2>{{range .Job.Answer.Recommendations}}<p>{{.Text}}<br><span class="muted">来源：{{range .Sources}}{{.}} {{end}}</span></p>{{end}}{{else}}<h2>智能总结</h2><p>智能总结不可用或未启用，完整统计来源仍可复核。</p>{{end}}<h2>运行记录</h2><p>作业：{{.Job.ID}} · 处理状态：{{.Job.State}} · 处理代码：{{.Job.Result.Code}}</p><p>输入快照 SHA-256：{{.Job.Evidence.SHA256}}</p><p>生成时间：{{.Job.CreatedAt.Format "2006-01-02T15:04:05Z07:00"}}</p>{{range .Job.Evidence.Segments}}{{range .Limitations}}<p class="muted">{{.}}</p>{{end}}{{end}}</main></body></html>`))

func ReportHTML(job Job) ([]byte, error) {
	kind := map[string]string{"daily": "日报", "weekly": "周报", "monthly": "月报"}[job.Request.Kind]
	if kind == "" || job.State == "queued" || job.State == "running" {
		return nil, ErrInput
	}
	var output bytes.Buffer
	err := reportTemplate.Execute(&output, struct {
		Job   Job
		Kind  string
		Facts []Fact
	}{job, kind, job.Evidence.Facts()})
	return output.Bytes(), err
}
