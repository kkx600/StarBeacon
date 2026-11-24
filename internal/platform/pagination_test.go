package platform

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseListLimit(t *testing.T) {
	if size, err := parseListLimit(nil); err != nil || size != 20 {
		t.Fatal("缺省页长错误", size, err)
	}
	for _, size := range []int{10, 20, 50, 100} {
		if actual, err := parseListLimit([]string{strconv.Itoa(size)}); err != nil || actual != size {
			t.Fatal("合法页长被拒绝", size, actual, err)
		}
	}
	for _, values := range [][]string{{""}, {"0"}, {"9"}, {"51"}, {"101"}, {"010"}, {"+10"}, {" 10 "}, {"10.0"}, {"10", "20"}} {
		if _, err := parseListLimit(values); err == nil {
			t.Fatal("接受了无效页长", values)
		}
	}
}

func TestPlatformListsRejectInvalidLimits(t *testing.T) {
	a := &API{}
	routes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/notifications/deliveries", a.notificationDeliveries},
		{"/analysis/threads", a.analysisThreads},
		{"/analysis/threads/{id}", a.analysisConversation},
		{"/analysis/plans/{id}/runs", a.reportPlanRuns},
		{"/alerts/{id}/assessment/history", a.alertAssessmentHistory},
		{"/alerts/{id}/triage", a.alertTriages},
		{"/rule-generation/jobs", a.ruleGenerations},
		{"/packet-archives", a.packetArchives},
		{"/incidents", a.incidents},
		{"/incidents/{id}/history", a.incidentHistory},
		{"/incidents/{id}/tasks", a.incidentTasks},
		{"/incidents/{id}/tasks/{task}/history", a.incidentTaskHistory},
		{"/incidents/{id}/notes", a.incidentNotes},
		{"/incidents/{id}/notes/{note}/history", a.incidentNoteHistory},
		{"/users", a.users},
		{"/decision-policies/{id}/revisions/{revision}/triggers", a.automaticTriages},
		{"/rule-sync-plans", a.ruleSyncPlans},
		{"/rule-rollouts", a.ruleRollouts},
		{"/sensor-enrollments", a.probeEnrollments},
		{"/sensors/{id}/certificates", a.probeCertificates},
		{"/sensors/quality-events", a.qualityEvents},
		{"/sensors", a.sensors},
		{"/audits/operations", a.audits},
		{"/audits/logins", a.loginAudits},
		{"/inventory/{kind}", a.inventoryList},
		{"/analysis/jobs", a.analysisJobs},
		{"/sensor-groups", a.sensorGroups},
		{"/saved-searches", a.savedSearches},
		{"/application-rules", a.applicationRules},
		{"/decision-policies", a.decisionPolicies},
		{"/decision-evaluations", a.decisionEvaluations},
		{"/response-actions", a.responseActions},
		{"/response-connectors", a.responseConnectors},
		{"/syslog/sources", a.syslogSources},
		{"/correlation-rules", a.correlationRules},
		{"/watchlists", a.watchlists},
		{"/watchlists/{id}/hits", a.watchlistHits},
	}
	if len(routes) != 37 {
		t.Fatal("缺少分页接口", len(routes))
	}
	mux := http.NewServeMux()
	replace := strings.NewReplacer("{id}", "owned", "{revision}", "1", "{task}", "task_owned", "{note}", "note_owned", "{kind}", "groups")
	for _, entry := range routes {
		mux.HandleFunc("GET /api/v1"+entry.path, entry.handler)
	}
	for _, entry := range routes {
		t.Run(entry.path, func(t *testing.T) {
			path := "/api/v1" + replace.Replace(entry.path)
			query := "?"
			switch entry.path {
			case "/sensors/quality-events", "/response-actions", "/watchlists/{id}/hits":
				end := time.Now().UTC()
				query += "start=" + end.Add(-time.Hour).Format(time.RFC3339Nano) + "&end=" + end.Format(time.RFC3339Nano) + "&"
			}
			for _, value := range []string{"", "7", "51", "101", "010", "10&limit=20", "%zz"} {
				r := httptest.NewRequest(http.MethodGet, path+query+"limit="+value, nil)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, r)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("无效页长 %q 应返回 400，实际为 %d", value, w.Code)
				}
			}
		})
	}
}

func TestQualityListLimitAndSearchWindow(t *testing.T) {
	base := "/api/v1/sensors/quality-events?start=2026-11-10T00:00:00Z&end=2026-11-11T00:00:00Z"
	for _, tc := range []struct {
		query       string
		limit, page int
	}{
		{"", 20, 1},
		{"&limit=10&page=1000", 10, 1000},
		{"&limit=50&page=200", 50, 200},
		{"&limit=100&page=100", 100, 100},
	} {
		result, _, _, _, err := qualityQuery(httptest.NewRequest(http.MethodGet, base+tc.query, nil))
		if err != nil || result.PageSize != tc.limit || result.Page != tc.page {
			t.Fatal("质量事件页长或页码未保留", tc, result, err)
		}
	}
	for _, query := range []string{"&limit=10&page=1001", "&limit=50&page=201", "&limit=100&page=101"} {
		if _, _, _, _, err := qualityQuery(httptest.NewRequest(http.MethodGet, base+query, nil)); err == nil {
			t.Fatal("超出一万条的页码被接受", query)
		}
	}
}
