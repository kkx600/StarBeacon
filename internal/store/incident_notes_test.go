package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/incident"
	"github.com/kkx600/StarBeacon/internal/model"
)

type incidentNoteScanRow struct {
	values []any
	err    error
}

func (r incidentNoteScanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, target := range dest {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(r.values[i]))
	}
	return nil
}

func TestIncidentNoteStoredDirectoryMustMatchOriginalRecord(t *testing.T) {
	now := time.Now().UTC()
	r := incident.NoteRecord{ID: "case_note_owned", IncidentID: "case_owned", IncidentRevision: 1, Revision: 1, Spec: incident.NoteSpec{Title: "核对", Body: "实际材料", Status: "active"}, AuthorID: "user_owned", AuthorName: "核对员", ActorID: "user_owned", ActorName: "核对员", Reason: "建立调查笔记", CreatedAt: now, RecordedAt: now, ExpiresAt: now.Add(time.Hour)}
	raw, _ := json.Marshal(r)
	base := []any{raw, r.ID, r.IncidentID, r.Revision, r.Spec.Status, r.CreatedAt, r.ExpiresAt, r.AuthorID}
	got, err := scanIncidentNote(incidentNoteScanRow{values: base})
	if err != nil || got.ID != r.ID || got.AuthorID != r.AuthorID {
		t.Fatal("有效笔记目录无效", err)
	}
	if _, err := scanIncidentNote(incidentNoteScanRow{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("查询失败被隐藏")
	}
	for i, value := range map[int]any{0: []byte(`{`), 1: "other", 2: "case_other", 3: int64(2), 4: "withdrawn", 5: now.Add(time.Second), 6: now.Add(2 * time.Hour), 7: "user_other"} {
		values := append([]any{}, base...)
		values[i] = value
		if _, err := scanIncidentNote(incidentNoteScanRow{values: values}); err == nil {
			t.Fatal("笔记JSON与目录差异被接受", i)
		}
	}
	invalid := r
	invalid.Spec.Body = ""
	bad, _ := json.Marshal(invalid)
	values := append([]any{}, base...)
	values[0] = bad
	if _, err := scanIncidentNote(incidentNoteScanRow{values: values}); err == nil {
		t.Fatal("非法历史材料被接受")
	}
}

func TestIncidentNoteStoreRejectsInvalidScopeBeforeDatabase(t *testing.T) {
	p := &Postgres{}
	ctx := context.Background()
	u := model.Principal{}
	if _, err := p.IncidentNotes(ctx, u, "case_owned", incident.NoteQuery{}); !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal(err)
	}
	if _, err := p.IncidentNote(ctx, u, "case_owned", "note_owned"); !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal(err)
	}
	if _, err := p.CreateIncidentNote(ctx, u, "case_owned", "owned_key", incident.NoteCreate{}, "audit"); !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal(err)
	}
	if _, err := p.ChangeIncidentNote(ctx, u, "case_owned", "note_owned", "owned_key", incident.NoteChange{}, "audit"); !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal(err)
	}
	valid := incident.NoteCreate{IncidentRevision: 1, Spec: incident.NoteSpec{Title: "核对", Body: "材料", Status: "active"}}
	if _, err := p.CreateIncidentNote(ctx, u, "case_owned", "owned_key", valid, "audit"); !errors.Is(err, incident.ErrNoteInput) {
		t.Fatal(err)
	}
	for _, before := range []string{"", "invalid", "00", "0", "1001"} {
		if _, err := p.IncidentNoteHistory(ctx, u, "case_owned", "note_owned", before); !errors.Is(err, incident.ErrNoteInput) {
			t.Fatal("非法历史范围进入数据库", before, err)
		}
	}
}
