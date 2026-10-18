package store

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/detectionquality"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/qualityevent"
	"github.com/kkx600/StarBeacon/internal/transport"
)

func recordQuality(ctx context.Context, tx pgx.Tx, id transport.SensorIdentity, r *detectionquality.Report) error {
	if r == nil {
		return nil
	}
	var now time.Time
	var days int
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp(),COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='network'),180)`, id.TenantID).Scan(&now, &days); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sensor_quality_cursors(tenant_id,sensor_id,registration_id,run_id,sampled_at,evaluated_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz+make_interval(days=>$8)) ON CONFLICT DO NOTHING`, id.TenantID, id.SensorID, id.RegistrationID, r.EngineRunID, r.SampledAt, r.EvaluatedAt, now, days); err != nil {
		return err
	}
	var eventRun, eventID, eventConfig string
	var sampled, evaluated time.Time
	var emittedAt *time.Time
	var raw, observation []byte
	if err := tx.QueryRow(ctx, `SELECT event_run_id,sampled_at,evaluated_at,signal,event_id,event_created_at,observation,event_config_sha256 FROM sensor_quality_cursors WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3 FOR UPDATE`, id.TenantID, id.SensorID, id.RegistrationID).Scan(&eventRun, &sampled, &evaluated, &raw, &eventID, &emittedAt, &observation, &eventConfig); err != nil {
		return err
	}
	if r.EvaluatedAt.Before(evaluated) || r.SampledAt.Before(sampled) {
		return nil
	}
	var prior *detectionquality.Report
	if len(observation) > 0 {
		prior = new(detectionquality.Report)
		if json.Unmarshal(observation, prior) != nil {
			return qualityevent.ErrEvent
		}
	}
	interval, comparable, err := detectionquality.ReceivedInterval(prior, *r)
	if err != nil {
		return err
	}
	current, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var previous *qualityevent.Event
	if eventID != "" {
		previous = &qualityevent.Event{ID: eventID}
		previous.Report.EngineRunID = eventRun
		previous.Report.ConfigSHA256 = eventConfig
		if json.Unmarshal(raw, &previous.Signal) != nil {
			return qualityevent.ErrEvent
		}
	}
	signal, emit := qualityevent.Transition(previous, interval)
	if !comparable {
		emit = false
	}
	if comparable && !emit && signal.Kind != "quiet" && emittedAt != nil && now.Sub(*emittedAt) >= 15*time.Minute {
		emit = true
		signal.Reminder = true
	}
	if emit {
		e, err := qualityevent.New(id.TenantID, id.SensorID, id.RegistrationID, interval, signal, now)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(e.Document())
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO sensor_quality_outbox(tenant_id,id,sensor_id,registration_id,partition_day,document,state,created_at,expires_at) VALUES($1,$2,$3,$4,($5::timestamptz AT TIME ZONE 'UTC')::date,$6,'pending',$5,$5::timestamptz+make_interval(days=>$7)) ON CONFLICT DO NOTHING`, id.TenantID, e.ID, id.SensorID, id.RegistrationID, now, encoded, days); err != nil {
			return err
		}
		raw, _ = json.Marshal(signal)
		eventID = e.ID
		eventRun = r.EngineRunID
		eventConfig = r.ConfigSHA256
		emittedAt = &now
	}
	// 未报告增量但仍有缺测时保留最后事件，不伪造恢复。
	_, err = tx.Exec(ctx, `UPDATE sensor_quality_cursors SET run_id=$4,sampled_at=$5,evaluated_at=$6,signal=$7,event_id=$8,expires_at=$9::timestamptz+make_interval(days=>$10),event_run_id=$11,event_created_at=$12,observation=$13,event_config_sha256=$14 WHERE tenant_id=$1 AND sensor_id=$2 AND registration_id=$3`, id.TenantID, id.SensorID, id.RegistrationID, r.EngineRunID, r.SampledAt, r.EvaluatedAt, raw, eventID, now, days, eventRun, emittedAt, current, eventConfig)
	return err
}

type QualityLease struct {
	TenantID, ID, Token, Partition string
	Document                       model.Alert
	ExpiresAt                      time.Time
}

func (p *Postgres) LeaseQuality(ctx context.Context, tenant string) (QualityLease, error) {
	l := QualityLease{TenantID: tenant, Token: Token()}
	var raw []byte
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `WITH picked AS MATERIALIZED(SELECT id FROM sensor_quality_outbox WHERE tenant_id=$1 AND expires_at<=now() AND state IN('pending','leased') AND (lease_until IS NULL OR lease_until<=now()) ORDER BY expires_at,id LIMIT 20 FOR UPDATE SKIP LOCKED) UPDATE sensor_quality_outbox q SET state='expired',document=NULL,lease_token='',lease_until=NULL FROM picked WHERE q.tenant_id=$1 AND q.id=picked.id`, tenant); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `WITH picked AS MATERIALIZED(SELECT id FROM sensor_quality_outbox WHERE tenant_id=$1 AND expires_at>now() AND next_at<=now() AND (state='pending' OR (state='leased' AND lease_until<=now())) ORDER BY next_at,created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE sensor_quality_outbox q SET state='leased',lease_token=$2,lease_until=now()+interval '30 seconds',attempts=attempts+1 FROM picked WHERE q.tenant_id=$1 AND q.id=picked.id RETURNING q.id,q.partition_day::text,q.document,q.expires_at`, tenant, l.Token).Scan(&l.ID, &l.Partition, &raw, &l.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return nil
	})
	if err == nil && l.ID != "" {
		if json.Unmarshal(raw, &l.Document) != nil {
			return l, qualityevent.ErrEvent
		}
		e, decodeErr := qualityevent.Decode(l.Document)
		if decodeErr != nil || e.ID != l.ID || e.TenantID != tenant {
			return l, qualityevent.ErrEvent
		}
	}
	return l, err
}
func (p *Postgres) FinishQuality(ctx context.Context, l QualityLease, success bool) error {
	if !contract.ValidID(l.TenantID) || !contract.ValidID(l.ID) || l.Token == "" {
		return qualityevent.ErrEvent
	}
	return p.TenantTx(ctx, l.TenantID, func(tx pgx.Tx) error {
		query := `UPDATE sensor_quality_outbox SET state='pending',lease_token='',lease_until=NULL,last_error='dependency_unavailable',next_at=now()+make_interval(secs=>LEAST(300,power(2,LEAST(attempts,8)))::integer) WHERE tenant_id=$1 AND id=$2 AND state='leased' AND lease_token=$3 AND lease_until>now()`
		if success {
			query = `UPDATE sensor_quality_outbox SET state='done',document=NULL,lease_token='',lease_until=NULL,last_error='' WHERE tenant_id=$1 AND id=$2 AND state='leased' AND lease_token=$3 AND lease_until>now()`
		}
		tag, err := tx.Exec(ctx, query, l.TenantID, l.ID, l.Token)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrConflict
		}
		return err
	})
}

type QualityPage struct {
	Items    []qualityevent.Event `json:"items"`
	Total    string               `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
}

func (s *Elasticsearch) QualityEvents(ctx context.Context, tenant, sensor, registration, kind string, q model.SearchRequest) (QualityPage, error) {
	result := QualityPage{Items: []qualityevent.Event{}, Total: "0", Page: q.Page, PageSize: 20}
	q.PageSize = 20
	extra := []any{map[string]any{"term": map[string]string{"event.dataset": qualityevent.Dataset}}}
	for _, pair := range []struct{ field, value string }{{"sensor_id", sensor}, {"sensor_registration_id", registration}, {"rule.id", kind}} {
		if pair.value != "" {
			extra = append(extra, map[string]any{"term": map[string]string{pair.field: pair.value}})
		}
	}
	page, err := s.searchEvents(ctx, tenant, q, "context", []string{"quality"}, extra)
	if err != nil {
		return result, err
	}
	for _, doc := range page.Items {
		e, err := qualityevent.Decode(doc)
		if err != nil || sensor != "" && e.SensorID != sensor || registration != "" && e.RegistrationID != registration || kind != "" && e.Signal.Kind != kind {
			return result, qualityevent.ErrEvent
		}
		result.Items = append(result.Items, e)
	}
	result.Total = strconv.FormatInt(page.Total, 10)
	result.Page = page.Page
	return result, nil
}
