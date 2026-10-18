package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/model"
	"github.com/kkx600/StarBeacon/internal/notify"
	"github.com/kkx600/StarBeacon/internal/outbound"
	"github.com/kkx600/StarBeacon/internal/secrets"
)

type ChannelChange struct {
	ID               string         `json:"id"`
	ExpectedRevision int64          `json:"expected_revision"`
	Name             string         `json:"name"`
	Kind             string         `json:"kind"`
	Enabled          *bool          `json:"enabled"`
	Severities       []string       `json:"severities"`
	Streams          []string       `json:"streams,omitempty"`
	MutedUntil       *time.Time     `json:"muted_until"`
	Connection       *notify.Config `json:"connection"`
}

func (p *Postgres) NotificationChannels(ctx context.Context, tenant string) ([]notify.Channel, error) {
	result := []notify.Channel{}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,revision,name,kind,enabled,severities,streams,target,muted_until,updated_at FROM notification_channels WHERE tenant_id=$1 ORDER BY id LIMIT 50`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c notify.Channel
			if err := rows.Scan(&c.ID, &c.Revision, &c.Name, &c.Kind, &c.Enabled, &c.Severities, &c.Streams, &c.Target, &c.MutedUntil, &c.UpdatedAt); err != nil {
				return err
			}
			c.HasSecret = true
			result = append(result, c)
		}
		return rows.Err()
	})
	return result, err
}

func notificationConfig(ctx context.Context, tx pgx.Tx, vault *secrets.Vault, tenant, id string, revision int64) (notify.Config, error) {
	var config notify.Config
	var ciphertext string
	if err := tx.QueryRow(ctx, `SELECT ciphertext FROM notification_channel_versions WHERE tenant_id=$1 AND channel_id=$2 AND revision=$3`, tenant, id, revision).Scan(&ciphertext); err != nil {
		return config, err
	}
	data, err := vault.Open(tenant, "notification", id, revision, ciphertext)
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, secrets.ErrUnavailable
	}
	return config, nil
}

func (p *Postgres) SaveNotificationChannel(ctx context.Context, user model.Principal, change ChannelChange, vault *secrets.Vault, policy outbound.Policy, request string) (notify.Channel, error) {
	var result notify.Channel
	if !contract.ValidID(change.ID) || change.ExpectedRevision < 0 || change.Enabled == nil {
		return result, ErrConflict
	}
	err := p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		// 租户级锁同时保护渠道数量上限，避免并发创建绕过配额。
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, user.TenantID+"/notifications"); err != nil {
			return err
		}
		var revision int64
		var kind string
		var streams []string
		err := tx.QueryRow(ctx, `SELECT revision,kind,streams FROM notification_channels WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, user.TenantID, change.ID).Scan(&revision, &kind, &streams)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revision != change.ExpectedRevision || (revision > 0 && kind != change.Kind) {
			return ErrConflict
		}
		if revision == 0 {
			var count int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE tenant_id=$1`, user.TenantID).Scan(&count); err != nil {
				return err
			}
			if count >= 50 {
				return ErrConflict
			}
		}
		var config notify.Config
		if change.Connection != nil {
			config = *change.Connection
		} else if revision > 0 {
			config, err = notificationConfig(ctx, tx, vault, user.TenantID, change.ID, revision)
			if err != nil {
				return err
			}
		} else {
			return notify.ErrConfig
		}
		config.Name = change.Name
		config.Kind = change.Kind
		config.Enabled = *change.Enabled
		config.Severities = change.Severities
		config.Streams = change.Streams
		if config.Streams == nil && revision > 0 {
			config.Streams = streams
		}
		config.Streams = config.LogStreams()
		config.MutedUntil = change.MutedUntil
		if err := config.Validate(policy); err != nil {
			return err
		}
		data, err := notify.Encode(config)
		if err != nil {
			return err
		}
		ciphertext, err := vault.Seal(user.TenantID, "notification", change.ID, revision+1, data)
		if err != nil {
			return err
		}
		result = config.Public()
		result.ID = change.ID
		result.Revision = revision + 1
		if err := tx.QueryRow(ctx, `INSERT INTO notification_channels(tenant_id,id,revision,name,kind,enabled,severities,target,muted_until,streams) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,id) DO UPDATE SET revision=EXCLUDED.revision,name=EXCLUDED.name,enabled=EXCLUDED.enabled,severities=EXCLUDED.severities,streams=EXCLUDED.streams,target=EXCLUDED.target,muted_until=EXCLUDED.muted_until,updated_at=clock_timestamp() RETURNING updated_at`, user.TenantID, result.ID, result.Revision, result.Name, result.Kind, result.Enabled, result.Severities, result.Target, result.MutedUntil, result.Streams).Scan(&result.UpdatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,revision,ciphertext,expires_at) VALUES($1,$2,$3,$4,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='notifications'),180)))`, user.TenantID, result.ID, result.Revision, ciphertext); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "notifications.channel.save", change.ID, request)
	})
	return result, err
}

func (p *Postgres) EnqueueNotifications(ctx context.Context, tenant, batchID string, alerts []notify.Summary, vault *secrets.Vault, testChannel string) error {
	if testChannel != "" && !contract.ValidID(testChannel) {
		return ErrConflict
	}
	if err := notify.ValidateBatch(tenant, batchID, alerts); err != nil {
		return err
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		return enqueueNotificationTx(ctx, tx, tenant, batchID, alerts, vault, testChannel)
	})
}

func enqueueNotificationTx(ctx context.Context, tx pgx.Tx, tenant, batchID string, alerts []notify.Summary, vault *secrets.Vault, testChannel string) error {
	return enqueueMessageTx(ctx, tx, tenant, batchID, alerts, nil, vault, testChannel)
}

func (p *Postgres) EnqueueQualityNotifications(ctx context.Context, tenant, batchID string, quality []notify.QualitySummary, vault *secrets.Vault) error {
	if err := notify.ValidateQuality(tenant, batchID, quality); err != nil {
		return err
	}
	return p.TenantTx(ctx, tenant, func(tx pgx.Tx) error { return enqueueMessageTx(ctx, tx, tenant, batchID, nil, quality, vault, "") })
}

func enqueueMessageTx(ctx context.Context, tx pgx.Tx, tenant, batchID string, alerts []notify.Summary, quality []notify.QualitySummary, vault *secrets.Vault, testChannel string) error {
	rows, err := tx.Query(ctx, `SELECT id,revision,enabled,muted_until FROM notification_channels WHERE tenant_id=$1 AND ($2='' OR id=$2) ORDER BY id LIMIT 50 FOR SHARE`, tenant, testChannel)
	if err != nil {
		return err
	}
	type target struct {
		id       string
		revision int64
		enabled  bool
		muted    *time.Time
	}
	targets := []target{}
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.revision, &t.enabled, &t.muted); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	if testChannel != "" && len(targets) == 0 {
		return pgx.ErrNoRows
	}
	for _, target := range targets {
		config, err := notificationConfig(ctx, tx, vault, tenant, target.id, target.revision)
		if err != nil {
			return err
		}
		selected := config.Select(alerts)
		if len(quality) > 0 && !config.Accepts("quality") {
			continue
		}
		if len(selected) == 0 && len(quality) == 0 && testChannel == "" {
			continue
		}
		upstream := batchID
		if len(quality) > 0 {
			upstream = "quality:" + quality[0].ID
			selected = []notify.Summary{}
		}
		id := "notice_" + Hash(tenant + "/" + upstream + "/" + target.id)[:57]
		message := notify.Message{TenantID: tenant, BatchID: batchID, CreatedAt: time.Now().UTC(), Alerts: selected, Quality: quality, Test: testChannel != ""}
		encoded, err := json.Marshal(message)
		if err != nil {
			return err
		}
		inserted, err := tx.Exec(ctx, `INSERT INTO notification_batches(tenant_id,id,upstream_batch_id,channel_id,channel_revision,message,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+make_interval(days=>COALESCE((SELECT days FROM retention_policies WHERE tenant_id=$1 AND category='notifications'),180))) ON CONFLICT(tenant_id,upstream_batch_id,channel_id) DO NOTHING`, tenant, id, upstream, target.id, target.revision, encoded)
		if err != nil {
			return err
		}
		if inserted.RowsAffected() == 0 {
			continue
		}
		state := "queued"
		if testChannel == "" && (!target.enabled || (target.muted != nil && target.muted.After(time.Now()))) {
			state = "suppressed"
		}
		recipients := []string{""}
		if config.Kind == "email" {
			recipients = config.Recipients
		}
		for _, recipient := range recipients {
			jobID := "delivery_" + Hash(id + "/" + recipient)[:55]
			if _, err := tx.Exec(ctx, `INSERT INTO notification_deliveries(tenant_id,id,batch_id,recipient,state,expires_at) SELECT tenant_id,$3,id,$4,$5,expires_at FROM notification_batches WHERE tenant_id=$1 AND id=$2`, tenant, id, jobID, recipient, state); err != nil {
				return err
			}
		}
	}
	return nil
}

type Delivery struct {
	ID              string          `json:"id"`
	ChannelID       string          `json:"channel_id"`
	ChannelName     string          `json:"channel_name"`
	Kind            string          `json:"kind"`
	ChannelRevision int64           `json:"channel_revision"`
	Recipient       string          `json:"recipient"`
	State           string          `json:"state"`
	Version         int64           `json:"version"`
	Attempts        int             `json:"attempts"`
	AlertCount      int             `json:"alert_count"`
	RecordCount     int             `json:"record_count"`
	Stream          string          `json:"stream"`
	Receipt         json.RawMessage `json:"receipt"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

var ErrNotificationQuery = errors.New("推送日志查询参数无效")

func deliveryCursor(d Delivery) string {
	return base64.RawURLEncoding.EncodeToString([]byte(d.CreatedAt.UTC().Format(time.RFC3339Nano) + "\n" + d.ID))
}

func parseDeliveryCursor(cursor string) (*time.Time, string, error) {
	if cursor == "" {
		return nil, "", nil
	}
	if len(cursor) > 256 {
		return nil, "", ErrNotificationQuery
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	fields := strings.Split(string(data), "\n")
	if err != nil || len(fields) != 2 || !contract.ValidID(fields[1]) {
		return nil, "", ErrNotificationQuery
	}
	at, err := time.Parse(time.RFC3339Nano, fields[0])
	if err != nil || at.Year() < 1970 || at.Year() > 9999 {
		return nil, "", ErrNotificationQuery
	}
	return &at, fields[1], nil
}

func (p *Postgres) NotificationDeliveries(ctx context.Context, tenant, cursor, state string) ([]Delivery, string, error) {
	result := []Delivery{}
	next := ""
	at, after, cursorError := parseDeliveryCursor(cursor)
	if cursorError != nil || (state != "" && !slices.Contains([]string{"queued", "running", "retry", "accepted", "transport_written", "failed", "uncertain", "suppressed", "cancelled"}, state)) {
		return result, next, ErrNotificationQuery
	}
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id,b.channel_id,c.name,c.kind,b.channel_revision,d.recipient,d.state,d.version,d.attempts,jsonb_array_length(b.message->'alerts'),CASE WHEN b.message ? 'logs' THEN jsonb_array_length(b.message->'logs') WHEN b.message ? 'quality' THEN jsonb_array_length(b.message->'quality') ELSE jsonb_array_length(b.message->'alerts') END,COALESCE(b.message->'logs'->0->>'stream',CASE WHEN b.message ? 'quality' THEN 'quality' WHEN (b.message->>'test')::boolean THEN 'test' ELSE 'alerts' END),d.receipt,d.created_at,d.updated_at FROM notification_deliveries d JOIN notification_batches b ON b.tenant_id=d.tenant_id AND b.id=d.batch_id JOIN notification_channels c ON c.tenant_id=b.tenant_id AND c.id=b.channel_id WHERE d.tenant_id=$1 AND ($2::timestamptz IS NULL OR (d.created_at,d.id)<($2::timestamptz,$3::text)) AND ($4='' OR d.state=$4) AND d.expires_at>now() ORDER BY d.created_at DESC,d.id DESC LIMIT 21`, tenant, at, after, state)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Delivery
			if err := rows.Scan(&d.ID, &d.ChannelID, &d.ChannelName, &d.Kind, &d.ChannelRevision, &d.Recipient, &d.State, &d.Version, &d.Attempts, &d.AlertCount, &d.RecordCount, &d.Stream, &d.Receipt, &d.CreatedAt, &d.UpdatedAt); err != nil {
				return err
			}
			result = append(result, d)
		}
		return rows.Err()
	})
	if len(result) > 20 {
		next = deliveryCursor(result[19])
		result = result[:20]
	}
	return result, next, err
}

func (p *Postgres) NotificationTenants(ctx context.Context, cursor string) ([]string, error) {
	rows, err := p.Pool.Query(ctx, `SELECT id FROM tenants WHERE active AND id>$1 ORDER BY id LIMIT 100`, cursor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

type NotificationLease struct {
	ID, Token, TenantID string
	Config              notify.Config
	Message             notify.Message
}

func (p *Postgres) LeaseNotification(ctx context.Context, tenant string, vault *secrets.Vault) (NotificationLease, error) {
	var lease NotificationLease
	err := p.TenantTx(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='uncertain',version=version+1,lease_token=NULL,lease_until=NULL,receipt='{"state":"uncertain","code":"worker_interrupted"}'::jsonb,updated_at=clock_timestamp() WHERE tenant_id=$1 AND state='running' AND lease_until<now()`, tenant); err != nil {
			return err
		}
		var channel, recipient string
		var revision int64
		var message []byte
		err := tx.QueryRow(ctx, `SELECT d.id,b.channel_id,b.channel_revision,d.recipient,b.message FROM notification_deliveries d JOIN notification_batches b ON b.tenant_id=d.tenant_id AND b.id=d.batch_id JOIN notification_channels c ON c.tenant_id=b.tenant_id AND c.id=b.channel_id WHERE c.next_delivery_at<=now() AND d.tenant_id=$1 AND d.state IN ('queued','retry') AND d.next_attempt_at<=now() AND d.expires_at>now() ORDER BY d.next_attempt_at,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED`, tenant).Scan(&lease.ID, &channel, &revision, &recipient, &message)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// 空队列也必须提交过期租约的处理结果。
				return nil
			}
			return err
		}
		var current int64
		var enabled bool
		var muted *time.Time
		var nextDelivery time.Time
		if err := tx.QueryRow(ctx, `SELECT revision,enabled,muted_until,next_delivery_at FROM notification_channels WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, channel).Scan(&current, &enabled, &muted, &nextDelivery); err != nil {
			return err
		}
		if nextDelivery.After(time.Now()) {
			lease.ID = ""
			return nil
		}
		if err := json.Unmarshal(message, &lease.Message); err != nil {
			return err
		}
		if current != revision || (!lease.Message.Test && (!enabled || (muted != nil && muted.After(time.Now())))) {
			_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET state='cancelled',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, lease.ID)
			lease.ID = ""
			return err
		}
		lease.Config, err = notificationConfig(ctx, tx, vault, tenant, channel, revision)
		if err != nil {
			return err
		}
		// 办公机器人限速不适用于日志流；Syslog 由工作进程的有界投递容量控制。
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET next_delivery_at=now()+CASE WHEN kind IN ('syslog_tls','syslog_tcp') THEN interval '0 seconds' ELSE interval '3 seconds' END WHERE tenant_id=$1 AND id=$2`, tenant, channel); err != nil {
			return err
		}
		lease.Token = Token()
		lease.TenantID = tenant
		lease.Message.ID = lease.ID
		lease.Message.Recipient = recipient
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries SET state='running',version=version+1,attempts=attempts+1,lease_token=$3,lease_until=now()+interval '30 seconds',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, lease.ID, lease.Token)
		return err
	})
	if err == nil && lease.ID == "" {
		return lease, pgx.ErrNoRows
	}
	return lease, err
}

func (p *Postgres) FinishNotification(ctx context.Context, lease NotificationLease, out notify.Outcome) error {
	if !slices.Contains([]string{"retry", "accepted", "transport_written", "failed", "uncertain"}, out.State) {
		return ErrConflict
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return p.TenantTx(ctx, lease.TenantID, func(tx pgx.Tx) error {
		changed, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state=CASE WHEN $4='retry' AND attempts>=5 THEN 'failed' ELSE $4 END,version=version+1,lease_token=NULL,lease_until=NULL,receipt=$5,next_attempt_at=now()+make_interval(secs=>LEAST(300,5*power(2,attempts)::integer)),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND lease_token=$3 AND state='running' AND lease_until>now()`, lease.TenantID, lease.ID, lease.Token, out.State, data)
		if err == nil && changed.RowsAffected() != 1 {
			return ErrConflict
		}
		return err
	})
}

func (p *Postgres) RetryNotification(ctx context.Context, user model.Principal, id string, version int64, request string) error {
	if !contract.ValidID(id) || version < 1 {
		return ErrConflict
	}
	return p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		changed, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='queued',version=version+1,attempts=0,next_attempt_at=now(),receipt='{}',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND version=$3 AND state IN ('failed','uncertain') AND expires_at>now()`, user.TenantID, id, version)
		if err != nil {
			return err
		}
		if changed.RowsAffected() != 1 {
			return ErrConflict
		}
		return insertOperationAudit(ctx, tx, user, "notifications.delivery.retry", id+"/"+strconv.FormatInt(version, 10), request)
	})
}

func (p *Postgres) TestNotification(ctx context.Context, user model.Principal, channel, idempotency string, vault *secrets.Vault, request string) error {
	if !contract.ValidID(idempotency) {
		return ErrConflict
	}
	// 记录测试的稳定业务标识；配置凭据和接收人不会出现在操作审计对象中。
	if !contract.ValidID(channel) {
		return ErrConflict
	}
	return p.TenantTx(ctx, user.TenantID, func(tx pgx.Tx) error {
		if err := enqueueNotificationTx(ctx, tx, user.TenantID, "test_"+Hash(user.ID + "/" + idempotency)[:59], nil, vault, channel); err != nil {
			return err
		}
		return insertOperationAudit(ctx, tx, user, "notifications.channel.test", channel, request)
	})
}
