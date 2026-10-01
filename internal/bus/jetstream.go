// Package bus 管理有界持久流，接收确认仅在 JetStream PubAck 之后产生。
package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/kkx600/StarBeacon/internal/contract"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const Alerts = "SB_ALERTS"
const Context = "SB_CONTEXT"
const Quarantine = "SB_QUARANTINE"
const Indexed = "SB_INDEXED"

type Envelope struct {
	TenantID   string    `json:"tenant_id"`
	Partition  string    `json:"partition"`
	ReceivedAt time.Time `json:"received_at"`
	Batch      []byte    `json:"batch"`
}
type Bus struct {
	Namespace string
	NC        *nats.Conn
	JS        jetstream.JetStream
}

func Open(ctx context.Context, url string) (*Bus, error) {
	return OpenNamespace(ctx, url, "sb")
}
func OpenNamespace(ctx context.Context, url, namespace string) (*Bus, error) {
	if !contract.ValidID(namespace) {
		return nil, fmt.Errorf("队列命名空间不合法")
	}
	nc, e := nats.Connect(url, nats.Name("starbeacon"), nats.Timeout(5*time.Second), nats.MaxReconnects(-1))
	if e != nil {
		return nil, e
	}
	js, e := jetstream.New(nc)
	if e != nil {
		nc.Close()
		return nil, e
	}
	return &Bus{NC: nc, JS: js, Namespace: namespace}, nil
}
func (b *Bus) StreamName(name string) string {
	return strings.ToUpper(b.Namespace) + "_" + strings.TrimPrefix(name, "SB_")
}
func (b *Bus) Subject(subject string) string {
	return b.Namespace + "." + strings.TrimPrefix(subject, "sb.")
}
func (b *Bus) Close() { b.NC.Close() }
func (b *Bus) Ensure(ctx context.Context, replicas int, maxBytes int64) error {
	for _, s := range []struct{ name, subject string }{{Alerts, "sb.events.alerts"}, {Context, "sb.events.context"}, {Quarantine, "sb.quarantine"}, {Indexed, "sb.indexed"}} {
		age := 72 * time.Hour
		retention := jetstream.LimitsPolicy
		if s.name == Alerts || s.name == Context {
			age = 0
			retention = jetstream.WorkQueuePolicy
		}
		if s.name == Quarantine {
			age = 180 * 24 * time.Hour
		}
		_, e := b.JS.CreateOrUpdateStream(ctx, jetstream.StreamConfig{Name: b.StreamName(s.name), Subjects: []string{b.Subject(s.subject)}, Storage: jetstream.FileStorage, Replicas: replicas, Retention: retention, Discard: jetstream.DiscardNew, MaxAge: age, MaxBytes: maxBytes, MaxMsgSize: 4 * 1024 * 1024, Duplicates: 2 * time.Minute})
		if e != nil {
			return e
		}
	}
	return nil
}
func (b *Bus) Publish(ctx context.Context, subject, id string, v any) error {
	if !strings.HasPrefix(subject, "sb.") {
		return fmt.Errorf("队列主题不合法")
	}
	data, e := json.Marshal(v)
	if e != nil {
		return e
	}
	ack, e := b.JS.Publish(ctx, b.Subject(subject), data, jetstream.WithMsgID(id))
	if e != nil {
		return e
	}
	if ack == nil || ack.Sequence == 0 {
		return fmt.Errorf("缺少持久接收确认")
	}
	return nil
}
func (b *Bus) Consumer(ctx context.Context, stream string) (jetstream.Consumer, error) {
	stream = b.StreamName(stream)
	return b.JS.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{Durable: "indexer-v1", AckPolicy: jetstream.AckExplicitPolicy, DeliverPolicy: jetstream.DeliverAllPolicy, AckWait: 60 * time.Second, MaxAckPending: 8, MaxDeliver: -1, MaxWaiting: 16})
}
