package packetarchive

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/kkx600/StarBeacon/internal/packetpolicy"
	bolt "go.etcd.io/bbolt"
)

var ErrRetentionConflict = errors.New("留存策略修订或网络域已变化，请刷新后核对")
var ErrRetentionUnavailable = errors.New("采集器尚无可核对的留存策略")
var retentionSettings = []byte("packet_retention_settings")
var activeRetentionKey = []byte("active")

func saveRetentionObservation(tx *bolt.Tx, o packetpolicy.Observation) error {
	bucket, err := tx.CreateBucketIfNotExists(retentionSettings)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return bucket.Put(activeRetentionKey, raw)
}

// 只有主动通过界面管理过的采集器才写入当前配置。此后引导文件仍可发布同域的更高修订。
func (s *Spool) retentionObservation(tx *bolt.Tx) (packetpolicy.Observation, error) {
	var current packetpolicy.Observation
	if s.RetentionFile == "" {
		return current, ErrRetentionUnavailable
	}
	if bucket := tx.Bucket(retentionSettings); bucket != nil {
		if json.Unmarshal(bucket.Get(activeRetentionKey), &current) != nil || !current.Valid() {
			return packetpolicy.Observation{}, ErrIntegrity
		}
	}
	file, err := readRetentionPolicy(s.RetentionFile)
	if current.Origin != "" && (err != nil || file.NetworkDomain != current.Policy.NetworkDomain || file.Revision <= current.Policy.Revision) {
		return current, nil
	}
	if err != nil {
		return packetpolicy.Observation{}, ErrRetentionUnavailable
	}
	if bucket := tx.Bucket(retentionPolicies); bucket != nil {
		if raw := bucket.Get([]byte(file.NetworkDomain)); raw != nil {
			var frozen RetentionPolicy
			if json.Unmarshal(raw, &frozen) != nil || !frozen.Valid() {
				return packetpolicy.Observation{}, ErrIntegrity
			}
			if file.Revision < frozen.Revision || file.Revision == frozen.Revision && !file.Equal(frozen) {
				// 保留上次封存身份供保底清单记录；查询端不会将它报告成当前配置。
				return packetpolicy.Observation{Policy: frozen}, ErrRetentionUnavailable
			}
		}
	}
	fromFile := packetpolicy.Observation{Policy: file, SHA256: file.Digest(), Origin: "file"}
	if current.Origin != "" && tx.Writable() {
		if err := saveRetentionObservation(tx, fromFile); err != nil {
			return packetpolicy.Observation{}, err
		}
	}
	return fromFile, nil
}

func (s *Spool) RetentionObservation() (result packetpolicy.Observation, err error) {
	err = s.DB.View(func(tx *bolt.Tx) error {
		result, err = s.retentionObservation(tx)
		return err
	})
	return result, err
}

func (s *Spool) UpdateRetention(p packetpolicy.Change, origin, taskID string, audit func(*bolt.Tx) error) (result packetpolicy.Observation, err error) {
	now := time.Now().UTC()
	next := packetpolicy.Observation{Policy: p.Policy, SHA256: p.Policy.Digest(), Origin: origin, TaskID: taskID, AppliedAt: &now}
	if p.Validate() != nil || !next.Valid() || audit == nil {
		return result, ErrIntegrity
	}
	err = s.DB.Update(func(tx *bolt.Tx) error {
		current, err := s.retentionObservation(tx)
		if err != nil {
			return err
		}
		// 设备任务重投递时只承认同一任务的同一内容；其他来源的同值写入仍有独立身份。
		if origin == "platform" && p.Confirms(current, taskID) {
			result = current
			return nil
		}
		if !current.Matches(p) {
			return ErrRetentionConflict
		}
		if err := saveRetentionObservation(tx, next); err != nil {
			return err
		}
		if err := audit(tx); err != nil {
			return err
		}
		result = next
		return nil
	})
	return result, err
}
