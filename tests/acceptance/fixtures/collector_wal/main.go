// 本程序只构造和核对升级试验中的既有 WAL，不授予真实平台路由或持久接收资格。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kkx600/StarBeacon/internal/agent"
	bolt "go.etcd.io/bbolt"
)

func run() error {
	mode := flag.String("mode", "inspect", "seed 或 inspect")
	dir := flag.String("directory", "", "本试验数据目录")
	flag.Parse()
	if !filepath.IsAbs(*dir) || flag.NArg() != 0 || *mode != "seed" && *mode != "inspect" {
		return fmt.Errorf("试验参数无效")
	}
	name := filepath.Join(*dir, "agent.db")
	if *mode == "seed" {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			return fmt.Errorf("既有 WAL 已存在，禁止覆盖")
		}
		wal, err := agent.OpenWAL(name, "tenant_update", "sensor_update", "registration_update", 1<<30)
		if err != nil {
			return err
		}
		reader := &agent.EVEReader{WAL: wal, Path: filepath.Join(*dir, "eve.json"), Route: func(context.Context, string) (string, error) { return "fixture_existing_route", nil }}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = reader.Poll(ctx)
		cancel()
		reader.Close()
		closeErr := wal.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	db, err := bolt.Open(name, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		hash := sha256.New()
		count := 0
		for _, name := range []string{"alerts", "context"} {
			bucket := tx.Bucket([]byte(name))
			if bucket == nil {
				return fmt.Errorf("试验 WAL 事件目录缺失")
			}
			if err := bucket.ForEach(func(k, v []byte) error {
				count++
				hash.Write([]byte(name))
				hash.Write(k)
				hash.Write(v)
				return nil
			}); err != nil {
				return err
			}
		}
		meta := tx.Bucket([]byte("meta"))
		if meta == nil {
			return fmt.Errorf("试验 WAL 元数据缺失")
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"identity": string(meta.Get([]byte("identity"))), "epoch": string(meta.Get([]byte("epoch"))), "source_sha256": fmt.Sprintf("%x", sha256.Sum256(meta.Get([]byte("source")))), "records_sha256": hex.EncodeToString(hash.Sum(nil)), "pending": count})
	})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "WAL 试验失败：", err)
		os.Exit(1)
	}
}
