package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	sensorv1 "github.com/kkx600/StarBeacon/api/sensor/v1"
	"github.com/kkx600/StarBeacon/internal/contract"
	"github.com/kkx600/StarBeacon/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrRecordTooLarge = errors.New("EVE 记录超过允许上限，读取已暂停")

type EVEReader struct {
	WAL    *WAL
	Path   string
	file   *os.File
	source Source
	Route  func(context.Context, string) (string, error)
}

func fileID(i os.FileInfo) string {
	if s, ok := i.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", s.Dev, s.Ino)
	}
	return i.Name() + ":" + i.ModTime().String()
}
func (r *EVEReader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
func (r *EVEReader) open() error {
	s, e := r.WAL.Source()
	if e != nil {
		return e
	}
	f, e := os.Open(r.Path)
	if e != nil {
		return e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	id := fileID(info)
	if s.FileID != "" && s.FileID != id {
		// 重启后先查找同目录的轮转文件，不能将未读的旧来源静默跳过。
		entries, e := os.ReadDir(filepath.Dir(r.Path))
		if e != nil {
			f.Close()
			return e
		}
		found := false
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			p := filepath.Join(filepath.Dir(r.Path), entry.Name())
			i, e := os.Stat(p)
			if e != nil || fileID(i) != s.FileID {
				continue
			}
			old, e := os.Open(p)
			if e != nil {
				continue
			}
			f.Close()
			f = old
			info = i
			id = s.FileID
			found = true
			break
		}
		if !found {
			f.Close()
			return fmt.Errorf("无法定位尚未读完的轮转来源；需要确认数据缺口后恢复")
		}
	}
	if s.Generation == "" || uint64(info.Size()) < s.Offset {
		s = Source{FileID: id, Generation: store.RandomID("src_")}
	}
	r.source = s
	r.file = f
	return nil
}
func (r *EVEReader) Poll(ctx context.Context) error {
	if r.file == nil {
		if e := r.open(); e != nil {
			return e
		}
	}
	info, e := r.file.Stat()
	if e != nil {
		return e
	}
	changed := uint64(info.Size()) < r.source.Offset
	if !changed && r.source.PrefixBytes > 0 {
		fingerprint, e := prefix(r.file, r.source.PrefixBytes)
		if e != nil {
			return e
		}
		changed = fingerprint != r.source.PrefixSHA256
	}
	if changed {
		r.source = Source{FileID: fileID(info), Generation: store.RandomID("src_")}
	}
	if _, e = r.file.Seek(int64(r.source.Offset), io.SeekStart); e != nil {
		return e
	}
	reader := bufio.NewReaderSize(r.file, 64*1024)
	next := r.source
	entries := make([]Entry, 0, 100)
	bytesRead := 0
	commit := func() error {
		if len(entries) == 0 {
			return nil
		}
		if next.PrefixBytes == 0 {
			next.PrefixBytes = int(min(next.Offset, 256))
			next.PrefixSHA256, e = prefix(r.file, next.PrefixBytes)
			if e != nil {
				return e
			}
		}
		if e := r.WAL.AppendBatch(next, entries); e != nil {
			return e
		}
		r.source = next
		entries = nil
		return nil
	}
	fail := func(cause error) error {
		if e := commit(); e != nil {
			return e
		}
		return cause
	}
	for i := 0; i < 100; i++ {
		if ctx.Err() != nil {
			return fail(ctx.Err())
		}
		line := make([]byte, 0, 1024)
		for {
			part, e := reader.ReadSlice('\n')
			line = append(line, part...)
			if len(line) > contract.MaxPayloadBytes+1 {
				return fail(ErrRecordTooLarge)
			}
			if e == bufio.ErrBufferFull {
				continue
			}
			if e == io.EOF {
				if e := commit(); e != nil {
					return e
				}
				info, se := os.Stat(r.Path)
				if se != nil {
					return se
				}
				current, se := r.file.Stat()
				if se != nil {
					return se
				}
				if fileID(info) != fileID(current) {
					if len(line) > 0 {
						return fmt.Errorf("轮转来源末尾有未完成记录，读取已暂停")
					}
					r.file.Close()
					r.file = nil
					r.source = Source{FileID: fileID(info), Generation: store.RandomID("src_")}
					f, se := os.Open(r.Path)
					if se != nil {
						return se
					}
					r.file = f
					return nil
				}
				return nil
			}
			if e != nil {
				return fail(e)
			}
			break
		}
		payload := bytes.Clone(line[:len(line)-1])
		// 空行同样保留原始字节，由规范化隔离队列记录，避免零长载荷阻塞上传。
		if len(payload) == 0 {
			payload = bytes.Clone(line)
		}
		if bytesRead+len(payload) > contract.MaxBatchBytes {
			break
		}
		now := time.Now().UTC()
		var header struct {
			EventType string `json:"event_type"`
			Timestamp string `json:"timestamp"`
		}
		_ = json.Unmarshal(payload, &header)
		stream := "context"
		if header.EventType == "alert" {
			stream = "alerts"
		}
		route, e := r.Route(ctx, stream)
		if e != nil {
			return fail(e)
		}
		eventTime, e := time.Parse(time.RFC3339Nano, header.Timestamp)
		if e != nil {
			eventTime = now
		}
		h := sha256.Sum256(payload)
		record := &sensorv1.EventRecord{SourceGenerationId: next.Generation, SourceOffset: next.Offset, EventTime: timestamppb.New(eventTime), ObservedAt: timestamppb.New(now), EventType: header.EventType, RawSha256: h[:], Payload: payload, PayloadSchema: "suricata.eve.v1", ContentType: "application/json", PayloadSha256: h[:]}
		next.Offset += uint64(len(line))
		bytesRead += len(payload)
		entries = append(entries, Entry{Stream: stream, Route: route, Record: record})
	}
	return commit()
}

func prefix(file *os.File, n int) (string, error) {
	data := make([]byte, n)
	if _, e := file.ReadAt(data, 0); e != nil {
		return "", e
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
