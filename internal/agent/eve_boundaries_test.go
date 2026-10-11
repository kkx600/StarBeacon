package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/kkx600/StarBeacon/internal/contract"
)

func TestEVERestartDrainsRenamedFileAndRejectsMissingHistory(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "recover", true: "history_missing"}[missing], func(t *testing.T) {
			w, r, path := readerFor(t, 1024*1024)
			if err := r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			first, err := w.Source()
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			r.file = nil
			old := path + ".1"
			if err = os.Rename(path, old); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.WriteString(eveSample + "\n"); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()
			if err = os.Mkdir(filepath.Join(filepath.Dir(path), "unrelated"), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, []byte(eveSample+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink("missing", filepath.Join(filepath.Dir(path), "dangling")); err != nil {
				t.Fatal(err)
			}
			if missing {
				if err = os.Remove(old); err != nil {
					t.Fatal(err)
				}
				if err = r.Poll(context.Background()); err == nil {
					t.Fatal("轮转历史丢失后静默跳过未读数据")
				}
				after, _ := w.Source()
				if after != first {
					t.Fatal("恢复失败推进了检查点")
				}
				return
			}
			if err = r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = r.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			batch, err := w.Next("alerts")
			if err != nil || len(batch.Records) != 3 {
				t.Fatal("重启轮转丢失数据", err)
			}
			if batch.Records[0].SourceGenerationId != batch.Records[1].SourceGenerationId || batch.Records[1].SourceOffset != uint64(len(eveSample)+1) || batch.Records[2].SourceGenerationId == first.Generation {
				t.Fatal("轮转恢复来源区间错误")
			}
		})
	}
	info, err := (fstest.MapFS{"log": &fstest.MapFile{Data: []byte("sample")}}).Stat("log")
	if err != nil || fileID(info) == "" {
		t.Fatal("非 Unix 来源没有稳定标识", err)
	}
}

func TestEVEBackpressureCancellationAndRecordLimitsPreserveCheckpoint(t *testing.T) {
	for _, mode := range []string{"route_error", "cancel", "oversize", "wal_error"} {
		t.Run(mode, func(t *testing.T) {
			w, r, path := readerFor(t, 4*1024*1024)
			data := eveSample + "\n" + eveSample + "\n"
			if mode == "oversize" {
				data = eveSample + "\n" + strings.Repeat("x", contract.MaxPayloadBytes+2) + "\n"
			}
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("route unavailable")
			calls := 0
			r.Route = func(context.Context, string) (string, error) {
				calls++
				if calls == 2 && mode == "route_error" {
					return "", cause
				}
				if calls == 1 && mode == "cancel" {
					cancel()
				}
				if calls == 2 && mode == "wal_error" {
					w.MaxBytes = 1
					return "", cause
				}
				return "route_test", nil
			}
			err := r.Poll(ctx)
			want := cause
			if mode == "cancel" {
				want = context.Canceled
			}
			if mode == "oversize" {
				want = ErrRecordTooLarge
			}
			if mode == "wal_error" {
				want = ErrWALFull
			}
			if !errors.Is(err, want) {
				t.Fatalf("未返回实际背压原因：%v", err)
			}
			s, err := w.Source()
			if err != nil {
				t.Fatal(err)
			}
			count, _, err := w.Stats()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "wal_error" {
				if count != 0 || s.Offset != 0 {
					t.Fatal("WAL 失败留下部分提交")
				}
			} else if count != 1 || s.Offset != uint64(len(eveSample)+1) {
				t.Fatal("异常前完整记录未提交，或跳过了失败记录", count, s)
			}
		})
	}
	t.Run("bounded_batch", func(t *testing.T) {
		w, r, path := readerFor(t, 8*1024*1024)
		if err := os.WriteFile(path, []byte(strings.Repeat(eveSample+"\n", 101)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		n, _, _ := w.Stats()
		if n != 100 {
			t.Fatal("单次读取未遵守批量上限", n)
		}
		if err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		n, _, _ = w.Stats()
		if n != 101 {
			t.Fatal("下一次读取丢失剩余事件", n)
		}
	})
	t.Run("large_line_batch", func(t *testing.T) {
		w, r, path := readerFor(t, 16*1024*1024)
		line := `{"event_type":"alert","body":"` + strings.Repeat("a", contract.MaxPayloadBytes-100) + `"}` + "\n"
		if err := os.WriteFile(path, []byte(strings.Repeat(line, 6)), 0600); err != nil {
			t.Fatal(err)
		}
		if err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		n, _, _ := w.Stats()
		if n == 0 || n >= 6 {
			t.Fatal("载荷字节预算没有限制批量", n)
		}
		if err := r.Poll(context.Background()); err != nil {
			t.Fatal(err)
		}
		after, _, _ := w.Stats()
		if after <= n {
			t.Fatal("超出批量的完整行被跳过")
		}
	})
}

func TestEVEUnavailableSourcesStopWithoutAdvancing(t *testing.T) {
	for _, mode := range []string{"missing", "closed_file", "closed_wal", "incomplete_rotation", "removed_path", "short_prefix"} {
		t.Run(mode, func(t *testing.T) {
			w, r, path := readerFor(t, 1024*1024)
			if mode == "missing" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if mode == "closed_wal" {
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := r.Poll(context.Background()); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "closed_file":
					r.file.Close()
				case "removed_path":
					os.Remove(path)
				case "incomplete_rotation":
					f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					f.WriteString("{")
					f.Close()
					os.Rename(path, path+".1")
					os.WriteFile(path, []byte(eveSample+"\n"), 0600)
				case "short_prefix":
					r.source.PrefixBytes = 4096
				}
			}
			if err := r.Poll(context.Background()); err == nil {
				t.Fatal("不可用来源被视为正常完成")
			}
		})
	}
}
