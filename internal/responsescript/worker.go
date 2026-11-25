package responsescript

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const (
	WorkerCommand = "response-script-worker"
	workerPath    = "/starbeacon-response-script"
	workerMemory  = 1572864 * 1024
)

type wireValue struct {
	JSON json.RawMessage `json:"json,omitempty"`
	Ref  string          `json:"ref,omitempty"`
}

type program struct {
	Source string            `json:"source"`
	Entry  string            `json:"entry"`
	Args   []json.RawMessage `json:"args"`
	Origin string            `json:"origin"`
	TaskID string            `json:"task_id"`
	Now    string            `json:"now"`
}

type frame struct {
	Kind    string               `json:"kind,omitempty"`
	Code    Code                 `json:"code,omitempty"`
	Program *program             `json:"program,omitempty"`
	Method  string               `json:"method,omitempty"`
	URL     string               `json:"url,omitempty"`
	Status  int                  `json:"status,omitempty"`
	Name    string               `json:"name,omitempty"`
	Text    string               `json:"text,omitempty"`
	Bytes   []byte               `json:"bytes,omitempty"`
	Level   string               `json:"level,omitempty"`
	TTL     int                  `json:"ttl,omitempty"`
	Value   wireValue            `json:"value,omitzero"`
	Fields  map[string]wireValue `json:"fields,omitempty"`
	Headers map[string]wireValue `json:"headers,omitempty"`
	Query   map[string]string    `json:"query,omitempty"`
}

type channel struct {
	read  io.Reader
	write io.Writer
}

func (c channel) receive() (frame, error) {
	var header [4]byte
	if _, err := io.ReadFull(c.read, header[:]); err != nil {
		return frame{}, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxFrame {
		return frame{}, Size
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(c.read, raw); err != nil {
		return frame{}, err
	}
	var result frame
	if err := json.Unmarshal(raw, &result); err != nil {
		return frame{}, Isolation
	}
	return result, nil
}

func (c channel) send(value frame) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return Isolation
	}
	if len(raw) > maxFrame {
		return Size
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if _, err := c.write.Write(header[:]); err != nil {
		return err
	}
	_, err = c.write.Write(raw)
	return err
}

func (r *Runtime) launch(ctx context.Context, start program, b *broker) (Code, json.RawMessage) {
	if ctx.Err() != nil {
		return Timeout, nil
	}
	if runtime.GOOS != "linux" {
		return Isolation, nil
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return Isolation, nil
	}
	process, stop := context.WithCancel(ctx)
	defer stop()
	// 固定 shell 仅下调硬上限。解释器进程只挂载采集器程序和自己的 proc。
	cmd := exec.CommandContext(process, "/bin/sh", "-c",
		`ulimit -c 0 && ulimit -t 3 && ulimit -f 0 && ulimit -n 32 && ulimit -v 1572864 && exec "$@"`,
		"starbeacon-response-script", bwrap, "--clearenv", "--die-with-parent", "--new-session",
		"--unshare-all", "--unshare-user", "--cap-drop", "ALL", "--ro-bind", r.binary, workerPath, "--proc", "/proc",
		"--remount-ro", "/", "--chdir", "/", "--setenv", "GOMAXPROCS", "1",
		"--setenv", "GOMEMLIMIT", "64MiB", workerPath, WorkerCommand)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.WaitDelay = 500 * time.Millisecond
	input, err := cmd.StdinPipe()
	if err != nil {
		return Isolation, nil
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		return Isolation, nil
	}
	defer output.Close()
	if err := cmd.Start(); err != nil {
		return Isolation, nil
	}
	unblock := context.AfterFunc(ctx, func() {
		_ = input.Close()
		_ = output.Close()
	})
	defer unblock()
	code, value := b.exchange(ctx, channel{read: output, write: input}, start)
	_ = input.Close()
	if code != OK {
		stop()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return Timeout, nil
	}
	if code == OK && waitErr != nil {
		return Isolation, nil
	}
	return code, value
}

func (b *broker) exchange(ctx context.Context, link channel, start program) (Code, json.RawMessage) {
	hello, err := link.receive()
	if err != nil || hello.Kind != "ready" {
		return Isolation, nil
	}
	if err := link.send(frame{Kind: "start", Program: &start}); err != nil {
		if err == Size {
			return Size, nil
		}
		return Isolation, nil
	}
	for count := 0; count <= maxCalls; count++ {
		request, err := link.receive()
		if err != nil {
			return Isolation, nil
		}
		if request.Kind == "result" {
			switch request.Code {
			case OK:
				if request.Value.Ref != "" {
					return Credential, nil
				}
				_, code := b.r.decode(request.Value.JSON)
				if code != OK {
					return code, nil
				}
				return OK, request.Value.JSON
			case Credential, Scope, Size, Steps, Input, ScriptError:
				return request.Code, nil
			default:
				return Isolation, nil
			}
		}
		if count == maxCalls {
			return Rate, nil
		}
		reply := b.dispatch(ctx, request)
		if reply.Code != OK {
			return reply.Code, nil
		}
		if err := link.send(reply); err != nil {
			if err == Size {
				return Size, nil
			}
			return Isolation, nil
		}
	}
	return Isolation, nil
}

// WorkerMain 只在采集器创建的内层受限进程中接收脚本。
func WorkerMain() int {
	if runtime.GOOS != "linux" || os.Args[0] != workerPath || len(os.Args) != 2 || !systemLimits() {
		return 1
	}
	if serve(channel{read: os.Stdin, write: os.Stdout}) != nil {
		return 1
	}
	return 0
}

func systemLimits() bool {
	for resource, limit := range map[int]uint64{unix.RLIMIT_AS: workerMemory, unix.RLIMIT_CPU: 3, unix.RLIMIT_CORE: 0, unix.RLIMIT_FSIZE: 0, unix.RLIMIT_NOFILE: 32} {
		var actual unix.Rlimit
		if err := unix.Getrlimit(resource, &actual); err != nil || actual.Cur > limit || actual.Max > limit {
			return false
		}
	}
	return true
}

func serve(link channel) error {
	if err := link.send(frame{Kind: "ready"}); err != nil {
		return err
	}
	start, err := link.receive()
	if err != nil || start.Kind != "start" || start.Program == nil {
		return Isolation
	}
	v := &interpreter{link: link}
	value, code := v.run(*start.Program)
	return link.send(frame{Kind: "result", Code: code, Value: wireValue{JSON: value}})
}
