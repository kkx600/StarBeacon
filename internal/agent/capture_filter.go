package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kkx600/StarBeacon/internal/config"
	"golang.org/x/net/bpf"
)

var (
	ErrCaptureFilterCompilerUnavailable = errors.New("捕获过滤器编译器不可用")
	ErrCaptureFilterBudget              = errors.New("捕获过滤器编译超出资源预算")
)

// 只编译 Ethernet BPF，不读取网卡或生成业务帧；空 PCAP 会使原生检测引擎等待首包。
func validateCaptureFilter(ctx context.Context, cfg config.Config, filter string) error {
	_, err := compileCaptureFilter(ctx, cfg, filter, 65535)
	return err
}
func compileCaptureFilter(ctx context.Context, cfg config.Config, filter string, snap int) ([]bpf.RawInstruction, error) {
	if filter == "" {
		return nil, nil
	}
	job, err := os.MkdirTemp(filepath.Dir(cfg.StatePath), "capture-filter-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(job)
	job, err = filepath.EvalSymlinks(job)
	if err != nil {
		return nil, err
	}
	input, output := filepath.Join(job, "input"), filepath.Join(job, "output")
	for _, dir := range []string{input, output} {
		if err = os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
	}
	file := filepath.Join(input, "filter.bpf")
	if err = durableFile(file, []byte(filter)); err != nil {
		return nil, err
	}
	binary := cfg.BPFCompilerBinary
	if binary == "" {
		binary = "/usr/sbin/tcpdump"
	}
	// -ddd 与指定链路类型使用 pcap_open_dead；过滤器文件通过 argv 传入，没有 shell 展开。
	args := []string{"-ddd", "-y", "EN10MB", "-s", strconv.Itoa(snap), "-F", file}
	log, _, limit, err := executeBounded(ctx, binary, job, input, output, args)
	if limit == "isolation" {
		return nil, ErrCaptureFilterCompilerUnavailable
	}
	if limit != "" || log.truncated {
		return nil, ErrCaptureFilterBudget
	}
	if err != nil {
		return nil, errors.New("捕获过滤器编译失败")
	}
	raw := string(log.data)
	if err = validateBPFInstructions(raw); err != nil {
		return nil, err
	}
	fields := strings.Fields(raw)
	out := make([]bpf.RawInstruction, (len(fields)-1)/4)
	for i := range out {
		code, _ := strconv.ParseUint(fields[1+i*4], 10, 16)
		jt, _ := strconv.ParseUint(fields[2+i*4], 10, 8)
		jf, _ := strconv.ParseUint(fields[3+i*4], 10, 8)
		k, _ := strconv.ParseUint(fields[4+i*4], 10, 32)
		out[i] = bpf.RawInstruction{Op: uint16(code), Jt: uint8(jt), Jf: uint8(jf), K: uint32(k)}
	}
	return out, nil
}

// 原生编译退出成功仍需核对指令数量与字段范围，防止截断输出或超出内核指令限制。
func validateBPFInstructions(raw string) error {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return errors.New("捕获过滤器没有编译结果")
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil || count < 1 || count > 4096 || len(fields) != 1+count*4 {
		return errors.New("捕获过滤器指令数量无效")
	}
	for i, field := range fields[1:] {
		bits := []int{16, 8, 8, 32}[i%4]
		if _, err = strconv.ParseUint(field, 10, bits); err != nil {
			return errors.New("捕获过滤器指令字段无效")
		}
	}
	return nil
}
