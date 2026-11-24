package packetarchive

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket/layers"
)

func tlsRecord(kind byte, body []byte) []byte {
	return append([]byte{kind, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestStreamRetentionConfirmsOnlyObservableHandshakeBoundary(t *testing.T) {
	hello := tlsRecord(22, []byte{1, 0, 0, 6, 3, 3})
	change := tlsRecord(20, []byte{1})
	finished := tlsRecord(22, []byte{1, 2, 3, 4})
	app := tlsRecord(23, bytes.Repeat([]byte{0x8f}, 32))
	full := bytes.Join([][]byte{hello, change, finished, app}, nil)
	var tls12 streamPrefix
	for _, value := range full {
		tls12.consume([]byte{value})
	}
	if tls12.kind != "tls" || tls12.unknown || tls12.application != int64(len(hello)+len(change)+len(finished)) {
		t.Fatalf("分片的 TLS 握手边界错误 %+v", tls12)
	}
	var tls13 streamPrefix
	tls13.consume(bytes.Join([][]byte{hello, change, app, app}, nil))
	if tls13.kind != "tls" || tls13.application != 0 || tls13.unknown {
		t.Fatalf("TLS 1.3 的外层类型不能证明握手结束 %+v", tls13)
	}
	tls12.consume([]byte{23, 1, 2, 1, 1})
	if !tls12.unknown {
		t.Fatal("畸形记录未保守留存")
	}

	banner := []byte("SSH-2.0-retention-test\r\n")
	message := []byte{0, 0, 0, 8, 6, 21, 0, 0, 0, 0, 0, 0}
	var ssh streamPrefix
	ssh.consume(banner[:8])
	ssh.consume(banner[8:])
	ssh.consume(message[:5])
	ssh.consume(append(bytes.Clone(message[5:]), app...))
	if ssh.kind != "ssh" || ssh.unknown || ssh.application != int64(len(banner)+len(message)) {
		t.Fatalf("SSH NEWKEYS 边界不准确 %+v", ssh)
	}
	var invalidSSH streamPrefix
	invalidSSH.consume(append(bytes.Clone(banner), 0, 0, 0, 8, 12, 21))
	if !invalidSSH.unknown {
		t.Fatal("畸形 SSH 记录未保守留存")
	}
}

func TestRetentionDirectionalCapsAndUnknownTraffic(t *testing.T) {
	encrypted, window := 16, 0
	policy := RetentionPolicy{EncryptedBytes: &encrypted, DedupMillis: &window, PlainBytes: 64}
	var dir directionPrefix
	if dir.tcp(&layers.TCP{SYN: true}) != -1 || dir.tcp(&layers.TCP{Seq: 1, BaseLayer: layers.BaseLayer{Payload: []byte("HTTP/1.1 200 OK\r\n")}}) != 0 {
		t.Fatal("TCP 控制帧或首个正文偏移不正确")
	}
	if got := dir.tcp(&layers.TCP{Seq: 1, BaseLayer: layers.BaseLayer{Payload: []byte("HTTP/1.1 200 OK\r\n")}}); got != 0 || dir.bytes != 17 {
		t.Fatal("重传被重复计入正文长度", got, dir.bytes)
	}
	flow := retentionFlowState{RetentionSession: RetentionSession{Protocol: "http"}, directions: [2]directionPrefix{dir}}
	if !retainSmart(retentionMark{offset: 63}, &flow, policy) || retainSmart(retentionMark{offset: 64}, &flow, policy) {
		t.Fatal("明文方向预算没有生效")
	}
	dir.tcp(&layers.TCP{Seq: 120, BaseLayer: layers.BaseLayer{Payload: []byte("gap")}})
	flow.directions[0] = dir
	if !retainSmart(retentionMark{offset: 120}, &flow, policy) {
		t.Fatal("存在正文缺口时仍信任前缀偏移")
	}

	long := []byte{0xc0, 0, 0, 0, 1, 1, 0x55, 1, 0x56, 0x57}
	short := make([]byte, 23)
	short[0] = 0x40
	var quic directionPrefix
	if quic.udp(short) != -1 || quic.udp(long) != -1 || quic.udp(short) != 0 || quic.udp(short) != 23 {
		t.Fatal("QUIC 的首包和握手保留范围不正确")
	}
	binary.BigEndian.PutUint32(long[1:5], 0x6b3343cf)
	if quicLong(long) {
		t.Fatal("QUIC v2 Retry 不能证明进入相同连接的握手")
	}
	long[0] = 0xd0
	if !quicLong(long) || quicLong(long[:7]) {
		t.Fatal("QUIC v2 长包头结构判定错误")
	}
	flow = retentionFlowState{RetentionSession: RetentionSession{Protocol: "quic"}, directions: [2]directionPrefix{quic}}
	if !retainSmart(retentionMark{offset: 0}, &flow, policy) || retainSmart(retentionMark{offset: 23}, &flow, policy) {
		t.Fatal("QUIC 只裁剪可识别的握手后短包")
	}
	if !retainSmart(retentionMark{offset: 23, direction: 1}, &flow, policy) {
		t.Fatal("没有观测到握手的方向应保留")
	}
}
