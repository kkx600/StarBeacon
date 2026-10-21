package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kkx600/StarBeacon/internal/privatefile"
	"github.com/kkx600/StarBeacon/internal/syslogdata"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

type syslogSource struct {
	config  syslogdata.Source
	tls     *tls.Config
	limiter *rate.Limiter
	mu      sync.Mutex
	health  syslogdata.Health
}
type syslogSubmission struct {
	input  SyslogInput
	source *syslogSource
	done   chan error
}
type SyslogService struct {
	wal     *WAL
	sources []*syslogSource
	queue   chan syslogSubmission
	running atomic.Bool
}

func NewSyslogService(wal *WAL, path string) (*SyslogService, error) {
	file, err := syslogdata.LoadFile(path)
	if err != nil {
		return nil, err
	}
	s := &SyslogService{wal: wal, queue: make(chan syslogSubmission, 256)}
	for _, c := range file.Sources {
		v := &syslogSource{config: c, limiter: rate.NewLimiter(rate.Limit(c.MaxEventsPerSecond), c.MaxEventsPerSecond)}
		if c.Transport == "tls" {
			cert, e := privatefile.Read(c.TLS.CertificateFile, 1024*1024)
			if e != nil {
				return nil, syslogdata.ErrInput
			}
			key, e := privatefile.Read(c.TLS.PrivateKeyFile, 1024*1024)
			if e != nil {
				return nil, syslogdata.ErrInput
			}
			ca, e := privatefile.Read(c.TLS.ClientCAFile, 1024*1024)
			if e != nil {
				return nil, syslogdata.ErrInput
			}
			pair, e := tls.X509KeyPair(cert, key)
			if e != nil {
				return nil, syslogdata.ErrInput
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, syslogdata.ErrInput
			}
			allowed := map[string]bool{}
			for _, fingerprint := range c.TLS.ClientFingerprints {
				allowed[fingerprint] = true
			}
			v.tls = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || !allowed[syslogdata.Hash(state.PeerCertificates[0].Raw)] {
					return syslogdata.ErrInput
				}
				return nil
			}}
		}
		identity := "certificate"
		loss := "unknown"
		if c.Transport != "tls" {
			identity = "network_allowlist"
		}
		if c.Transport == "udp" {
			loss = "unmeasurable"
		}
		v.health = syslogdata.Health{ReceiverBinding: c.Binding(), State: "starting", Reason: "listener_not_ready", ObservedAt: time.Now().UTC(), StartedAt: time.Now().UTC(), Received: "0", Persisted: "0", Dropped: "0", Rejected: "0", FramingErrors: "0", MaxMessageBytes: c.MaxMessageBytes, IdentityQuality: identity, UpstreamLoss: loss}
		s.sources = append(s.sources, v)
	}
	return s, nil
}
func (v *syslogSource) change(fn func(*syslogdata.Health)) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fn(&v.health)
	v.health.ObservedAt = time.Now().UTC()
}
func increment(p *string) {
	n, _ := strconv.ParseUint(*p, 10, 64)
	if n < ^uint64(0) {
		*p = strconv.FormatUint(n+1, 10)
	}
}
func (s *SyslogService) Health() []syslogdata.Health {
	result := make([]syslogdata.Health, 0, len(s.sources))
	for _, v := range s.sources {
		v.mu.Lock()
		h := v.health
		h.ObservedAt = time.Now().UTC()
		if v.health.LastPersistedAt != nil {
			t := *v.health.LastPersistedAt
			h.LastPersistedAt = &t
		}
		v.mu.Unlock()
		result = append(result, h)
	}
	return result
}
func (s *SyslogService) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("Syslog 接收器已运行")
	}
	defer s.running.Store(false)
	group, run := errgroup.WithContext(ctx)
	group.Go(func() error { return s.persist(run) })
	for _, v := range s.sources {
		group.Go(func() error {
			defer v.change(func(h *syslogdata.Health) { h.State = "stopped"; h.Reason = "listener_stopped" })
			for run.Err() == nil {
				err := s.listen(run, v)
				if run.Err() != nil {
					return nil
				}
				if err != nil {
					v.change(func(h *syslogdata.Health) { h.State = "unavailable"; h.Reason = "listener_unavailable" })
				}
				if !pause(run, time.Second) {
					return nil
				}
			}
			return nil
		})
	}
	return group.Wait()
}
func (s *SyslogService) persist(ctx context.Context) error {
	for {
		var first syslogSubmission
		select {
		case <-ctx.Done():
			return nil
		case first = <-s.queue:
		}
		batch := []syslogSubmission{first}
		timer := time.NewTimer(5 * time.Millisecond)
	gather:
		for len(batch) < 64 {
			select {
			case next := <-s.queue:
				batch = append(batch, next)
			case <-timer.C:
				break gather
			case <-ctx.Done():
				timer.Stop()
				for _, v := range batch {
					if v.done != nil {
						v.done <- ctx.Err()
					}
				}
				return nil
			}
		}
		timer.Stop()
		inputs := make([]SyslogInput, 0, len(batch))
		for _, v := range batch {
			inputs = append(inputs, v.input)
		}
		err := s.wal.AppendSyslogBatch(inputs)
		for _, v := range batch {
			v.source.change(func(h *syslogdata.Health) {
				if err == nil {
					increment(&h.Persisted)
					t := time.Now().UTC()
					h.LastPersistedAt = &t
					h.State = "listening"
					h.Reason = ""
				} else {
					increment(&h.Dropped)
					h.State = "degraded"
					h.Reason = "durable_queue_unavailable"
				}
			})
			if v.done != nil {
				v.done <- err
			}
		}
	}
}
func (s *SyslogService) submit(ctx context.Context, v *syslogSource, peer syslogdata.Peer, raw []byte, datagram bool) error {
	v.change(func(h *syslogdata.Health) { increment(&h.Received) })
	if !v.limiter.Allow() {
		v.change(func(h *syslogdata.Health) { increment(&h.Dropped) })
		return errors.New("日志来源速率超限")
	}
	work := syslogSubmission{input: SyslogInput{Binding: v.config.Binding(), ObservedAt: time.Now().UTC(), Peer: peer, Raw: append([]byte(nil), raw...)}, source: v}
	if datagram {
		select {
		case s.queue <- work:
			return nil
		default:
			v.change(func(h *syslogdata.Health) { increment(&h.Dropped) })
			return ErrWALFull
		}
	}
	work.done = make(chan error, 1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.queue <- work:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-work.done:
		return err
	}
}
func remotePeer(addr net.Addr) (syslogdata.Peer, netip.Addr, bool) {
	p, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return syslogdata.Peer{}, netip.Addr{}, false
	}
	ip := p.Addr().Unmap()
	return syslogdata.Peer{IP: ip.String(), Port: p.Port()}, ip, p.Port() != 0
}
func (s *SyslogService) listen(ctx context.Context, v *syslogSource) error {
	if v.config.Transport == "udp" {
		return s.listenUDP(ctx, v)
	}
	listener, err := net.Listen("tcp", v.config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	v.change(func(h *syslogdata.Health) { h.State = "listening"; h.Reason = "" })
	slots := make(chan struct{}, v.config.MaxConnections)
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		peer, ip, ok := remotePeer(conn.RemoteAddr())
		if !ok || !v.config.Allows(ip) {
			v.change(func(h *syslogdata.Health) { increment(&h.Rejected) })
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			v.change(func(h *syslogdata.Health) { increment(&h.Rejected) })
			conn.Close()
			continue
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer func() { <-slots }()
			defer conn.Close()
			rawConn := conn
			stop := context.AfterFunc(ctx, func() { rawConn.Close() })
			defer stop()
			if v.tls != nil {
				secure := tls.Server(conn, v.tls)
				handshake, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := secure.HandshakeContext(handshake)
				cancel()
				if err != nil {
					v.change(func(h *syslogdata.Health) { increment(&h.Rejected) })
					return
				}
				conn = secure
				cert := secure.ConnectionState().PeerCertificates[0]
				peer.CertificateSHA256 = syslogdata.Hash(cert.Raw)
			}
			reader := bufio.NewReaderSize(conn, 4096)
			for ctx.Err() == nil {
				if conn.SetReadDeadline(time.Now().Add(15*time.Second)) != nil {
					return
				}
				raw, err := readSyslogFrame(reader, v.config.MaxMessageBytes)
				if err != nil {
					if err != io.EOF && ctx.Err() == nil {
						v.change(func(h *syslogdata.Health) { increment(&h.FramingErrors) })
					}
					return
				}
				if s.submit(ctx, v, peer, raw, false) != nil {
					return
				}
			}
		}()
	}
}
func (s *SyslogService) listenUDP(ctx context.Context, v *syslogSource) error {
	addr, err := net.ResolveUDPAddr("udp", v.config.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	v.change(func(h *syslogdata.Health) { h.State = "listening"; h.Reason = "" })
	buffer := make([]byte, v.config.MaxMessageBytes+1)
	for ctx.Err() == nil {
		n, addr, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		peer, ip, ok := remotePeer(net.UDPAddrFromAddrPort(addr))
		if !ok || !v.config.Allows(ip) {
			v.change(func(h *syslogdata.Health) { increment(&h.Rejected) })
			continue
		}
		if n == 0 || n > v.config.MaxMessageBytes {
			v.change(func(h *syslogdata.Health) { increment(&h.FramingErrors) })
			continue
		}
		_ = s.submit(ctx, v, peer, buffer[:n], true)
	}
	return nil
}

// RFC 6587 长度前缀不包含空格自身；先限制长度字段，再读取原始字节。
// 不使用按行分帧，正文中的换行不会被当作另一条日志。
func readSyslogFrame(r *bufio.Reader, max int) ([]byte, error) {
	n := 0
	for digits := 0; digits < 7; digits++ {
		b, err := r.ReadByte()
		if err != nil {
			if digits == 0 {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		if b == ' ' && digits > 0 {
			if n < 1 || n > max {
				return nil, syslogdata.ErrInput
			}
			raw := make([]byte, n)
			_, err := io.ReadFull(r, raw)
			return raw, err
		}
		if b < '0' || b > '9' || digits == 0 && b == '0' {
			return nil, syslogdata.ErrInput
		}
		n = n*10 + int(b-'0')
		if n > max {
			return nil, syslogdata.ErrInput
		}
	}
	return nil, syslogdata.ErrInput
}
