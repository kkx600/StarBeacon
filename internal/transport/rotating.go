package transport

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
)

// RotatingConn 使现有 RPC 客户端在证书切换后使用新连接；旧流由各自的持久重试机制恢复。
type RotatingConn struct {
	connection atomic.Pointer[grpc.ClientConn]
}

func NewRotatingConn(c *grpc.ClientConn) *RotatingConn {
	r := &RotatingConn{}
	r.connection.Store(c)
	return r
}
func (r *RotatingConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return r.connection.Load().Invoke(ctx, method, args, reply, opts...)
}
func (r *RotatingConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return r.connection.Load().NewStream(ctx, desc, method, opts...)
}
func (r *RotatingConn) Replace(c *grpc.ClientConn) error {
	old := r.connection.Swap(c)
	return old.Close()
}
func (r *RotatingConn) Close() error { return r.connection.Load().Close() }
