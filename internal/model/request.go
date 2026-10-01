package model

import "context"

type RequestMetadata struct{ SourceIP, UserAgent, RequestID string }
type requestMetadataKey struct{}

func WithRequestMetadata(ctx context.Context, meta RequestMetadata) context.Context {
	return context.WithValue(ctx, requestMetadataKey{}, meta)
}
func RequestMetadataFrom(ctx context.Context) RequestMetadata {
	meta, _ := ctx.Value(requestMetadataKey{}).(RequestMetadata)
	return meta
}
