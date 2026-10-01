package model

import "errors"

// ErrUnauthenticated 仅表示身份不存在或已失效，不表示依赖服务故障。
var ErrUnauthenticated = errors.New("身份或会话无效")
