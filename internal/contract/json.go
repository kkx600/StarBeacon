package contract

import "github.com/kkx600/StarBeacon/internal/strictjson"

var ErrJSON = strictjson.ErrJSON

// JSONFields 复用有界解码检查，保留领域契约的既有调用入口。
func JSONFields(text string, fields []string, limit int) error {
	return strictjson.Fields(text, fields, limit)
}
