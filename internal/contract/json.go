package contract

import (
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrJSON = errors.New("JSON 不符合唯一字段与资源边界")

// JSONFields 拒绝重复键、大小写别名及超深对象；结构和必填值由领域解码器继续核对。
func JSONFields(text string, fields []string, limit int) error {
	if !utf8.ValidString(text) || strings.ContainsRune(text, 0) || len(text) > limit || limit < 1 {
		return ErrJSON
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 8 {
			return ErrJSON
		}
		token, err := d.Token()
		if err != nil {
			return ErrJSON
		}
		delim, compound := token.(json.Delim)
		if depth == 0 && (!compound || delim != '{') {
			return ErrJSON
		}
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, valid := key.(string)
				if err != nil || !valid || seen[name] || !slices.Contains(fields, name) {
					return ErrJSON
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrJSON
			}
		case '[':
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrJSON
			}
		default:
			return ErrJSON
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrJSON
	}
	return nil
}
