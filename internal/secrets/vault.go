// Package secrets 以对象作用域绑定凭据密文，防止跨租户或跨修订复用。
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

var ErrUnavailable = errors.New("凭据密钥未配置或凭据校验失败")

type Vault struct{ aead cipher.AEAD }

func New(key string) (*Vault, error) {
	bytes, err := hex.DecodeString(key)
	if err != nil || len(bytes) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(bytes)
	if err != nil {
		return nil, ErrUnavailable
	}
	aead, err := cipher.NewGCM(block)
	return &Vault{aead}, err
}

func scope(tenant, kind, id string, revision int64) ([]byte, error) {
	if tenant == "" || kind == "" || id == "" || revision < 1 {
		return nil, ErrUnavailable
	}
	return json.Marshal([]any{tenant, kind, id, revision})
}

func (v *Vault) Seal(tenant, kind, id string, revision int64, value []byte) (string, error) {
	if v == nil || v.aead == nil || len(value) > 65536 {
		return "", ErrUnavailable
	}
	aad, err := scope(tenant, kind, id, revision)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrUnavailable
	}
	return base64.StdEncoding.EncodeToString(v.aead.Seal(nonce, nonce, value, aad)), nil
}

func (v *Vault) Open(tenant, kind, id string, revision int64, value string) ([]byte, error) {
	if v == nil || v.aead == nil || len(value) > 90000 {
		return nil, ErrUnavailable
	}
	aad, err := scope(tenant, kind, id, revision)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(data) < v.aead.NonceSize()+v.aead.Overhead() {
		return nil, ErrUnavailable
	}
	plain, err := v.aead.Open(nil, data[:v.aead.NonceSize()], data[v.aead.NonceSize():], aad)
	if err != nil {
		return nil, ErrUnavailable
	}
	return plain, nil
}
