// This file is auto-generated. DO NOT EDIT

package jwk

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwa"
)

const (
	AlgorithmKey = "alg"
	KeyIDKey     = "kid"
	KeyTypeKey   = "kty"
	KeyUsageKey  = "use"
	KeyOpsKey    = "key_ops"
)

type Headers interface {
	Remove(string)
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
	PopulateMap(map[string]interface{}) error
	ExtractMap(map[string]interface{}) error
	Walk(func(string, interface{}) error) error
	Algorithm() string
	KeyID() string
	KeyType() jwa.KeyType
	KeyUsage() string
	KeyOps() KeyOperationList
}

type StandardHeaders struct {
	algorithm     *string          // https://tools.ietf.org/html/rfc7517#section-4.4
	keyID         *string          // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyType       *jwa.KeyType     // https://tools.ietf.org/html/rfc7517#section-4.1
	keyUsage      *string          // https://tools.ietf.org/html/rfc7517#section-4.2
	keyops        KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	privateParams map[string]interface{}
}

func (h *StandardHeaders) Remove(s string) {
	delete(h.privateParams, s)
}

func (h *StandardHeaders) Algorithm() string {
	if v := h.algorithm; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) KeyID() string {
	if v := h.keyID; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) KeyType() jwa.KeyType {
	if v := h.keyType; v != nil {
		return *v
	}
	return jwa.InvalidKeyType
}

func (h *StandardHeaders) KeyUsage() string {
	if v := h.keyUsage; v != nil {
		return *v
	}
	return ""
}

func (h *StandardHeaders) KeyOps() KeyOperationList {
	return h.keyops
}

func (h *StandardHeaders) Get(name string) (interface{}, bool) {
	switch name {
	case AlgorithmKey:
		v := h.algorithm
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyIDKey:
		v := h.keyID
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyTypeKey:
		v := h.keyType
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyUsageKey:
		v := h.keyUsage
		if v == nil {
			return nil, false
		}
		return *v, true
	case KeyOpsKey:
		v := h.keyops
		if v == nil {
			return nil, false
		}
		return v, true
	default:
		v, ok := h.privateParams[name]
		return v, ok
	}
}

func (h *StandardHeaders) Set(name string, value interface{}) error {
	switch name {
	case AlgorithmKey:
		switch v := value.(type) {
		case string:
			h.algorithm = &v
			return nil
		case fmt.Stringer:
			s := v.String()
			h.algorithm = &s
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, AlgorithmKey, value)
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyTypeKey:
		var acceptor jwa.KeyType
		if err := acceptor.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyTypeKey)
		}
		h.keyType = &acceptor
		return nil
	case KeyUsageKey:
		if v, ok := value.(string); ok {
			h.keyUsage = &v
			return nil
		}
		return errors.Errorf(`invalid value for %s key: %T`, KeyUsageKey, value)
	case KeyOpsKey:
		if err := h.keyops.Accept(value); err != nil {
			return errors.Wrapf(err, `invalid value for %s key`, KeyOpsKey)
		}
		return nil
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

// PopulateMap populates a map with appropriate values that represent
// the headers as a JSON object. This exists primarily because JWKs are
// represented as flat objects instead of differentiating the different
// parts of the message in separate sub objects.
func (h StandardHeaders) PopulateMap(m map[string]interface{}) error {
	for k, v := range h.privateParams {
		m[k] = v
	}
	if v, ok := h.Get(AlgorithmKey); ok {
		m[AlgorithmKey] = v
	}
	if v, ok := h.Get(KeyIDKey); ok {
		m[KeyIDKey] = v
	}
	if v, ok := h.Get(KeyTypeKey); ok {
		m[KeyTypeKey] = v
	}
	if v, ok := h.Get(KeyUsageKey); ok {
		m[KeyUsageKey] = v
	}
	if v, ok := h.Get(KeyOpsKey); ok {
		m[KeyOpsKey] = v
	}

	return nil
}

// ExtractMap populates the appropriate values from a map that represent
// the headers as a JSON object. This exists primarily because JWKs are
// represented as flat objects instead of differentiating the different
// parts of the message in separate sub objects.
func (h *StandardHeaders) ExtractMap(m map[string]interface{}) (err error) {
	if v, ok := m[AlgorithmKey]; ok {
		if err := h.Set(AlgorithmKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, AlgorithmKey)
		}
		delete(m, AlgorithmKey)
	}
	if v, ok := m[KeyIDKey]; ok {
		if err := h.Set(KeyIDKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyIDKey)
		}
		delete(m, KeyIDKey)
	}
	if v, ok := m[KeyTypeKey]; ok {
		if err := h.Set(KeyTypeKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyTypeKey)
		}
		delete(m, KeyTypeKey)
	}
	if v, ok := m[KeyUsageKey]; ok {
		if err := h.Set(KeyUsageKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyUsageKey)
		}
		delete(m, KeyUsageKey)
	}
	if v, ok := m[KeyOpsKey]; ok {
		if err := h.Set(KeyOpsKey, v); err != nil {
			return errors.Wrapf(err, `failed to set value for key %s`, KeyOpsKey)
		}
		delete(m, KeyOpsKey)
	}
	// Fix: A nil map is different from a empty map as far as deep.equal is concerned
	if len(m) > 0 {
		h.privateParams = m
	}

	return nil
}

func (h StandardHeaders) Walk(f func(string, interface{}) error) error {
	for _, key := range []string{AlgorithmKey, KeyIDKey, KeyTypeKey, KeyUsageKey, KeyOpsKey} {
		if v, ok := h.Get(key); ok {
			if err := f(key, v); err != nil {
				return errors.Wrapf(err, `walk function returned error for %s`, key)
			}
		}
	}

	for k, v := range h.privateParams {
		if err := f(k, v); err != nil {
			return errors.Wrapf(err, `walk function returned error for %s`, k)
		}
	}
	return nil
}
