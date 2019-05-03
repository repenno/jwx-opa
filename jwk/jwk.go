// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
package jwk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/internal/base64"
	"github.com/repenno/jwx-opa/jwa"
)

// GetPublicKey returns the public key based on the private key type.
// For rsa key types *rsa.PublicKey is returned; for ecdsa key types *ecdsa.PublicKey;
// for byte slice (raw) keys, the key itself is returned. If the corresponding
// public key cannot be deduced, an error is returned
func GetPublicKey(key interface{}) (interface{}, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	switch v := key.(type) {
	// Mental note: although Public() is defined in both types,
	// you can not coalesce the clauses for rsa.PrivateKey and
	// ecdsa.PrivateKey, as then `v` becomes interface{}
	// b/c the compiler cannot deduce the exact type.
	case *rsa.PrivateKey:
		return v.Public(), nil
	case *ecdsa.PrivateKey:
		return v.Public(), nil
	case []byte:
		return v, nil
	default:
		return nil, errors.Errorf(`invalid key type %T`, key)
	}
}

// New creates a jwk.Key from the given key.
func New(key interface{}) (Key, error) {
	if key == nil {
		return nil, errors.New(`jwk.New requires a non-nil key`)
	}

	switch v := key.(type) {
	case *rsa.PrivateKey:
		return newRSAPrivateKey(v)
	case *rsa.PublicKey:
		return newRSAPublicKey(v)
	case *ecdsa.PrivateKey:
		return newECDSAPrivateKey(v)
	case *ecdsa.PublicKey:
		return newECDSAPublicKey(v)
	case []byte:
		return newSymmetricKey(v)
	default:
		return nil, errors.Errorf(`invalid key type %T`, key)
	}
}

func (set *Set) UnmarshalJSON(data []byte) error {
	v, err := ParseBytes(data)
	if err != nil {
		return errors.Wrap(err, `failed to parse jwk.Set`)
	}
	*set = *v
	return nil
}

// Parse parses JWK from the incoming io.Reader.
func Parse(jwkSrc string) (*Set, error) {
	var jwkKeySet Set
	var jwkKey Key
	rawKeySetJSON := &RawKeySetJSON{}
	err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to unmarshal JWK Set")
	}
	if len(rawKeySetJSON.Keys) == 0 {

		// It might be a single key
		rawKeyJSON := &RawKeyJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeyJSON)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to unmarshal JWK")
		}
		jwkKey, err = rawKeyJSON.GenerateKey()
		if err != nil {
			return nil, errors.Wrap(err, "Failed to generate key")
		}
		// Add to set
		jwkKeySet.Keys = append(jwkKeySet.Keys, jwkKey)
	} else {
		for i := range rawKeySetJSON.Keys {
			rawKeyJSON := rawKeySetJSON.Keys[i]
			jwkKey, err = rawKeyJSON.GenerateKey()
			if err != nil {
				return nil, errors.Wrap(err, "Failed to generate key: %s")
			}
			jwkKeySet.Keys = append(jwkKeySet.Keys, jwkKey)
		}
	}
	return &jwkKeySet, nil
}

// ParseBytes parses JWK from the incoming byte buffer.
func ParseBytes(buf []byte) (*Set, error) {
	return Parse(string(buf[:]))
}

// ParseString parses JWK from the incoming string.
func ParseString(s string) (*Set, error) {
	return Parse(s)
}

// LookupKeyID looks for keys matching the given key id. Note that the
// Set *may* contain multiple keys with the same key id
func (s Set) LookupKeyID(kid string) []Key {
	var keys []Key
	for _, key := range s.Keys {
		if key.GetKeyID() == kid {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Set) ExtractMap(m map[string]interface{}) error {
	raw, ok := m["keys"]
	if !ok {
		return errors.New("missing 'keys' parameter")
	}

	v, ok := raw.([]interface{})
	if !ok {
		return errors.New("invalid 'keys' parameter")
	}

	var ks Set
	for _, c := range v {
		conf, ok := c.(map[string]interface{})
		if !ok {
			return errors.New("invalid element in 'keys'")
		}

		k, err := constructKey(conf)
		if err != nil {
			return errors.Wrap(err, `failed to construct key from map`)
		}
		ks.Keys = append(ks.Keys, k)
	}

	*s = ks
	return nil
}

func constructKey(m map[string]interface{}) (Key, error) {
	kty, ok := m[KeyTypeKey].(string)
	if !ok {
		return nil, errors.Errorf(`unsupported kty type %T`, m[KeyTypeKey])
	}

	var key Key
	switch jwa.KeyType(kty) {
	case jwa.RSA:
		if _, ok := m["d"]; ok {
			key = &RSAPrivateKey{}
		} else {
			key = &RSAPublicKey{}
		}
	case jwa.EC:
		if _, ok := m["d"]; ok {
			key = &ECDSAPrivateKey{}
		} else {
			key = &ECDSAPublicKey{}
		}
	case jwa.OctetSeq:
		key = &SymmetricKey{}
	default:
		return nil, errors.Errorf(`invalid kty %s`, kty)
	}

	if err := key.ExtractMap(m); err != nil {
		return nil, errors.Wrap(err, `failed to extract key from map`)
	}

	return key, nil
}

func getRequiredKey(m map[string]interface{}, key string) ([]byte, error) {
	return getKey(m, key, true)
}

func getOptionalKey(m map[string]interface{}, key string) ([]byte, error) {
	return getKey(m, key, false)
}

func getKey(m map[string]interface{}, key string, required bool) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		if !required {
			return nil, errors.Errorf(`missing parameter '%s'`, key)
		}
		return nil, errors.Errorf(`missing required parameter '%s'`, key)
	}

	vs, ok := v.(string)
	if !ok {
		return nil, errors.Errorf(`invalid type for parameter '%s': %T`, key, v)
	}

	buf, err := base64.DecodeString(vs)
	if err != nil {
		return nil, errors.Wrapf(err, `failed to base64 decode key %s`, key)
	}
	return buf, nil
}

func (r *RawKeyJSON) GenerateKey() (Key, error) {

	var key Key

	switch r.KeyType {
	case jwa.RSA:
		if r.D != nil {
			key = &RSAPrivateKey{}
		} else {
			key = &RSAPublicKey{}
		}
	case jwa.EC:
		if r.D != nil {
			key = &ECDSAPrivateKey{}
		} else {
			key = &ECDSAPublicKey{}
		}
	case jwa.OctetSeq:
		key = &SymmetricKey{}
	default:
		return nil, errors.Errorf(`Unrecognized key type`)
	}
	err := key.GenerateKey(r)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate key from JWK")
	}
	return key, nil
}
