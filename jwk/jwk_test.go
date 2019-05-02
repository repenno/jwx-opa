package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwk"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	k, err := jwk.New(nil)
	if k != nil {
		t.Fatalf("key should be nil: %s", err.Error())
	}
	if err == nil {
		t.Fatal("nil key should cause an error")
	}
}

func TestRoundTrip(t *testing.T) {
	generateRSA := func(use string, keyID string) (jwk.Key, error) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate RSA private key`)
		}

		k, err := jwk.New(key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
		}

		err = k.Set(jwk.KeyUsageKey, use)
		if err != nil {
			t.Fatalf("Failed to set Key Usage: %s", err.Error())
		}
		err = k.Set(jwk.KeyIDKey, keyID)
		if err != nil {
			t.Fatalf("Failed to set Key ID: %s", err.Error())
		}
		return k, nil
	}

	generateECDSA := func(use, keyID string) (jwk.Key, error) {
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
		}

		k, err := jwk.New(key)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
		}

		err = k.Set(jwk.KeyUsageKey, use)
		if err != nil {
			t.Fatalf("Failed to set Key Usage: %s", err.Error())
		}
		err = k.Set(jwk.KeyIDKey, keyID)
		if err != nil {
			t.Fatalf("Failed to set Key ID: %s", err.Error())
		}
		return k, nil
	}

	generateSymmetric := func(use, keyID string) (jwk.Key, error) {
		sharedKey := make([]byte, 64)
		_, err := rand.Read(sharedKey)
		if err != nil {
			t.Fatalf("Failed to generate symmetric key: %s", err.Error())
		}

		k, err := jwk.New(sharedKey)
		if err != nil {
			return nil, errors.Wrap(err, `failed to generate jwk.SymmetricKey`)
		}

		err = k.Set(jwk.KeyUsageKey, use)
		if err != nil {
			t.Fatalf("Failed to set Key Usage: %s", err.Error())
		}
		err = k.Set(jwk.KeyIDKey, keyID)
		if err != nil {
			t.Fatalf("Failed to set Key ID: %s", err.Error())
		}
		return k, nil
	}

	tests := []struct {
		use      string
		keyID    string
		generate func(string, string) (jwk.Key, error)
	}{
		{
			use:      "enc",
			keyID:    "enc1",
			generate: generateRSA,
		},
		{
			use:      "enc",
			keyID:    "enc2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig1",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig3",
			generate: generateSymmetric,
		},
		{
			use:      "enc",
			keyID:    "enc4",
			generate: generateECDSA,
		},
		{
			use:      "enc",
			keyID:    "enc5",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig4",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig5",
			generate: generateECDSA,
		},
	}

	var ks1 jwk.Set
	for _, tc := range tests {
		key, err := tc.generate(tc.use, tc.keyID)
		if !assert.NoError(t, err, `tc.generate should succeed`) {
			return
		}
		ks1.Keys = append(ks1.Keys, key)
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := jwk.ParseBytes(buf)
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		t.Logf("%s", buf)
		return
	}

	for _, tc := range tests {
		keys := ks2.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}
		key1 := keys[0]

		keys = ks1.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}

		key2 := keys[0]

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		if !assert.Equal(t, pk1json, pk2json, "Keys should match (kid = %s)", tc.keyID) {
			return
		}
	}
}

func TestAppendix(t *testing.T) {

	t.Run("A1", func(t *testing.T) {
		var jwkSrc = []byte(`{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use": "enc",
      "kid": "1"
    },
    {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "2011-04-29"
    }
  ]
}`)

		var jwkKey jwk.Key
		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		if len(rawKeySetJSON.Keys) == 0 {
			// It might be a single key
			rawKeyJSON := &jwk.RawKeyJSON{}
			err := json.Unmarshal([]byte(jwkSrc), rawKeyJSON)
			if err != nil {
				t.Fatalf("Failed to unmarshal JWK: %s", err.Error())
			}
			jwkKey, err = rawKeyJSON.GenerateKey()
			if _, ok := jwkKey.(*jwk.RSAPrivateKey); !ok {
				t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
			}
		} else {
			rawKeyJSON0 := rawKeySetJSON.Keys[0]
			jwkKey, err = rawKeyJSON0.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %s", err.Error())
			}
			if _, ok := jwkKey.(*jwk.ECDSAPublicKey); !ok {
				t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
			}
			rawKeyJSON1 := rawKeySetJSON.Keys[1]
			jwkKey, err = rawKeyJSON1.GenerateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %s", err.Error())
			}
			if _, ok := jwkKey.(*jwk.RSAPublicKey); !ok {
				t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
			}
		}
	})
}
