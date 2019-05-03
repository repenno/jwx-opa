package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwk"
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
		if err != nil {
			t.Fatalf("tc.generate should succeed: %s", err.Error())
		}
		ks1.Keys = append(ks1.Keys, key)
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if err != nil {
		t.Fatalf("JSON marshal failed: %s", err.Error())
	}

	ks2, err := jwk.ParseBytes(buf)
	if err != nil {
		t.Fatalf("JSON marshal failed: %s", err.Error())
	}

	for _, tc := range tests {
		keys := ks2.LookupKeyID(tc.keyID)
		if len(keys) != 1 {
			t.Fatalf("Failed to lookup Key ID: %s", tc.keyID)
		}
		key1 := keys[0]

		keys = ks1.LookupKeyID(tc.keyID)
		if len(keys) != 1 {
			t.Fatalf("Failed to lookup Key ID: %s", tc.keyID)
		}

		key2 := keys[0]

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		if bytes.Compare(pk1json, pk2json) != 0 {
			t.Fatalf("Mismatched keys (%s):(%s)", key1.GetKeyID(), key2.GetKeyID())
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

		var jwkKeySet *jwk.Set
		jwkKeySet, err := jwk.ParseBytes(jwkSrc)
		if err != nil {
			t.Fatalf("Failed to parse JWK Set: %s", err.Error())
		}
		if len(jwkKeySet.Keys) != 2 {
			t.Fatalf("Failed to parse JWK Set: %s", err.Error())
		}
	})
}
