package jwk_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/repenno/jwx-opa/internal/base64"
	"github.com/repenno/jwx-opa/jwk"
	"reflect"
	"testing"
)

func TestSymmetric(t *testing.T) {

	t.Run("A3", func(t *testing.T) {
		const (
			key1 = `GawgguFyGrWKav7AX4VKUg`
			key2 = `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow`
		)

		buf1, err := base64.DecodeString(key1)
		if err != nil {
			t.Fatalf("Failed to decode key1: %s", err.Error())
		}
		buf2, err := base64.DecodeString(key2)
		if err != nil {
			t.Fatalf("Failed to decode key2: %s", err.Error())
		}

		var jwkSrc = []byte(`{
  "keys": [
    {
      "kty": "oct",
      "alg": "A128KW",
      "k": "GawgguFyGrWKav7AX4VKUg"
    },
    {
      "kty": "oct",
      "kid": "HMAC key used in JWS spec Appendix A.1 example",
      "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }
  ]
}`)
		var jwkKey jwk.Key
		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err = json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		rawKeyJSON0 := rawKeySetJSON.Keys[0]
		jwkKey0, err := rawKeyJSON0.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %s", err.Error())
		}
		if _, ok := jwkKey0.(*jwk.SymmetricKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
		}
		realizedKey0, err := jwkKey0.Materialize()
		if err != nil {
			t.Fatalf("Failed to materialize key: %s", err.Error())
		}
		if bytes.Compare(realizedKey0.([]byte), buf1) != 0 {
			t.Fatalf("Mismatched key values %s:%s", realizedKey0.([]byte), buf1)
		}

		rawKeyJSON1 := rawKeySetJSON.Keys[1]
		jwkKey1, err := rawKeyJSON1.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %s", err.Error())
		}
		if _, ok := jwkKey1.(*jwk.SymmetricKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
		}
		realizedKey1, err := jwkKey1.Materialize()
		if err != nil {
			t.Fatalf("Failed to materialize key: %s", err.Error())
		}
		if bytes.Compare(realizedKey1.([]byte), buf2) != 0 {
			t.Fatalf("Mismatched key values %s:%s", realizedKey1.([]byte), buf1)
		}
	})
	t.Run("Test New Key", func(t *testing.T) {

		var jwkSrc = []byte(`{
  "keys": [
    {
      "kty": "oct",
      "kid": "HMAC key used in JWS spec Appendix A.1 example",
      "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }
  ]
}`)
		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		rawKeyJSON0 := rawKeySetJSON.Keys[0]
		jwkKey0, err := rawKeyJSON0.GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key: %s", err.Error())
		}
		realizedKey0, err := jwkKey0.Materialize()
		if err != nil {
			t.Fatalf("Failed to materialize key: %s", err.Error())
		}
		jwkKey1, err := jwk.New(realizedKey0)
		if err != nil {
			t.Fatalf("Failed to create new symmetric key: %s", err.Error())
		}
		realizedKey1, err := jwkKey1.Materialize()
		if err != nil {
			t.Fatalf("Failed to materialize key: %s", err.Error())
		}
		if !reflect.DeepEqual(realizedKey1, realizedKey0) {
			t.Fatalf("Mismatched symmetric keys")
		}
	})

}
