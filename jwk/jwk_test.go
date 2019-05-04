package jwk_test

import (
	"testing"

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
