package jwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jws"
	"github.com/repenno/jwx-opa/jwt"
)

func TestJWTParse(t *testing.T) {

	alg := jwa.RS256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Failed to generate RSA key")
	}
	t1 := jwt.New()
	signed, err := t1.Sign(alg, key)
	if err != nil {
		t.Fatal("Failed to sign JWT")
	}

	t.Run("Parse (no signature verification)", func(t *testing.T) {
		t2, err := jwt.ParseBytes(signed)
		if err != nil {
			t.Fatalf("Failed to parse token: %s", err.Error())
		}
		if !reflect.DeepEqual(t1, t2) {
			t.Fatal("Mismatched token values")
		}
	})
	t.Run("ParseString (no signature verification)", func(t *testing.T) {
		t2, err := jwt.ParseString(string(signed))
		if err != nil {
			t.Fatalf("Failed to parse token: %s", err.Error())
		}
		if !reflect.DeepEqual(t1, t2) {
			t.Fatal("Mismatched token values")
		}
	})
	t.Run("ParseBytes (no signature verification)", func(t *testing.T) {
		t2, err := jwt.ParseBytes(signed)
		if err != nil {
			t.Fatalf("Failed to parse token: %s", err.Error())
		}
		if !reflect.DeepEqual(t1, t2) {
			t.Fatal("Mismatched token values")
		}
	})
	t.Run("Parse (correct signature key)", func(t *testing.T) {
		t2, err := jwt.Parse(string([]byte(signed)), jwt.WithVerify(alg, &key.PublicKey))
		if err != nil {
			t.Fatalf("Failed to parse token: %s", err.Error())
		}
		if !reflect.DeepEqual(t1, t2) {
			t.Fatal("Mismatched token values")
		}
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		_, err := jwt.Parse(string([]byte(signed)), jwt.WithVerify(jwa.RS512, &key.PublicKey))
		if err == nil {
			t.Fatalf("Parsing should fail")
		}
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		pubkey := key.PublicKey
		pubkey.E = 0 // bogus value
		_, err := jwt.Parse(string([]byte(signed)), jwt.WithVerify(alg, &pubkey))
		if err == nil {
			t.Fatalf("Parsing should fail")
		}
	})
}

func TestJWTParseVerify(t *testing.T) {
	alg := jwa.RS256
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %s", err.Error())
	}
	t1 := jwt.New()
	signed, err := t1.Sign(alg, key)

	t.Run("parse (no signature verification)", func(t *testing.T) {
		_, err := jwt.ParseVerify(string(signed[:]), "", nil)
		if err == nil {
			t.Fatalf("Verificaition should fail")
		}
	})
	t.Run("parse (correct signature key)", func(t *testing.T) {
		t2, err := jwt.ParseVerify(string(signed[:]), alg, &key.PublicKey)
		if err != nil {
			t.Fatalf("Failed to verify jws: %s", err.Error())
		}
		if !reflect.DeepEqual(t1, t2) {
			t.Fatal("Mismatched token values")
		}
	})
	t.Run("parse (wrong signature algorithm)", func(t *testing.T) {
		_, err := jwt.ParseVerify(string([]byte(signed)), jwa.RS512, &key.PublicKey)
		if err == nil {
			t.Fatalf("Verificaition should fail")
		}
	})
	t.Run("parse (wrong signature key)", func(t *testing.T) {
		pubKey := key.PublicKey
		pubKey.E = 0 // bogus value
		_, err := jwt.ParseVerify(string([]byte(signed)), alg, &pubKey)
		if err == nil {
			t.Fatalf("Verificaition should fail")
		}
	})
}

func TestVerifyClaims(t *testing.T) {
	// GitHub issue #37: tokens are invalid in the second they are created (because Now() is not after IssuedAt())
	t.Run(jwt.IssuedAtKey+"+skew", func(t *testing.T) {
		token := jwt.New()
		now := time.Now().UTC()
		err := token.Set(jwt.IssuedAtKey, now)
		if err != nil {
			t.Fatalf("Failed to set iss: %s", err.Error())
		}

		const DefaultSkew = 0

		args := []jwt.Option{
			jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
			jwt.WithAcceptableSkew(DefaultSkew),
		}

		err = token.Verify(args...)
		if err != nil {
			t.Fatalf("Token valiadation should succeed in the same second they are created: %s", err.Error())
		}
		return
	})
}

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func TestUnmarshal(t *testing.T) {
	testcases := []struct {
		Title        string
		Source       string
		Expected     func() *jwt.Token
		ExpectedJSON string
	}{
		{
			Title:  "single aud",
			Source: `{"aud":"foo"}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
			ExpectedJSON: `{"aud":["foo"]}`,
		},
		{
			Title:  "multiple aud's",
			Source: `{"aud":["foo","bar"]}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
			ExpectedJSON: `{"aud":["foo","bar"]}`,
		},
		{
			Title:  "issuedAt",
			Source: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
			ExpectedJSON: `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			var token jwt.Token
			err := json.Unmarshal([]byte(tc.Source), &token)
			if err != nil {
				t.Fatalf("Failed to unmarshal token")
			}
			if !reflect.DeepEqual(tc.Expected(), &token) {
				t.Fatal("Mismatched token values")
			}

			var buf bytes.Buffer
			err = json.NewEncoder(&buf).Encode(token)
			if err != nil {
				t.Fatalf("Failed to marshal token: %s", err.Error())
			}
			if tc.ExpectedJSON != strings.TrimSpace(buf.String()) {
				t.Fatal("Mismatched JSON values")
			}
		})
	}
}

func TestGH52(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %s", err.Error())
	}

	pub := &privateKey.PublicKey
	for i := 0; i < 1000; i++ {
		token := jwt.New()

		s, err := token.Sign(jwa.ES256, privateKey)
		if err != nil {
			t.Fatalf("Failed to siggn token: %s", err.Error())
		}

		_, err = jws.Verify([]byte(s), jwa.ES256, pub)
		if err != nil {
			t.Fatalf("Failed to verify token: %s", err.Error())
		}
	}
}

func TestUnmarshalJSON(t *testing.T) {

	t.Run("Unmarshal audience with multiple values", func(t *testing.T) {
		var t1 jwt.Token
		err := json.Unmarshal([]byte(`{"aud":["foo", "bar", "baz"]}`), &t1)
		if err != nil {
			t.Fatalf("Failed to unmarshal aud: %s", err.Error())
		}
		aud, ok := t1.Get(jwt.AudienceKey)
		if !ok {
			t.Fatal("Failed to get aud")
		}

		if !reflect.DeepEqual(aud.([]string), []string{"foo", "bar", "baz"}) {
			t.Fatal("Mismatched audience values")
		}
	})
}
