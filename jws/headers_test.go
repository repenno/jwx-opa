package jws_test

import (
	"encoding/json"
	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jws"
	"reflect"
	"testing"
)

func TestHeader(t *testing.T) {
	jwkSrc := `{
  "kty": "RSA",
  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  "e": "AQAB",
  "alg": "RS256",
  "kid": "2011-04-29"
}`

	values := map[string]interface{}{
		jws.AlgorithmKey:   jwa.ES256,
		jws.ContentTypeKey: "example",
		jws.CriticalKey:    []string{"exp"},
		jws.JWKKey:         jwkSrc,
		jws.JWKSetURLKey:   "https://www.jwk.com/key.json",
		jws.TypeKey:        "JWT",
		jws.KeyIDKey:       "e9bc097a-ce51-4036-9562-d2ade882db0d",
	}
	t.Run("Roundtrip", func(t *testing.T) {

		var h jws.StandardHeaders
		for k, v := range values {
			err := h.Set(k, v)
			if err != nil {
				t.Fatalf("Set failed for %s", k)
			}
			got, ok := h.Get(k)
			if !ok {
				t.Fatalf("Set failed for %s", k)
			}
			//fmt.Println(reflect.TypeOf(got).String())
			//fmt.Println(reflect.TypeOf(v).String())
			if !reflect.DeepEqual(v, got) {
				t.Fatalf("Values do not match: (%v, %v)", v, got)
			}
		}
	})
	t.Run("JSON Marshal Unmarshal", func(t *testing.T) {

		var h jws.StandardHeaders
		for k, v := range values {
			err := h.Set(k, v)
			if err != nil {
				t.Fatalf("Set failed for %s", k)
			}
			got, ok := h.Get(k)
			if !ok {
				t.Fatalf("Set failed for %s", k)
			}
			if !reflect.DeepEqual(v, got) {
				t.Fatalf("Values do not match: (%v, %v)", v, got)
			}
		}
		hByte, err := json.Marshal(h)
		if err != nil {
			t.Fatal("Failed to JSON marshal")
		}
		var hNew jws.StandardHeaders
		err = json.Unmarshal(hByte, &hNew)
		if err != nil {
			t.Fatal("Failed to JSON marshal")
		}
	})
	t.Run("RoundtripError", func(t *testing.T) {

		type dummyStruct struct {
			dummy1 int
			dummy2 float64
		}
		dummy := &dummyStruct{1, 3.4}

		values := map[string]interface{}{
			jws.AlgorithmKey:   dummy,
			jws.ContentTypeKey: dummy,
			jws.CriticalKey:    dummy,
			jws.JWKKey:         dummy,
			jws.JWKSetURLKey:   dummy,
			jws.KeyIDKey:       dummy,
			jws.TypeKey:        dummy,
		}

		var h jws.StandardHeaders
		for k, v := range values {
			err := h.Set(k, v)
			if err == nil {
				t.Fatalf("Setting %s value should have failed", k)
			}
		}
		err := h.Set("default", dummy) // private params
		if err != nil {
			t.Fatalf("Setting %s value failed", "default")
		}
		for k, _ := range values {
			_, ok := h.Get(k)
			if ok {
				t.Fatalf("Getting %s value should have failed", k)
			}
		}
		_, ok := h.Get("default")
		if !ok {
			t.Fatal("Failed to get default value")
		}
	})
}
