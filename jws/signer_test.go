package jws_test

import (
	"testing"

	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jws"
)

func TestSign(t *testing.T) {
	t.Run("Bad algorithm", func(t *testing.T) {
		_, err := jws.SignWithOption([]byte(nil), jwa.SignatureAlgorithm("FooBar"), nil)
		if err == nil {
			t.Fatal("Unknown algorithm should return error")
		}
	})
	t.Run("No private key", func(t *testing.T) {
		_, err := jws.SignWithOption([]byte{'a', 'b', 'c'}, jwa.RS256, nil)
		if err == nil {
			t.Fatal("SignWithOption with no private key should return error")
		}
	})
	t.Run("RSA verify with no public key", func(t *testing.T) {
		_, err := jws.Verify([]byte(nil), jwa.RS256, nil)
		if err == nil {
			t.Fatal("Verify with no private key should return error")
		}
	})
}
