package jwk_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jwk"
	"github.com/stretchr/testify/assert"
)

func TestECDSA(t *testing.T) {
	t.Run("Parse Private Key", func(t *testing.T) {
		jwkSrc := `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
  }`
		// Heuristics for parsing Set and single keys
		// TODO
		rawKeyJson := &jwk.RawKeyJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeyJson)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err = json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		if len(rawKeySetJSON.Keys) != 1 {
			t.Fatalf("Failed to parse JWK Set: %s", err.Error())
		}
		rawKeyJSON := rawKeySetJSON.Keys[0]
		curveName := rawKeyJSON.Crv
		if curveName != "P-256" {
			t.Fatalf("Curve name should be P-256, not: %s ", curveName)
		}
		jwkKey, err := rawKeyJSON.GenerateKey()
		if _, ok := jwkKey.(*jwk.ECDSAPrivateKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
		}
		privateKey, err := jwkKey.Materialize()
		if err != nil {
			t.Fatalf("Failed to expose private key: %s", err.Error())
		}
		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", privateKey))
		}
		publicKey, err := jwk.GetPublicKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to expose public key: %s", err.Error())
		}
		if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", privateKey))
		}
	})
	t.Run("Initialization", func(t *testing.T) {
		// Generate an ECDSA P-256 test key.
		ecPrk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if !assert.NoError(t, err, "Failed to generate EC P-256 key") {
			return
		}
		// Test initialization of a private EC JWK.
		prk, err := jwk.New(ecPrk)
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}
		err = prk.Set(jwk.KeyIDKey, "MyKey")
		if err != nil {
			t.Fatalf("Faild to set KeyID: %s", err.Error())
		}
		if prk.GetKeyID() != "MyKey" {
			t.Fatalf("KeyID should be MyKey, not: %s", prk.GetKeyID())
		}

		if prk.GetKeyType() != jwa.EC {
			t.Fatalf("Key type should be %s, not: %s", jwa.EC, prk.GetKeyType())
		}

		// Test initialization of a public EC JWK.
		puk, err := jwk.New(&ecPrk.PublicKey)
		if !assert.NoError(t, err, `jwk.New should succeed`) {
			return
		}

		err = puk.Set(jwk.KeyIDKey, "MyKey")
		if err != nil {
			t.Fatalf("Faild to set KeyID: %s", err.Error())
		}
		if puk.GetKeyID() != "MyKey" {
			t.Fatalf("KeyID should be MyKey, not: %s", puk.GetKeyID())
		}

		if puk.GetKeyType() != jwa.EC {
			t.Fatalf("Key type should be %s, not: %s", jwa.EC, puk.GetKeyType())
		}
	})
	t.Run("Marshall Unmarshal Public Key", func(t *testing.T) {
		jwkSrc := `{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "key_ops": [
        "verify"
      ],
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
    }
  ]
}`
		expectedPublicKeyBytes := []byte{123, 34, 99, 114, 118, 34, 58, 34, 80, 45, 50, 53, 54, 34, 44, 34, 107, 116, 121, 34, 58, 34, 69, 67, 34, 44, 34, 120, 34, 58, 34, 77, 75, 66, 67, 84, 78, 73, 99, 75, 85, 83, 68, 105, 105, 49, 49, 121, 83, 115, 51, 53, 50, 54, 105, 68, 90, 56, 65, 105, 84, 111, 55, 84, 117, 54, 75, 80, 65, 113, 118, 55, 68, 52, 34, 44, 34, 121, 34, 58, 34, 52, 69, 116, 108, 54, 83, 82, 87, 50, 89, 105, 76, 85, 114, 78, 53, 118, 102, 118, 86, 72, 117, 104, 112, 55, 120, 56, 80, 120, 108, 116, 109, 87, 87, 108, 98, 98, 77, 52, 73, 70, 121, 77, 34, 125}

		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		if len(rawKeySetJSON.Keys) != 1 {
			t.Fatalf("Failed to parse JWK Set: %s", err.Error())
		}
		rawKeyJSON := rawKeySetJSON.Keys[0]
		curveName := rawKeyJSON.Crv
		if curveName != "P-256" {
			t.Fatalf("Curve name should be P-256, not: %s ", curveName)
		}
		jwkKey, err := rawKeyJSON.GenerateKey()
		if _, ok := jwkKey.(*jwk.ECDSAPrivateKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
		}
		privateKey, err := jwkKey.Materialize()
		if err != nil {
			t.Fatalf("Failed to expose private key: %s", err.Error())
		}
		if _, ok := privateKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", privateKey))
		}
		publicKey, err := jwk.GetPublicKey(privateKey)
		if err != nil {
			t.Fatalf("Failed to expose public key: %s", err.Error())
		}
		if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", privateKey))
		}
		eCDSAPublicKey, err := jwk.New(publicKey)
		if err != nil {
			t.Fatal("Failed to create ECDSAPublicKey")
		}
		// verify marshal
		pubKeyBytes, err := json.Marshal(eCDSAPublicKey)
		if err != nil {
			t.Fatal("Failed to marshal ECDSAPublicKey")
		}
		if bytes.Compare(pubKeyBytes, expectedPublicKeyBytes) != 0 {
			t.Fatal("Expected and created ECDSA Public Keys do not match")
		}

		// verify unmarshal
		eCDSAPublicKey2 := &jwk.ECDSAPublicKey{}
		err = json.Unmarshal(expectedPublicKeyBytes, eCDSAPublicKey2)
		if err != nil {
			t.Fatal("Failed to unmarshal ECDSAPublicKey")
		}
		pECDSAPublicKey := eCDSAPublicKey.(*jwk.ECDSAPublicKey)
		if !reflect.DeepEqual(pECDSAPublicKey, eCDSAPublicKey2) {
			t.Fatal("ECDSA Public Keys do not match")
		}
	})
	t.Run("Marshall Unmarshal Private Key", func(t *testing.T) {
		jwkSrc := `{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "key_ops": ["verify"],
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
				 }
       ]
  }`
		expectedPrivKey := []byte{123, 34, 99, 114, 118, 34, 58, 34, 80, 45, 50, 53, 54, 34, 44, 34, 100, 34, 58, 34, 56, 55, 48, 77, 66, 54, 103, 102, 117, 84, 74, 52, 72, 116, 85, 110, 85, 118, 89, 77, 121, 74, 112, 114, 53, 101, 85, 90, 78, 80, 52, 66, 107, 52, 51, 98, 86, 100, 106, 51, 101, 65, 69, 34, 44, 34, 107, 101, 121, 95, 111, 112, 115, 34, 58, 91, 34, 118, 101, 114, 105, 102, 121, 34, 93, 44, 34, 107, 116, 121, 34, 58, 34, 69, 67, 34, 44, 34, 120, 34, 58, 34, 77, 75, 66, 67, 84, 78, 73, 99, 75, 85, 83, 68, 105, 105, 49, 49, 121, 83, 115, 51, 53, 50, 54, 105, 68, 90, 56, 65, 105, 84, 111, 55, 84, 117, 54, 75, 80, 65, 113, 118, 55, 68, 52, 34, 44, 34, 121, 34, 58, 34, 52, 69, 116, 108, 54, 83, 82, 87, 50, 89, 105, 76, 85, 114, 78, 53, 118, 102, 118, 86, 72, 117, 104, 112, 55, 120, 56, 80, 120, 108, 116, 109, 87, 87, 108, 98, 98, 77, 52, 73, 70, 121, 77, 34, 125}

		rawKeySetJSON := &jwk.RawKeySetJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeySetJSON)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		if len(rawKeySetJSON.Keys) != 1 {
			t.Fatalf("Failed to parse JWK Set: %s", err.Error())
		}
		rawKeyJSON := rawKeySetJSON.Keys[0]
		curveName := rawKeyJSON.Crv
		if curveName != "P-256" {
			t.Fatalf("Curve name should be P-256, not: %s ", curveName)
		}
		jwkKey, err := rawKeyJSON.GenerateKey()
		if _, ok := jwkKey.(*jwk.ECDSAPrivateKey); !ok {
			t.Fatalf("Key type should be of type: %s", fmt.Sprintf("%T", jwkKey))
		}

		//
		privKeyBytes, err := json.Marshal(jwkKey)
		if err != nil {
			t.Fatal("Failed to marshal ECDSAPrivateKey")
		}
		// verify marshal

		if bytes.Compare(privKeyBytes, expectedPrivKey) != 0 {
			t.Fatal("ECDSAPrivate in bytes do not match")
		}

		// verify unmarshal

		expECDSAPrivateKey := &jwk.ECDSAPrivateKey{}
		err = json.Unmarshal(expectedPrivKey, expECDSAPrivateKey)
		if err != nil {
			t.Fatal("Failed to unmarshal ECDSAPublicKey")
		}

		if !reflect.DeepEqual(expECDSAPrivateKey, jwkKey) {
			t.Fatal("ECDSAPrivate Keys do not match")
		}
	})
	t.Run("Invalid ECDSA Private Key", func(t *testing.T) {
		const jwkSrc = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		rawKeyJson := &jwk.RawKeyJSON{}
		err := json.Unmarshal([]byte(jwkSrc), rawKeyJson)
		if err != nil {
			t.Fatalf("Failed to unmarshal JWK Set: %s", err.Error())
		}
		_, err = rawKeyJson.GenerateKey()
		if err == nil {
			t.Fatalf("Key Generation should fail")
		}
	})
}
