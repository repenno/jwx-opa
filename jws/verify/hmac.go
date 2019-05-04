package verify

import (
	"crypto/hmac"
	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jws/sign"
)

func newHMAC(alg jwa.SignatureAlgorithm) (*HMACVerifier, error) {

	s, err := sign.New(alg)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate HMAC signer`)
	}
	return &HMACVerifier{signer: s}, nil
}

func (v HMACVerifier) Verify(payload, signature []byte, key interface{}) (err error) {

	expected, err := v.signer.Sign(payload, key)
	if err != nil {
		return errors.Wrap(err, `failed to generated signature`)
	}

	if !hmac.Equal(signature, expected) {
		return errors.New(`failed to match hmac signature`)
	}
	return nil
}
