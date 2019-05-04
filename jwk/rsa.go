package jwk

import (
	"crypto/rsa"
	"math/big"

	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwa"
)

func newRSAPublicKey(key *rsa.PublicKey) (*RSAPublicKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil rsa.PublicKey required`)
	}

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.RSA)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}
	return &RSAPublicKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func newRSAPrivateKey(key *rsa.PrivateKey) (*RSAPrivateKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil rsa.PrivateKey required`)
	}

	if len(key.Primes) < 2 {
		return nil, errors.New("two primes required for RSA private key")
	}

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.RSA)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}
	return &RSAPrivateKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func (k RSAPrivateKey) PublicKey() (*RSAPublicKey, error) {
	return newRSAPublicKey(&k.key.PublicKey)
}

func (k *RSAPublicKey) Materialize() (interface{}, error) {
	if k.key == nil {
		return nil, errors.New(`key has no rsa.PublicKey associated with it`)
	}
	return k.key, nil
}

func (k *RSAPrivateKey) Materialize() (interface{}, error) {
	if k.key == nil {
		return nil, errors.New(`key has no rsa.PrivateKey associated with it`)
	}
	return k.key, nil
}

func (k *RSAPublicKey) GenerateKey(keyJSON *RawKeyJSON) error {

	if keyJSON.N == nil || keyJSON.E == nil {
		return errors.Errorf("Missing mandatory key parameters")
	}
	rsaPublicKey := &rsa.PublicKey{
		N: (&big.Int{}).SetBytes(keyJSON.N.Bytes()),
		E: int((&big.Int{}).SetBytes(keyJSON.E.Bytes()).Int64()),
	}
	k.key = rsaPublicKey
	k.StandardHeaders = &keyJSON.StandardHeaders
	return nil
}

func (k *RSAPrivateKey) GenerateKey(keyJSON *RawKeyJSON) error {

	rsaPublicKey := &RSAPublicKey{}
	err := rsaPublicKey.GenerateKey(keyJSON)
	if err != nil {
		return errors.Wrap(err, "failed to generate public key")
	}

	if keyJSON.D == nil || keyJSON.P == nil || keyJSON.Q == nil {
		return errors.Errorf("Missing mandatory key parameters")
	}
	privateKey := &rsa.PrivateKey{
		PublicKey: *rsaPublicKey.key,
		D:         (&big.Int{}).SetBytes(keyJSON.D.Bytes()),
		Primes: []*big.Int{
			(&big.Int{}).SetBytes(keyJSON.P.Bytes()),
			(&big.Int{}).SetBytes(keyJSON.Q.Bytes()),
		},
	}

	if keyJSON.Dp.Len() > 0 {
		privateKey.Precomputed.Dp = (&big.Int{}).SetBytes(keyJSON.Dp.Bytes())
	}
	if keyJSON.Dq.Len() > 0 {
		privateKey.Precomputed.Dq = (&big.Int{}).SetBytes(keyJSON.Dq.Bytes())
	}
	if keyJSON.Qi.Len() > 0 {
		privateKey.Precomputed.Qinv = (&big.Int{}).SetBytes(keyJSON.Qi.Bytes())
	}

	k.key = privateKey
	k.StandardHeaders = &keyJSON.StandardHeaders
	return nil
}
