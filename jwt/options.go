package jwt

import (
	"github.com/repenno/jwx-opa/internal/option"
	"github.com/repenno/jwx-opa/jwa"
)

type Option = option.Interface

const (
	optkeyVerify = `verify`
)

type VerifyParameters interface {
	Algorithm() jwa.SignatureAlgorithm
	Key() interface{}
}

type verifyParams struct {
	alg jwa.SignatureAlgorithm
	key interface{}
}

func (p *verifyParams) Algorithm() jwa.SignatureAlgorithm {
	return p.alg
}

func (p *verifyParams) Key() interface{} {
	return p.key
}

func WithVerify(alg jwa.SignatureAlgorithm, key interface{}) Option {
	return option.New(optkeyVerify, &verifyParams{
		alg: alg,
		key: key,
	})
}
