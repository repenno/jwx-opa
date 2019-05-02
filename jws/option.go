package jws

import (
	"github.com/repenno/jwx-opa/internal/option"
	"github.com/repenno/jwx-opa/jws/sign"
)

type Option = option.Interface

const (
	optkeyPayloadSigner = `Payload-signer`
	optkeyHeaders       = `Headers`
)

func WithSigner(signer sign.Signer, key interface{}, public, protected Headers) Option {
	return option.New(optkeyPayloadSigner, &payloadSigner{
		signer:    signer,
		key:       key,
		protected: protected,
		public:    public,
	})
}

func WithHeaders(h Headers) Option {
	return option.New(optkeyHeaders, h)
}
