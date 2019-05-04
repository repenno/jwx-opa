package jws

import (
	"github.com/repenno/jwx-opa/internal/option"
)

type Option = option.Interface

const (
	optkeyHeaders = `Headers`
)

func WithHeaders(h Headers) Option {
	return option.New(optkeyHeaders, h)
}
