// Package jwt implements JSON Web Tokens as described in https://tools.ietf.org/html/rfc7519
package jwt

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/jwa"
	"github.com/repenno/jwx-opa/jws"
)

// ParseString calls Parse with the given string
func ParseString(s string, options ...Option) (*Token, error) {
	return Parse(s, options...)
}

// ParseBytes calls Parse with the given byte sequence
func ParseBytes(s []byte, options ...Option) (*Token, error) {
	return Parse(string(s[:]), options...)
}

// Parse parses the JWT token payload and creates a new `jwt.Token` object.
// The token must be encoded in either JSON format or compact format.
//
// If the token is signed and you want to verify the payload, you must
// pass the jwt.WithVerify(alg, key) option. If you do not specify these
// parameters, no verification will be performed.
func Parse(src string, options ...Option) (*Token, error) {
	var params VerifyParameters
	for _, o := range options {
		switch o.Name() {
		case optkeyVerify:
			params = o.Value().(VerifyParameters)
		}
	}

	if params != nil {
		return ParseVerify(src, params.Algorithm(), params.Key())
	}

	m, err := jws.ParseString(src)
	if err != nil {
		return nil, errors.Wrap(err, `invalid jws message`)
	}

	token := New()
	if err := json.Unmarshal(m.GetPayload(), token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}
	return token, nil
}

// ParseVerify is a function that is similar to Parse(), but does not
// allow for parsing without signature verification parameters.
func ParseVerify(src string, alg jwa.SignatureAlgorithm, key interface{}) (*Token, error) {

	v, err := jws.Verify([]byte(src), alg, key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to verify jws signature`)
	}

	var token Token
	if err := json.Unmarshal(v, &token); err != nil {
		return nil, errors.Wrap(err, `failed to parse token`)
	}
	return &token, nil
}

// New creates a new empty JWT token
func New() *Token {
	return &Token{}
}

// Sign is a convenience function to create a signed JWT token serialized in
// compact form. `key` must match the key type required by the given
// signature method `method`
func (t *Token) Sign(method jwa.SignatureAlgorithm, key interface{}) ([]byte, error) {
	buf, err := json.Marshal(t)
	if err != nil {
		return nil, errors.Wrap(err, `failed to marshal token`)
	}

	var hdr jws.StandardHeaders
	if hdr.Set(`alg`, method.String()) != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	if hdr.Set(`typ`, `JWT`) != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}
	sign, err := jws.SignWithOption(buf, method, key, jws.WithHeaders(&hdr))
	if err != nil {
		return nil, errors.Wrap(err, `failed to sign payload`)
	}

	return sign, nil
}
