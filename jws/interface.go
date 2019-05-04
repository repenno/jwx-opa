package jws

import (
	"github.com/repenno/jwx-opa/jwa"
)

type EncodedSignature struct {
	Protected string  `json:"protected,omitempty"`
	Headers   Headers `json:"header,omitempty"`
	Signature string  `json:"signature,omitempty"`
}

type EncodedSignatureUnmarshalProxy struct {
	Protected string           `json:"protected,omitempty"`
	Headers   *StandardHeaders `json:"header,omitempty"`
	Signature string           `json:"signature,omitempty"`
}

type EncodedMessage struct {
	Payload    string              `json:"payload"`
	Signatures []*EncodedSignature `json:"signatures,omitempty"`
}

type EncodedMessageUnmarshalProxy struct {
	Payload    string                            `json:"payload"`
	Signatures []*EncodedSignatureUnmarshalProxy `json:"signatures,omitempty"`
}

type FullEncodedMessage struct {
	*EncodedSignature // embedded to pick up flattened JSON message
	*EncodedMessage
}

type FullEncodedMessageUnmarshalProxy struct {
	*EncodedSignatureUnmarshalProxy // embedded to pick up flattened JSON message
	*EncodedMessageUnmarshalProxy
}

// PayloadSigner generates Signature for the given Payload
type PayloadSigner interface {
	Sign([]byte) ([]byte, error)
	Algorithm() jwa.SignatureAlgorithm
	ProtectedHeader() Headers
	PublicHeader() Headers
}

// Message represents a full JWS encoded message. Flattened serialization
// is not supported as a struct, but rather it's represented as a
// Message struct with only one `Signature` element.
//
// Do not expect to use the Message object to verify or construct a
// signed payloads with. You should only use this when you want to actually
// want to programmatically view the contents for the full JWS Payload.
//
// To sign and verify, use the appropriate `SignWithOption()` nad `Verify()` functions
type Message struct {
	Payload    []byte       `json:"payload"`
	Signatures []*Signature `json:"signatures,omitempty"`
}

type Signature struct {
	Headers   Headers `json:"header,omitempty"`    // Unprotected Headers
	Protected Headers `json:"Protected,omitempty"` // Protected Headers
	Signature []byte  `json:"signature,omitempty"` // GetSignature
}
