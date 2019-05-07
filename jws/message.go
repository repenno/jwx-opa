package jws

// PublicHeaders returns the public headers in a JWS
func (s Signature) PublicHeaders() Headers {
	return s.Headers
}

// PublicHeaders returns the protected headers in a JWS
func (s Signature) ProtectedHeaders() Headers {
	return s.Protected
}

// PublicHeaders returns the signature in a JWS
func (s Signature) GetSignature() []byte {
	return s.Signature
}

// PublicHeaders returns the payload in a JWS
func (m Message) GetPayload() []byte {
	return m.Payload
}

// PublicHeaders returns the all signatures in a JWS
func (m Message) GetSignatures() []*Signature {
	return m.Signatures
}
