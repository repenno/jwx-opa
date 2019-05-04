package jws

func (s Signature) PublicHeaders() Headers {
	return s.Headers
}

func (s Signature) ProtectedHeaders() Headers {
	return s.Protected
}

func (s Signature) GetSignature() []byte {
	return s.Signature
}

func (m Message) GetPayload() []byte {
	return m.Payload
}

func (m Message) GetSignatures() []*Signature {
	return m.Signatures
}
