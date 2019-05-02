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

// LookupSignature looks up a particular Signature entry using
// the `kid` value
func (m Message) LookupSignature(kid string) []*Signature {
	var sigs []*Signature
	for _, sig := range m.Signatures {
		if hdr := sig.PublicHeaders(); hdr != nil {
			hdrKeyId, ok := hdr.Get(KeyIDKey)
			if ok && hdrKeyId == kid {
				sigs = append(sigs, sig)
				continue
			}
		}

		if hdr := sig.ProtectedHeaders(); hdr != nil {
			hdrKeyId, ok := hdr.Get(KeyIDKey)
			if ok && hdrKeyId == kid {
				sigs = append(sigs, sig)
				continue
			}
		}
	}
	return sigs
}
