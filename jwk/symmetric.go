package jwk

import (
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/internal/base64"
	"github.com/repenno/jwx-opa/jwa"
)

func newSymmetricKey(key []byte) (*SymmetricKey, error) {
	if len(key) == 0 {
		return nil, errors.New(`non-empty []byte key required`)
	}
	var hdr StandardHeaders

	err := hdr.Set(KeyTypeKey, jwa.OctetSeq)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}
	// everything starts with 'none' signature
	err = hdr.Set(AlgorithmKey, jwa.NoSignature)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set alg")
	}
	return &SymmetricKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

// Materialize returns the octets for this symmetric key.
// Since this is a symmetric key, this just calls Octets
func (s SymmetricKey) Materialize() (interface{}, error) {
	return s.Octets(), nil
}

// Octets returns the octets in the key
func (s SymmetricKey) Octets() []byte {
	return s.key
}

func (s *SymmetricKey) ExtractMap(m map[string]interface{}) (err error) {

	const kKey = `k`

	kbuf, err := getRequiredKey(m, kKey)
	if err != nil {
		return errors.Wrapf(err, `failed to get required key '%s'`, kKey)
	}
	delete(m, kKey)

	var hdrs StandardHeaders
	if err := hdrs.ExtractMap(m); err != nil {
		return errors.Wrap(err, `failed to extract header values`)
	}

	*s = SymmetricKey{
		StandardHeaders: &hdrs,
		key:             kbuf,
	}
	return nil
}

func (s SymmetricKey) MarshalJSON() (buf []byte, err error) {

	m := make(map[string]interface{})
	if err := s.PopulateMap(m); err != nil {
		return nil, errors.Wrap(err, `failed to populate symmetric key values`)
	}

	return json.Marshal(m)
}

func (s SymmetricKey) PopulateMap(m map[string]interface{}) (err error) {

	if err := s.StandardHeaders.PopulateMap(m); err != nil {
		return errors.Wrap(err, `failed to populate header values`)
	}

	const kKey = `k`
	m[kKey] = base64.EncodeToString(s.key)
	return nil
}

func (s *SymmetricKey) GenerateKey(keyJSON *RawKeyJSON) error {

	*s = SymmetricKey{
		StandardHeaders: &keyJSON.StandardHeaders,
		key:             keyJSON.K,
	}
	return nil
}
