package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"math/big"

	"github.com/pkg/errors"
	"github.com/repenno/jwx-opa/internal/base64"
	"github.com/repenno/jwx-opa/jwa"
)

func newECDSAPublicKey(key *ecdsa.PublicKey) (*ECDSAPublicKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil ecdsa.PublicKey required`)
	}

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}
	// everything starts with 'none' signature
	/*	err = hdr.Set(AlgorithmKey, jwa.NoSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to set alg")
		}*/
	return &ECDSAPublicKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func newECDSAPrivateKey(key *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {
	if key == nil {
		return nil, errors.New(`non-nil ecdsa.PrivateKey required`)
	}

	var hdr StandardHeaders
	err := hdr.Set(KeyTypeKey, jwa.EC)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to set Key Type")
	}
	// TODO
	/*	err = hdr.Set(AlgorithmKey, jwa.NoSignature)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to set alg")
		}*/
	return &ECDSAPrivateKey{
		StandardHeaders: &hdr,
		key:             key,
	}, nil
}

func (k ECDSAPrivateKey) PublicKey() (*ECDSAPublicKey, error) {
	return newECDSAPublicKey(&k.key.PublicKey)
}

// Materialize returns the EC-DSA public key represented by this JWK
func (k ECDSAPublicKey) Materialize() (interface{}, error) {
	return k.key, nil
}

func (k ECDSAPublicKey) Curve() jwa.EllipticCurveAlgorithm {
	return jwa.EllipticCurveAlgorithm(k.key.Curve.Params().Name)
}

func (k ECDSAPrivateKey) Curve() jwa.EllipticCurveAlgorithm {
	return jwa.EllipticCurveAlgorithm(k.key.PublicKey.Curve.Params().Name)
}

// Materialize returns the EC-DSA private key represented by this JWK
func (k ECDSAPrivateKey) Materialize() (interface{}, error) {
	return k.key, nil
}

func (k ECDSAPublicKey) MarshalJSON() (buf []byte, err error) {

	m := make(map[string]interface{})
	if err := k.PopulateMap(m); err != nil {
		return nil, errors.Wrap(err, `failed to populate public key values`)
	}

	return json.Marshal(m)
}

func (k ECDSAPublicKey) PopulateMap(m map[string]interface{}) (err error) {

	if err := k.StandardHeaders.PopulateMap(m); err != nil {
		return errors.Wrap(err, `failed to populate header values`)
	}

	const (
		xKey   = `x`
		yKey   = `y`
		crvKey = `crv`
	)
	m[xKey] = base64.EncodeToString(k.key.X.Bytes())
	m[yKey] = base64.EncodeToString(k.key.Y.Bytes())
	m[crvKey] = k.key.Curve.Params().Name
	return nil
}

func (k ECDSAPrivateKey) MarshalJSON() (buf []byte, err error) {

	m := make(map[string]interface{})
	if err := k.PopulateMap(m); err != nil {
		return nil, errors.Wrap(err, `failed to populate public key values`)
	}

	return json.Marshal(m)
}

func (k ECDSAPrivateKey) PopulateMap(m map[string]interface{}) (err error) {

	if err := k.StandardHeaders.PopulateMap(m); err != nil {
		return errors.Wrap(err, `failed to populate header values`)
	}

	pubKey, err := newECDSAPublicKey(&k.key.PublicKey)
	if err != nil {
		return errors.Wrap(err, `failed to construct public key from private key`)
	}

	if err := pubKey.PopulateMap(m); err != nil {
		return errors.Wrap(err, `failed to populate public key values`)
	}

	m[`d`] = base64.EncodeToString(k.key.D.Bytes())

	return nil
}

func (k *ECDSAPublicKey) UnmarshalJSON(data []byte) (err error) {

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	if err := k.ExtractMap(m); err != nil {
		return errors.Wrap(err, `failed to extract data from map`)
	}
	return nil
}

func (k *ECDSAPublicKey) ExtractMap(m map[string]interface{}) (err error) {

	const (
		xKey   = `x`
		yKey   = `y`
		crvKey = `crv`
	)

	crvname, ok := m[crvKey]
	if !ok {
		return errors.Errorf(`failed to get required key crv`)
	}
	delete(m, crvKey)

	var crv jwa.EllipticCurveAlgorithm
	if err := crv.Accept(crvname); err != nil {
		return errors.Wrap(err, `failed to accept value for crv key`)
	}

	var curve elliptic.Curve
	switch crv {
	case jwa.P256:
		curve = elliptic.P256()
	case jwa.P384:
		curve = elliptic.P384()
	case jwa.P521:
		curve = elliptic.P521()
	default:
		return errors.Errorf(`invalid curve name %s`, crv)
	}

	xbuf, err := getRequiredKey(m, xKey)
	if err != nil {
		return errors.Wrapf(err, `failed to get required key %s`, xKey)
	}
	delete(m, xKey)

	ybuf, err := getRequiredKey(m, yKey)
	if err != nil {
		return errors.Wrapf(err, `failed to get required key %s`, yKey)
	}
	delete(m, yKey)

	var x, y big.Int
	x.SetBytes(xbuf)
	y.SetBytes(ybuf)

	var hdrs StandardHeaders
	if err := hdrs.ExtractMap(m); err != nil {
		return errors.Wrap(err, `failed to extract header values`)
	}

	*k = ECDSAPublicKey{
		StandardHeaders: &hdrs,
		key: &ecdsa.PublicKey{
			Curve: curve,
			X:     &x,
			Y:     &y,
		},
	}
	return nil
}

func (k *ECDSAPrivateKey) UnmarshalJSON(data []byte) (err error) {

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return errors.Wrap(err, `failed to unmarshal public key`)
	}

	if err := k.ExtractMap(m); err != nil {
		return errors.Wrap(err, `failed to extract data from map`)
	}
	return nil
}

func (k *ECDSAPrivateKey) ExtractMap(m map[string]interface{}) (err error) {

	const (
		dKey = `d`
	)

	dbuf, err := getRequiredKey(m, dKey)
	if err != nil {
		return errors.Wrapf(err, `failed to get required key %s`, dKey)
	}
	delete(m, dKey)

	var pubkey ECDSAPublicKey
	if err := pubkey.ExtractMap(m); err != nil {
		return errors.Wrap(err, `failed to extract public key values`)
	}

	var d big.Int
	d.SetBytes(dbuf)

	*k = ECDSAPrivateKey{
		StandardHeaders: pubkey.StandardHeaders,
		key: &ecdsa.PrivateKey{
			PublicKey: *(pubkey.key),
			D:         &d,
		},
	}
	pubkey.StandardHeaders = nil
	return nil
}

func (k *ECDSAPublicKey) GenerateKey(keyJSON *RawKeyJSON) error {

	var x, y big.Int

	if keyJSON.X == nil || keyJSON.Y == nil || keyJSON.Crv == "" {
		return errors.Errorf("Missing parameters to generate key")
	}

	x.SetBytes(keyJSON.X.Bytes())
	y.SetBytes(keyJSON.Y.Bytes())

	var curve elliptic.Curve
	switch keyJSON.Crv {
	case jwa.P256:
		curve = elliptic.P256()
	case jwa.P384:
		curve = elliptic.P384()
	case jwa.P521:
		curve = elliptic.P521()
	default:
		return errors.Errorf(`invalid curve name %s`, keyJSON.Crv)
	}

	*k = ECDSAPublicKey{
		StandardHeaders: &keyJSON.StandardHeaders,
		key: &ecdsa.PublicKey{
			Curve: curve,
			X:     &x,
			Y:     &y,
		},
	}
	return nil
}

func (k *ECDSAPrivateKey) GenerateKey(keyJSON *RawKeyJSON) error {

	if keyJSON.D == nil {
		return errors.Errorf(`Missing key parameter`)
	}
	eCDSAPublicKey := &ECDSAPublicKey{}
	err := eCDSAPublicKey.GenerateKey(keyJSON)
	if err != nil {
		return errors.Wrap(err, `failed to generate public key`)
	}

	privateKey := &ecdsa.PrivateKey{
		PublicKey: *eCDSAPublicKey.key,
		D:         (&big.Int{}).SetBytes(keyJSON.D.Bytes()),
	}

	k.key = privateKey
	k.StandardHeaders = &keyJSON.StandardHeaders

	return nil
}
