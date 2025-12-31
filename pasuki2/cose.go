package pasuki2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

const (
	COSE_KEY_TYPE = 1
	COSE_KEY_ALG  = 3

	COSE_KEYTYPE_EC2 = 2
	COSE_KEYTYPE_RSA = 3

	COSE_EC2_CRV      = -1
	COSE_EC2_X        = -2
	COSE_EC2_Y        = -3
	COSE_EC2_CRV_P256 = 1

	COSE_RSA_N = -1
	COSE_RSA_E = -2
)

var ErrInvalidCose = errors.New("invalid cose")

type CoseKey map[int]any

func parseCoseKeyUnchecked(raw []byte) (CoseKey, error) {
	var c CoseKey
	if err := cbor.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	return c, nil
}

func parseCoseKey(raw []byte) (CoseKey, error) {
	c, err := parseCoseKeyUnchecked(raw)
	if err != nil {
		return nil, err
	}

	kty, ok := c[COSE_KEY_TYPE]
	if !ok {
		return nil, ErrInvalidCose
	}

	alg, ok := c[COSE_KEY_ALG]
	if !ok {
		return nil, ErrInvalidCose
	}

	switch kty {
	case uint64(COSE_KEYTYPE_EC2):
		{
			if alg != int64(SIGNATURE_ALGORITHM_ES256) {
				return nil, errors.New("cose algorith not supported")
			}
			crv, ok := c[COSE_EC2_CRV]
			if !ok {
				return nil, ErrInvalidCose
			}
			if crv != uint64(COSE_EC2_CRV_P256) {
				return nil, errors.New("ec2 curve not supported")
			}

			_, ok = c[COSE_EC2_X]
			if !ok {
				return nil, ErrInvalidCose
			}
			_, ok = c[COSE_EC2_Y]
			if !ok {
				return nil, ErrInvalidCose
			}
		}
	case uint64(COSE_KEYTYPE_RSA):
		{
			if alg != int64(SIGNATURE_ALGORITHM_RS256) {
				return nil, errors.New("cose algorith not supported")
			}

			_, ok := c[COSE_RSA_N]
			if !ok {
				return nil, ErrInvalidCose
			}
			_, ok = c[COSE_RSA_E]
			if !ok {
				return nil, ErrInvalidCose
			}
		}
	default:
		return nil, errors.New("key type not supported")
	}

	return c, nil
}

func (k CoseKey) getEcdsaPubKey() (*ecdsa.PublicKey, error) {
	var crv elliptic.Curve
	{
		rawCrv, ok := k[COSE_EC2_CRV]
		if !ok {
			return nil, ErrInvalidCose
		}
		if rawCrv != uint64(COSE_EC2_CRV_P256) {
			return nil, errors.New("ec2 curve not supported")
		}

		crv = elliptic.P256()
	}
	var x []byte
	{
		rawX, ok := k[COSE_EC2_X]
		if !ok {
			return nil, ErrInvalidCose
		}
		x, ok = rawX.([]byte)
		if !ok {
			return nil, ErrInvalidCose
		}
	}
	var y []byte
	{
		rawY, ok := k[COSE_EC2_Y]
		if !ok {
			return nil, ErrInvalidCose
		}
		y, ok = rawY.([]byte)
		if !ok {
			return nil, ErrInvalidCose
		}
	}

	return &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func (k CoseKey) getRsaPubKeyUnchecked() (*rsa.PublicKey, error) {
	var n []byte
	{
		rawN, ok := k[COSE_RSA_N]
		if !ok {
			return nil, ErrInvalidCose
		}
		n, ok = rawN.([]byte)
		if !ok {
			return nil, ErrInvalidCose
		}
	}
	var e int
	{
		rawE, ok := k[COSE_RSA_E]
		if !ok {
			return nil, ErrInvalidCose
		}
		e, ok = rawE.(int)
		if !ok {
			return nil, ErrInvalidCose
		}
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: e,
	}, nil
}
