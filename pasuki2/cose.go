package pasuki2

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const (
	COSE_KEY_ALG = 3

	COSE_EC2_CRV      = -1
	COSE_EC2_X        = -2
	COSE_EC2_Y        = -3
	COSE_EC2_CRV_P256 = 1
)

var ErrInvalidCose = errors.New("invalid cose")

type Cose map[int]any

func CoseFromBytes(raw []byte) (Cose, error) {
	var c Cose
	if err := cbor.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	return c, nil
}

func ParseCose(raw []byte) (Cose, error) {
	var c Cose
	if err := cbor.Unmarshal(raw, &c); err != nil {
		return nil, err
	}

	alg, ok := c[COSE_KEY_ALG]
	if !ok {
		return nil, ErrInvalidCose
	}

	switch alg {
	case int64(SIGNATURE_ALGORITHM_ES256):
		crv, ok := c[COSE_EC2_CRV]
		if !ok {
			return nil, ErrInvalidCose
		}
		_, ok = c[COSE_EC2_X]
		if !ok {
			return nil, ErrInvalidCose
		}
		_, ok = c[COSE_EC2_Y]
		if !ok {
			return nil, ErrInvalidCose
		}

		switch crv {
		case uint64(COSE_EC2_CRV_P256):
		default:
			return nil, errors.New("ec2 curve not supported")
		}
	case int64(SIGNATURE_ALGORITHM_RS256):
		// rs256 should be implemented as it is one of default algorithms
		return nil, errors.New("rs256 is not implemented yet")
	default:
		return nil, errors.New("cose algorith not supported")
	}

	return c, nil
}

func (c Cose) IsEs256() bool {
	return c[COSE_KEY_ALG] == int64(SIGNATURE_ALGORITHM_ES256)
}
