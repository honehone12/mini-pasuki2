package pasuki2

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Helper to create a valid ES256 CoseKey
func createEs256Key() CoseKey {
	return CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_EC2),
		COSE_KEY_ALG:  int64(SIGNATURE_ALGORITHM_ES256),
		COSE_EC2_CRV:  uint64(COSE_EC2_CRV_P256),
		COSE_EC2_X:    []byte("12345678901234567890123456789012"),
		COSE_EC2_Y:    []byte("12345678901234567890123456789012"),
	}
}

// Helper to create a valid RS256 CoseKey
func createRs256Key() CoseKey {
	return CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_RSA),
		COSE_KEY_ALG:  int64(SIGNATURE_ALGORITHM_RS256),
		COSE_RSA_N:    []byte("a long n value"),
		COSE_RSA_E:    []byte{1, 0, 1}, // 65537
	}
}

func TestParseCoseKeyUnchecked(t *testing.T) {
	key := createEs256Key()
	rawData, _ := cbor.Marshal(key)

	t.Run("successful parse", func(t *testing.T) {
		parsedKey, err := parseCoseKeyUnchecked(rawData)
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
		if parsedKey == nil {
			t.Fatal("parsed key is nil")
		}
	})

	t.Run("fail on invalid cbor", func(t *testing.T) {
		_, err := parseCoseKeyUnchecked([]byte("invalid cbor data"))
		if err == nil {
			t.Fatal("expected an error, but got nil")
		}
	})
}

func TestParseCoseKey(t *testing.T) {
	t.Run("successful parse ec2", func(t *testing.T) {
		key := createEs256Key()
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err != nil {
			t.Errorf("expected no error for ec2 key, but got %v", err)
		}
	})

	t.Run("successful parse rsa", func(t *testing.T) {
		key := createRs256Key()
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err != nil {
			t.Errorf("expected no error for rsa key, but got %v", err)
		}
	})

	t.Run("fail on missing key type", func(t *testing.T) {
		key := createEs256Key()
		delete(key, COSE_KEY_TYPE)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for missing key type, but got nil")
		}
	})

	t.Run("fail on missing algorithm", func(t *testing.T) {
		key := createEs256Key()
		delete(key, COSE_KEY_ALG)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for missing algorithm, but got nil")
		}
	})

	t.Run("fail on unsupported key type", func(t *testing.T) {
		key := createEs256Key()
		key[COSE_KEY_TYPE] = uint64(999) // unsupported
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for unsupported key type, but got nil")
		}
	})

	t.Run("fail on unsupported ec2 algorithm", func(t *testing.T) {
		key := createEs256Key()
		key[COSE_KEY_ALG] = int64(-999) // unsupported
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for unsupported ec2 algorithm, but got nil")
		}
	})

	t.Run("fail on unsupported rsa algorithm", func(t *testing.T) {
		key := createRs256Key()
		key[COSE_KEY_ALG] = int64(-999) // unsupported
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for unsupported rsa algorithm, but got nil")
		}
	})

	t.Run("fail on ec2 missing curve", func(t *testing.T) {
		key := createEs256Key()
		delete(key, COSE_EC2_CRV)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for ec2 missing curve, but got nil")
		}
	})

	t.Run("fail on ec2 unsupported curve", func(t *testing.T) {
		key := createEs256Key()
		key[COSE_EC2_CRV] = uint64(999) // unsupported
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for ec2 unsupported curve, but got nil")
		}
	})

	t.Run("fail on ec2 missing x", func(t *testing.T) {
		key := createEs256Key()
		delete(key, COSE_EC2_X)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for ec2 missing x, but got nil")
		}
	})

	t.Run("fail on ec2 missing y", func(t *testing.T) {
		key := createEs256Key()
		delete(key, COSE_EC2_Y)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for ec2 missing y, but got nil")
		}
	})

	t.Run("fail on rsa missing n", func(t *testing.T) {
		key := createRs256Key()
		delete(key, COSE_RSA_N)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for rsa missing n, but got nil")
		}
	})

	t.Run("fail on rsa missing e", func(t *testing.T) {
		key := createRs256Key()
		delete(key, COSE_RSA_E)
		rawData, _ := cbor.Marshal(key)
		_, err := parseCoseKey(rawData)
		if err == nil {
			t.Error("expected error for rsa missing e, but got nil")
		}
	})
}

func TestCoseKeyGetEcdsaPubKey(t *testing.T) {
	// A valid P256 public key
	p256 := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(p256, rand.Reader)
	key := CoseKey{
		COSE_EC2_CRV: uint64(COSE_EC2_CRV_P256),
		COSE_EC2_X:   x.Bytes(),
		COSE_EC2_Y:   y.Bytes(),
	}

	pubKey, err := key.getEcdsaPubKey()
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	if pubKey.Curve != p256 {
		t.Error("incorrect curve")
	}
	if pubKey.X.Cmp(x) != 0 {
		t.Error("incorrect x coordinate")
	}
	if pubKey.Y.Cmp(y) != 0 {
		t.Error("incorrect y coordinate")
	}

	// Test error cases
	errorCases := []struct {
		name    string
		key     CoseKey
		wantErr string
	}{
		{"missing curve", CoseKey{COSE_EC2_X: x.Bytes(), COSE_EC2_Y: y.Bytes()}, "could not find ec2 curve"},
		{"unsupported curve", CoseKey{COSE_EC2_CRV: 2, COSE_EC2_X: x.Bytes(), COSE_EC2_Y: y.Bytes()}, "ec2 curve not supported"},
		{"missing x", CoseKey{COSE_EC2_CRV: uint64(COSE_EC2_CRV_P256), COSE_EC2_Y: y.Bytes()}, "could not find p256 x"},
		{"missing y", CoseKey{COSE_EC2_CRV: uint64(COSE_EC2_CRV_P256), COSE_EC2_X: x.Bytes()}, "could not find p256 y"},
		{"invalid x type", CoseKey{COSE_EC2_CRV: uint64(COSE_EC2_CRV_P256), COSE_EC2_X: 123, COSE_EC2_Y: y.Bytes()}, "invalid p256 x"},
		{"invalid y type", CoseKey{COSE_EC2_CRV: uint64(COSE_EC2_CRV_P256), COSE_EC2_X: x.Bytes(), COSE_EC2_Y: 123}, "invalid p256 y"},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.key.getEcdsaPubKey()
			if err == nil {
				t.Errorf("expected error '%s', but got nil", tc.wantErr)
			} else if err.Error() != tc.wantErr {
				t.Errorf("expected error '%s', but got '%s'", tc.wantErr, err.Error())
			}
		})
	}
}

func TestCoseKeyGetRsaPubKey(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKey := privKey.PublicKey
	key := CoseKey{
		COSE_RSA_N: pubKey.N.Bytes(),
		COSE_RSA_E: big.NewInt(int64(pubKey.E)).Bytes(),
	}

	parsedPubKey, err := key.getRsaPubKey()
	if err != nil {
		t.Fatalf("expected no error, but got %v", err)
	}

	if parsedPubKey.N.Cmp(pubKey.N) != 0 {
		t.Error("incorrect n value")
	}
	if parsedPubKey.E != pubKey.E {
		t.Error("incorrect e value")
	}

	// Test error cases
	errorCases := []struct {
		name    string
		key     CoseKey
		wantErr string
	}{
		{"missing n", CoseKey{COSE_RSA_E: big.NewInt(int64(pubKey.E)).Bytes()}, "could not find rsa n"},
		{"missing e", CoseKey{COSE_RSA_N: pubKey.N.Bytes()}, "could not find rsa e"},
		{"invalid n type", CoseKey{COSE_RSA_N: 123, COSE_RSA_E: big.NewInt(int64(pubKey.E)).Bytes()}, "invalid rsa n"},
		{"invalid e type", CoseKey{COSE_RSA_N: pubKey.N.Bytes(), COSE_RSA_E: 123}, "invalid rsa e"},
	}

	for _, tc := range errorCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.key.getRsaPubKey()
			if err == nil {
				t.Errorf("expected error containing '%s', but got nil", tc.wantErr)
			}
		})
	}
}
