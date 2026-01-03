package pasuki2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"mini-pasuki2/form"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// Re-usable test data
var (
	testOrigin       = "https://localhost:8443"
	testRelyingParty = "localhost"
	rpIdHash         = sha256.Sum256([]byte(testRelyingParty))
)

func TestRegisterStart(t *testing.T) {
	req := &form.RegisterStartRequest{
		Email: "test@example.com",
		Name:  "Test User",
	}
	challenge := "test-challenge"

	opts := RegisterStart(req, testRelyingParty, challenge)

	if opts.Challenge != challenge {
		t.Errorf("expected challenge %s, got %s", challenge, opts.Challenge)
	}
	if opts.Rp.Name != testRelyingParty {
		t.Errorf("expected rp name %s, got %s", testRelyingParty, opts.Rp.Name)
	}
	if opts.User.Name != req.Email {
		t.Errorf("expected user name %s, got %s", req.Email, opts.User.Name)
	}
	if opts.User.DisplayName != req.Name {
		t.Errorf("expected user display name %s, got %s", req.Name, opts.User.DisplayName)
	}
	if len(opts.PublicKeyCredentialParams) != 2 {
		t.Errorf("expected 2 pub key cred params, got %d", len(opts.PublicKeyCredentialParams))
	}
}

func TestRegisterFinish(t *testing.T) {
	challenge, _ := GenerateChallenge()
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge)

	// 1. Build valid attestation object
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x := privKey.X.Bytes()
	y := privKey.Y.Bytes()
	coseKey := CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_EC2),
		COSE_KEY_ALG:  int64(SIGNATURE_ALGORITHM_ES256),
		COSE_EC2_CRV:  uint64(COSE_EC2_CRV_P256),
		COSE_EC2_X:    x,
		COSE_EC2_Y:    y,
	}
	rawCoseKey, _ := cbor.Marshal(coseKey)
	credId, _ := GenerateChallenge() // use challenge generator for random bytes
	
	attested := &attestedCredentialData{
		aaguid:       testAaguid,
		credentialId: credId,
		coseKey:      rawCoseKey,
	}
	authData := buildAuthData(rpIdHash[:], FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attested, nil)
	attObj := AttestationObject{
		AuthData: authData,
		Fmt:      ATTESTATION_NONE,
		AttStmt:  map[string]any{},
	}
	rawAttObj, _ := cbor.Marshal(attObj)

	// 2. Build valid client data
	clientData := ParsedClientData{
		Type:      CLIENT_DATA_TYPE_CREATE,
		Challenge: encodedChallenge,
		Origin:    testOrigin,
	}
	rawClientData, _ := json.Marshal(clientData)

	// 3. Create request form
	req := &form.RegisterFinishRequest{
		Id:                base64.RawURLEncoding.EncodeToString(credId),
		AttestationObject: base64.RawURLEncoding.EncodeToString(rawAttObj),
		ClientDataJson:    base64.RawURLEncoding.EncodeToString(rawClientData),
	}

	t.Run("success", func(t *testing.T) {
		res := RegisterFinish(req, rpIdHash[:], testOrigin, encodedChallenge)
		if res.Error != nil {
			t.Fatalf("expected no error, but got %v", res.Error)
		}
		if res.AttestationObject == nil {
			t.Fatal("attestation object is nil")
		}
		if res.ClientData == nil {
			t.Fatal("client data is nil")
		}
	})

	t.Run("fail on bad client data", func(t *testing.T) {
		badReq := *req
		badReq.ClientDataJson = "invalid"
		res := RegisterFinish(&badReq, rpIdHash[:], testOrigin, encodedChallenge)
		if res.Error == nil {
			t.Fatal("expected error for bad client data, but got nil")
		}
	})

	t.Run("fail on bad attestation object", func(t *testing.T) {
		badReq := *req
		badReq.AttestationObject = "invalid"
		res := RegisterFinish(&badReq, rpIdHash[:], testOrigin, encodedChallenge)
		if res.Error == nil {
			t.Fatal("expected error for bad attestation object, but got nil")
		}
	})

	t.Run("fail on bad credential id", func(t *testing.T) {
		badReq := *req
		badReq.Id = "invalid"
		res := RegisterFinish(&badReq, rpIdHash[:], testOrigin, encodedChallenge)
		if res.Error == nil {
			t.Fatal("expected error for bad credential id, but got nil")
		}
	})
}

func TestVerifyStart(t *testing.T) {
	challenge := "test-challenge"
	opts := VerifyStart(nil, challenge)

	if opts.Challenge != challenge {
		t.Errorf("expected challenge %s, got %s", challenge, opts.Challenge)
	}
	if opts.Timeout != DEFAULT_TIME_OUT_MIL {
		t.Errorf("expected timeout %d, got %d", DEFAULT_TIME_OUT_MIL, opts.Timeout)
	}
	if opts.UserVerification != AUTHENTICATOR_REQUIRED {
		t.Errorf("expected user verification %s, got %s", AUTHENTICATOR_REQUIRED, opts.UserVerification)
	}
}

func TestVerifySignature(t *testing.T) {
	// ECDSA
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	coseKey := CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_EC2),
		COSE_EC2_CRV:  uint64(COSE_EC2_CRV_P256),
		COSE_EC2_X:    privKey.X.Bytes(),
		COSE_EC2_Y:    privKey.Y.Bytes(),
	}
	rawCoseKey, _ := cbor.Marshal(coseKey)
	hash := sha256.Sum256([]byte("test data"))
	sig, _ := ecdsa.SignASN1(rand.Reader, privKey, hash[:])

	// RSA
	rsaPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCoseKey := CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_RSA),
		COSE_RSA_N:    rsaPrivKey.N.Bytes(),
		COSE_RSA_E:    big.NewInt(int64(rsaPrivKey.E)).Bytes(),
	}
	rawRsaCoseKey, _ := cbor.Marshal(rsaCoseKey)
	rsaSig, _ := rsa.SignPKCS1v15(rand.Reader, rsaPrivKey, crypto.SHA256, hash[:])

	t.Run("success ecdsa", func(t *testing.T) {
		ok, err := verifySignature(rawCoseKey, hash[:], sig)
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
		if !ok {
			t.Fatal("expected signature to be valid")
		}
	})

	t.Run("success rsa", func(t *testing.T) {
		ok, err := verifySignature(rawRsaCoseKey, hash[:], rsaSig)
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
		if !ok {
			t.Fatal("expected signature to be valid")
		}
	})

	t.Run("fail ecdsa invalid signature", func(t *testing.T) {
		badSig := []byte("bad signature")
		ok, err := verifySignature(rawCoseKey, hash[:], badSig)
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
		if ok {
			t.Fatal("expected signature to be invalid")
		}
	})

	t.Run("fail rsa invalid signature", func(t *testing.T) {
		badSig := []byte("bad signature")
		ok, err := verifySignature(rawRsaCoseKey, hash[:], badSig)
		// rsa.VerifyPKCS1v15 returns an error on malformed signature
		if err == nil && ok {
			t.Fatal("expected signature to be invalid")
		}
	})
}

func TestVerifyFinish(t *testing.T) {
	// 1. Setup keys and signature
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	coseKey := CoseKey{
		COSE_KEY_TYPE: uint64(COSE_KEYTYPE_EC2),
		COSE_KEY_ALG:  int64(SIGNATURE_ALGORITHM_ES256),
		COSE_EC2_CRV:  uint64(COSE_EC2_CRV_P256),
		COSE_EC2_X:    privKey.X.Bytes(),
		COSE_EC2_Y:    privKey.Y.Bytes(),
	}
	rawCoseKey, _ := cbor.Marshal(coseKey)
	challenge, _ := GenerateChallenge()
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge)

	// 2. Build auth data and client data
	authData := buildAuthData(rpIdHash[:], FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 5, nil, nil)
	clientData := ParsedClientData{Type: CLIENT_DATA_TYPE_GET, Challenge: encodedChallenge, Origin: testOrigin}
	rawClientData, _ := json.Marshal(clientData)

	// 3. Create signature
	hashSrc, _ := makeHash(authData, rawClientData)
	sig, _ := ecdsa.SignASN1(rand.Reader, privKey, hashSrc)

	// 4. Build request form and params
	req := &form.VerifyFinishRequest{
		ClientDataJson:    base64.RawURLEncoding.EncodeToString(rawClientData),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(authData),
		Signature:         base64.RawURLEncoding.EncodeToString(sig),
	}
	params := &VerifyFinishParams{
		PublicKey:          rawCoseKey,
		RelyingPartyIdHash: rpIdHash[:],
		Origin:             testOrigin,
		Challenge:          encodedChallenge,
		CurrentCount:       4, // lower than sign count in authData
	}

	t.Run("success", func(t *testing.T) {
		res := VerifyFinish(req, params)
		if res.SystemErr != nil {
			t.Fatalf("expected no system error, but got %v", res.SystemErr)
		}
		if res.ValidationErr != nil {
			t.Fatalf("expected no validation error, but got %v", res.ValidationErr)
		}
		if res.AuthData == nil {
			t.Fatal("auth data is nil")
		}
		if res.ClientData == nil {
			t.Fatal("client data is nil")
		}
	})

	t.Run("fail validation bad signature", func(t *testing.T) {
		badReq := *req
		badReq.Signature = base64.RawURLEncoding.EncodeToString([]byte("bad"))
		res := VerifyFinish(&badReq, params)
		if res.ValidationErr == nil {
			t.Fatal("expected validation error for bad signature, but got nil")
		}
	})

	t.Run("fail validation bad authenticator data", func(t *testing.T) {
		badReq := *req
		badReq.AuthenticatorData = base64.RawURLEncoding.EncodeToString([]byte("bad"))
		res := VerifyFinish(&badReq, params)
		if res.ValidationErr == nil {
			t.Fatal("expected validation error for bad auth data, but got nil")
		}
	})

	t.Run("fail validation bad client data", func(t *testing.T) {
		badReq := *req
		badReq.ClientDataJson = base64.RawURLEncoding.EncodeToString([]byte("bad"))
		res := VerifyFinish(&badReq, params)
		if res.ValidationErr == nil {
			t.Fatal("expected validation error for bad client data, but got nil")
		}
	})
}
