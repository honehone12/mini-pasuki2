package pasuki2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var (
	testRpIdHash     = sha256.Sum256([]byte("example.com"))
	testAaguid       = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	testCredentialId = []byte("test-credential-id")
	testCoseKey, _   = cbor.Marshal(createEs256Key())
)

func buildAuthData(
	rpIdHash []byte,
	flags byte,
	signCount uint32,
	attestedData *attestedCredentialData,
	extensions map[string]any,
) []byte {
	var buf bytes.Buffer
	buf.Write(rpIdHash)
	buf.WriteByte(flags)
	scBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(scBytes, signCount)
	buf.Write(scBytes)

	if attestedData != nil {
		buf.Write(attestedData.aaguid)
		idLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(idLenBytes, uint16(len(attestedData.credentialId)))
		buf.Write(idLenBytes)
		buf.Write(attestedData.credentialId)
		buf.Write(attestedData.coseKey)
	}

	if extensions != nil {
		extBytes, _ := cbor.Marshal(extensions)
		buf.Write(extBytes)
	}

	return buf.Bytes()
}

type attestedCredentialData struct {
	aaguid         []byte
	credentialId   []byte
	coseKey        []byte
}

func TestVerifyAuthenticatorData(t *testing.T) {
	rpIdHash := testRpIdHash[:]

	t.Run("success fromGet=true", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 1, nil, nil)
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
	})

	t.Run("success fromGet=false with attested data", func(t *testing.T) {
		attested := &attestedCredentialData{
			aaguid:       testAaguid,
			credentialId: testCredentialId,
			coseKey:      testCoseKey,
		}
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attested, nil)
		_, p, err := verifyAuthenticatorData(authData, rpIdHash, false, 0)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
		// check if the offset p is correct
		expectedOffset := RP_ID_HASH_LEN + 1 + SIGN_COUNT_LEN
		if p != expectedOffset {
			t.Errorf("expected offset %d, but got %d", expectedOffset, p)
		}
	})

	t.Run("success with extensions", func(t *testing.T) {
		extensions := map[string]any{"hmac-secret": true}
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_EXTENSION_DATA, 1, nil, extensions)
		parsed, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
		if !parsed.ExtBit {
			t.Error("expected ExtBit to be true")
		}
		if parsed.Extensions == nil {
			t.Error("expected extensions to be parsed")
		}
	})

	t.Run("fail data too short", func(t *testing.T) {
		authData := make([]byte, __AUTHDATA_MIN_LEN-1)
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err == nil {
			t.Error("expected error for short data, but got nil")
		}
	})

	t.Run("fail unexpected rp id hash", func(t *testing.T) {
		wrongHash := sha256.Sum256([]byte("wrong.com"))
		authData := buildAuthData(wrongHash[:], FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 1, nil, nil)
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err == nil {
			t.Error("expected error for wrong rp id hash, but got nil")
		}
	})

	t.Run("fail missing user presence flag", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_VERIFICATION, 1, nil, nil) // UP missing
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err == nil {
			t.Error("expected error for missing UP flag, but got nil")
		}
	})
	
	// In the spec, UV is not strictly required. Some authenticators might not set it.
	// The current implementation requires it. Let's test this behavior.
	t.Run("fail missing user verification flag", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE, 1, nil, nil) // UV missing
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err == nil {
			t.Error("expected error for missing UV flag, but got nil")
		} else {
			t.Logf("Note: Implementation requires UV flag. This might be stricter than the spec requires. Error: %v", err)
		}
	})

	t.Run("fail fromGet=false missing AT flag", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 0, nil, nil) // AT missing
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, false, 0)
		if err == nil {
			t.Error("expected error for missing AT flag, but got nil")
		}
	})

	t.Run("fail invalid sign count", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 5, nil, nil)
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 10) // currentCount is 10
		if err == nil {
			t.Error("expected error for invalid sign count, but got nil")
		}
	})

	t.Run("fail fromGet=true with leftover data", func(t *testing.T) {
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION, 1, nil, nil)
		authData = append(authData, []byte("leftover")...)
		_, _, err := verifyAuthenticatorData(authData, rpIdHash, true, 0)
		if err == nil {
			t.Error("expected error for leftover data, but got nil")
		}
	})
}

func TestVerifyAttestationObject(t *testing.T) {
	rpIdHash := testRpIdHash[:]

	t.Run("success", func(t *testing.T) {
		attested := &attestedCredentialData{
			aaguid:       testAaguid,
			credentialId: testCredentialId,
			coseKey:      testCoseKey,
		}
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attested, nil)

		attObj := AttestationObject{
			AuthData: authData,
			Fmt:      "packed",
			AttStmt:  map[string]any{"ver": "2.0"},
		}
		rawAttObj, _ := cbor.Marshal(attObj)

		_, err := verifyAttestationObject(rawAttObj, rpIdHash, testCredentialId)
		if err != nil {
			t.Fatalf("expected no error, but got %v", err)
		}
	})

	t.Run("fail on invalid cbor", func(t *testing.T) {
		_, err := verifyAttestationObject([]byte("invalid"), rpIdHash, testCredentialId)
		if err == nil {
			t.Fatal("expected error for invalid cbor, but got nil")
		}
	})

	t.Run("fail on invalid auth data length", func(t *testing.T) {
		attObj := AttestationObject{
			AuthData: make([]byte, 10),
			Fmt:      "packed",
		}
		rawAttObj, _ := cbor.Marshal(attObj)
		_, err := verifyAttestationObject(rawAttObj, rpIdHash, testCredentialId)
		if err == nil {
			t.Fatal("expected error for invalid auth data length, but got nil")
		}
	})

	t.Run("fail on credential id mismatch", func(t *testing.T) {
		attested := &attestedCredentialData{
			aaguid:       testAaguid,
			credentialId: testCredentialId,
			coseKey:      testCoseKey,
		}
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attested, nil)
		attObj := AttestationObject{AuthData: authData, Fmt: "packed"}
		rawAttObj, _ := cbor.Marshal(attObj)

		_, err := verifyAttestationObject(rawAttObj, rpIdHash, []byte("different-id"))
		if err == nil {
			t.Fatal("expected error for credential id mismatch, but got nil")
		}
	})
	
	t.Run("fail when auth data is missing public key", func(t *testing.T){
		// Build data up to credential ID, but omit the key
		var buf bytes.Buffer
		buf.Write(rpIdHash)
		buf.WriteByte(FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA)
		scBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(scBytes, 0)
		buf.Write(scBytes)
		buf.Write(testAaguid)
		idLenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(idLenBytes, uint16(len(testCredentialId)))
		buf.Write(idLenBytes)
		buf.Write(testCredentialId)
		authData := buf.Bytes()
		
		attObj := AttestationObject{AuthData: authData, Fmt: "packed"}
		rawAttObj, _ := cbor.Marshal(attObj)

		_, err := verifyAttestationObject(rawAttObj, rpIdHash, testCredentialId)
		if err == nil {
			t.Fatal("expected error for missing public key, but got nil")
		}
	})

	t.Run("subtle.ConstantTimeEq bug in verifyAttestationObject", func(t *testing.T) {
		// The check `subtle.ConstantTimeEq(int32(len(credentialId)), int32(len(credId)))`
		// compares the lengths. If they differ, it should fail.
		attested := &attestedCredentialData{
			aaguid:       testAaguid,
			credentialId: []byte("a-different-length-id"),
			coseKey:      testCoseKey,
		}
		authData := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attested, nil)
		attObj := AttestationObject{AuthData: authData, Fmt: "packed"}
		rawAttObj, _ := cbor.Marshal(attObj)

		// We pass in the original testCredentialId which has a different length
		_, err := verifyAttestationObject(rawAttObj, rpIdHash, testCredentialId)
		if err == nil {
			t.Fatal("expected 'invalid credential id length' error, but got nil")
		}
		if err.Error() != "invalid credential id length" {
			t.Errorf("expected 'invalid credential id length', but got '%v'", err)
		}

		// Now, let's look at the second check:
		// `subtle.ConstantTimeCompare(credentialId, credId)`.
		// If the lengths are the same but the content is different, this should fail.
		attestedSameLength := &attestedCredentialData{
			aaguid:       testAaguid,
			credentialId: []byte("xxxxxxxxxxxxxxxxxx"), // same length as testCredentialId
			coseKey:      testCoseKey,
		}
		authDataSameLength := buildAuthData(rpIdHash, FLAG_USER_PRESENCE|FLAG_USER_VERIFICATION|FLAG_ATTESTED_CREDENTIAL_DATA, 0, attestedSameLength, nil)
		attObjSameLength := AttestationObject{AuthData: authDataSameLength, Fmt: "packed"}
		rawAttObjSameLength, _ := cbor.Marshal(attObjSameLength)
		
		_, err = verifyAttestationObject(rawAttObjSameLength, rpIdHash, testCredentialId)
		if err == nil {
			t.Fatal("expected 'invalid credential id' error, but got nil")
		}
		if err.Error() != "invalid credential id" {
			t.Errorf("expected 'invalid credential id', but got '%v'", err)
		}

		// Now let's point out the bug.
		// If `credentialId` (from parameters) has length X
		// and `credId` (from authdata) has length Y
		// and `subtle.ConstantTimeEq(X, Y)` is 0 (false)
		// the code returns "invalid credential id length" - Correct.
		// Then it proceeds to `subtle.ConstantTimeCompare(credentialId, credId)`.
		// `subtle.ConstantTimeCompare` returns 1 if they are equal, 0 if not.
		// The code checks if the result is 0, and if so, returns "invalid credential id".
		// There is no bug here. The logic seems correct. My initial thought was that it might panic if lengths are different, but `ConstantTimeCompare` handles that.
		// I'll leave this test case here to confirm the logic is sound.
	})
}
