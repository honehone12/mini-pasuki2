package pasuki2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestVerifyClientData(t *testing.T) {
	origin := "https://example.com"
	challenge, _ := GenerateChallenge()
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge)

	t.Run("successful verification for create", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: encodedChallenge,
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)

		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
	})

	t.Run("successful verification for get", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_GET,
			Challenge: encodedChallenge,
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)

		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_GET)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}
	})

	t.Run("fail on invalid json", func(t *testing.T) {
		raw := []byte("invalid json")
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for invalid json, but got nil")
		}
	})

	t.Run("fail on crossOrigin", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:        CLIENT_DATA_TYPE_CREATE,
			Challenge:   encodedChallenge,
			Origin:      origin,
			CrossOrigin: true,
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for crossOrigin, but got nil")
		}
	})

	t.Run("fail on topOrigin", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: encodedChallenge,
			Origin:    origin,
			TopOrigin: "https://some-other-origin.com",
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for topOrigin, but got nil")
		}
	})

	t.Run("fail on unexpected data type", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      "unexpected.type",
			Challenge: encodedChallenge,
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for unexpected data type, but got nil")
		}
	})

	t.Run("fail on unexpected origin", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: encodedChallenge,
			Origin:    "https://wrong.origin.com",
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for unexpected origin, but got nil")
		}
	})

	t.Run("fail on invalid challenge length", func(t *testing.T) {
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: "short",
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for invalid challenge length, but got nil")
		}
	})

	t.Run("fail on invalid challenge", func(t *testing.T) {
		wrongChallenge, _ := GenerateChallenge()
		encodedWrongChallenge := base64.RawURLEncoding.EncodeToString(wrongChallenge)

		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: encodedWrongChallenge,
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error for invalid challenge, but got nil")
		}
	})

	t.Run("challenge encoding check", func(t *testing.T) {
		// This is not a direct test of verifyClientData, but it highlights a potential issue.
		// The challenge in ParsedClientData is a string, but it's compared to another string.
		// The spec expects the challenge to be Base64URL encoded in the JSON.
		// The comparison `clientData.Challenge == cachedChal` works if both are encoded strings.
		// Let's create a test case that assumes the cached challenge is raw bytes, which would fail.
		clientData := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: encodedChallenge,
			Origin:    origin,
		}
		raw, _ := json.Marshal(clientData)

		// This will fail because the function expects `cachedChal` to be an encoded string, not raw bytes.
		// The function implementation seems to expect an encoded string, so this is more of a note.
		// The implementation compares two strings, so as long as both are encoded, it's fine.
		// The bug would be if the CALLER of verifyClientData passes raw bytes as cachedChal.
		// Let's check `pasuki2.go` to see how `verifyClientData` is called.
		// `RegisterFinish` and `VerifyFinish` both pass `challenge` which is a string.
		// `RegisterStart` and `VerifyStart` set the challenge from a string.
		// The source of the challenge is `GenerateChallenge` which returns `[]byte`.
		// It seems the calling code is responsible for encoding.
		// Let's check the code for subtle.ConstantTimeCompare. It takes []byte.
		// The code is `subtle.ConstantTimeCompare([]byte(clientData.Challenge), []byte(cachedChal))`
		// This is correct if both are encoded strings.

		// Let's confirm the current implementation is correct by using it as intended.
		_, err := verifyClientData(raw, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err != nil {
			t.Errorf("verification with encoded challenge string failed: %v", err)
		}

		// Now let's test a potential misuse.
		// The parameter name `cachedChal` doesn't make it obvious if it should be encoded or not.
		// What if the caller passes the raw challenge?
		clientDataWithUnencodedChallenge := ParsedClientData{
			Type:      CLIENT_DATA_TYPE_CREATE,
			Challenge: string(challenge), // Unencoded challenge
			Origin:    origin,
		}
		rawUnencoded, _ := json.Marshal(clientDataWithUnencodedChallenge)

		// This should fail because the lengths won't match, and the comparison will fail.
		_, err = verifyClientData(rawUnencoded, origin, encodedChallenge, CLIENT_DATA_TYPE_CREATE)
		if err == nil {
			t.Error("expected an error when clientData has unencoded challenge but cached is encoded, but got nil")
		} else {
			fmt.Printf("Note: Found a potential misuse case. The function correctly returns an error: %v\n", err)
			fmt.Println("This suggests the caller must be careful to pass an encoded challenge string.")
		}
	})
}
