package pasuki2

import (
	"testing"
)

func TestGenerateChallenge(t *testing.T) {
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() returned an error: %v", err)
	}

	if len(challenge) != CHALLENGE_LEN {
		t.Errorf("Expected challenge length %d, but got %d", CHALLENGE_LEN, len(challenge))
	}

	// Test that multiple calls generate different challenges
	challenge2, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() returned an error on second call: %v", err)
	}

	if string(challenge) == string(challenge2) {
		t.Error("GenerateChallenge() returned the same challenge on multiple calls")
	}
}
