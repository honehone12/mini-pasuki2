package challenge

import "crypto/rand"

const CHALLENGE_LEN = 32

func GenChallenge() ([]byte, error) {
	b := make([]byte, CHALLENGE_LEN)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
