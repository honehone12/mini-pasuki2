package pasuki2

import (
	"context"
	"encoding/base64"
	"mini-pasuki2/binid"
	"mini-pasuki2/challenge"
	"mini-pasuki2/ent"
)

const PUBLIC_KEY_TYPE = "public-key"
const (
	SIGNATURE_ALGORITHM_ES256 = -7
	SIGNATURE_ALGORITHM_RS256 = -257
)

const DEFAULT_TIME_OUT = 60000

const ATTESTATION_NONE = "none" // i will not implement hardawre attestation

const AUTHENTICATOR_PREFERED = "preferred" // leave to brower default

type Pasuki2 struct {
	passKeyClient *ent.PasskeyClient
}

type RegisterStartParams struct {
	Id    binid.BinId
	Email string
	Name  string
}

func NewPasuki2(ent *ent.PasskeyClient) *Pasuki2 {
	return &Pasuki2{ent}
}

func (p2 *Pasuki2) RegisterStart(
	ctx context.Context,
	p RegisterStartParams,
) (*RegistrationOptions, error) {
	chal, err := challenge.GenChallenge()
	if err != nil {
		return nil, err
	}

	id, err := binid.NewSequential()
	if err != nil {
		return nil, err
	}

	err = p2.passKeyClient.Create().
		SetID(id).
		SetUserID(p.Id).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	encChal := base64.RawURLEncoding.EncodeToString(chal)
	op := &RegistrationOptions{
		Challenge: encChal,
		Rp: RelyingParty{
			Name: "MiniPasuki2",
		},
		User: User{
			Id:          p.Id.String(),
			Name:        p.Email,
			DisplayName: p.Name,
		},
		PublicKeyCredentialParams: []PublicKeyCredentialParams{{
			Type: PUBLIC_KEY_TYPE,
			Alg:  SIGNATURE_ALGORITHM_ES256,
		}, {
			Type: PUBLIC_KEY_TYPE,
			Alg:  SIGNATURE_ALGORITHM_RS256,
		}},
		Timeout:     DEFAULT_TIME_OUT,
		Attestation: ATTESTATION_NONE,
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:      AUTHENTICATOR_PREFERED,
			UserVerification: AUTHENTICATOR_PREFERED,
		},
	}

	return op, nil
}
