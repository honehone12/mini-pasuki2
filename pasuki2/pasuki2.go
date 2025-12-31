package pasuki2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mini-pasuki2/binid"
	"mini-pasuki2/ent"
	"mini-pasuki2/gen"
	"time"

	"github.com/redis/go-redis/v9"
)

const PUBLIC_KEY_TYPE = "public-key"
const (
	SIGNATURE_ALGORITHM_ES256 = -7
	SIGNATURE_ALGORITHM_RS256 = -257
)

const DEFAULT_TIME_OUT_MIL = 180000

const ATTESTATION_NONE = "none" // i will not implement hardawre attestation

const AUTHENTICATOR_REQUIRED = "required" // leave to brower default

const REDIS_REGISTRATION_CHALLENGE_KEY = "REGCHAL"

type Pasuki2 struct {
	passKeyClient *ent.PasskeyClient
	redis         *redis.Client
	origin        string
	rpIdHash      []byte
}

type RegisterStartParams struct {
	UserId binid.BinId
	Email  string
	Name   string
}

type RegisterFinishParams struct {
	UserId            binid.BinId
	Email             string
	Id                string
	Type              string
	AttestationObject string
	ClientDataJson    string
}

type E struct {
	ValidationErr error
	SystemErr     error
}

type RegisterFinishResult struct {
	ClientData        *RegistrationClientData
	AttestationObject *RegistrationAttestationObject
	E
}

func NewPasuki2(
	ent *ent.PasskeyClient,
	redis *redis.Client,
	origin string,
	rpId string,
) *Pasuki2 {
	rpIdHash := sha256.Sum256([]byte(rpId))
	return &Pasuki2{ent, redis, origin, rpIdHash[:]}
}

func (p2 *Pasuki2) RegisterStart(
	ctx context.Context,
	p RegisterStartParams,
) (*RegistrationOptions, error) {
	chal, err := gen.Gen(gen.CHALLENGE_LEN)
	if err != nil {
		return nil, err
	}

	encChal := base64.RawURLEncoding.EncodeToString(chal)
	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, p.Email)
	err = p2.redis.SetEx(
		ctx,
		key,
		encChal,
		time.Millisecond*DEFAULT_TIME_OUT_MIL,
	).Err()
	if err != nil {
		return nil, err
	}

	op := &RegistrationOptions{
		Challenge: encChal,
		Rp: RelyingParty{
			Name: "MiniPasuki2",
		},
		User: User{
			Id:          p.UserId.String(),
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
		Timeout:     DEFAULT_TIME_OUT_MIL,
		Attestation: ATTESTATION_NONE,
		AuthenticatorSelection: AuthenticatorSelection{
			UserVerification: AUTHENTICATOR_REQUIRED,
		},
	}

	return op, nil
}

func (p2 *Pasuki2) RegisterFinish(
	ctx context.Context,
	p RegisterFinishParams,
) *RegisterFinishResult {
	r := &RegisterFinishResult{}

	if p.Type != PUBLIC_KEY_TYPE {
		r.ValidationErr = errors.New("invalid credential type")
		return r
	}

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, p.Email)
	cachedChal, err := p2.redis.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	clientData, err := p2.verifyRegistrationClientData(p.ClientDataJson, cachedChal)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	attObj, err := p2.verifyRegistrationAttestationObject(p.AttestationObject)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	if p.Id != base64.RawURLEncoding.EncodeToString(attObj.CredentialId) {
		r.ValidationErr = errors.New("credential id is not correct")
		return r
	}

	r.ClientData = clientData
	r.AttestationObject = attObj
	return r
}
