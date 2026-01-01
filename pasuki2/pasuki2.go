package pasuki2

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mini-pasuki2/challenge"
	"mini-pasuki2/ent"
	"mini-pasuki2/form"
	"time"

	"github.com/redis/go-redis/v9"
)

const PUBLIC_KEY_TYPE = "public-key"

const (
	SIGNATURE_ALGORITHM_ES256 = -7
	SIGNATURE_ALGORITHM_RS256 = -257
)

const DEFAULT_TIME_OUT_MIL = 180000

const ATTESTATION_NONE = "none"

const AUTHENTICATOR_REQUIRED = "required"

const REDIS_REGISTRATION_CHALLENGE_KEY = "REGCHAL"
const REDIS_VERIFY_CHALLENGE_KEY = "VERCHAL"

type Pasuki2 struct {
	passKeyClient *ent.PasskeyClient
	redis         *redis.Client
	origin        string
	rpIdHash      []byte
}

type E struct {
	ValidationErr error
	SystemErr     error
}

type RegisterStartResult struct {
	Options *RegistrationOptions
	E
}

type RegisterFinishResult struct {
	ClientData        *ParsedClientData
	AttestationObject *ParsedAttestationObject
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
	email string,
	name string,
) *RegisterStartResult {
	r := &RegisterStartResult{}

	chal, err := challenge.Gen()
	if err != nil {
		r.SystemErr = err
		return r
	}
	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, email)
	err = p2.redis.SetArgs(
		ctx,
		key,
		encChal,
		redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * DEFAULT_TIME_OUT_MIL,
		},
	).Err()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("challenge already exists")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	emailHash := md5.Sum([]byte(email))
	encId := base64.RawURLEncoding.EncodeToString(emailHash[:])
	op := &RegistrationOptions{
		Challenge: encChal,
		Rp: RelyingParty{
			Name: "MiniPasuki2",
		},
		User: User{
			Name:        email,
			DisplayName: name,
			Id:          encId,
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
			ResidentKey:      AUTHENTICATOR_REQUIRED,
		},
		AttestationFormats: nil,
		ExcludeCredentials: nil,
		Extensions:         nil,
	}

	r.Options = op
	return r
}

func (p2 *Pasuki2) RegisterFinish(
	ctx context.Context,
	f *form.RegisterFinishRequest,
) *RegisterFinishResult {
	r := &RegisterFinishResult{}

	if f.Type != PUBLIC_KEY_TYPE {
		r.ValidationErr = errors.New("invalid credential type")
		return r
	}

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, f.Email)
	cachedChal, err := p2.redis.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	clientData, err := p2.verifyClientData(f.ClientDataJson, cachedChal)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	attObj, err := p2.verifyAttestationObject(f.AttestationObject)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	if f.Id != base64.RawURLEncoding.EncodeToString(attObj.CredentialId) {
		r.ValidationErr = errors.New("credential id is not correct")
		return r
	}

	r.ClientData = clientData
	r.AttestationObject = attObj
	return r
}

func (p2 *Pasuki2) VerifyStart(
	ctx context.Context,
	session []byte,
) (*VerifyOptions, error) {
	chal, err := challenge.Gen()
	if err != nil {
		return nil, err
	}

	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%x", REDIS_VERIFY_CHALLENGE_KEY, session)
	err = p2.redis.SetArgs(
		ctx,
		key,
		encChal,
		redis.SetArgs{
			Mode: "NX",
			TTL:  time.Millisecond * DEFAULT_TIME_OUT_MIL,
		},
	).Err()
	if err != nil {
		return nil, err
	}

	op := &VerifyOptions{
		AllowCredentials: nil,
		Challenge:        encChal,
		Timeout:          DEFAULT_TIME_OUT_MIL,
		UserVerification: AUTHENTICATOR_REQUIRED,
	}

	return op, nil
}

func (p2 *Pasuki2) VerifyFinish(
	ctx context.Context,
	f *form.VerifyFinishRequest,
) {

}
