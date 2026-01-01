package pasuki2

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mini-pasuki2/binid"
	"mini-pasuki2/challenge"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/passkey"
	"mini-pasuki2/ent/user"
	"time"

	"entgo.io/ent/dialect/sql"
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

type Passkey2Params struct {
	UserId binid.BinId
	Email  string
}

type RegisterStartParams struct {
	Passkey2Params
	Name string
}

type RegisterFinishParams struct {
	Passkey2Params
	Id                string
	Type              string
	AttestationObject string
	ClientDataJson    string
}

type VerifyStartParams = Passkey2Params

type E struct {
	ValidationErr error
	SystemErr     error
}

type RegisterStartResult struct {
	Options *RegistrationOptions
	E
}

type RegisterFinishResult struct {
	ClientData        *RegistrationClientData
	AttestationObject *RegistrationAttestationObject
	E
}

type VerifyStartResult struct {
	Options *VerifyOptions
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
) *RegisterStartResult {
	r := &RegisterStartResult{}

	chal, err := challenge.Gen()
	if err != nil {
		r.SystemErr = err
		return r
	}
	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, p.Email)
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
		AttestationFormats: nil,
		ExcludeCredentials: nil,
		Extensions:         nil,
	}

	r.Options = op
	return r
}

func (p2 *Pasuki2) RegisterFinish(
	ctx context.Context,
	p *RegisterFinishParams,
) *RegisterFinishResult {
	r := &RegisterFinishResult{}

	if p.Type != PUBLIC_KEY_TYPE {
		r.ValidationErr = errors.New("invalid credential type")
		return r
	}

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, p.Email)
	cachedChal, err := p2.redis.GetDel(ctx, key).Result()
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

	id, err := binid.NewSequential()
	if err != nil {
		r.SystemErr = err
		return r
	}

	err = p2.passKeyClient.Create().
		SetID(id).
		SetOrigin(clientData.Origin).
		SetCrossOrigin(clientData.CrossOrigin).
		SetTopOrigin(clientData.TopOrigin).
		SetAttestationFmt(passkey.AttestationFmt(r.AttestationObject.Fmt)).
		SetBackupEligibilityBit(r.AttestationObject.BeBit).
		SetBackupStateBit(r.AttestationObject.BsBit).
		SetSignCount(r.AttestationObject.SignCount).
		SetAaguid(r.AttestationObject.Aaguid).
		SetCredentialID(r.AttestationObject.CredentialId).
		SetPublicKey(r.AttestationObject.CredentialPublicKey).
		SetExtensionBit(r.AttestationObject.ExtBit).
		SetUserID(p.UserId).
		Exec(ctx)
	if err != nil {
		r.SystemErr = err
		return r
	}

	r.ClientData = clientData
	r.AttestationObject = attObj
	return r
}

func (p2 *Pasuki2) VerifyStart(
	ctx context.Context,
	p VerifyStartParams,
) *VerifyStartResult {
	r := &VerifyStartResult{}

	pk, err := p2.passKeyClient.Query().
		Select(passkey.FieldCredentialID).
		Where(
			passkey.UserID(p.UserId),
			passkey.DeletedAtIsNil(),
		).
		Order(sql.OrderByField(user.FieldCreatedAt, sql.OrderDesc()).ToFunc()).
		Limit(1).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = errors.New("could not find passkey")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	chal, err := challenge.Gen()
	if err != nil {
		r.SystemErr = err
		return r
	}
	encChal := base64.RawURLEncoding.EncodeToString(chal)

	key := fmt.Sprintf("%s:%x", REDIS_VERIFY_CHALLENGE_KEY, p.UserId)
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

	op := &VerifyOptions{
		AllowCredentials: []Credential{{
			Id:         pk.CredentialID,
			Transports: nil,
			Type:       PUBLIC_KEY_TYPE,
		}},
		Challenge:        encChal,
		Timeout:          DEFAULT_TIME_OUT_MIL,
		UserVerification: AUTHENTICATOR_REQUIRED,
	}

	r.Options = op
	return r
}
