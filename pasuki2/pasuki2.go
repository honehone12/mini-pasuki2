package pasuki2

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"mini-pasuki2/challenge"
	"mini-pasuki2/ent"
	"mini-pasuki2/ent/passkey"
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

type VerifyFinishResult = E

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

// this does not persist parsed data,
// because it want transaction with user record
func (p2 *Pasuki2) RegisterFinish(
	ctx context.Context,
	f *form.RegisterFinishRequest,
) *RegisterFinishResult {
	r := &RegisterFinishResult{}

	key := fmt.Sprintf("%s:%s", REDIS_REGISTRATION_CHALLENGE_KEY, f.Email)
	chal, err := p2.redis.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	rawclientD, err := base64.RawURLEncoding.DecodeString(f.ClientDataJson)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	clientD, err := p2.verifyClientData(rawclientD, chal, CLIENT_DATA_TYPE_CREATE)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	rawAtt, err := base64.RawURLEncoding.DecodeString(f.AttestationObject)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	id, err := base64.RawURLEncoding.DecodeString(f.Id)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	attObj, err := p2.verifyAttestationObject(rawAtt, id)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	r.ClientData = clientD
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
	session []byte,
) VerifyFinishResult {
	r := VerifyFinishResult{}

	id, err := base64.RawURLEncoding.DecodeString(f.Id)
	if err != nil {
		r.SystemErr = err
		return r
	}

	passK, err := p2.passKeyClient.Query().
		Select(passkey.FieldPublicKey).
		Where(
			passkey.CredentialID(id),
			passkey.DeletedAtIsNil(),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		r.ValidationErr = err
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	key := fmt.Sprintf("%s:%x", REDIS_VERIFY_CHALLENGE_KEY, session)
	encChal, err := p2.redis.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		r.ValidationErr = errors.New("challenge not found")
		return r
	} else if err != nil {
		r.SystemErr = err
		return r
	}

	rawclientD, err := base64.RawURLEncoding.DecodeString(f.ClientDataJson)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	_, err = p2.verifyClientData(rawclientD, encChal, CLIENT_DATA_TYPE_GET)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	rawauthD, err := base64.RawURLEncoding.DecodeString(f.AuthenticatorData)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	_, _, err = p2.verifyAuthenticatorData(rawauthD, true)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	rawSig, err := base64.RawURLEncoding.DecodeString(f.Signature)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	src, err := makeHash(rawauthD, rawclientD)
	if err != nil {
		r.SystemErr = err
		return r
	}

	ok, err := verifySignature(passK.PublicKey, src, rawSig)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("invalid signature")
		return r
	}

	return r
}

func makeHash(rawauthData, rawclientData []byte) ([]byte, error) {
	l := len(rawauthData)
	hashSrc := make([]byte, l+sha256.Size)
	if n := copy(hashSrc[:l], rawauthData); n != l {
		return nil, errors.New("failed to copy auth data")
	}
	cdHash := sha256.Sum256(rawclientData)
	if n := copy(hashSrc[l:], cdHash[:]); n != sha256.Size {
		return nil, errors.New("failed to copy client data hash")
	}

	hash := sha256.Sum256(hashSrc)
	return hash[:], nil
}

func verifySignature(publicKey, src, signature []byte) (bool, error) {
	cose, err := parseCoseKeyUnchecked(publicKey)
	if err != nil {
		return false, err
	}

	kty, ok := cose[COSE_KEY_TYPE]
	if !ok {
		return false, errors.New("could not find key type")
	}

	switch kty {
	case uint64(COSE_KEYTYPE_EC2):
		{
			pk, err := cose.getEcdsaPubKey()
			if err != nil {
				return false, err
			}
			return ecdsa.VerifyASN1(pk, src, signature), nil
		}
	case uint64(COSE_KEYTYPE_RSA):
		{
			pk, err := cose.getRsaPubKey()
			if err != nil {
				return false, err
			}
			err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, src, signature)
			if errors.Is(err, rsa.ErrVerification) {
				return false, nil
			} else if err != nil {
				return false, err
			}
			return true, nil
		}
	default:
		return false, errors.New("key type not supported")
	}
}
