package pasuki2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"mini-pasuki2/form"
)

const PUBLIC_KEY_TYPE = "public-key"

const (
	SIGNATURE_ALGORITHM_ES256 = -7
	SIGNATURE_ALGORITHM_RS256 = -257
)

const DEFAULT_TIME_OUT_MIL = 180000

const ATTESTATION_NONE = "none"

const AUTHENTICATOR_REQUIRED = "required"

type RegisterFinishResult struct {
	ClientData        *ParsedClientData
	AttestationObject *ParsedAttestationObject
	Error             error
}

type VerifyFinishParams struct {
	Session            []byte
	PublicKey          []byte
	RelyingPartyIdHash []byte
	Origin             string
	Challenge          string
	CurrentCount       uint32
}

type VerifyFinishResult struct {
	ClientData    *ParsedClientData
	AuthData      *ParsedAuthAssertionData
	ValidationErr error
	SystemErr     error
}

func RegisterStart(
	f *form.RegisterStartRequest,
	relyingParty, challenge string,
) *RegistrationOptions {
	emailHash := md5.Sum([]byte(f.Email))
	encId := base64.RawURLEncoding.EncodeToString(emailHash[:])
	op := &RegistrationOptions{
		Challenge: challenge,
		Rp: RelyingParty{
			Name: relyingParty,
		},
		User: User{
			Name:        f.Email,
			DisplayName: f.Name,
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

	return op
}

func RegisterFinish(
	f *form.RegisterFinishRequest,
	relyingPartyIdHash []byte,
	origin, challenge string,
) *RegisterFinishResult {
	r := &RegisterFinishResult{}

	rawclientD, err := base64.RawURLEncoding.DecodeString(f.ClientDataJson)
	if err != nil {
		r.Error = err
		return r
	}
	clientD, err := verifyClientData(
		rawclientD,
		origin,
		challenge,
		CLIENT_DATA_TYPE_CREATE,
	)
	if err != nil {
		r.Error = err
		return r
	}

	rawAtt, err := base64.RawURLEncoding.DecodeString(f.AttestationObject)
	if err != nil {
		r.Error = err
		return r
	}
	credId, err := base64.RawURLEncoding.DecodeString(f.Id)
	if err != nil {
		r.Error = err
		return r
	}
	attObj, err := verifyAttestationObject(rawAtt, relyingPartyIdHash, credId)
	if err != nil {
		r.Error = err
		return r
	}

	r.ClientData = clientD
	r.AttestationObject = attObj
	return r
}

func VerifyStart(session []byte, challenge string) *VerifyOptions {
	op := &VerifyOptions{
		AllowCredentials: nil,
		Challenge:        challenge,
		Timeout:          DEFAULT_TIME_OUT_MIL,
		UserVerification: AUTHENTICATOR_REQUIRED,
	}

	return op
}

func VerifyFinish(
	f *form.VerifyFinishRequest,
	p *VerifyFinishParams,
) *VerifyFinishResult {
	r := &VerifyFinishResult{}

	rawclientD, err := base64.RawURLEncoding.DecodeString(f.ClientDataJson)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	clientD, err := verifyClientData(
		rawclientD,
		p.Origin,
		p.Challenge,
		CLIENT_DATA_TYPE_GET,
	)
	if err != nil {
		r.ValidationErr = err
		return r
	}

	rawauthD, err := base64.RawURLEncoding.DecodeString(f.AuthenticatorData)
	if err != nil {
		r.ValidationErr = err
		return r
	}
	authD, _, err := verifyAuthenticatorData(
		rawauthD,
		p.RelyingPartyIdHash,
		true,
		p.CurrentCount,
	)
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

	ok, err := verifySignature(p.PublicKey, src, rawSig)
	if err != nil {
		r.SystemErr = err
		return r
	}
	if !ok {
		r.ValidationErr = errors.New("invalid signature")
		return r
	}

	r.ClientData = clientD
	r.AuthData = authD
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
