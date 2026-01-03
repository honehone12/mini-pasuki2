package pasuki2

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const (
	RP_ID_HASH_LEN           = 32
	SIGN_COUNT_LEN           = 4
	AAGUID_LEN               = 16
	CREDENTIAL_ID_LENGTH_LEN = 2
	__AUTHDATA_MIN_LEN       = RP_ID_HASH_LEN + 1 + SIGN_COUNT_LEN
	__AUTHDATA_KNOWN_LEN     = __AUTHDATA_MIN_LEN + AAGUID_LEN + CREDENTIAL_ID_LENGTH_LEN
)

const (
	FLAG_USER_PRESENCE            = 0b00000001
	FLAG_USER_VERIFICATION        = 0b00000100
	FLAG_BACKUP_ELIGIBILITY       = 0b00001000
	FLAG_BACKUP_STATE             = 0b00010000
	FLAG_ATTESTED_CREDENTIAL_DATA = 0b01000000
	FLAG_EXTENSION_DATA           = 0b10000000
)

type AttestationObject struct {
	AuthData []byte         `cbor:"authData"`
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
}

type ParsedAttestationObject struct {
	Fmt     string
	AttStmt map[string]any
	*ParsedAuthAttestationData
}

type ParsedAuthAssertionData struct {
	BeBit      bool
	BsBit      bool
	SignCount  uint32
	ExtBit     bool
	Extensions map[string]any
}

type ParsedAuthAttestationData struct {
	*ParsedAuthAssertionData
	Aaguid              []byte
	CredentialId        []byte
	CredentialPublicKey []byte
	CoseKey             CoseKey
}

func verifyAuthenticatorData(
	data, relyingPartyIdHash []byte,
	fromGet bool,
	currentCount uint32,
) (*ParsedAuthAssertionData, int, error) {
	l := len(data)
	if l < __AUTHDATA_MIN_LEN {
		return nil, 0, errors.New("invalid auth data assertion length")
	}

	p := RP_ID_HASH_LEN
	rpIdHash := data[:p]
	if subtle.ConstantTimeCompare(rpIdHash, relyingPartyIdHash) == 0 {
		return nil, p, errors.New("unexpected rp id hash")
	}

	flags := data[p]
	if flags&FLAG_USER_PRESENCE == 0 {
		return nil, p, errors.New("unexpected up bit")
	}
	if flags&FLAG_USER_VERIFICATION == 0 {
		return nil, p, errors.New("unexpected uv bit")
	}
	p += 1

	beBit := flags&FLAG_BACKUP_ELIGIBILITY == FLAG_BACKUP_ELIGIBILITY
	bsBit := flags&FLAG_BACKUP_STATE == FLAG_BACKUP_STATE
	extBit := flags&FLAG_EXTENSION_DATA == FLAG_EXTENSION_DATA

	if !fromGet && (flags&FLAG_ATTESTED_CREDENTIAL_DATA == 0) {
		return nil, p, errors.New("unexpected attested credential data bit")
	}

	signCount := binary.BigEndian.Uint32(data[p : p+SIGN_COUNT_LEN])
	if currentCount != 0 && signCount != 0 {
		if signCount <= currentCount {
			return nil, p, errors.New("invalid sign count")
		}
	}
	p += SIGN_COUNT_LEN

	var extensions map[string]any
	if fromGet && extBit {
		if l == p {
			return nil, p, errors.New("auth data is not enough for extension data")
		}

		ext, exp, err := parseExtension(p, data[p:])
		if err != nil {
			return nil, p, err
		}

		extensions = ext
		p = exp
	}

	if fromGet && l != p {
		return nil, p, errors.New("l != p, unexpected data structure")
	}

	d := &ParsedAuthAssertionData{
		BeBit:      beBit,
		BsBit:      bsBit,
		SignCount:  signCount,
		ExtBit:     extBit,
		Extensions: extensions,
	}
	return d, p, nil
}

func parseExtension(p int, data []byte) (map[string]any, int, error) {
	var rawExt cbor.RawMessage
	err := cbor.NewDecoder(bytes.NewReader(data)).
		Decode(&rawExt)
	if err != nil {
		return nil, p, err
	}
	p += len(rawExt)

	var extensions map[string]any
	if err := cbor.Unmarshal(rawExt, &extensions); err != nil {
		return nil, p, err
	}

	return extensions, p, nil
}

func verifyAttestationObject(
	data, relyingPartyIdHash, credentialId []byte,
) (*ParsedAttestationObject, error) {
	att := AttestationObject{}
	if err := cbor.Unmarshal(data, &att); err != nil {
		return nil, err
	}

	l := len(att.AuthData)
	if l < __AUTHDATA_KNOWN_LEN {
		return nil, errors.New("invalid auth data attestation length")
	}

	asseD, p, err := verifyAuthenticatorData(
		att.AuthData,
		relyingPartyIdHash,
		false,
		0,
	)
	if err != nil {
		return nil, err
	}

	aaguid := att.AuthData[p : p+AAGUID_LEN]
	p += AAGUID_LEN

	credIdLen := int(binary.BigEndian.Uint16(att.AuthData[p : p+CREDENTIAL_ID_LENGTH_LEN]))
	p += CREDENTIAL_ID_LENGTH_LEN
	if l <= p+credIdLen {
		return nil, errors.New("auth data is not enough for credential")
	}

	credId := att.AuthData[p : p+credIdLen]
	p += credIdLen

	if l == p {
		return nil, errors.New("auth data is not enough for publicKey")
	}

	var rawPk cbor.RawMessage
	err = cbor.NewDecoder(bytes.NewReader(att.AuthData[p:])).Decode(&rawPk)
	if err != nil {
		return nil, err
	}
	p += len(rawPk)

	coseKey, err := parseCoseKey(rawPk)
	if err != nil {
		return nil, err
	}

	if asseD.ExtBit {
		if l == p {
			return nil, errors.New("auth data is not enough for extension data")
		}

		extensions, exp, err := parseExtension(p, att.AuthData[p:])
		if err != nil {
			return nil, err
		}
		asseD.Extensions = extensions
		p = exp
	}

	if l != p {
		return nil, errors.New("l != p, unexpected data structure")
	}

	if subtle.ConstantTimeEq(int32(len(credentialId)), int32(len(credId))) == 0 {
		return nil, errors.New("invalid credential id length")
	}
	if subtle.ConstantTimeCompare(credentialId, credId) == 0 {
		return nil, errors.New("invalid credential id")
	}

	d := &ParsedAuthAttestationData{
		ParsedAuthAssertionData: asseD,
		Aaguid:                  aaguid,
		CredentialId:            credId,
		CredentialPublicKey:     rawPk,
		CoseKey:                 coseKey,
	}
	o := &ParsedAttestationObject{
		Fmt:                       att.Fmt,
		AttStmt:                   att.AttStmt,
		ParsedAuthAttestationData: d,
	}
	return o, nil
}
