package pasuki2

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

const (
	RP_ID_HASH_LEN           = 32
	SIGN_COUNT_LEN           = 4
	AAGUID_LEN               = 16
	CREDENTIAL_ID_LENGTH_LEN = 2
	__REGISTRATION_KNOWN_LEN = RP_ID_HASH_LEN + 1 + SIGN_COUNT_LEN + AAGUID_LEN + CREDENTIAL_ID_LENGTH_LEN
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
	*ParsedAuthenticatorData
}

type ParsedAuthenticatorData struct {
	BeBit               bool
	BsBit               bool
	SignCount           uint32
	Aaguid              []byte
	CredentialId        []byte
	CredentialPublicKey []byte
	CoseKey             CoseKey
	ExtBit              bool
	Extensions          map[string]any
}

func (p2 *Pasuki2) verifyAuthenticatorData(data []byte) (*ParsedAuthenticatorData, error) {
	l := len(data)
	if l < __REGISTRATION_KNOWN_LEN {
		return nil, errors.New("invalid auth data length")
	}

	p := RP_ID_HASH_LEN
	rpIdHash := data[:p]
	if subtle.ConstantTimeCompare(p2.rpIdHash, rpIdHash) == 0 {
		return nil, errors.New("unexpected rp id hash")
	}

	flags := data[p]
	if flags&FLAG_USER_PRESENCE == 0 {
		return nil, errors.New("unexpected up bit")
	}
	if flags&FLAG_USER_VERIFICATION == 0 {
		return nil, errors.New("unexpected uv bit")
	}
	p += 1

	beBit := flags&FLAG_BACKUP_ELIGIBILITY == 1
	bsBit := flags&FLAG_BACKUP_STATE == 1

	if flags&FLAG_ATTESTED_CREDENTIAL_DATA == 0 {
		return nil, errors.New("unexpected attested credential data bit")
	}

	signCount := binary.BigEndian.Uint32(data[p : p+SIGN_COUNT_LEN])
	p += SIGN_COUNT_LEN

	aaguid := data[p : p+AAGUID_LEN]
	p += AAGUID_LEN

	credIdLen := int(binary.BigEndian.Uint16(data[p : p+CREDENTIAL_ID_LENGTH_LEN]))
	p += CREDENTIAL_ID_LENGTH_LEN
	if l <= p+credIdLen {
		return nil, errors.New("auth data is not enough for credential")
	}

	credentialId := data[p : p+credIdLen]
	p += credIdLen

	var rawPk cbor.RawMessage
	err := cbor.NewDecoder(bytes.NewReader(data[p:])).
		Decode(&rawPk)
	if err != nil {
		return nil, err
	}
	p += len(rawPk)

	coseKey, err := parseCoseKey(rawPk)
	if err != nil {
		return nil, err
	}

	extBit := flags&FLAG_EXTENSION_DATA == 1
	var extensions map[string]any
	if extBit {
		if l == p {
			return nil, errors.New("auth data is not enough for extension data")
		}

		var rawExt cbor.RawMessage
		err = cbor.NewDecoder(bytes.NewReader(data[:p])).
			Decode(&rawExt)
		if err != nil {
			return nil, err
		}
		p += len(rawExt)

		if err := cbor.Unmarshal(rawExt, &extensions); err != nil {
			return nil, err
		}
	}

	if l != p {
		return nil, errors.New("l != p, unexpected data structure")
	}

	authData := &ParsedAuthenticatorData{
		BeBit:               beBit,
		BsBit:               bsBit,
		SignCount:           signCount,
		Aaguid:              aaguid,
		CredentialId:        credentialId,
		CredentialPublicKey: rawPk,
		CoseKey:             coseKey,
		ExtBit:              extBit,
		Extensions:          extensions,
	}

	return authData, nil
}

func (p2 *Pasuki2) verifyAttestationObject(
	encObj string,
) (*ParsedAttestationObject, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encObj)
	if err != nil {
		return nil, err
	}

	att := AttestationObject{}
	if err := cbor.Unmarshal(raw, &att); err != nil {
		return nil, err
	}

	authData, err := p2.verifyAuthenticatorData(att.AuthData)
	if err != nil {
		return nil, err
	}

	o := &ParsedAttestationObject{
		Fmt:                     att.Fmt,
		AttStmt:                 att.AttStmt,
		ParsedAuthenticatorData: authData,
	}

	return o, nil
}
