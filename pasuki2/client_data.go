package pasuki2

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
)

const (
	CLIENT_DATA_TYPE_CREATE = "webauthn.create"
	CLIENT_DATA_TYPE_GET    = "webauthn.get"
)

type ParsedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin"`
}

func verifyClientData(
	raw []byte,
	origin, cachedChal, datatype string,
) (*ParsedClientData, error) {
	clientData := &ParsedClientData{}
	if err := json.Unmarshal(raw, clientData); err != nil {
		return nil, err
	}

	// (!) navigator.credential api is callable from iframe
	// even though it's return values are top level contex only
	if clientData.CrossOrigin || len(clientData.TopOrigin) != 0 {
		return nil, errors.New("cross orign is not expected")
	}

	if clientData.Type != datatype {
		return nil, errors.New("unexpected client data type")
	}

	if clientData.Origin != origin {
		return nil, errors.New("unexpected client data origin")
	}

	if subtle.ConstantTimeEq(
		int32(len(clientData.Challenge)),
		int32(len(cachedChal)),
	) == 0 {
		return nil, errors.New("invalid client data challenge length")
	}

	if subtle.ConstantTimeCompare(
		[]byte(clientData.Challenge),
		[]byte(cachedChal),
	) == 0 {
		return nil, errors.New("invalid client data challenge")
	}

	return clientData, nil
}
