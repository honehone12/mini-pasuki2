package pasuki2

type RelyingParty struct {
	Name string `json:"name"`
	Id   string `json:"id,omitempty"`
}

type User struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParams struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type Credential struct {
	Id         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
	Type       string   `json:"type"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification"`
}

type RegistrationOptions struct {
	Challenge                 string                      `json:"challenge"`
	Rp                        RelyingParty                `json:"rp"`
	User                      User                        `json:"user"`
	PublicKeyCredentialParams []PublicKeyCredentialParams `json:"pubKeyCredParams"`
	Timeout                   uint                        `json:"timeout"`
	Attestation               string                      `json:"attestation"`
	AuthenticatorSelection    AuthenticatorSelection      `json:"authenticatorSelection"`
	AttestationFormats        []string                    `json:"attestationFormats,omitempty"`
	ExcludeCredentials        []Credential                `json:"excludeCredentials,omitempty"`
	Extensions                map[string]any              `json:"extensions,omitempty"`
}
