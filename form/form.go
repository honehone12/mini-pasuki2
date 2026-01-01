package form

type RegisterRequest struct {
	Email string `form:"email" validate:"required,email,max=256"`
	Name  string `form:"name" validate:"required,max=256"`
}

type RegisterStartRequest = RegisterRequest

type RegisterFinishRequest struct {
	RegisterRequest
	// (!) this is passkey credential id, not our database id
	Id                      string `form:"id" validate:"required,base64rawurl,min=22,max=86"`
	Type                    string `form:"type" validate:"required,eq=public-key"`
	ClientDataJson          string `form:"clientDataJson" validate:"required,base64rawurl,min=100,max=500"`
	AttestationObject       string `form:"attestationObject" validate:"required,base64rawurl,min=100,max=5000"`
	AuthenticatorAttachment string `form:"authenticatorAttachment" validate:"omitempty,oneof=platform cross-platform"`
}

type VerifyFinishRequest struct {
	// (!) this is passkey credential id, not our database id
	Id                string `form:"id" validate:"required,base64rawurl,min=22,max=86"`
	Type              string `form:"type" validate:"required,eq=public-key"`
	ClientDataJson    string `form:"clientDataJson" validate:"required,base64rawurl,min=100,max=500"`
	AuthenticatorData string `form:"authenticatorData" validate:"required,base64rawurl"`
	Signature         string `form:"signature" validate:"required,base64rawurl,min=43,max=683"`
	// (!) this is user.id, but can be null
	UserHandle              string `form:"userHandle" validate:"omitempty,base64rawurl,len=22"`
	AuthenticatorAttachment string `form:"authenticatorAttachment" validate:"omitempty,oneof=platform cross-platform"`
}
