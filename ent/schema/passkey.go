package schema

import (
	"mini-pasuki2/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Passkey holds the schema definition for the Passkey entity.
type Passkey struct {
	ent.Schema
}

// Fields of the Passkey.
func (Passkey) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("origin").
			NotEmpty().
			MaxLen(256).
			Immutable(),
		field.Enum("attestation_fmt").
			Values("none", "packed", "tpm" /* etc */).
			Immutable(),
		field.Bool("backup_eligibility_bit"),
		field.Bool("backup_state_bit"),
		field.Uint32("sign_count"),
		field.Bytes("aaguid").
			MinLen(16).
			MaxLen(16).
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Bytes("credential_id").
			NotEmpty().
			Immutable().
			MaxLen(64).
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "varbinary(64)"}),
		field.Bytes("public_key").
			NotEmpty().
			MaxLen(512).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "varbinary(512)"}),
		field.Bool("extension_bit"),
		field.UUID("user_id", binid.BinId{}).
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
	}
}

// Edges of the Passkey.
func (Passkey) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("passkeys").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (Passkey) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("credential_id").Unique(),
	}
}

func (Passkey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
