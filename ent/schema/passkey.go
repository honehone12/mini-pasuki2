package schema

import (
	"mini-pasuki2/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
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

func (Passkey) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
