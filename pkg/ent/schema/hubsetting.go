// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/google/uuid"
)

// HubSetting holds the schema definition for the HubSetting entity, a generic
// key/value store for hub-wide configuration (e.g. the default GCP identity
// mode and service account). The key is the natural identity and is immutable;
// the value is free-form and mutated via upsert.
type HubSetting struct {
	ent.Schema
}

// Fields of the HubSetting.
func (HubSetting) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", uuid.UUID{}).
			Default(uuid.New).
			Immutable(),
		field.String("key").
			NotEmpty().
			Immutable(),
		field.String("value").
			Default(""),
		field.Time("created").
			Default(time.Now).
			Immutable(),
		field.Time("updated").
			Default(time.Now).
			UpdateDefault(time.Now),
	}
}

// Indexes of the HubSetting.
func (HubSetting) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("key").
			Unique(),
	}
}

// Annotations of the HubSetting.
func (HubSetting) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "hub_settings"},
	}
}
