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

package entadapter

import (
	"context"
	"time"

	"github.com/GoogleCloudPlatform/scion/pkg/ent"
	enthubsetting "github.com/GoogleCloudPlatform/scion/pkg/ent/hubsetting"
	"github.com/GoogleCloudPlatform/scion/pkg/store"
)

// HubSettingStore implements store.HubSettingStore using Ent. Hub settings are
// a generic key/value store for hub-wide configuration; the key is the natural
// identity (unique, immutable) and the value is mutated via upsert.
type HubSettingStore struct {
	client *ent.Client
}

// NewHubSettingStore creates a new Ent-backed HubSettingStore.
func NewHubSettingStore(client *ent.Client) *HubSettingStore {
	return &HubSettingStore{client: client}
}

// GetHubSetting retrieves the value for a hub setting key.
func (s *HubSettingStore) GetHubSetting(ctx context.Context, key string) (string, error) {
	e, err := s.client.HubSetting.Query().
		Where(enthubsetting.KeyEQ(key)).
		Only(ctx)
	if err != nil {
		return "", mapError(err)
	}
	return e.Value, nil
}

// SetHubSetting creates or updates the value for a hub setting key, keyed by the
// unique key column.
func (s *HubSettingStore) SetHubSetting(ctx context.Context, key, value string) error {
	now := time.Now()
	err := s.client.HubSetting.Create().
		SetKey(key).
		SetValue(value).
		SetCreated(now).
		SetUpdated(now).
		OnConflictColumns(enthubsetting.FieldKey).
		Update(func(u *ent.HubSettingUpsert) {
			u.SetValue(value)
			u.SetUpdated(now)
		}).
		Exec(ctx)
	if err != nil {
		return mapError(err)
	}
	return nil
}

// DeleteHubSetting removes a hub setting by key.
func (s *HubSettingStore) DeleteHubSetting(ctx context.Context, key string) error {
	n, err := s.client.HubSetting.Delete().
		Where(enthubsetting.KeyEQ(key)).
		Exec(ctx)
	if err != nil {
		return mapError(err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
