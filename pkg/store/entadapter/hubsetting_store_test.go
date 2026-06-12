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

//go:build !no_sqlite

package entadapter

import (
	"context"
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/store"
	"github.com/GoogleCloudPlatform/scion/pkg/store/enttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHubSettingStore(t *testing.T) *HubSettingStore {
	t.Helper()
	client := enttest.NewClient(t)
	return NewHubSettingStore(client)
}

func TestHubSettingStore_GetMissingReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestHubSettingStore(t)

	_, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestHubSettingStore_SetThenGet(t *testing.T) {
	ctx := context.Background()
	s := newTestHubSettingStore(t)

	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, store.GCPMetadataModeAssign))

	got, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	require.NoError(t, err)
	assert.Equal(t, store.GCPMetadataModeAssign, got)
}

func TestHubSettingStore_SetOverwrites(t *testing.T) {
	ctx := context.Background()
	s := newTestHubSettingStore(t)

	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, store.GCPMetadataModeBlock))
	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, store.GCPMetadataModePassthrough))

	got, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	require.NoError(t, err)
	assert.Equal(t, store.GCPMetadataModePassthrough, got)

	// Overwrite must not create a second row for the same key.
	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, "x"))
	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, "y"))
	got, err = s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	require.NoError(t, err)
	assert.Equal(t, "y", got)
}

func TestHubSettingStore_KeysAreIndependent(t *testing.T) {
	ctx := context.Background()
	s := newTestHubSettingStore(t)

	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, store.GCPMetadataModeAssign))
	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID, "sa-uuid-123"))

	mode, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	require.NoError(t, err)
	assert.Equal(t, store.GCPMetadataModeAssign, mode)

	said, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID)
	require.NoError(t, err)
	assert.Equal(t, "sa-uuid-123", said)
}

func TestHubSettingStore_Delete(t *testing.T) {
	ctx := context.Background()
	s := newTestHubSettingStore(t)

	require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, store.GCPMetadataModeAssign))
	require.NoError(t, s.DeleteHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode))

	_, err := s.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	assert.ErrorIs(t, err, store.ErrNotFound)

	// Deleting a missing key returns ErrNotFound.
	assert.ErrorIs(t, s.DeleteHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode), store.ErrNotFound)
}
