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

package hub

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/scion/pkg/agent/state"
	"github.com/GoogleCloudPlatform/scion/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonAdminUser creates and persists a non-admin (member) user with hub
// membership, suitable for 403 assertions against admin-only hub endpoints.
func nonAdminUser(t *testing.T, s store.Store) *store.User {
	t.Helper()
	ctx := context.Background()
	u := &store.User{
		ID:          tid("hub-gcp-nonadmin"),
		Email:       "hub-gcp-nonadmin@test.com",
		DisplayName: "Hub GCP Non-Admin",
		Role:        store.UserRoleMember,
		Status:      "active",
		Created:     time.Now(),
	}
	require.NoError(t, s.CreateUser(ctx, u))
	ensureHubMembership(ctx, s, u.ID)
	return u
}

// createHubSA registers a hub-scoped SA directly in the store and returns it.
func createHubSA(t *testing.T, srv *Server, s store.Store, email string, verified bool) *store.GCPServiceAccount {
	t.Helper()
	sa := &store.GCPServiceAccount{
		ID:                 tid("hub-sa-" + email),
		Scope:              store.ScopeHub,
		ScopeID:            srv.hubID,
		Email:              email,
		ProjectID:          projectIDFromServiceAccountEmail(email),
		CreatedBy:          "admin",
		CreatedAt:          time.Now(),
		Verified:           verified,
		VerificationStatus: "unverified",
	}
	if verified {
		sa.VerifiedAt = time.Now()
		sa.VerificationStatus = "verified"
	}
	require.NoError(t, s.CreateGCPServiceAccount(context.Background(), sa))
	return sa
}

// ============================================================================
// Hub-scoped SA CRUD (admin allowed; non-admin 403)
// ============================================================================

func TestHubGCPSA_CreateListGetDeleteVerify_AdminAllowed(t *testing.T) {
	srv, _ := testServer(t)
	srv.SetGCPTokenGenerator(&mockGCPTokenGenerator{email: "hub@test.iam.gserviceaccount.com"})

	// Create (auto-verify succeeds via mock).
	rec := doRequest(t, srv, http.MethodPost, "/api/v1/hub/gcp-service-accounts",
		map[string]string{"email": "agent@my-project.iam.gserviceaccount.com"})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var created createGCPServiceAccountResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&created))
	assert.Equal(t, store.ScopeHub, created.Scope)
	assert.Equal(t, srv.hubID, created.ScopeID)
	assert.True(t, created.Verified, "should auto-verify via mock")
	require.NotEmpty(t, created.ID)

	// List.
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/hub/gcp-service-accounts", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var list ListGCPServiceAccountsResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&list))
	require.Len(t, list.Items, 1)
	assert.Equal(t, created.ID, list.Items[0].ID)

	// Get.
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/hub/gcp-service-accounts/"+created.ID, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var got store.GCPServiceAccount
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&got))
	assert.Equal(t, created.ID, got.ID)

	// Verify.
	rec = doRequest(t, srv, http.MethodPost, "/api/v1/hub/gcp-service-accounts/"+created.ID+"/verify", nil)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// Delete.
	rec = doRequest(t, srv, http.MethodDelete, "/api/v1/hub/gcp-service-accounts/"+created.ID, nil)
	require.Equal(t, http.StatusNoContent, rec.Code)

	// Gone.
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/hub/gcp-service-accounts/"+created.ID, nil)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHubGCPSA_NonAdminForbidden(t *testing.T) {
	srv, s := testServer(t)
	srv.SetGCPTokenGenerator(&mockGCPTokenGenerator{email: "hub@test.iam.gserviceaccount.com"})
	user := nonAdminUser(t, s)
	sa := createHubSA(t, srv, s, "existing@my-project.iam.gserviceaccount.com", true)

	cases := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodGet, "/api/v1/hub/gcp-service-accounts", nil},
		{http.MethodPost, "/api/v1/hub/gcp-service-accounts", map[string]string{"email": "x@p.iam.gserviceaccount.com"}},
		{http.MethodGet, "/api/v1/hub/gcp-service-accounts/" + sa.ID, nil},
		{http.MethodPost, "/api/v1/hub/gcp-service-accounts/" + sa.ID + "/verify", nil},
		{http.MethodDelete, "/api/v1/hub/gcp-service-accounts/" + sa.ID, nil},
		{http.MethodPost, "/api/v1/hub/gcp-service-accounts/mint", map[string]string{}},
	}
	for _, tc := range cases {
		rec := doRequestAsUser(t, srv, user, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"%s %s should be 403 for non-admin; got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
	}
}

func TestHubGCPSA_Mint_AdminAllowed(t *testing.T) {
	srv, _ := testServer(t)
	mock := &mockGCPServiceAccountAdmin{}
	srv.SetGCPServiceAccountAdmin(mock)
	srv.SetGCPProjectID("test-hub-project")
	srv.SetGCPTokenGenerator(&mockGCPTokenGenerator{email: "hub-sa@test-hub-project.iam.gserviceaccount.com"})

	rec := doRequest(t, srv, http.MethodPost, "/api/v1/hub/gcp-service-accounts/mint", map[string]string{})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	var sa store.GCPServiceAccount
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&sa))
	assert.Equal(t, store.ScopeHub, sa.Scope)
	assert.Equal(t, srv.hubID, sa.ScopeID)
	assert.True(t, sa.Managed)
	assert.True(t, sa.Verified)
	assert.Len(t, mock.createdSAs, 1)
}

// ============================================================================
// Hub settings GET/PUT
// ============================================================================

func TestHubSettings_GetPutRoundTrip(t *testing.T) {
	srv, _ := testServer(t)

	// Default GET: empty.
	rec := doRequest(t, srv, http.MethodGet, "/api/v1/hub/settings", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var hs HubSettings
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hs))
	assert.Empty(t, hs.DefaultGCPIdentityMode)
	assert.Empty(t, hs.DefaultGCPIdentityServiceAccountID)

	// PUT passthrough.
	rec = doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings",
		HubSettings{DefaultGCPIdentityMode: store.GCPMetadataModePassthrough})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hs))
	assert.Equal(t, store.GCPMetadataModePassthrough, hs.DefaultGCPIdentityMode)

	// GET reflects it.
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/hub/settings", nil)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hs))
	assert.Equal(t, store.GCPMetadataModePassthrough, hs.DefaultGCPIdentityMode)

	// PUT empty clears.
	rec = doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings", HubSettings{})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doRequest(t, srv, http.MethodGet, "/api/v1/hub/settings", nil)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hs))
	assert.Empty(t, hs.DefaultGCPIdentityMode)
	assert.Empty(t, hs.DefaultGCPIdentityServiceAccountID)
}

func TestHubSettings_PutAssign_VerifiedSA(t *testing.T) {
	srv, s := testServer(t)
	sa := createHubSA(t, srv, s, "verified@my-project.iam.gserviceaccount.com", true)

	rec := doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings", HubSettings{
		DefaultGCPIdentityMode:             store.GCPMetadataModeAssign,
		DefaultGCPIdentityServiceAccountID: sa.ID,
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var hs HubSettings
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hs))
	assert.Equal(t, store.GCPMetadataModeAssign, hs.DefaultGCPIdentityMode)
	assert.Equal(t, sa.ID, hs.DefaultGCPIdentityServiceAccountID)
}

func TestHubSettings_PutAssign_UnverifiedSA_400(t *testing.T) {
	srv, s := testServer(t)
	sa := createHubSA(t, srv, s, "unverified@my-project.iam.gserviceaccount.com", false)

	rec := doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings", HubSettings{
		DefaultGCPIdentityMode:             store.GCPMetadataModeAssign,
		DefaultGCPIdentityServiceAccountID: sa.ID,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
}

func TestHubSettings_PutAssign_NonexistentSA_400(t *testing.T) {
	srv, _ := testServer(t)

	rec := doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings", HubSettings{
		DefaultGCPIdentityMode:             store.GCPMetadataModeAssign,
		DefaultGCPIdentityServiceAccountID: "does-not-exist",
	})
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
}

func TestHubSettings_PutAssign_ProjectScopedSA_400(t *testing.T) {
	srv, s := testServer(t)
	// A verified SA but project-scoped, not hub-scoped.
	sa := &store.GCPServiceAccount{
		ID:        tid("proj-sa-for-hub"),
		Scope:     store.ScopeProject,
		ScopeID:   "some-project",
		Email:     "proj@my-project.iam.gserviceaccount.com",
		ProjectID: "my-project",
		Verified:  true,
		CreatedBy: "admin",
		CreatedAt: time.Now(),
	}
	require.NoError(t, s.CreateGCPServiceAccount(context.Background(), sa))

	rec := doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings", HubSettings{
		DefaultGCPIdentityMode:             store.GCPMetadataModeAssign,
		DefaultGCPIdentityServiceAccountID: sa.ID,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
}

func TestHubSettings_PutInvalidMode_400(t *testing.T) {
	srv, _ := testServer(t)
	rec := doRequest(t, srv, http.MethodPut, "/api/v1/hub/settings",
		HubSettings{DefaultGCPIdentityMode: "bogus"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHubSettings_NonAdminForbidden(t *testing.T) {
	srv, s := testServer(t)
	user := nonAdminUser(t, s)

	rec := doRequestAsUser(t, srv, user, http.MethodGet, "/api/v1/hub/settings", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doRequestAsUser(t, srv, user, http.MethodPut, "/api/v1/hub/settings",
		HubSettings{DefaultGCPIdentityMode: store.GCPMetadataModeBlock})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ============================================================================
// Precedence chain (hub default applied in createAgentInProject)
// ============================================================================

// setHubDefault writes the hub-default GCP identity setting directly to the store.
func setHubDefault(t *testing.T, s store.Store, mode, said string) {
	t.Helper()
	ctx := context.Background()
	if mode == "" {
		require.NoError(t, ignoreNotFound(s.DeleteHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)))
	} else {
		require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, mode))
	}
	if said == "" {
		require.NoError(t, ignoreNotFound(s.DeleteHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID)))
	} else {
		require.NoError(t, s.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID, said))
	}
}

func ignoreNotFound(err error) error {
	if err == store.ErrNotFound {
		return nil
	}
	return err
}

func createAgentAndGetIdentity(t *testing.T, srv *Server, s store.Store, project *store.Project, req CreateAgentRequest) *store.GCPIdentityConfig {
	t.Helper()
	rec := doRequest(t, srv, http.MethodPost, "/api/v1/agents", req)
	require.Equal(t, http.StatusCreated, rec.Code, "create agent: %s", rec.Body.String())
	var resp CreateAgentResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Agent)
	persisted, err := s.GetAgent(context.Background(), resp.Agent.ID)
	require.NoError(t, err)
	require.NotNil(t, persisted.AppliedConfig)
	return persisted.AppliedConfig.GCPIdentity
}

func TestPrecedence_HubDefaultAssign_ProjectUnset(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	hubSA := createHubSA(t, srv, s, "hubdefault@my-project.iam.gserviceaccount.com", true)
	setHubDefault(t, s, store.GCPMetadataModeAssign, hubSA.ID)

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:      "hub-default-assign",
		ProjectID: project.ID,
		Task:      "do something",
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModeAssign, gcp.MetadataMode)
	assert.Equal(t, hubSA.ID, gcp.ServiceAccountID)
	assert.Equal(t, hubSA.Email, gcp.ServiceAccountEmail)
}

func TestPrecedence_ProjectBlock_SuppressesHubDefault(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	hubSA := createHubSA(t, srv, s, "hubdefault2@my-project.iam.gserviceaccount.com", true)
	setHubDefault(t, s, store.GCPMetadataModeAssign, hubSA.ID)

	// Project explicitly sets block.
	ctx := context.Background()
	if project.Annotations == nil {
		project.Annotations = map[string]string{}
	}
	project.Annotations[projectSettingDefaultGCPIdentityMode] = store.GCPMetadataModeBlock
	require.NoError(t, s.UpdateProject(ctx, project))

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:      "project-block",
		ProjectID: project.ID,
		Task:      "do something",
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModeBlock, gcp.MetadataMode,
		"explicit project block must suppress the hub default")
}

func TestPrecedence_ExplicitRequest_WinsOverHubDefault(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	hubSA := createHubSA(t, srv, s, "hubdefault3@my-project.iam.gserviceaccount.com", true)
	setHubDefault(t, s, store.GCPMetadataModeAssign, hubSA.ID)

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:        "explicit-block",
		ProjectID:   project.ID,
		Task:        "do something",
		GCPIdentity: &GCPIdentityAssignment{MetadataMode: store.GCPMetadataModeBlock},
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModeBlock, gcp.MetadataMode,
		"explicit request identity must win over the hub default")
}

func TestPrecedence_HubDefaultAssign_UnverifiedSA_FallsToBlock(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	hubSA := createHubSA(t, srv, s, "unverified-default@my-project.iam.gserviceaccount.com", false)
	setHubDefault(t, s, store.GCPMetadataModeAssign, hubSA.ID)

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:      "unverified-hub-default",
		ProjectID: project.ID,
		Task:      "do something",
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModeBlock, gcp.MetadataMode,
		"unverified hub-default SA must fall through to block, never a weaker mode")
}

func TestPrecedence_NoHubDefault_FallsToBlock(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:      "no-hub-default",
		ProjectID: project.ID,
		Task:      "do something",
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModeBlock, gcp.MetadataMode)
}

func TestPrecedence_HubDefaultPassthrough_ProjectUnset(t *testing.T) {
	disp := &createAgentDispatcher{createPhase: string(state.PhaseRunning)}
	srv, s, project := setupCreateAgentServer(t, disp)

	setHubDefault(t, s, store.GCPMetadataModePassthrough, "")

	gcp := createAgentAndGetIdentity(t, srv, s, project, CreateAgentRequest{
		Name:      "hub-default-passthrough",
		ProjectID: project.ID,
		Task:      "do something",
	})
	require.NotNil(t, gcp)
	assert.Equal(t, store.GCPMetadataModePassthrough, gcp.MetadataMode)
}
