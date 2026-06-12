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

package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/scion/pkg/store"
	"github.com/google/uuid"
)

// =============================================================================
// Hub-scoped GCP Service Accounts
//
// These mirror the project-scoped handlers in handlers_gcp_identity.go but are
// scoped to the hub instance (Scope=store.ScopeHub, ScopeID=s.hubID) and are
// admin-only. Hub-scoped SAs back the hub-wide default GCP identity (see
// handleHubSettings and the precedence chain in createAgentInProject).
// =============================================================================

// requireHubAdmin returns the authenticated admin user, or writes a 403 and
// returns nil if the caller is not an authenticated admin.
func (s *Server) requireHubAdmin(w http.ResponseWriter, r *http.Request) UserIdentity {
	user := GetUserIdentityFromContext(r.Context())
	if user == nil || user.Role() != "admin" {
		Forbidden(w)
		return nil
	}
	return user
}

// handleHubGCPServiceAccounts handles /api/v1/hub/gcp-service-accounts.
func (s *Server) handleHubGCPServiceAccounts(w http.ResponseWriter, r *http.Request) {
	if s.requireHubAdmin(w, r) == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listHubGCPServiceAccounts(w, r)
	case http.MethodPost:
		s.createHubGCPServiceAccount(w, r)
	default:
		MethodNotAllowed(w)
	}
}

// handleHubGCPServiceAccountRoutes dispatches /api/v1/hub/gcp-service-accounts/...
// to the by-id / action handler, stripping the route prefix.
func (s *Server) handleHubGCPServiceAccountRoutes(w http.ResponseWriter, r *http.Request) {
	const prefix = "/api/v1/hub/gcp-service-accounts/"
	saPath := strings.TrimPrefix(r.URL.Path, prefix)
	s.handleHubGCPServiceAccountByID(w, r, saPath)
}

// handleHubGCPServiceAccountByID handles
// /api/v1/hub/gcp-service-accounts/{id}[/action] and the collection-level
// /mint action. saPath is the portion after "gcp-service-accounts/".
func (s *Server) handleHubGCPServiceAccountByID(w http.ResponseWriter, r *http.Request, saPath string) {
	if s.requireHubAdmin(w, r) == nil {
		return
	}

	// Collection-level action: mint.
	if saPath == "mint" && r.Method == http.MethodPost {
		s.mintHubGCPServiceAccount(w, r)
		return
	}

	parts := strings.SplitN(saPath, "/", 2)
	saID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	if action == "verify" && r.Method == http.MethodPost {
		s.verifyHubGCPServiceAccount(w, r, saID)
		return
	}

	if action != "" {
		NotFound(w, "GCP Service Account action")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getHubGCPServiceAccount(w, r, saID)
	case http.MethodDelete:
		s.deleteHubGCPServiceAccount(w, r, saID)
	default:
		MethodNotAllowed(w)
	}
}

func (s *Server) createHubGCPServiceAccount(w http.ResponseWriter, r *http.Request) {
	user := GetUserIdentityFromContext(r.Context())

	var req createGCPServiceAccountRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body: "+err.Error(), nil)
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "missing required field(s): email", nil)
		return
	}

	if req.ProjectID == "" {
		req.ProjectID = projectIDFromServiceAccountEmail(req.Email)
	}
	if req.ProjectID == "" {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
			"could not infer projectId from email; please provide it explicitly", nil)
		return
	}

	sa := &store.GCPServiceAccount{
		ID:            uuid.New().String(),
		Scope:         store.ScopeHub,
		ScopeID:       s.hubID,
		Email:         req.Email,
		ProjectID:     req.ProjectID,
		DisplayName:   req.DisplayName,
		DefaultScopes: req.Scopes,
		CreatedBy:     user.ID(),
		CreatedAt:     time.Now(),
	}
	if len(sa.DefaultScopes) == 0 {
		sa.DefaultScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}
	}

	if err := s.store.CreateGCPServiceAccount(r.Context(), sa); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, ErrCodeConflict,
				"a service account with this email already exists for the hub", nil)
			return
		}
		writeErrorFromErr(w, err, "")
		return
	}

	// Auto-verify impersonation after registration (same behavior as project path).
	resp := createGCPServiceAccountResponse{GCPServiceAccount: *sa}
	if s.gcpTokenGenerator != nil {
		if err := s.gcpTokenGenerator.VerifyImpersonation(r.Context(), sa.Email); err != nil {
			sa.Verified = false
			sa.VerificationStatus = "failed"
			sa.VerificationError = err.Error()
			_ = s.store.UpdateGCPServiceAccount(r.Context(), sa)
			resp.GCPServiceAccount = *sa
			resp.VerificationFailed = true
			resp.VerificationDetails = &verificationFailedDetails{
				HubServiceAccountEmail: s.gcpTokenGenerator.ServiceAccountEmail(),
				TargetEmail:            sa.Email,
			}
		} else {
			sa.Verified = true
			sa.VerifiedAt = time.Now()
			sa.VerificationStatus = "verified"
			sa.VerificationError = ""
			_ = s.store.UpdateGCPServiceAccount(r.Context(), sa)
			resp.GCPServiceAccount = *sa
		}
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) listHubGCPServiceAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sas, err := s.store.ListGCPServiceAccounts(ctx, store.GCPServiceAccountFilter{
		Scope:   store.ScopeHub,
		ScopeID: s.hubID,
	})
	if err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	if sas == nil {
		sas = []store.GCPServiceAccount{}
	}

	items := make([]GCPServiceAccountWithCapabilities, len(sas))
	for i := range sas {
		items[i] = GCPServiceAccountWithCapabilities{GCPServiceAccount: sas[i]}
	}

	// Include mint quota info when minting is configured.
	var mintQuota *GCPMintQuotaInfo
	if s.gcpIAMAdmin != nil && s.config.GCPProjectID != "" {
		managed := true
		hubCount, _ := s.store.CountGCPServiceAccounts(ctx, store.GCPServiceAccountFilter{
			Scope:   store.ScopeHub,
			ScopeID: s.hubID,
			Managed: &managed,
		})
		globalCount, _ := s.store.CountGCPServiceAccounts(ctx, store.GCPServiceAccountFilter{
			Managed: &managed,
		})
		mintQuota = &GCPMintQuotaInfo{
			ProjectMinted: hubCount,
			ProjectCap:    s.config.GCPMintCapPerProject,
			GlobalMinted:  globalCount,
			GlobalCap:     s.config.GCPMintCapGlobal,
		}
	}

	writeJSON(w, http.StatusOK, ListGCPServiceAccountsResponse{
		Items:     items,
		MintQuota: mintQuota,
	})
}

// getHubScopedSA loads a SA by ID and confirms it is hub-scoped for this hub.
// Writes a 404 and returns nil if missing or not hub-scoped.
func (s *Server) getHubScopedSA(w http.ResponseWriter, r *http.Request, saID string) *store.GCPServiceAccount {
	sa, err := s.store.GetGCPServiceAccount(r.Context(), saID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			NotFound(w, "GCP Service Account")
			return nil
		}
		writeErrorFromErr(w, err, "")
		return nil
	}
	if sa.Scope != store.ScopeHub || sa.ScopeID != s.hubID {
		NotFound(w, "GCP Service Account")
		return nil
	}
	return sa
}

func (s *Server) getHubGCPServiceAccount(w http.ResponseWriter, r *http.Request, saID string) {
	sa := s.getHubScopedSA(w, r, saID)
	if sa == nil {
		return
	}
	writeJSON(w, http.StatusOK, sa)
}

func (s *Server) deleteHubGCPServiceAccount(w http.ResponseWriter, r *http.Request, saID string) {
	sa := s.getHubScopedSA(w, r, saID)
	if sa == nil {
		return
	}
	if err := s.store.DeleteGCPServiceAccount(r.Context(), saID); err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) verifyHubGCPServiceAccount(w http.ResponseWriter, r *http.Request, saID string) {
	sa := s.getHubScopedSA(w, r, saID)
	if sa == nil {
		return
	}

	if s.gcpTokenGenerator != nil {
		if err := s.gcpTokenGenerator.VerifyImpersonation(r.Context(), sa.Email); err != nil {
			sa.Verified = false
			sa.VerificationStatus = "failed"
			sa.VerificationError = err.Error()
			_ = s.store.UpdateGCPServiceAccount(r.Context(), sa)

			details := map[string]interface{}{
				"hubServiceAccountEmail": s.gcpTokenGenerator.ServiceAccountEmail(),
				"targetEmail":            sa.Email,
			}
			writeError(w, http.StatusBadGateway, "gcp_verification_failed",
				"Failed to verify impersonation: "+err.Error(), details)
			return
		}
	}

	sa.Verified = true
	sa.VerifiedAt = time.Now()
	sa.VerificationStatus = "verified"
	sa.VerificationError = ""

	if err := s.store.UpdateGCPServiceAccount(r.Context(), sa); err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, sa)
}

func (s *Server) mintHubGCPServiceAccount(w http.ResponseWriter, r *http.Request) {
	user := GetUserIdentityFromContext(r.Context())

	if s.gcpIAMAdmin == nil {
		writeError(w, http.StatusServiceUnavailable, ErrCodeUnavailable,
			"GCP service account minting is not configured on this Hub", nil)
		return
	}

	hubGCPProjectID := s.config.GCPProjectID
	if hubGCPProjectID == "" {
		writeError(w, http.StatusServiceUnavailable, ErrCodeUnavailable,
			"GCP project ID is not configured for service account minting", nil)
		return
	}

	var req mintGCPServiceAccountRequest
	if r.Body != nil {
		if err := readJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body: "+err.Error(), nil)
			return
		}
	}

	// Enforce per-hub mint cap (uses the same per-scope cap as projects).
	managed := true
	hubCount, err := s.store.CountGCPServiceAccounts(r.Context(), store.GCPServiceAccountFilter{
		Scope:   store.ScopeHub,
		ScopeID: s.hubID,
		Managed: &managed,
	})
	if err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	if s.config.GCPMintCapPerProject > 0 && hubCount >= s.config.GCPMintCapPerProject {
		writeError(w, http.StatusConflict, ErrCodeConflict,
			fmt.Sprintf("per-hub mint limit reached (%d/%d)", hubCount, s.config.GCPMintCapPerProject), nil)
		return
	}

	// Enforce global mint cap.
	if s.config.GCPMintCapGlobal > 0 {
		globalCount, err := s.store.CountGCPServiceAccounts(r.Context(), store.GCPServiceAccountFilter{
			Managed: &managed,
		})
		if err != nil {
			writeErrorFromErr(w, err, "")
			return
		}
		if globalCount >= s.config.GCPMintCapGlobal {
			writeError(w, http.StatusConflict, ErrCodeConflict,
				fmt.Sprintf("global mint limit reached (%d/%d)", globalCount, s.config.GCPMintCapGlobal), nil)
			return
		}
	}

	// Generate or validate the account ID.
	var accountID string
	if req.AccountID != "" {
		accountID = "scion-" + slugifyAccountID(req.AccountID)
	} else {
		accountID, err = generateRandomAccountID()
		if err != nil {
			writeErrorFromErr(w, err, "")
			return
		}
	}

	if len(accountID) < 6 || len(accountID) > 30 {
		writeError(w, http.StatusBadRequest, ErrCodeValidationError,
			fmt.Sprintf("account ID %q must be 6-30 characters (got %d)", accountID, len(accountID)), nil)
		return
	}
	if !gcpSAAccountIDRegexp.MatchString(accountID) {
		writeError(w, http.StatusBadRequest, ErrCodeValidationError,
			fmt.Sprintf("account ID %q must match [a-z][a-z0-9-]*[a-z0-9]", accountID), nil)
		return
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = "Scion agent (hub default)"
	}
	description := req.Description
	if description == "" {
		description = fmt.Sprintf("Minted by Scion Hub for hub %s by user %s", s.hubID, user.ID())
	}

	saEmail, _, err := s.gcpIAMAdmin.CreateServiceAccount(r.Context(), hubGCPProjectID, accountID, displayName, description)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "409") || strings.Contains(errStr, "alreadyExists") {
			writeError(w, http.StatusConflict, ErrCodeConflict,
				fmt.Sprintf("service account %s already exists in project %s", accountID, hubGCPProjectID), nil)
			return
		}
		slog.Error("Hub GCP SA mint: failed to create service account",
			"hub_gcp_project_id", hubGCPProjectID, "account_id", accountID, "error", err)
		writeError(w, http.StatusBadGateway, ErrCodeRuntimeError,
			"failed to create GCP service account: "+err.Error(), nil)
		return
	}

	// Grant token creator role to Hub SA on the new SA.
	if s.gcpTokenGenerator != nil {
		hubEmail := s.gcpTokenGenerator.ServiceAccountEmail()
		if hubEmail != "" {
			member := "serviceAccount:" + hubEmail
			if err := s.gcpIAMAdmin.SetIAMPolicy(r.Context(), saEmail, member, "roles/iam.serviceAccountTokenCreator"); err != nil {
				slog.Error("Hub GCP SA mint: failed to set IAM policy",
					"sa_email", saEmail, "hub_email", hubEmail, "error", err)
			}
		}
	}

	sa := &store.GCPServiceAccount{
		ID:                 uuid.New().String(),
		Scope:              store.ScopeHub,
		ScopeID:            s.hubID,
		Email:              saEmail,
		ProjectID:          hubGCPProjectID,
		DisplayName:        displayName,
		DefaultScopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
		Verified:           true,
		VerifiedAt:         time.Now(),
		VerificationStatus: "verified",
		CreatedBy:          user.ID(),
		CreatedAt:          time.Now(),
		Managed:            true,
		ManagedBy:          s.config.HubID,
	}

	if err := s.store.CreateGCPServiceAccount(r.Context(), sa); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, ErrCodeConflict,
				"a service account with this email already exists for the hub", nil)
			return
		}
		writeErrorFromErr(w, err, "")
		return
	}

	LogGCPTokenGeneration(r.Context(), s.auditLogger, GCPTokenEventMintSA,
		"", "", saEmail, sa.ID, true, "")

	slog.Info("Hub GCP SA minted",
		"hub_id", s.hubID, "sa_id", sa.ID, "email", saEmail,
		"account_id", accountID, "user", user.ID())

	writeJSON(w, http.StatusCreated, sa)
}

// =============================================================================
// Hub settings (hub-wide default GCP identity)
// =============================================================================

// HubSettings is the request/response shape for GET/PUT /api/v1/hub/settings.
type HubSettings struct {
	DefaultGCPIdentityMode             string `json:"defaultGcpIdentityMode"`
	DefaultGCPIdentityServiceAccountID string `json:"defaultGcpIdentityServiceAccountId"`
}

// handleHubSettings handles GET/PUT /api/v1/hub/settings. Admin-only.
func (s *Server) handleHubSettings(w http.ResponseWriter, r *http.Request) {
	if s.requireHubAdmin(w, r) == nil {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getHubSettings(w, r)
	case http.MethodPut:
		s.putHubSettings(w, r)
	default:
		MethodNotAllowed(w)
	}
}

// hubSettingsFromStore reads the hub default GCP identity settings from the
// HubSetting key/value store. Missing keys resolve to empty strings.
func (s *Server) hubSettingsFromStore(r *http.Request) (HubSettings, error) {
	var hs HubSettings
	mode, err := s.store.GetHubSetting(r.Context(), store.HubSettingDefaultGCPIdentityMode)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return hs, err
	}
	hs.DefaultGCPIdentityMode = mode

	said, err := s.store.GetHubSetting(r.Context(), store.HubSettingDefaultGCPIdentityServiceAccountID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return hs, err
	}
	hs.DefaultGCPIdentityServiceAccountID = said
	return hs, nil
}

func (s *Server) getHubSettings(w http.ResponseWriter, r *http.Request) {
	hs, err := s.hubSettingsFromStore(r)
	if err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, hs)
}

func (s *Server) putHubSettings(w http.ResponseWriter, r *http.Request) {
	var req HubSettings
	if err := readJSON(r, &req); err != nil {
		BadRequest(w, "Invalid request body: "+err.Error())
		return
	}

	// Validate mode.
	switch req.DefaultGCPIdentityMode {
	case "", store.GCPMetadataModeBlock, store.GCPMetadataModePassthrough, store.GCPMetadataModeAssign:
		// ok
	default:
		writeError(w, http.StatusBadRequest, ErrCodeValidationError,
			fmt.Sprintf("invalid defaultGcpIdentityMode %q (must be one of block, passthrough, assign, or empty)", req.DefaultGCPIdentityMode), nil)
		return
	}

	// For assign mode, the referenced SA must exist, be hub-scoped, and verified.
	if req.DefaultGCPIdentityMode == store.GCPMetadataModeAssign {
		if req.DefaultGCPIdentityServiceAccountID == "" {
			writeError(w, http.StatusBadRequest, ErrCodeValidationError,
				"defaultGcpIdentityServiceAccountId is required when mode is \"assign\"", nil)
			return
		}
		sa, err := s.store.GetGCPServiceAccount(r.Context(), req.DefaultGCPIdentityServiceAccountID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusBadRequest, ErrCodeValidationError,
					"defaultGcpIdentityServiceAccountId does not reference an existing service account", nil)
				return
			}
			writeErrorFromErr(w, err, "")
			return
		}
		if sa.Scope != store.ScopeHub || sa.ScopeID != s.hubID {
			writeError(w, http.StatusBadRequest, ErrCodeValidationError,
				"defaultGcpIdentityServiceAccountId must reference a hub-scoped service account", nil)
			return
		}
		if !sa.Verified {
			writeError(w, http.StatusBadRequest, ErrCodeValidationError,
				"the referenced service account must be verified before it can be set as the hub default", nil)
			return
		}
	}

	ctx := r.Context()

	// Persist the mode: empty clears the key.
	if req.DefaultGCPIdentityMode == "" {
		if err := s.clearHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode); err != nil {
			writeErrorFromErr(w, err, "")
			return
		}
	} else if err := s.store.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode, req.DefaultGCPIdentityMode); err != nil {
		writeErrorFromErr(w, err, "")
		return
	}

	// Persist the SA id. Only meaningful for assign; clear it otherwise.
	if req.DefaultGCPIdentityMode == store.GCPMetadataModeAssign {
		if err := s.store.SetHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID, req.DefaultGCPIdentityServiceAccountID); err != nil {
			writeErrorFromErr(w, err, "")
			return
		}
	} else if err := s.clearHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID); err != nil {
		writeErrorFromErr(w, err, "")
		return
	}

	hs, err := s.hubSettingsFromStore(r)
	if err != nil {
		writeErrorFromErr(w, err, "")
		return
	}
	writeJSON(w, http.StatusOK, hs)
}

// clearHubSetting deletes a hub setting key, treating "not found" as success.
func (s *Server) clearHubSetting(ctx context.Context, key string) error {
	if err := s.store.DeleteHubSetting(ctx, key); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// resolveHubDefaultGCPIdentity computes the GCP identity an agent should receive
// from the hub-wide default (last step before the secure "block" fallback in the
// precedence chain). It reads the HubSetting keys for the default mode and SA id.
//
// Rules:
//   - mode "" / "block" / unknown  -> block (secure default).
//   - mode "passthrough"           -> passthrough.
//   - mode "assign"                -> the configured hub-scoped SA, but only if
//     it exists, is hub-scoped for this hub, and is Verified. An invalid or
//     unverified SA falls through to block (never to a weaker mode).
//
// This never returns nil — callers can assign the result directly.
func (s *Server) resolveHubDefaultGCPIdentity(ctx context.Context) *store.GCPIdentityConfig {
	block := &store.GCPIdentityConfig{MetadataMode: store.GCPMetadataModeBlock}

	mode, err := s.store.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityMode)
	if err != nil {
		// Missing key (ErrNotFound) or any read error -> secure default.
		return block
	}

	switch mode {
	case store.GCPMetadataModePassthrough:
		return &store.GCPIdentityConfig{MetadataMode: store.GCPMetadataModePassthrough}
	case store.GCPMetadataModeAssign:
		said, err := s.store.GetHubSetting(ctx, store.HubSettingDefaultGCPIdentityServiceAccountID)
		if err != nil || said == "" {
			return block
		}
		sa, err := s.store.GetGCPServiceAccount(ctx, said)
		if err != nil || sa.Scope != store.ScopeHub || sa.ScopeID != s.hubID || !sa.Verified {
			// Missing / not hub-scoped / unverified -> block, never weaker.
			return block
		}
		return &store.GCPIdentityConfig{
			MetadataMode:        store.GCPMetadataModeAssign,
			ServiceAccountID:    sa.ID,
			ServiceAccountEmail: sa.Email,
			ProjectID:           sa.ProjectID,
		}
	default:
		return block
	}
}
