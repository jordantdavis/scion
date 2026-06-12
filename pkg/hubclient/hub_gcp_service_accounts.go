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

package hubclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/GoogleCloudPlatform/scion/pkg/apiclient"
)

// HubGCPServiceAccountService handles hub-scoped GCP service account operations.
// Unlike GCPServiceAccountService, it is not scoped to a project; all endpoints
// live under /api/v1/hub/gcp-service-accounts and are admin-only on the server.
type HubGCPServiceAccountService interface {
	// List returns all hub-scoped GCP service accounts.
	List(ctx context.Context) ([]GCPServiceAccount, error)

	// Get returns a specific hub-scoped GCP service account by ID.
	Get(ctx context.Context, id string) (*GCPServiceAccount, error)

	// Create registers a new hub-scoped GCP service account.
	Create(ctx context.Context, req *CreateGCPServiceAccountRequest) (*GCPServiceAccount, error)

	// Delete removes a hub-scoped GCP service account registration.
	Delete(ctx context.Context, id string) error

	// Verify triggers verification that the Hub can impersonate the SA.
	Verify(ctx context.Context, id string) (*GCPServiceAccount, error)

	// Mint creates a new GCP service account in the Hub's GCP project,
	// registered at hub scope.
	Mint(ctx context.Context, req *MintGCPServiceAccountRequest) (*GCPServiceAccount, error)
}

// hubGCPServiceAccountService is the implementation of HubGCPServiceAccountService.
type hubGCPServiceAccountService struct {
	c *client
}

func (s *hubGCPServiceAccountService) basePath() string {
	return "/api/v1/hub/gcp-service-accounts"
}

func (s *hubGCPServiceAccountService) List(ctx context.Context) ([]GCPServiceAccount, error) {
	resp, err := s.c.get(ctx, s.basePath(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, apiclient.ParseErrorResponse(resp)
	}
	var result []GCPServiceAccount
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}

func (s *hubGCPServiceAccountService) Get(ctx context.Context, id string) (*GCPServiceAccount, error) {
	path := fmt.Sprintf("%s/%s", s.basePath(), id)
	resp, err := s.c.get(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[GCPServiceAccount](resp)
}

func (s *hubGCPServiceAccountService) Create(ctx context.Context, req *CreateGCPServiceAccountRequest) (*GCPServiceAccount, error) {
	resp, err := s.c.post(ctx, s.basePath(), req, nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[GCPServiceAccount](resp)
}

func (s *hubGCPServiceAccountService) Delete(ctx context.Context, id string) error {
	path := fmt.Sprintf("%s/%s", s.basePath(), id)
	_, err := s.c.delete(ctx, path, nil)
	return err
}

func (s *hubGCPServiceAccountService) Verify(ctx context.Context, id string) (*GCPServiceAccount, error) {
	path := fmt.Sprintf("%s/%s/verify", s.basePath(), id)
	resp, err := s.c.post(ctx, path, nil, nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[GCPServiceAccount](resp)
}

func (s *hubGCPServiceAccountService) Mint(ctx context.Context, req *MintGCPServiceAccountRequest) (*GCPServiceAccount, error) {
	path := fmt.Sprintf("%s/mint", s.basePath())
	resp, err := s.c.post(ctx, path, req, nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[GCPServiceAccount](resp)
}
