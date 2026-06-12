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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHubGCPServiceAccounts_List(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"sa-1","scope":"hub","email":"a@example.iam.gserviceaccount.com"}]`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	out, err := client.HubGCPServiceAccounts().List(context.Background())
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(out) != 1 || out[0].ID != "sa-1" || out[0].Scope != "hub" {
		t.Errorf("unexpected result: %+v", out)
	}
}

func TestHubGCPServiceAccounts_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts/sa-1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"sa-1","email":"a@example.iam.gserviceaccount.com"}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	sa, err := client.HubGCPServiceAccounts().Get(context.Background(), "sa-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if sa.ID != "sa-1" {
		t.Errorf("unexpected id %q", sa.ID)
	}
}

func TestHubGCPServiceAccounts_Create(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req CreateGCPServiceAccountRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Email != "a@example.iam.gserviceaccount.com" {
			t.Errorf("unexpected email %q", req.Email)
		}
		if req.ProjectID != "gcp-proj" {
			t.Errorf("unexpected projectId %q", req.ProjectID)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"sa-new","email":"a@example.iam.gserviceaccount.com"}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	sa, err := client.HubGCPServiceAccounts().Create(context.Background(), &CreateGCPServiceAccountRequest{
		Email:     "a@example.iam.gserviceaccount.com",
		ProjectID: "gcp-proj",
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if sa.ID != "sa-new" {
		t.Errorf("unexpected id %q", sa.ID)
	}
}

func TestHubGCPServiceAccounts_Delete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts/sa-1" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := New(server.URL)
	if err := client.HubGCPServiceAccounts().Delete(context.Background(), "sa-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
}

func TestHubGCPServiceAccounts_Verify(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts/sa-1/verify" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"sa-1","verified":true}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	sa, err := client.HubGCPServiceAccounts().Verify(context.Background(), "sa-1")
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !sa.Verified {
		t.Errorf("expected verified=true")
	}
}

func TestHubGCPServiceAccounts_Mint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/gcp-service-accounts/mint" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req MintGCPServiceAccountRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.AccountID != "minted" {
			t.Errorf("unexpected account_id %q", req.AccountID)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"sa-minted","managed":true}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	sa, err := client.HubGCPServiceAccounts().Mint(context.Background(), &MintGCPServiceAccountRequest{
		AccountID:   "minted",
		DisplayName: "Minted",
	})
	if err != nil {
		t.Fatalf("Mint failed: %v", err)
	}
	if sa.ID != "sa-minted" || !sa.Managed {
		t.Errorf("unexpected result: %+v", sa)
	}
}

func TestGetHubSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/settings" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"defaultGcpIdentityMode":"assign","defaultGcpIdentityServiceAccountId":"sa-1"}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	settings, err := client.GetHubSettings(context.Background())
	if err != nil {
		t.Fatalf("GetHubSettings failed: %v", err)
	}
	if settings.DefaultGCPIdentityMode != "assign" {
		t.Errorf("unexpected mode %q", settings.DefaultGCPIdentityMode)
	}
	if settings.DefaultGCPIdentityServiceAccountID != "sa-1" {
		t.Errorf("unexpected sa id %q", settings.DefaultGCPIdentityServiceAccountID)
	}
}

func TestUpdateHubSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/hub/settings" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req HubSettings
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.DefaultGCPIdentityMode != "passthrough" {
			t.Errorf("unexpected mode in body %q", req.DefaultGCPIdentityMode)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"defaultGcpIdentityMode":"passthrough"}`))
	}))
	defer server.Close()

	client, _ := New(server.URL)
	out, err := client.UpdateHubSettings(context.Background(), &HubSettings{
		DefaultGCPIdentityMode: "passthrough",
	})
	if err != nil {
		t.Fatalf("UpdateHubSettings failed: %v", err)
	}
	if out.DefaultGCPIdentityMode != "passthrough" {
		t.Errorf("unexpected mode %q", out.DefaultGCPIdentityMode)
	}
}

func TestHubGCPServiceAccountsAccessor(t *testing.T) {
	client, _ := New("https://hub.example.com")
	if client.HubGCPServiceAccounts() == nil {
		t.Error("expected non-nil hub GCP service accounts service")
	}
}
