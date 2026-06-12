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

	"github.com/GoogleCloudPlatform/scion/pkg/apiclient"
)

// HubSettings represents hub-level default settings. The JSON keys match the
// hub settings handler (GET/PUT /api/v1/hub/settings).
type HubSettings struct {
	// DefaultGCPIdentityMode is one of "block", "passthrough", "assign", or "".
	DefaultGCPIdentityMode string `json:"defaultGcpIdentityMode,omitempty"`
	// DefaultGCPIdentityServiceAccountID references a hub-scoped SA id; required when mode is "assign".
	DefaultGCPIdentityServiceAccountID string `json:"defaultGcpIdentityServiceAccountId,omitempty"`
}

// GetHubSettings retrieves hub-level settings.
func (c *client) GetHubSettings(ctx context.Context) (*HubSettings, error) {
	resp, err := c.get(ctx, "/api/v1/hub/settings", nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[HubSettings](resp)
}

// UpdateHubSettings updates hub-level settings.
func (c *client) UpdateHubSettings(ctx context.Context, settings *HubSettings) (*HubSettings, error) {
	resp, err := c.put(ctx, "/api/v1/hub/settings", settings, nil)
	if err != nil {
		return nil, err
	}
	return apiclient.DecodeResponse[HubSettings](resp)
}
