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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/hubclient"
)

func TestOAuthConfig_IsConfigured(t *testing.T) {
	tests := []struct {
		name     string
		config   OAuthConfig
		expected bool
	}{
		{
			name:     "empty config",
			config:   OAuthConfig{},
			expected: false,
		},
		{
			name: "web google configured",
			config: OAuthConfig{
				Web: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "google-client-id",
						ClientSecret: "google-secret",
					},
				},
			},
			expected: true,
		},
		{
			name: "cli github configured",
			config: OAuthConfig{
				CLI: OAuthClientConfig{
					GitHub: OAuthProviderConfig{
						ClientID:     "github-client-id",
						ClientSecret: "github-secret",
					},
				},
			},
			expected: true,
		},
		{
			name: "device google configured",
			config: OAuthConfig{
				Device: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "device-google-client-id",
						ClientSecret: "device-google-secret",
					},
				},
			},
			expected: true,
		},
		{
			name: "both web and cli configured",
			config: OAuthConfig{
				Web: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "web-google-client-id",
						ClientSecret: "web-google-secret",
					},
				},
				CLI: OAuthClientConfig{
					GitHub: OAuthProviderConfig{
						ClientID:     "cli-github-client-id",
						ClientSecret: "cli-github-secret",
					},
				},
			},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.config.IsConfigured(); got != tc.expected {
				t.Errorf("IsConfigured() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestOAuthConfig_IsProviderConfigured(t *testing.T) {
	config := OAuthConfig{
		Web: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
			},
		},
		CLI: OAuthClientConfig{
			GitHub: OAuthProviderConfig{
				ClientID: "github-client-id",
				// Missing secret
			},
		},
		Device: OAuthClientConfig{
			GitHub: OAuthProviderConfig{
				ClientID:     "device-github-id",
				ClientSecret: "device-github-secret",
			},
		},
	}

	tests := []struct {
		provider string
		expected bool
	}{
		{"google", true}, // configured in web
		{"github", true}, // configured in device (cli missing secret)
		{"unknown", false},
	}

	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			if got := config.IsProviderConfigured(tc.provider); got != tc.expected {
				t.Errorf("IsProviderConfigured(%s) = %v, want %v", tc.provider, got, tc.expected)
			}
		})
	}
}

func TestOAuthService_GetAuthorizationURL(t *testing.T) {
	config := OAuthConfig{
		CLI: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "google-client-id",
				ClientSecret: "google-secret",
			},
			GitHub: OAuthProviderConfig{
				ClientID:     "github-client-id",
				ClientSecret: "github-secret",
			},
		},
	}

	service := NewOAuthService(config)

	t.Run("google authorization URL", func(t *testing.T) {
		url, err := service.GetAuthorizationURL("google", "http://localhost:18271/callback", "test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.HasPrefix(url, "https://accounts.google.com/o/oauth2/v2/auth") {
			t.Errorf("unexpected URL prefix: %s", url)
		}
		if !strings.Contains(url, "client_id=google-client-id") {
			t.Errorf("URL missing client_id: %s", url)
		}
		if !strings.Contains(url, "state=test-state") {
			t.Errorf("URL missing state: %s", url)
		}
		if !strings.Contains(url, "redirect_uri=http") {
			t.Errorf("URL missing redirect_uri: %s", url)
		}
	})

	t.Run("github authorization URL", func(t *testing.T) {
		url, err := service.GetAuthorizationURL("github", "http://localhost:18271/callback", "test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.HasPrefix(url, "https://github.com/login/oauth/authorize") {
			t.Errorf("unexpected URL prefix: %s", url)
		}
		if !strings.Contains(url, "client_id=github-client-id") {
			t.Errorf("URL missing client_id: %s", url)
		}
		if !strings.Contains(url, "state=test-state") {
			t.Errorf("URL missing state: %s", url)
		}
	})

	t.Run("unsupported provider", func(t *testing.T) {
		_, err := service.GetAuthorizationURL("unknown", "http://localhost:18271/callback", "test-state")
		if err == nil {
			t.Error("expected error for unsupported provider")
		}
	})
}

func TestOAuthService_NotConfigured(t *testing.T) {
	config := OAuthConfig{} // Empty config

	service := NewOAuthService(config)

	t.Run("google not configured", func(t *testing.T) {
		_, err := service.GetAuthorizationURL("google", "http://localhost:18271/callback", "test-state")
		if err == nil {
			t.Error("expected error when google is not configured")
		}
	})

	t.Run("github not configured", func(t *testing.T) {
		_, err := service.GetAuthorizationURL("github", "http://localhost:18271/callback", "test-state")
		if err == nil {
			t.Error("expected error when github is not configured")
		}
	})
}

func TestOAuthConfig_ClientTypeConfigs(t *testing.T) {
	tests := []struct {
		name             string
		config           OAuthConfig
		webConfigured    bool
		cliConfigured    bool
		deviceConfigured bool
		webGoogleID      string
		cliGoogleID      string
		deviceGoogleID   string
	}{
		{
			name:             "empty config",
			config:           OAuthConfig{},
			webConfigured:    false,
			cliConfigured:    false,
			deviceConfigured: false,
			webGoogleID:      "",
			cliGoogleID:      "",
			deviceGoogleID:   "",
		},
		{
			name: "web-specific config only",
			config: OAuthConfig{
				Web: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "web-google-id",
						ClientSecret: "web-secret",
					},
				},
			},
			webConfigured:    true,
			cliConfigured:    false,
			deviceConfigured: false,
			webGoogleID:      "web-google-id",
			cliGoogleID:      "",
			deviceGoogleID:   "",
		},
		{
			name: "cli-specific config only",
			config: OAuthConfig{
				CLI: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "cli-google-id",
						ClientSecret: "cli-secret",
					},
				},
			},
			webConfigured:    false,
			cliConfigured:    true,
			deviceConfigured: false,
			webGoogleID:      "",
			cliGoogleID:      "cli-google-id",
			deviceGoogleID:   "",
		},
		{
			name: "device-specific config only",
			config: OAuthConfig{
				Device: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "device-google-id",
						ClientSecret: "device-secret",
					},
				},
			},
			webConfigured:    false,
			cliConfigured:    false,
			deviceConfigured: true,
			webGoogleID:      "",
			cliGoogleID:      "",
			deviceGoogleID:   "device-google-id",
		},
		{
			name: "separate web, cli, and device configs",
			config: OAuthConfig{
				Web: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "web-google-id",
						ClientSecret: "web-secret",
					},
				},
				CLI: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "cli-google-id",
						ClientSecret: "cli-secret",
					},
				},
				Device: OAuthClientConfig{
					Google: OAuthProviderConfig{
						ClientID:     "device-google-id",
						ClientSecret: "device-secret",
					},
				},
			},
			webConfigured:    true,
			cliConfigured:    true,
			deviceConfigured: true,
			webGoogleID:      "web-google-id",
			cliGoogleID:      "cli-google-id",
			deviceGoogleID:   "device-google-id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			webCfg := tc.config.Web
			cliCfg := tc.config.CLI
			deviceCfg := tc.config.Device

			if webCfg.IsConfigured() != tc.webConfigured {
				t.Errorf("Web.IsConfigured() = %v, want %v", webCfg.IsConfigured(), tc.webConfigured)
			}
			if cliCfg.IsConfigured() != tc.cliConfigured {
				t.Errorf("CLI.IsConfigured() = %v, want %v", cliCfg.IsConfigured(), tc.cliConfigured)
			}
			if deviceCfg.IsConfigured() != tc.deviceConfigured {
				t.Errorf("Device.IsConfigured() = %v, want %v", deviceCfg.IsConfigured(), tc.deviceConfigured)
			}
			if webCfg.Google.ClientID != tc.webGoogleID {
				t.Errorf("Web.Google.ClientID = %q, want %q", webCfg.Google.ClientID, tc.webGoogleID)
			}
			if cliCfg.Google.ClientID != tc.cliGoogleID {
				t.Errorf("CLI.Google.ClientID = %q, want %q", cliCfg.Google.ClientID, tc.cliGoogleID)
			}
			if deviceCfg.Google.ClientID != tc.deviceGoogleID {
				t.Errorf("Device.Google.ClientID = %q, want %q", deviceCfg.Google.ClientID, tc.deviceGoogleID)
			}
		})
	}
}

func TestOAuthService_GetAuthorizationURLForClient(t *testing.T) {
	config := OAuthConfig{
		Web: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "web-google-id",
				ClientSecret: "web-secret",
			},
		},
		CLI: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "cli-google-id",
				ClientSecret: "cli-secret",
			},
		},
		Device: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "device-google-id",
				ClientSecret: "device-secret",
			},
		},
	}

	service := NewOAuthService(config)

	t.Run("web client uses web config", func(t *testing.T) {
		url, err := service.GetAuthorizationURLForClient(OAuthClientTypeWeb, "google", "http://example.com/callback", "test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(url, "client_id=web-google-id") {
			t.Errorf("URL should contain web client ID: %s", url)
		}
	})

	t.Run("cli client uses cli config", func(t *testing.T) {
		url, err := service.GetAuthorizationURLForClient(OAuthClientTypeCLI, "google", "http://localhost:18271/callback", "test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(url, "client_id=cli-google-id") {
			t.Errorf("URL should contain CLI client ID: %s", url)
		}
	})

	t.Run("device client uses device config", func(t *testing.T) {
		url, err := service.GetAuthorizationURLForClient(OAuthClientTypeDevice, "google", "http://localhost:18271/callback", "test-state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(url, "client_id=device-google-id") {
			t.Errorf("URL should contain device client ID: %s", url)
		}
	})
}

func TestOAuthService_DefaultProviderForClient(t *testing.T) {
	t.Run("returns google when both providers configured", func(t *testing.T) {
		service := NewOAuthService(OAuthConfig{
			CLI: OAuthClientConfig{
				Google: OAuthProviderConfig{ClientID: "g-id", ClientSecret: "g-secret"},
				GitHub: OAuthProviderConfig{ClientID: "gh-id", ClientSecret: "gh-secret"},
			},
		})
		if got := service.DefaultProviderForClient(OAuthClientTypeCLI); got != "google" {
			t.Errorf("DefaultProviderForClient(CLI) = %q, want %q", got, "google")
		}
	})

	t.Run("returns github when only github configured", func(t *testing.T) {
		service := NewOAuthService(OAuthConfig{
			CLI: OAuthClientConfig{
				GitHub: OAuthProviderConfig{ClientID: "gh-id", ClientSecret: "gh-secret"},
			},
		})
		if got := service.DefaultProviderForClient(OAuthClientTypeCLI); got != "github" {
			t.Errorf("DefaultProviderForClient(CLI) = %q, want %q", got, "github")
		}
	})

	t.Run("returns google when no providers configured", func(t *testing.T) {
		service := NewOAuthService(OAuthConfig{})
		if got := service.DefaultProviderForClient(OAuthClientTypeCLI); got != "google" {
			t.Errorf("DefaultProviderForClient(CLI) = %q, want %q", got, "google")
		}
	})
}

func TestOAuthService_IsProviderConfiguredForClient(t *testing.T) {
	config := OAuthConfig{
		Web: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "web-google-id",
				ClientSecret: "web-secret",
			},
		},
		CLI: OAuthClientConfig{
			GitHub: OAuthProviderConfig{
				ClientID:     "cli-github-id",
				ClientSecret: "cli-secret",
			},
		},
		Device: OAuthClientConfig{
			Google: OAuthProviderConfig{
				ClientID:     "device-google-id",
				ClientSecret: "device-secret",
			},
		},
	}

	service := NewOAuthService(config)

	tests := []struct {
		clientType OAuthClientType
		provider   string
		expected   bool
	}{
		{OAuthClientTypeWeb, "google", true},
		{OAuthClientTypeWeb, "github", false},
		{OAuthClientTypeCLI, "google", false},
		{OAuthClientTypeCLI, "github", true},
		{OAuthClientTypeDevice, "google", true},
		{OAuthClientTypeDevice, "github", false},
	}

	for _, tc := range tests {
		name := string(tc.clientType) + "_" + tc.provider
		t.Run(name, func(t *testing.T) {
			got := service.IsProviderConfiguredForClient(tc.clientType, tc.provider)
			if got != tc.expected {
				t.Errorf("IsProviderConfiguredForClient(%s, %s) = %v, want %v", tc.clientType, tc.provider, got, tc.expected)
			}
		})
	}
}

// TestOAuthService_IsProviderConfiguredForClient_CustomBothHalvesRequired
// pins the AND in the custom-provider branch of IsProviderConfiguredForClient
// (oauth.go): the custom provider is only "configured" when BOTH per-client
// credentials AND the provider-level endpoint URLs (OAuthConfig.Custom) are
// set. Without this coverage, collapsing the AND back to a plain
// cfg.IsProviderConfigured(provider) check would pass the rest of the suite
// silently, since every other custom-provider test configures both halves.
func TestOAuthService_IsProviderConfiguredForClient_CustomBothHalvesRequired(t *testing.T) {
	t.Run("credentials without endpoint URLs", func(t *testing.T) {
		svc := NewOAuthService(OAuthConfig{
			CLI: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "id", ClientSecret: "sec"}},
			// Custom (provider-level endpoint URLs) intentionally left empty.
		})
		if svc.IsProviderConfiguredForClient(OAuthClientTypeCLI, hubclient.OAuthProviderCustom) {
			t.Fatal("expected false: credentials set but endpoint URLs are not")
		}
	})

	t.Run("endpoint URLs without credentials", func(t *testing.T) {
		svc := NewOAuthService(OAuthConfig{
			Custom: OAuthCustomProviderConfig{
				AuthorizeURL: "https://sso.acme.com/a", TokenURL: "https://sso.acme.com/t", UserinfoURL: "https://sso.acme.com/u",
			},
			// Device.Custom credentials intentionally left empty.
		})
		if svc.IsProviderConfiguredForClient(OAuthClientTypeDevice, hubclient.OAuthProviderCustom) {
			t.Fatal("expected false: endpoint URLs set but credentials are not")
		}
	})

	t.Run("both set", func(t *testing.T) {
		svc := NewOAuthService(OAuthConfig{
			Custom: OAuthCustomProviderConfig{
				AuthorizeURL: "https://sso.acme.com/a", TokenURL: "https://sso.acme.com/t", UserinfoURL: "https://sso.acme.com/u",
			},
			Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "id", ClientSecret: "sec"}},
		})
		if !svc.IsProviderConfiguredForClient(OAuthClientTypeWeb, hubclient.OAuthProviderCustom) {
			t.Fatal("expected true: both credentials and endpoint URLs are set")
		}
	})
}

func TestCustomProviderConfigDefaults(t *testing.T) {
	c := &OAuthCustomProviderConfig{}
	if c.IsConfigured() {
		t.Fatal("empty custom config reported configured")
	}
	if got := c.EffectiveDisplayName(); got != "SSO" {
		t.Fatalf("EffectiveDisplayName = %q, want SSO", got)
	}
	if got := c.EffectiveScopes(); got != "openid email profile" {
		t.Fatalf("EffectiveScopes = %q", got)
	}
	if c.EffectiveEmailClaim() != "email" || c.EffectiveNameClaim() != "name" || c.EffectiveAvatarClaim() != "picture" {
		t.Fatal("claim defaults wrong")
	}
	c.DisplayName, c.EmailClaim = "Acme SSO", "mail"
	c.AuthorizeURL, c.TokenURL, c.UserinfoURL = "https://a", "https://t", "https://u"
	if !c.IsConfigured() || c.EffectiveDisplayName() != "Acme SSO" || c.EffectiveEmailClaim() != "mail" {
		t.Fatal("overrides not honored")
	}
}

func TestClientConfigCustomArm(t *testing.T) {
	cc := &OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "id", ClientSecret: "sec"}}
	if !cc.IsConfigured() {
		t.Fatal("custom-only client config reported unconfigured")
	}
	if !cc.IsProviderConfigured(hubclient.OAuthProviderCustom) {
		t.Fatal("IsProviderConfigured(custom) = false")
	}
	if got := cc.GetProvider(hubclient.OAuthProviderCustom); got.ClientID != "id" {
		t.Fatalf("GetProvider(custom).ClientID = %q", got.ClientID)
	}
}

func TestValidateOAuthConfigCustom(t *testing.T) {
	cases := []struct {
		name            string
		cfg             OAuthConfig
		wantErr         bool
		wantErrContains string // when non-empty, err must also contain this substring
	}{
		{"no custom anywhere", OAuthConfig{}, false, ""},
		{"creds without URLs", OAuthConfig{Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}}}, true, ""},
		{"creds with URLs", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, false, ""},
		{"http non-localhost rejected", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "http://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, ""},
		{"http localhost allowed", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "http://localhost:9999/auth", TokenURL: "http://127.0.0.1:9999/tok", UserinfoURL: "http://localhost:9999/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, false, ""},
		{"device creds without device URL", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, ""},
		{"non-http(s) scheme on localhost rejected", OAuthConfig{
			// Regression case for the bug where the scheme check was skipped
			// entirely on localhost/127.0.0.1 hosts instead of merely being
			// relaxed to also permit http (in addition to https).
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "ftp://localhost/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, "oauth.custom.authorizeUrl"},
		{"non-http(s) scheme on non-localhost rejected", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "ftp://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, "oauth.custom.authorizeUrl"},
		{"unparseable URL rejected", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "://bad", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, "oauth.custom.authorizeUrl"},
		{"empty-host URL rejected", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "not-a-url", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, "oauth.custom.authorizeUrl"},
		{"multiple invalid fields report the first in field order", OAuthConfig{
			// tokenUrl and userinfoUrl are also invalid (missing/http-non-local),
			// but authorizeUrl comes first in field order, so it must be named —
			// deterministically, not depending on map iteration order.
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "", TokenURL: "http://a.example/tok", UserinfoURL: "not-a-url"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true, "oauth.custom.authorizeUrl"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOAuthConfig(&tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOAuthConfig() err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrContains)) {
				t.Fatalf("ValidateOAuthConfig() err = %v, want containing %q", err, tc.wantErrContains)
			}
		})
	}
}

func TestCustomAuthorizationURL(t *testing.T) {
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{
			AuthorizeURL: "https://sso.acme.com/authorize",
			TokenURL:     "https://sso.acme.com/token",
			UserinfoURL:  "https://sso.acme.com/userinfo",
			Scopes:       "openid email",
		},
		Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	got, err := svc.GetAuthorizationURLForClient(OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "https://hub.example/auth/callback/custom", "state123")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if u.Scheme != "https" || u.Host != "sso.acme.com" || u.Path != "/authorize" {
		t.Fatalf("base = %s", got)
	}
	if q.Get("client_id") != "cid" || q.Get("state") != "state123" || q.Get("response_type") != "code" || q.Get("scope") != "openid email" || q.Get("redirect_uri") != "https://hub.example/auth/callback/custom" {
		t.Fatalf("params = %v", q)
	}
}

func TestCustomAuthorizationURLPreservesExistingQuery(t *testing.T) {
	// Azure AD B2C-style authorize URLs carry a tenant policy parameter
	// (?p=B2C_1_signin) that must survive alongside the standard OAuth params.
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{
			AuthorizeURL: "https://tenant.b2clogin.com/tenant/oauth2/v2.0/authorize?p=B2C_1_signin",
			TokenURL:     "https://tenant.b2clogin.com/tenant/oauth2/v2.0/token",
			UserinfoURL:  "https://tenant.b2clogin.com/tenant/openid/userinfo",
		},
		Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	got, err := svc.GetAuthorizationURLForClient(OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "https://hub.example/cb", "state123")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("result is not a valid URL: %v (%s)", err, got)
	}
	q := u.Query()
	if q.Get("p") != "B2C_1_signin" {
		t.Fatalf("pre-existing query param %q dropped: %s", "p", got)
	}
	if q.Get("client_id") != "cid" || q.Get("redirect_uri") != "https://hub.example/cb" || q.Get("response_type") != "code" || q.Get("scope") != "openid email profile" || q.Get("state") != "state123" {
		t.Fatalf("params = %v", q)
	}
}

func TestCustomExchangeAndUserinfo(t *testing.T) {
	var gotTokenReq url.Values
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			// GitHub-style endpoints only return JSON when asked; pin that
			// exchangeCodeForToken sends Accept: application/json.
			if r.Header.Get("Accept") != "application/json" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			_ = r.ParseForm()
			gotTokenReq = r.PostForm
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer"}`))
		case "/me":
			if r.Header.Get("Authorization") != "Bearer at-1" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"u-9","mail":"jordan@acme.com","displayName":"Jordan","photo":"https://img"}`))
		}
	}))
	defer idp.Close()
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{
			AuthorizeURL: idp.URL + "/authorize", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/me",
			EmailClaim: "mail", NameClaim: "displayName", AvatarClaim: "photo",
		},
		Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	info, err := svc.ExchangeCodeForClient(context.Background(), OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "code-1", "https://hub.example/cb")
	if err != nil {
		t.Fatal(err)
	}
	if gotTokenReq.Get("grant_type") != "authorization_code" || gotTokenReq.Get("code") != "code-1" ||
		gotTokenReq.Get("client_id") != "cid" || gotTokenReq.Get("client_secret") != "sec" ||
		gotTokenReq.Get("redirect_uri") != "https://hub.example/cb" {
		t.Fatalf("token request = %v", gotTokenReq)
	}
	if info.ID != "u-9" || info.Email != "jordan@acme.com" || info.DisplayName != "Jordan" || info.AvatarURL != "https://img" || info.Provider != "custom" {
		t.Fatalf("userinfo = %+v", info)
	}
}

func TestCustomUserinfoMissingEmailFails(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer"}`))
		case "/me":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"u-9","name":"NoMail"}`))
		}
	}))
	defer idp.Close()
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/me"},
		Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	_, err := svc.ExchangeCodeForClient(context.Background(), OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "code-1", "https://hub.example/cb")
	if err == nil {
		t.Fatal("expected error for missing email claim, got nil")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Fatalf("error should name the configured email claim key %q, got: %v", "email", err)
	}
}

func TestCustomExchangeEmptyAccessTokenFails(t *testing.T) {
	userinfoCalled := false
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`)) // no access_token
		case "/me":
			userinfoCalled = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"u-9","email":"jordan@acme.com"}`))
		}
	}))
	defer idp.Close()
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/me"},
		Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	if _, err := svc.ExchangeCodeForClient(context.Background(), OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "code-1", "https://hub.example/cb"); err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
	if userinfoCalled {
		t.Fatal("userinfo endpoint must not be called when the token endpoint returns no access_token")
	}
}

func TestCustomDeviceFlowUnconfigured(t *testing.T) {
	// DeviceAuthorizationURL is unset: the custom provider must refuse device
	// flow at runtime even though Task 3's ValidateOAuthConfig would already
	// have rejected this combination at server start — defence in depth.
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a/x", TokenURL: "https://a/t", UserinfoURL: "https://a/u"},
		Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid"}},
	})
	_, err := svc.RequestDeviceCode(context.Background(), OAuthClientTypeDevice, hubclient.OAuthProviderCustom)
	if err == nil || !strings.Contains(err.Error(), "does not support device-flow") {
		t.Fatalf("err = %v, want does-not-support error", err)
	}
}

func TestCustomDeviceFlow(t *testing.T) {
	polls := 0
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device":
			_, _ = w.Write([]byte(`{"device_code":"dc-1","user_code":"ABCD-1234","verification_uri":"https://sso.acme.com/activate","expires_in":900,"interval":1}`))
		case "/token":
			polls++
			switch polls {
			case 1:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			case 2:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"slow_down"}`))
			default:
				_, _ = w.Write([]byte(`{"access_token":"at-dev","token_type":"Bearer"}`))
			}
		}
	}))
	defer idp.Close()
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{
			AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/u",
			DeviceAuthorizationURL: idp.URL + "/device",
		},
		Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})

	dc, err := svc.RequestDeviceCode(context.Background(), OAuthClientTypeDevice, hubclient.OAuthProviderCustom)
	if err != nil {
		t.Fatal(err)
	}
	if dc.UserCode != "ABCD-1234" || dc.VerificationURI == "" {
		t.Fatalf("device code response = %+v", dc)
	}

	// First poll: authorization_pending maps to the codebase's existing
	// pending signal, *DeviceAuthError (see pollGoogleDeviceToken /
	// pollGitHubDeviceToken), with a nil token.
	tok1, err1 := svc.PollDeviceToken(context.Background(), OAuthClientTypeDevice, hubclient.OAuthProviderCustom, "dc-1")
	authErr1, ok := err1.(*DeviceAuthError)
	if !ok || authErr1.Code != "authorization_pending" || tok1 != nil {
		t.Fatalf("first poll: tok=%v err=%v, want *DeviceAuthError{Code: authorization_pending}", tok1, err1)
	}

	// Second poll: slow_down uses the same pending-signal convention.
	tok2, err2 := svc.PollDeviceToken(context.Background(), OAuthClientTypeDevice, hubclient.OAuthProviderCustom, "dc-1")
	authErr2, ok := err2.(*DeviceAuthError)
	if !ok || authErr2.Code != "slow_down" || tok2 != nil {
		t.Fatalf("second poll: tok=%v err=%v, want *DeviceAuthError{Code: slow_down}", tok2, err2)
	}

	// Third poll: success.
	tok3, err3 := svc.PollDeviceToken(context.Background(), OAuthClientTypeDevice, hubclient.OAuthProviderCustom, "dc-1")
	if err3 != nil || tok3 == nil || tok3.AccessToken != "at-dev" {
		t.Fatalf("third poll: tok=%+v err=%v", tok3, err3)
	}
}

func TestCustomTokenEndpointErrorFails(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
		}
	}))
	defer idp.Close()
	svc := NewOAuthService(OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/me"},
		Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	if _, err := svc.ExchangeCodeForClient(context.Background(), OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "code-1", "https://hub.example/cb"); err == nil {
		t.Fatal("expected error for non-2xx token endpoint response, got nil")
	}
}
