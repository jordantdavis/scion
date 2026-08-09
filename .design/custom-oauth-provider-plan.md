# Custom OAuth Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a config-driven `custom` OAuth 2.0 provider (corporate SSO) alongside Google/GitHub for hub web and CLI login, with opt-in RFC 8628 device flow.

**Architecture:** One new provider ID `custom` threaded through the existing switch-based dispatch in `pkg/hub/oauth.go` — no provider interface, no OIDC library. Provider-level endpoint URLs/claim mapping live once at `oauth.custom`; credentials follow the existing `oauth.<web|cli|device>.<provider>` matrix. Identity flows through the existing `OAuthUserInfo` seam; everything downstream (provisioning, domain gating, JWTs) is untouched.

**Tech Stack:** Go (stdlib `net/http`, `net/url`, `encoding/json`), koanf config, Lit/TypeScript web frontend. No new dependencies.

**Spec:** `.design/custom-oauth-provider.md` (committed on this branch). Read it before starting.

## Global Constraints

- Work in `/Users/jordandavis/dev/scion-jordantdavis` on branch `custom-oauth-provider`. Never touch `agents.md` (has unrelated uncommitted changes) or the `.scion/` directory.
- Go build inside worktrees/sandbox: use `go build -buildvcs=false ./...` if plain build fails with VCS errors.
- Run `gofmt` via `make fmt` before every commit; run package tests for each task; run `make ci` before the final task's commit.
- New code uses `project` vocabulary, never `grove` (see CLAUDE.md).
- Provider ID is the literal string `custom` everywhere (URLs `/auth/login/custom`, config key `custom`, constant `OAuthProviderCustom`).
- Defaults are implemented in accessor methods (`Effective*()`), NOT in koanf default registration — zero-value config must behave per spec.
- All new endpoint URL config must be validated at server start: `authorizeUrl`, `tokenUrl`, `userinfoUrl` all required if any client type has custom credentials; `https` required except for `localhost`/`127.0.0.1` hosts.
- Line numbers below were verified against fork main `056eff3b`; if they've drifted, locate by the quoted symbol names.

---

### Task 1: Provider registry constant (`hubclient`)

**Files:**
- Modify: `pkg/hubclient/auth.go` (constants at ~:29, `OAuthProviderOrder()` at ~:37, `IsKnownOAuthProvider()` below it)
- Test: `pkg/hubclient/auth_test.go`

**Interfaces:**
- Produces: `hubclient.OAuthProviderCustom = "custom"`; `OAuthProviderOrder()` returns `["google", "github", "custom"]`; `IsKnownOAuthProvider("custom") == true`. All later tasks import these.

- [ ] **Step 1: Write the failing test** — append to `pkg/hubclient/auth_test.go` (create the file with package header matching neighbors if absent):

```go
func TestCustomProviderRegistered(t *testing.T) {
	if OAuthProviderCustom != "custom" {
		t.Fatalf("OAuthProviderCustom = %q, want %q", OAuthProviderCustom, "custom")
	}
	order := OAuthProviderOrder()
	if len(order) != 3 || order[2] != OAuthProviderCustom {
		t.Fatalf("OAuthProviderOrder() = %v, want custom appended last", order)
	}
	if !IsKnownOAuthProvider("custom") {
		t.Fatal("IsKnownOAuthProvider(custom) = false, want true")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/hubclient/ -run TestCustomProviderRegistered -v`
Expected: FAIL (undefined: OAuthProviderCustom)

- [ ] **Step 3: Implement** — in `pkg/hubclient/auth.go`, add to the provider constant block, append to the slice in `OAuthProviderOrder()`. `IsKnownOAuthProvider` iterates `OAuthProviderOrder()` (verify at ~:45) so it needs no edit; if it switches on literals instead, add a `case OAuthProviderCustom`.

```go
// OAuthProviderCustom is a config-driven OAuth 2.0 provider (corporate SSO).
OAuthProviderCustom = "custom"
```

- [ ] **Step 4: Run test to verify it passes** — same command, expected PASS. Also run `go test ./pkg/hubclient/` (whole package).

- [ ] **Step 5: Commit** — `git add pkg/hubclient && git commit -m "feat(hubclient): register custom OAuth provider ID"`

---

### Task 2: Hub-side config structs and provider accessors

**Files:**
- Modify: `pkg/hub/oauth.go` (`OAuthClientConfig` at :37-40, `IsConfigured` :43, `IsProviderConfigured` :48, `GetProvider` :60, `OAuthConfig` :73)
- Test: `pkg/hub/oauth_test.go`

**Interfaces:**
- Produces (all in package `hub`):

```go
// Provider-level settings for the custom provider (mirrors pkg/config version).
type OAuthCustomProviderConfig struct {
	DisplayName            string
	AuthorizeURL           string
	TokenURL               string
	UserinfoURL            string
	DeviceAuthorizationURL string
	Scopes                 string
	EmailClaim             string
	NameClaim              string
	AvatarClaim            string
}

func (c *OAuthCustomProviderConfig) IsConfigured() bool          // AuthorizeURL != "" && TokenURL != "" && UserinfoURL != ""
func (c *OAuthCustomProviderConfig) EffectiveDisplayName() string // default "SSO"
func (c *OAuthCustomProviderConfig) EffectiveScopes() string      // default "openid email profile"
func (c *OAuthCustomProviderConfig) EffectiveEmailClaim() string  // default "email"
func (c *OAuthCustomProviderConfig) EffectiveNameClaim() string   // default "name"
func (c *OAuthCustomProviderConfig) EffectiveAvatarClaim() string // default "picture"
```

- `OAuthClientConfig` gains field `Custom OAuthProviderConfig`; its `IsConfigured`/`IsProviderConfigured`/`GetProvider` gain `custom` arms (credentials only — URL presence is checked by the service/validation layer).
- `OAuthConfig` (hub) gains field `Custom OAuthCustomProviderConfig`.

- [ ] **Step 1: Write the failing test** — append to `pkg/hub/oauth_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify failure** — `go test ./pkg/hub/ -run 'TestCustomProviderConfigDefaults|TestClientConfigCustomArm' -v` → FAIL (undefined types/fields).

- [ ] **Step 3: Implement** — add the struct + methods exactly as in Interfaces (each `Effective*` is `if c.X == "" { return "<default>" }; return c.X`; `IsConfigured` as noted). Add `Custom OAuthProviderConfig` to `OAuthClientConfig` and extend the three existing switches/or-chains with the custom arm, matching the Google/GitHub pattern exactly. Add `Custom OAuthCustomProviderConfig` to hub `OAuthConfig` with a doc comment `// Custom provider-level settings (endpoint URLs, scopes, claim mapping).`

- [ ] **Step 4: Run to verify pass** — same command → PASS; then `go test ./pkg/hub/ -run TestOAuth -v` to confirm no regression in existing oauth tests.

- [ ] **Step 5: Commit** — `git commit -am "feat(hub): custom OAuth provider config structs and accessors"`

---

### Task 3: Global config structs, env mapping, startup validation

**Files:**
- Modify: `pkg/config/hub_config.go` (`OAuthClientConfig` ~:293-303, `OAuthConfig` ~:302-315, `camelCaseFields` ~:825, `snakeCaseFields` ~:775)
- Create: validation func in `pkg/hub/oauth.go`: `ValidateOAuthConfig(cfg *OAuthConfig) error`
- Modify: `cmd/server_foreground.go` — call validation right after the `OAuthConfig: hub.OAuthConfig{...}` literal is built (~:1422); also extend that literal (see Task 4 for the copy lines).
- Test: `pkg/config/hub_config_test.go`, `pkg/hub/oauth_test.go`

**Interfaces:**
- Produces in `pkg/config`: `OAuthCustomProviderConfig` struct (same nine fields as hub's, with tags — see below); `config.OAuthConfig` gains `Custom OAuthCustomProviderConfig` (koanf `custom`); `config.OAuthClientConfig` gains `Custom OAuthProviderConfig` (koanf `custom`).
- Produces in `pkg/hub`: `func ValidateOAuthConfig(cfg *OAuthConfig) error`.

- [ ] **Step 1: Write failing config test** — append to `pkg/config/hub_config_test.go`:

```go
func TestCustomOAuthEnvOverride(t *testing.T) {
	t.Setenv("SCION_SERVER_OAUTH_CUSTOM_AUTHORIZEURL", "https://sso.example.com/authorize")
	t.Setenv("SCION_SERVER_OAUTH_CUSTOM_DISPLAYNAME", "Acme SSO")
	t.Setenv("SCION_SERVER_OAUTH_WEB_CUSTOM_CLIENTID", "web-id")
	cfg := loadTestGlobalConfig(t) // use this file's existing env-load helper; match neighboring tests
	if cfg.OAuth.Custom.AuthorizeURL != "https://sso.example.com/authorize" {
		t.Fatalf("AuthorizeURL = %q", cfg.OAuth.Custom.AuthorizeURL)
	}
	if cfg.OAuth.Custom.DisplayName != "Acme SSO" {
		t.Fatalf("DisplayName = %q", cfg.OAuth.Custom.DisplayName)
	}
	if cfg.OAuth.Web.Custom.ClientID != "web-id" {
		t.Fatalf("Web.Custom.ClientID = %q", cfg.OAuth.Web.Custom.ClientID)
	}
}
```

(Adapt the load-helper call to whatever the existing env-override tests in that file use — copy their pattern verbatim.)

- [ ] **Step 2: Run to verify failure** — `go test ./pkg/config/ -run TestCustomOAuthEnvOverride -v` → FAIL.

- [ ] **Step 3: Implement config structs** — in `pkg/config/hub_config.go`:

```go
// OAuthCustomProviderConfig holds provider-level settings for the config-driven
// custom OAuth provider (corporate SSO). Endpoint URLs are defined once here;
// per-client-type credentials live in OAuthClientConfig.Custom.
type OAuthCustomProviderConfig struct {
	DisplayName            string `json:"displayName,omitempty" yaml:"displayName,omitempty" koanf:"displayName"`
	AuthorizeURL           string `json:"authorizeUrl,omitempty" yaml:"authorizeUrl,omitempty" koanf:"authorizeUrl"`
	TokenURL               string `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty" koanf:"tokenUrl"`
	UserinfoURL            string `json:"userinfoUrl,omitempty" yaml:"userinfoUrl,omitempty" koanf:"userinfoUrl"`
	DeviceAuthorizationURL string `json:"deviceAuthorizationUrl,omitempty" yaml:"deviceAuthorizationUrl,omitempty" koanf:"deviceAuthorizationUrl"`
	Scopes                 string `json:"scopes,omitempty" yaml:"scopes,omitempty" koanf:"scopes"`
	EmailClaim             string `json:"emailClaim,omitempty" yaml:"emailClaim,omitempty" koanf:"emailClaim"`
	NameClaim              string `json:"nameClaim,omitempty" yaml:"nameClaim,omitempty" koanf:"nameClaim"`
	AvatarClaim            string `json:"avatarClaim,omitempty" yaml:"avatarClaim,omitempty" koanf:"avatarClaim"`
}
```

Add `Custom OAuthProviderConfig \`json:"custom" yaml:"custom" koanf:"custom"\`` to `config.OAuthClientConfig` and `Custom OAuthCustomProviderConfig \`json:"custom,omitempty" yaml:"custom,omitempty" koanf:"custom"\`` to `config.OAuthConfig`. Extend `camelCaseFields` (keep alphabetical order):

```go
"authorizeurl":           "authorizeUrl",
"avatarclaim":            "avatarClaim",
"deviceauthorizationurl": "deviceAuthorizationUrl",
"displayname":            "displayName",
"emailclaim":             "emailClaim",
"nameclaim":              "nameClaim",
"tokenurl":               "tokenUrl",
"userinfourl":            "userinfoUrl",
```

(Check for pre-existing entries first — e.g. `displayname` may already exist; skip duplicates.) Extend `snakeCaseFields` analogously (`"authorizeurl": "authorize_url"`, etc.) if the opsettings keyspace covers oauth keys — inspect how `client_id` is handled there and follow the same pattern; if oauth keys are absent from snakeCaseFields today, leave it alone.

- [ ] **Step 4: Run config test** — PASS.

- [ ] **Step 5: Write failing validation test** — append to `pkg/hub/oauth_test.go`:

```go
func TestValidateOAuthConfigCustom(t *testing.T) {
	cases := []struct {
		name    string
		cfg     OAuthConfig
		wantErr bool
	}{
		{"no custom anywhere", OAuthConfig{}, false},
		{"creds without URLs", OAuthConfig{Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}}}, true},
		{"creds with URLs", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, false},
		{"http non-localhost rejected", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "http://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true},
		{"http localhost allowed", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "http://localhost:9999/auth", TokenURL: "http://127.0.0.1:9999/tok", UserinfoURL: "http://localhost:9999/me"},
			Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, false},
		{"device creds without device URL", OAuthConfig{
			Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a.example/auth", TokenURL: "https://a.example/tok", UserinfoURL: "https://a.example/me"},
			Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "x", ClientSecret: "y"}},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOAuthConfig(&tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOAuthConfig() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
```

- [ ] **Step 6: Implement `ValidateOAuthConfig`** in `pkg/hub/oauth.go`:

```go
// ValidateOAuthConfig checks custom-provider invariants at server start so a
// misconfigured corporate SSO fails fast instead of at login time.
func ValidateOAuthConfig(cfg *OAuthConfig) error {
	credsSet := cfg.Web.Custom.ClientID != "" || cfg.CLI.Custom.ClientID != "" || cfg.Device.Custom.ClientID != ""
	if !credsSet {
		return nil
	}
	required := map[string]string{
		"oauth.custom.authorizeUrl": cfg.Custom.AuthorizeURL,
		"oauth.custom.tokenUrl":     cfg.Custom.TokenURL,
		"oauth.custom.userinfoUrl":  cfg.Custom.UserinfoURL,
	}
	for key, val := range required {
		if val == "" {
			return fmt.Errorf("custom OAuth provider: %s is required when custom client credentials are set", key)
		}
	}
	urls := map[string]string{
		"oauth.custom.authorizeUrl":           cfg.Custom.AuthorizeURL,
		"oauth.custom.tokenUrl":               cfg.Custom.TokenURL,
		"oauth.custom.userinfoUrl":            cfg.Custom.UserinfoURL,
		"oauth.custom.deviceAuthorizationUrl": cfg.Custom.DeviceAuthorizationURL,
	}
	for key, raw := range urls {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return fmt.Errorf("custom OAuth provider: %s is not a valid URL: %q", key, raw)
		}
		host := u.Hostname()
		if u.Scheme != "https" && host != "localhost" && host != "127.0.0.1" {
			return fmt.Errorf("custom OAuth provider: %s must use https (got %q)", key, raw)
		}
	}
	if cfg.Device.Custom.ClientID != "" && cfg.Custom.DeviceAuthorizationURL == "" {
		return fmt.Errorf("custom OAuth provider: oauth.device.custom credentials set but oauth.custom.deviceAuthorizationUrl is empty")
	}
	return nil
}
```

- [ ] **Step 7: Run** — `go test ./pkg/hub/ -run TestValidateOAuthConfigCustom -v` → PASS.

- [ ] **Step 8: Wire validation into server start** — in `cmd/server_foreground.go`, immediately after the struct literal containing `OAuthConfig: hub.OAuthConfig{...}` is assigned (the enclosing config var, ~:1422), add:

```go
if err := hub.ValidateOAuthConfig(&hubConfig.OAuthConfig); err != nil {
	return fmt.Errorf("invalid OAuth configuration: %w", err)
}
```

(Adapt the variable name and error-return idiom to the enclosing function — read a few lines around the literal first. If the enclosing function doesn't return error, use the same fatal-log pattern its neighbors use.)

- [ ] **Step 9: Build + commit** — `go build -buildvcs=false ./... && go test ./pkg/config/ ./pkg/hub/` then `git commit -am "feat(config): custom OAuth provider config surface with startup validation"`

---

### Task 4: v1 settings mirror, conversion, config→hub copy, JSON schema, example

**Files:**
- Modify: `pkg/config/settings_v1.go` (`V1OAuthConfig` :537, `V1OAuthClientConfig` :544, conversion block at :1482-1495, and the reverse global→v1 conversion — find it via `grep -n 'OAuth' pkg/config/settings_v1.go`, it mirrors the forward one)
- Modify: `pkg/config/schemas/settings-v1.schema.json` (`serverOAuth` :911, `oauthClientConfig` :920)
- Modify: `cmd/server_foreground.go` (`OAuthConfig: hub.OAuthConfig{...}` literal :1422-1453)
- Modify: `settings.yaml.example` (oauth section)
- Test: `pkg/config/settings_v1_test.go`

**Interfaces:**
- Consumes: `config.OAuthCustomProviderConfig` (Task 3), hub `OAuthConfig.Custom` (Task 2).
- Produces: `V1OAuthCustomProviderConfig` struct (snake_case keys); v1↔global round-trip carries custom settings; hub server receives them.

- [ ] **Step 1: Write the failing round-trip test** — append to `pkg/config/settings_v1_test.go`, copying the file's existing round-trip test pattern:

```go
func TestV1OAuthCustomRoundTrip(t *testing.T) {
	yamlDoc := []byte(`
version: 1
server:
  oauth:
    custom:
      display_name: "Acme SSO"
      authorize_url: "https://sso.acme.com/authorize"
      token_url: "https://sso.acme.com/token"
      userinfo_url: "https://sso.acme.com/userinfo"
      device_authorization_url: "https://sso.acme.com/device"
      scopes: "openid email"
      email_claim: "mail"
      name_claim: "displayName"
      avatar_claim: "photo"
    web:
      custom:
        client_id: "web-id"
        client_secret: "web-sec"
`)
	// Use this file's existing parse/convert helpers (match neighboring tests).
	gc := parseV1ToGlobal(t, yamlDoc)
	if gc.OAuth.Custom.AuthorizeURL != "https://sso.acme.com/authorize" || gc.OAuth.Custom.EmailClaim != "mail" {
		t.Fatalf("forward conversion lost custom provider fields: %+v", gc.OAuth.Custom)
	}
	if gc.OAuth.Web.Custom.ClientID != "web-id" {
		t.Fatalf("forward conversion lost custom web creds: %+v", gc.OAuth.Web.Custom)
	}
	v1 := convertGlobalToV1(t, gc)
	if v1.Server.OAuth.Custom == nil || v1.Server.OAuth.Custom.AuthorizeURL != "https://sso.acme.com/authorize" {
		t.Fatal("reverse conversion lost custom provider block")
	}
}
```

(`parseV1ToGlobal`/`convertGlobalToV1` are placeholders for whatever helpers the existing tests in that file actually use — read two neighboring tests and mirror them exactly. Note: the v1 `oauth` block may live under `server:` or top-level; copy whichever nesting the existing oauth tests use.)

- [ ] **Step 2: Run to verify failure** — `go test ./pkg/config/ -run TestV1OAuthCustomRoundTrip -v` → FAIL.

- [ ] **Step 3: Implement v1 structs + conversion**:

```go
// V1OAuthCustomProviderConfig holds provider-level settings for the custom
// (corporate SSO) OAuth provider.
type V1OAuthCustomProviderConfig struct {
	DisplayName            string `json:"display_name,omitempty" yaml:"display_name,omitempty" koanf:"display_name"`
	AuthorizeURL           string `json:"authorize_url,omitempty" yaml:"authorize_url,omitempty" koanf:"authorize_url"`
	TokenURL               string `json:"token_url,omitempty" yaml:"token_url,omitempty" koanf:"token_url"`
	UserinfoURL            string `json:"userinfo_url,omitempty" yaml:"userinfo_url,omitempty" koanf:"userinfo_url"`
	DeviceAuthorizationURL string `json:"device_authorization_url,omitempty" yaml:"device_authorization_url,omitempty" koanf:"device_authorization_url"`
	Scopes                 string `json:"scopes,omitempty" yaml:"scopes,omitempty" koanf:"scopes"`
	EmailClaim             string `json:"email_claim,omitempty" yaml:"email_claim,omitempty" koanf:"email_claim"`
	NameClaim              string `json:"name_claim,omitempty" yaml:"name_claim,omitempty" koanf:"name_claim"`
	AvatarClaim            string `json:"avatar_claim,omitempty" yaml:"avatar_claim,omitempty" koanf:"avatar_claim"`
}
```

Add `Custom *V1OAuthCustomProviderConfig \`json:"custom,omitempty" yaml:"custom,omitempty" koanf:"custom"\`` to `V1OAuthConfig` and `Custom *V1OAuthProviderConfig \`json:"custom,omitempty" yaml:"custom,omitempty" koanf:"custom"\`` to `V1OAuthClientConfig`. In the forward conversion block (:1482), mirror the Google/GitHub nil-guarded copies for `Custom` in all three client types, plus:

```go
if v1.OAuth.Custom != nil {
	gc.OAuth.Custom.DisplayName = v1.OAuth.Custom.DisplayName
	gc.OAuth.Custom.AuthorizeURL = v1.OAuth.Custom.AuthorizeURL
	gc.OAuth.Custom.TokenURL = v1.OAuth.Custom.TokenURL
	gc.OAuth.Custom.UserinfoURL = v1.OAuth.Custom.UserinfoURL
	gc.OAuth.Custom.DeviceAuthorizationURL = v1.OAuth.Custom.DeviceAuthorizationURL
	gc.OAuth.Custom.Scopes = v1.OAuth.Custom.Scopes
	gc.OAuth.Custom.EmailClaim = v1.OAuth.Custom.EmailClaim
	gc.OAuth.Custom.NameClaim = v1.OAuth.Custom.NameClaim
	gc.OAuth.Custom.AvatarClaim = v1.OAuth.Custom.AvatarClaim
}
```

Mirror in the reverse (global→v1) conversion: emit the `Custom` pointer blocks only when non-zero, matching how Google/GitHub blocks decide emptiness there.

- [ ] **Step 4: JSON schema** — in `settings-v1.schema.json`: add `"custom": { "$ref": "#/$defs/oauthCustomProviderConfig" }` to `serverOAuth.properties`; add `"custom": { "$ref": "#/$defs/oauthProviderConfig" }` to `oauthClientConfig.properties`; add new `$def`:

```json
"oauthCustomProviderConfig": {
  "type": "object",
  "description": "Provider-level settings for the config-driven custom OAuth provider (corporate SSO).",
  "properties": {
    "display_name": { "type": "string" },
    "authorize_url": { "type": "string" },
    "token_url": { "type": "string" },
    "userinfo_url": { "type": "string" },
    "device_authorization_url": { "type": "string" },
    "scopes": { "type": "string" },
    "email_claim": { "type": "string" },
    "name_claim": { "type": "string" },
    "avatar_claim": { "type": "string" }
  }
}
```

If schema-conformance tests exist (`go test ./pkg/config/ -run Schema`), run them.

- [ ] **Step 5: config→hub copy** — in the `OAuthConfig: hub.OAuthConfig{...}` literal in `cmd/server_foreground.go` (:1422-1453), add `Custom: hub.OAuthProviderConfig{ClientID: cfg.OAuth.Web.Custom.ClientID, ClientSecret: cfg.OAuth.Web.Custom.ClientSecret},` to each of Web/CLI/Device (with the matching `cfg.OAuth.<Type>`), and at the `hub.OAuthConfig` level:

```go
Custom: hub.OAuthCustomProviderConfig{
	DisplayName:            cfg.OAuth.Custom.DisplayName,
	AuthorizeURL:           cfg.OAuth.Custom.AuthorizeURL,
	TokenURL:               cfg.OAuth.Custom.TokenURL,
	UserinfoURL:            cfg.OAuth.Custom.UserinfoURL,
	DeviceAuthorizationURL: cfg.OAuth.Custom.DeviceAuthorizationURL,
	Scopes:                 cfg.OAuth.Custom.Scopes,
	EmailClaim:             cfg.OAuth.Custom.EmailClaim,
	NameClaim:              cfg.OAuth.Custom.NameClaim,
	AvatarClaim:            cfg.OAuth.Custom.AvatarClaim,
},
```

- [ ] **Step 6: settings.yaml.example** — extend the oauth example section with a commented custom block matching the spec's YAML example (snake_case keys as in Step 1's test doc).

- [ ] **Step 7: Run + commit** — `go test ./pkg/config/ ./pkg/hub/ && go build -buildvcs=false ./...` → `git commit -am "feat(config): v1 settings, schema, and server wiring for custom OAuth provider"`

---

### Task 5: Authorize URL, code exchange, and userinfo for custom

**Files:**
- Modify: `pkg/hub/oauth.go` — `GetAuthorizationURLForClient` switch (~:207), `ExchangeCodeForClient` switch (~:277); new funcs `getCustomAuthorizationURL`, `exchangeCustomCode`, `getCustomUserInfo`
- Test: `pkg/hub/oauth_test.go`

**Interfaces:**
- Consumes: `OAuthCustomProviderConfig` accessors (Task 2), `hubclient.OAuthProviderCustom` (Task 1), existing `OAuthUserInfo` struct (:170) and `OAuthService` fields (read the Google implementations at :228/:298/:450 first and mirror their structure, HTTP client usage, and error style exactly).
- Produces: `custom` arms in both switches; `getCustomUserInfo(ctx, accessToken) (*OAuthUserInfo, error)`.

- [ ] **Step 1: Write the failing tests**:

```go
func TestCustomAuthorizationURL(t *testing.T) {
	svc := newTestOAuthService(t, OAuthConfig{ // use/adapt this file's existing service constructor helper
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

func TestCustomExchangeAndUserinfo(t *testing.T) {
	var gotTokenReq url.Values
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
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
	svc := newTestOAuthService(t, OAuthConfig{
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
	if gotTokenReq.Get("grant_type") != "authorization_code" || gotTokenReq.Get("code") != "code-1" || gotTokenReq.Get("client_id") != "cid" {
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
	svc := newTestOAuthService(t, OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/me"},
		Web:    OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	if _, err := svc.ExchangeCodeForClient(context.Background(), OAuthClientTypeWeb, hubclient.OAuthProviderCustom, "code-1", "https://hub.example/cb"); err == nil {
		t.Fatal("expected error for missing email claim, got nil")
	}
}
```

(`newTestOAuthService` stands in for however existing tests construct `OAuthService` — likely `NewOAuthService(cfg)` or a struct literal; read `oauth_test.go`'s existing tests and match. HTTP-scheme note: these httptest URLs are `http://127.0.0.1`, which validation permits.)

- [ ] **Step 2: Run to verify failure** — `go test ./pkg/hub/ -run TestCustom -v` → FAIL (unsupported provider).

- [ ] **Step 3: Implement.** In `GetAuthorizationURLForClient`'s switch add `case hubclient.OAuthProviderCustom: return s.getCustomAuthorizationURL(clientType, redirectURI, state)`. New functions (mirror the file's receiver/helper conventions; `cfg := s.config.<ClientType>` resolution follows the Google arm's pattern):

```go
func (s *OAuthService) getCustomAuthorizationURL(clientType OAuthClientType, redirectURI, state string) (string, error) {
	creds := s.clientConfig(clientType).GetProvider(hubclient.OAuthProviderCustom) // use the file's existing per-client-type accessor
	if creds.ClientID == "" || !s.config.Custom.IsConfigured() {
		return "", fmt.Errorf("custom OAuth provider is not configured")
	}
	q := url.Values{}
	q.Set("client_id", creds.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("response_type", "code")
	q.Set("scope", s.config.Custom.EffectiveScopes())
	q.Set("state", state)
	return s.config.Custom.AuthorizeURL + "?" + q.Encode(), nil
}

func (s *OAuthService) exchangeCustomCode(ctx context.Context, clientType OAuthClientType, code, redirectURI string) (string, error) {
	creds := s.clientConfig(clientType).GetProvider(hubclient.OAuthProviderCustom)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", creds.ClientID)
	form.Set("client_secret", creds.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.Custom.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req) // use the same client the Google path uses
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("custom token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decoding custom token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("custom token endpoint returned no access_token")
	}
	return tok.AccessToken, nil
}

func (s *OAuthService) getCustomUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.Custom.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("custom userinfo endpoint returned %d: %s", resp.StatusCode, body)
	}
	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decoding custom userinfo response: %w", err)
	}
	str := func(key string) string {
		if v, ok := claims[key].(string); ok {
			return v
		}
		return ""
	}
	email := str(s.config.Custom.EffectiveEmailClaim())
	if email == "" {
		return nil, fmt.Errorf("custom userinfo response missing email claim %q", s.config.Custom.EffectiveEmailClaim())
	}
	id := str("sub")
	if id == "" {
		id = email
	}
	return &OAuthUserInfo{
		ID:          id,
		Email:       email,
		DisplayName: str(s.config.Custom.EffectiveNameClaim()),
		AvatarURL:   str(s.config.Custom.EffectiveAvatarClaim()),
		Provider:    hubclient.OAuthProviderCustom,
	}, nil
}
```

Wire `ExchangeCodeForClient`'s switch: `case hubclient.OAuthProviderCustom:` → `exchangeCustomCode` then `getCustomUserInfo`, matching how the Google arm chains exchange→userinfo. `s.clientConfig`/`s.httpClient` are placeholders for the file's actual accessors — read the Google arm and use identical mechanisms.

- [ ] **Step 4: Run to verify pass** — `go test ./pkg/hub/ -run TestCustom -v` → PASS; full package `go test ./pkg/hub/`.

- [ ] **Step 5: Commit** — `git commit -am "feat(hub): custom provider authorize/exchange/userinfo flows"`

---

### Task 6: Generic RFC 8628 device flow for custom

**Files:**
- Modify: `pkg/hub/oauth.go` — `RequestDeviceCode` switch (~:626), `PollDeviceToken` switch (~:720); new funcs `requestCustomDeviceCode`, `pollCustomDeviceToken`
- Modify: `pkg/hub/handlers_auth.go` — `getDeviceFlowUserInfo` switch (~:1121): custom arm calls `getCustomUserInfo`
- Test: `pkg/hub/oauth_test.go`

**Interfaces:**
- Consumes: `DeviceAuthorizationURL` config, existing device-flow response structs (read the Google/GitHub device funcs at :639/:682 for the shared `DeviceCodeResponse`/poll result types — reuse those exact types).
- Produces: custom arms in both device switches; "not supported" error when `DeviceAuthorizationURL` is empty.

- [ ] **Step 1: Write the failing tests**:

```go
func TestCustomDeviceFlowUnconfigured(t *testing.T) {
	svc := newTestOAuthService(t, OAuthConfig{
		Custom: OAuthCustomProviderConfig{AuthorizeURL: "https://a/x", TokenURL: "https://a/t", UserinfoURL: "https://a/u"},
		Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid"}},
	})
	_, err := svc.RequestDeviceCode(context.Background(), hubclient.OAuthProviderCustom)
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
			if polls == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"at-dev","token_type":"Bearer"}`))
		}
	}))
	defer idp.Close()
	svc := newTestOAuthService(t, OAuthConfig{
		Custom: OAuthCustomProviderConfig{
			AuthorizeURL: idp.URL + "/a", TokenURL: idp.URL + "/token", UserinfoURL: idp.URL + "/u",
			DeviceAuthorizationURL: idp.URL + "/device",
		},
		Device: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	dc, err := svc.RequestDeviceCode(context.Background(), hubclient.OAuthProviderCustom)
	if err != nil {
		t.Fatal(err)
	}
	// Field names below follow the existing shared device-code response type; adjust selectors to it.
	if dc.UserCode != "ABCD-1234" || dc.VerificationURI == "" {
		t.Fatalf("device code response = %+v", dc)
	}
	tok1, err1 := svc.PollDeviceToken(context.Background(), hubclient.OAuthProviderCustom, "dc-1")
	// First poll: authorization_pending must map to the same sentinel/pending signal the Google/GitHub arms use (read how callers of PollDeviceToken distinguish pending; assert accordingly).
	_ = tok1
	_ = err1
	tok2, err2 := svc.PollDeviceToken(context.Background(), hubclient.OAuthProviderCustom, "dc-1")
	if err2 != nil || tok2 == "" {
		t.Fatalf("second poll: tok=%q err=%v", tok2, err2)
	}
}
```

(The pending-poll assertion is intentionally written after reading the existing contract — Step 0 of this task is: read `RequestDeviceCode`/`PollDeviceToken` signatures, their response types, and the pending-state convention, then finalize these assertions to that exact contract before running.)

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement** — `requestCustomDeviceCode`: POST `DeviceAuthorizationURL` with form `client_id`, `scope` (EffectiveScopes), decode standard RFC 8628 JSON (`device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`) into the shared response type. `pollCustomDeviceToken`: POST `TokenURL` with form `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id`, `client_secret`; on JSON `error` field `authorization_pending`/`slow_down` return the pending signal per existing convention; `access_denied`/`expired_token` return terminal errors; otherwise return `access_token`. Both send `Accept: application/json` and honor non-200 with body-limited error text (same shape as Task 5 funcs). Unconfigured guard in `RequestDeviceCode`'s custom arm: `if s.config.Custom.DeviceAuthorizationURL == "" { return nil, fmt.Errorf("provider %q does not support device-flow login", hubclient.OAuthProviderCustom) }`. Add custom arm in `getDeviceFlowUserInfo` calling `getCustomUserInfo`.

- [ ] **Step 4: Run to verify pass** — `go test ./pkg/hub/ -run TestCustomDevice -v`, then whole package.

- [ ] **Step 5: Commit** — `git commit -am "feat(hub): generic RFC 8628 device flow for custom provider"`

---

### Task 7: Dispatch/validation sites and providers endpoints

**Files:**
- Modify: `pkg/hub/handlers_auth.go` — provider allow-check at ~:345 area (`provider != "google" && provider != "github"`; replace with `!hubclient.IsKnownOAuthProvider(provider)`), and the equivalent check near :238 in the same file
- Modify: `pkg/hub/web.go` — login handler provider check (~:1557-ish, `GET /auth/login/{provider}`), callback provider check (~:1614-ish), and `handleAuthProviders` (:1909-1923)
- Modify: `pkg/hub/server.go` — `logOAuthProviders` (find via grep) adds a custom line
- Modify: `pkg/hub/admin_settings.go` — masking func at :566-575 adds `if c.Custom != nil && c.Custom.ClientSecret != "" { c.Custom.ClientSecret = "********" }`
- Modify: `cmd/server_helpers.go` — debug redaction (grep `clientSecret`/`ClientSecret`) adds custom lines following the google/github pattern
- Test: `pkg/hub/web_test.go`

**Interfaces:**
- Consumes: `hubclient.IsKnownOAuthProvider` (Task 1), `IsProviderConfiguredForClient` (existing service method; custom arm must also require `s.config.Custom.IsConfigured()` — add that inside the service method's custom handling, since `handleAuthProviders` and the API providers list both flow through it).
- Produces: `GET /auth/providers` (web) response gains `"custom": bool` and `"customDisplayName": string`; `/api/v1/auth/providers` list includes `"custom"` when configured (this falls out of the registry+config work — verify, don't reimplement).

- [ ] **Step 1: Write the failing web test** — append to `pkg/hub/web_test.go`, following the file's existing `handleAuthProviders`-style test setup:

```go
func TestAuthProvidersIncludesCustom(t *testing.T) {
	ws := newTestWebServerWithOAuth(t, OAuthConfig{ // mirror existing test constructor
		Custom: OAuthCustomProviderConfig{
			DisplayName:  "Acme SSO",
			AuthorizeURL: "https://sso.acme.com/a", TokenURL: "https://sso.acme.com/t", UserinfoURL: "https://sso.acme.com/u",
		},
		Web: OAuthClientConfig{Custom: OAuthProviderConfig{ClientID: "cid", ClientSecret: "sec"}},
	})
	rr := httptest.NewRecorder()
	ws.handleAuthProviders(rr, httptest.NewRequest(http.MethodGet, "/auth/providers", nil))
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["custom"] != true {
		t.Fatalf("custom = %v, want true", resp["custom"])
	}
	if resp["customDisplayName"] != "Acme SSO" {
		t.Fatalf("customDisplayName = %v", resp["customDisplayName"])
	}
	if resp["google"] != false {
		t.Fatalf("google = %v, want false", resp["google"])
	}
}
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement `handleAuthProviders`** (web.go :1909):

```go
resp := map[string]interface{}{
	"google": false,
	"github": false,
	"custom": false,
}
// In proxy mode, no OAuth providers are active (auth is handled by the proxy).
if ws.config.AuthMode == "proxy" {
	resp["authMode"] = "proxy"
} else if ws.oauthService != nil {
	resp["google"] = ws.oauthService.IsProviderConfiguredForClient(OAuthClientTypeWeb, "google")
	resp["github"] = ws.oauthService.IsProviderConfiguredForClient(OAuthClientTypeWeb, "github")
	if ws.oauthService.IsProviderConfiguredForClient(OAuthClientTypeWeb, "custom") {
		resp["custom"] = true
		resp["customDisplayName"] = ws.oauthService.CustomDisplayName()
	}
}
```

Add `func (s *OAuthService) CustomDisplayName() string { return s.config.Custom.EffectiveDisplayName() }` to oauth.go. Inside `IsProviderConfiguredForClient`, make the custom case `clientCfg.IsProviderConfigured("custom") && s.config.Custom.IsConfigured()`.

- [ ] **Step 4: Update the string-literal provider checks** — replace `provider != "google" && provider != "github"` sites (handlers_auth.go ~:238 and ~:345, web.go login+callback) with `!hubclient.IsKnownOAuthProvider(provider)`. IMPORTANT: grep first — `grep -n '"google"' pkg/hub/handlers_auth.go pkg/hub/web.go` — and update every provider-enumeration site found, but do NOT touch the redirect-URI substring inference fallback (the `strings.Contains(req.RedirectURI, "github")` block) — it stays as-is per the spec.

- [ ] **Step 5: Mechanical sites** — `logOAuthProviders` (server.go), admin masking (admin_settings.go :569-574 pattern), `cmd/server_helpers.go` redaction: add custom lines mirroring the GitHub lines exactly. Note the admin-settings masking operates on the v1 pointer types — the new `Custom *V1OAuthProviderConfig` field from Task 4. Also check whether the admin UI types file `web/src/components/pages/admin-server-config.ts` enumerates oauth provider fields; if so add `custom` entries matching the github ones.

- [ ] **Step 6: Verify the CLI list** — run `go test ./pkg/hub/ -run Providers -v`; then grep the handler for `/api/v1/auth/providers` (handlers_auth.go, `CLIAuthProvidersResponse`) and confirm it derives the list from `OAuthProviderOrder()` + `IsProviderConfiguredForClient` (in which case custom appears automatically). If it hardcodes google/github, extend it the same way and add a test mirroring the web one.

- [ ] **Step 7: Run + commit** — `go test ./pkg/hub/ ./cmd/... && go build -buildvcs=false ./...` → `git commit -am "feat(hub): surface custom provider through auth endpoints and dispatch sites"`

---

### Task 8: Web login page

**Files:**
- Modify: `web/src/components/pages/login.ts` — state fields (near `googleEnabled`/`githubEnabled`), `fetchProviders()` (:331-345), `getProviders()` (:431-446), `renderProviderIcon()` (:474-510)
- Test: `web/src/components/pages/login.test.ts` if the repo has component tests (check `ls web/src/**/*.test.ts`); otherwise verification is typecheck + build + manual flow in Task 9

**Interfaces:**
- Consumes: `/auth/providers` response fields `custom` + `customDisplayName` (Task 7).
- Produces: a third provider button `Continue with <displayName>` linking to `/auth/login/custom`.

- [ ] **Step 1: Implement state + fetch** — add fields alongside the existing ones:

```ts
@state() private customEnabled = false;
@state() private customDisplayName = 'SSO';
```

(match the file's actual state-declaration idiom — decorators vs static properties). In `fetchProviders()` after the github line:

```ts
this.customEnabled = !!data.custom;
if (typeof data.customDisplayName === 'string' && data.customDisplayName) {
  this.customDisplayName = data.customDisplayName;
}
```

- [ ] **Step 2: Extend `getProviders()`** — append (only when enabled, so a disabled custom provider shows no grayed-out button — unlike google/github which always render; corporate SSO absence should be invisible):

```ts
...(this.customEnabled
  ? [{
      id: 'custom',
      name: this.customDisplayName,
      icon: 'custom',
      available: true,
    }]
  : []),
```

(If `getProviders()`'s return type or the render path makes conditional inclusion awkward, follow the existing pattern and include it with `available: this.customEnabled` instead — but then confirm the disabled-button copy uses the display name, not "Custom".)

- [ ] **Step 3: Icon** — in `renderProviderIcon`, add a `case 'custom':` returning an inline generic key SVG (Bootstrap Icons `key` outline, 16x16 viewBox, `fill="currentColor"`):

```ts
case 'custom':
  return html`<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
    <path d="M0 8a4 4 0 0 1 7.465-2H14a.5.5 0 0 1 .354.146l1.5 1.5a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0L13 9.207l-.646.647a.5.5 0 0 1-.708 0L11 9.207l-.646.647a.5.5 0 0 1-.708 0L9 9.207l-.532.532A4 4 0 0 1 0 8zm4-3a3 3 0 1 0 2.712 4.285.5.5 0 0 1 .452-.285h.878l.647-.646a.5.5 0 0 1 .708 0l.646.646.646-.646a.5.5 0 0 1 .708 0l.646.646.646-.646a.5.5 0 0 1 .708 0l.646.646.793-.793-1-1h-6.63a.5.5 0 0 1-.452-.285A3 3 0 0 0 4 5z"/>
  </svg>`;
```

(No `<sl-icon>` — so no `USED_ICONS`/`copy-shoelace-icons` step is needed; do not add one.)

- [ ] **Step 4: Verify** — `cd web && npm run typecheck && npm run build` (use the actual script names from `web/package.json`; run whichever exist of typecheck/lint/build). If component tests exist, add one asserting the custom button renders when the provider fetch returns `{custom: true, customDisplayName: "Acme SSO"}`.

- [ ] **Step 5: Commit** — `git add web/src && git commit -m "feat(web): custom SSO provider button on login page"`

---

### Task 9: End-to-end web flow test, docs, and CI

**Files:**
- Test: `pkg/hub/web_test.go` — full login→callback flow against a fake IdP
- Modify: `docs-site/src/content/docs/hosted/single-node/auth.md`
- Run: `make ci`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the end-to-end flow test** — locate the existing Google browser-flow test in `web_test.go` (the one driving `GET /auth/login/google` then `GET /auth/callback/google` with a stubbed exchange). Clone it for custom: fake IdP `httptest` server (token + userinfo endpoints as in Task 5's test), config with custom web creds + URLs, assert: login redirect Location points at the fake authorize URL with correct params; callback with valid state+code provisions a user (email from the mapped claim) and redirects to `returnTo`. Reuse the existing test's session/state-cookie machinery verbatim.

- [ ] **Step 2: Run** — `go test ./pkg/hub/ -run <NewTestName> -v` → PASS.

- [ ] **Step 3: Docs** — add a "Custom OAuth provider (corporate SSO)" section to `docs-site/.../auth.md` after the GitHub section: what it is (any OAuth 2.0 IdP; OIDC IdPs work by pasting the three endpoint URLs from the discovery document), full YAML example (snake_case, from the spec), env-var table (`SCION_SERVER_OAUTH_CUSTOM_*`, `SCION_SERVER_OAUTH_WEB_CUSTOM_*`), claim-mapping example for a bespoke `/me` endpoint, device-flow opt-in note, and the trust caveat sentence: "The `userinfo_url` is trust-critical: whoever controls hub configuration controls who can authenticate. Treat hub config with the same care as the IdP itself."

- [ ] **Step 4: Full CI** — `make ci` (and `make fmt` first). Fix anything it flags. Then `make ci-full` if time permits (adds web build/typecheck/golangci-lint; if golangci-lint OOMs, scope it: `GOGC=40 golangci-lint run --new-from-rev=main --concurrency=1 ./pkg/hub/... ./pkg/config/... ./pkg/hubclient/... ./cmd/...`).

- [ ] **Step 5: Commit** — `git commit -am "test(hub): end-to-end custom provider login flow; docs for corporate SSO setup"`

---

## Self-Review Notes (kept for reviewers)

- Spec coverage: config surface (T3/T4), provider logic (T5), device flow (T6), dispatch sites + endpoints (T7), frontend (T8), validation (T3), docs + e2e (T9), registry (T1), hub structs (T2). Identity-model changes, PKCE, ID-token verification: intentionally absent (spec non-goals).
- The `newTestOAuthService`/`newTestWebServerWithOAuth`/`parseV1ToGlobal` names in test snippets are stand-ins for the repo's actual test helpers; each task instructs the implementer to mirror neighboring tests. This is deliberate: the helpers exist, only their names must be read from the file.
- Line numbers verified against fork main `056eff3b` on 2026-08-08; symbols are the source of truth.
