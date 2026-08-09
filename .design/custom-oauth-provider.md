# Custom OAuth Provider (corporate SSO login)

## Status: Design approved in session (2026-08-08) — ready for implementation planning

## Problem Statement

Hub web-based login supports exactly two OAuth providers — Google and GitHub —
hardcoded as string switches throughout `pkg/hub/oauth.go`, `handlers_auth.go`,
and `web.go`. Organizations running a corporate SSO built on OAuth 2.0 (Okta,
Entra ID, Keycloak, Auth0, or homegrown) cannot log in with it; their only
option today is fronting the hub with Google IAP via proxy mode.

`auth-proxy-mode.md:17-19` already describes the OAuth mode as "full
browser/CLI/device flows against Google and GitHub (plus a partial custom OIDC
provider)" — but no such provider exists anywhere in the tree or its git
history. This design lands the missing piece, as a plain config-driven OAuth 2.0
provider rather than a full OIDC client.

## Goals

- One additional provider with the fixed ID `custom`, configured entirely from
  YAML/env: authorize/token/userinfo endpoint URLs, scopes, display name, and
  userinfo claim mapping.
- Web browser flow and CLI localhost-callback flow; device flow (RFC 8628) when
  a `deviceAuthorizationUrl` is configured.
- Minimal, mechanical diffs to the Google/GitHub paths (new switch arms only) —
  easy to review, and groundwork for a later provider-interface refactor.
- Reuse the entire provider-agnostic pipeline downstream of `OAuthUserInfo`:
  provisioning, `authorizedDomains`, `adminEmails`, `userAccessMode`, JWT
  issuance, sessions.

## Non-Goals

- OIDC discovery, ID-token/JWKS verification, nonce, or PKCE. Identity comes
  from the userinfo endpoint over TLS, exactly as the existing Google path does
  (it never verifies ID tokens either — see `pkg/hub/oauth.go:450`).
- Multiple simultaneous custom providers. One `custom` slot per hub.
- SAML or a generic arbitrary-IdP framework (consistent with the non-goal in
  `auth-proxy-mode.md:49`).
- Provider+subject identity columns on `store.User`. Email remains the join
  key; acceptable while a hub runs a single corporate IdP (flagged as future
  work below).
- A provider interface / config-map refactor of Google and GitHub. That is the
  natural follow-up once `custom` proves the shape.

## Background

- Current OAuth implementation: `pkg/hub/oauth.go` (endpoint constants,
  per-provider switches at :210, :280, :629, :723), normalized into
  `OAuthUserInfo{ID, Email, DisplayName, AvatarURL, Provider}` (:170) — the
  provider-agnostic seam this design plugs into.
- Provider registry: `pkg/hubclient/auth.go:29-51` (constants,
  `OAuthProviderOrder()`, `IsKnownOAuthProvider()`).
- Config matrix: `oauth.<web|cli|device>.<google|github>.{clientId,clientSecret}`
  in `pkg/config/hub_config.go:284-309`, mirrored in `settings_v1.go:470-488`,
  JSON schema `pkg/config/schemas/settings-v1.schema.json`, env mapping in
  `hub_config.go` (`envKeyToConfigKey` + `camelCaseFields`).
- Related design docs: `auth-proxy-mode.md` (proxy-mode alternative for
  enterprise IdPs; pluggable-proxy goal at :39), `ha-oidc.md` (transport-layer
  OIDC for machine clients traversing IAP — unrelated to user login despite the
  name).
- No existing design doc roadmaps additional OAuth providers. The nearest
  prior intent is `hosted/auth/auth-overview.md:49`, whose designed User model
  reads `Provider string // "google", "github", etc.` alongside a `ProviderID`
  field — anticipating more providers and provider-scoped identity. Neither
  field was ever implemented (`store.User` is email-only), which is exactly
  the gap Future Work item 2 tracks. `hosted/auth/oauth-setup.md` and
  `auth-milestones.md` enumerate only Google/GitHub with no expansion plans.

## Design

### Config

Two additions to the existing surface:

```yaml
oauth:
  custom:                      # NEW provider-level block, defined once
    displayName: "Acme SSO"    # optional; default "SSO"
    authorizeUrl: https://sso.acme.com/oauth2/authorize
    tokenUrl: https://sso.acme.com/oauth2/token
    userinfoUrl: https://sso.acme.com/oauth2/userinfo
    deviceAuthorizationUrl: "" # optional; enables device flow when set
    scopes: "openid email profile"   # default
    emailClaim: "email"        # optional; defaults shown
    nameClaim: "name"          # top-level JSON keys only (no dotted paths)
    avatarClaim: "picture"
  web:
    custom: {clientId: "...", clientSecret: "..."}   # NEW arm in existing matrix
  cli:
    custom: {clientId: "...", clientSecret: "..."}
  device:
    custom: {clientId: "...", clientSecret: "..."}
```

- New `OAuthCustomProviderConfig` struct at `oauth.custom` in
  `pkg/config/hub_config.go`; `Custom OAuthProviderConfig` field added to
  `OAuthClientConfig` (web/cli/device arms).
- Mirrored in `settings_v1.go` (snake_case: `authorize_url`, `client_id`, …)
  with two-way conversion; JSON schema `$defs` updated;
  `settings.yaml.example` gains a commented example.
- Env vars follow the existing derivation: `SCION_SERVER_OAUTH_CUSTOM_AUTHORIZEURL`,
  `SCION_SERVER_OAUTH_CUSTOM_DISPLAYNAME`, `SCION_SERVER_OAUTH_WEB_CUSTOM_CLIENTID`,
  etc. (`camelCaseFields` table extended).
- Admin settings API masks `clientSecret` for custom exactly as for
  google/github (`pkg/hub/admin_settings.go`); debug redaction in
  `cmd/server_helpers.go` likewise.

**Startup validation** (fail server start, not login time): if any client type
has custom credentials set, then `authorizeUrl`, `tokenUrl`, and `userinfoUrl`
are all required and must be `https` (plain `http` permitted only for localhost,
to allow dev/testing against a local fake IdP). `deviceAuthorizationUrl`, when
set, follows the same URL rules. Device-type custom credentials without a
`deviceAuthorizationUrl` is a validation error.

### Hub provider logic

New arms in the existing switches in `pkg/hub/oauth.go` (config mirror structs
extended the same way):

- **Authorize URL** (`GetAuthorizationURLForClient`): built from `authorizeUrl`
  with standard `client_id`, `redirect_uri`, `state`, `response_type=code`, and
  the configured `scopes`. No Google-style `access_type`/`prompt` extras.
- **Code exchange** (`ExchangeCodeForClient`): reuses the existing generic
  `exchangeCodeForToken` (`oauth.go:356`), sending `Accept: application/json`
  (harmless for RFC-compliant servers, required by GitHub-style ones).
- **Userinfo**: new `getCustomUserInfo` — GET `userinfoUrl` with
  `Authorization: Bearer <access token>`; extract email/name/avatar via the
  configured claim keys; `ID` from `sub`, falling back to email. Missing/empty
  email is a hard login failure with a log line naming the claim key consulted.
- **Device flow**: when `deviceAuthorizationUrl` is set, a generic RFC 8628
  implementation (standard `device_code`/`user_code`/`verification_uri` fields;
  standard `authorization_pending`/`slow_down` error handling — none of
  Google's `verification_url` or GitHub's 200-with-error-body quirks). When
  unset, `RequestDeviceCode` returns a clear "provider does not support
  device-flow login" error.

### Registry and dispatch sites

- `pkg/hubclient/auth.go`: add `OAuthProviderCustom = "custom"`; append last in
  `OAuthProviderOrder()` (google/github keep precedence when co-configured; a
  hub with only custom configured gets it as the default automatically); add to
  `IsKnownOAuthProvider()`.
- Provider-validation sites accept `custom` when configured:
  `handlers_auth.go:238`, `:345` (`getDeviceFlowUserInfo` switch at
  `:1121-1128`), `web.go:1557`, `web.go:1614`.
- The redirect-URI substring inference fallback (`handlers_auth.go:334`) is
  left untouched: custom logins always carry an explicit `provider`, and the
  fallback continues to default to google/github.
- `logOAuthProviders` (`server.go:3056`) and the config→hub copy
  (`cmd/server_foreground.go:1303-1334`) gain the corresponding lines.

### API surface

- Web `GET /auth/providers` (`web.go:1843`): response gains
  `custom: bool` and `customDisplayName: string`.
- API `GET /api/v1/auth/providers` (`CLIAuthProvidersResponse`): the
  `providers` string list includes `"custom"` when configured. The CLI already
  consumes this list dynamically (`cmd/hub_auth.go:287-310`) and will display
  the raw name `custom`; a label map is deferred to the provider-abstraction
  follow-up rather than changing the response shape now.

### Frontend

- `web/src/components/pages/login.ts`: `getProviders()` gains a third entry
  gated on `data.custom`; button label "Continue with {customDisplayName}";
  generic key-icon SVG inlined alongside the existing Google/GitHub SVGs (no
  new Shoelace icon, so no `USED_ICONS` change).

### Identity & security posture

- Unchanged: email is the join key; `checkUserAuthorized` gates
  domains/invites/suspension; roles from `adminEmails`; re-evaluated on login
  and token refresh.
- `userinfoUrl` is trust-critical config: whoever controls hub config controls
  authentication. Same posture as the existing Google flow; stated plainly in
  the docs.
- HTTPS enforcement (above) prevents accidental plaintext identity fetches.

## Testing

- Table-driven unit tests: authorize-URL construction; claim mapping (defaults,
  overridden keys, missing email → error); config round-trips (v1 YAML ↔
  global config, env-var overrides, JSON-schema validation); startup validation
  errors (missing URLs, http on non-localhost, device creds without device URL).
- `httptest` fake IdP exercising the full code-exchange → userinfo path, and
  the generic device flow (pending → success, `slow_down`), mirroring existing
  `oauth_test.go` patterns.
- Web login/callback flow test for `custom` mirroring the existing Google flow
  test in `web_test.go`; `/auth/providers` (both servers) response-shape tests.
- Existing test fixtures constructing `OAuthClientConfig{Google:…, GitHub:…}`
  literally are unaffected (new field is additive).

## Documentation

- New "Custom OAuth provider" section in
  `docs-site/src/content/docs/hosted/single-node/auth.md`: YAML + env-var
  setup, claim-mapping examples (OIDC-compliant IdP vs bespoke `/me`
  endpoint), device-flow opt-in, and the userinfo-trust caveat.

## Future Work (explicitly out of scope)

1. **Provider interface refactor**: fold Google, GitHub, and custom behind a
   `Provider` interface with a config map keyed by provider ID — removes the
   ~20 switch sites and allows multiple custom providers. This design keeps
   diffs mechanical precisely so that refactor stays tractable.
2. **`(provider, subject)` identity columns** on `store.User` to stop keying
   identity on email alone — matters if a hub ever runs multiple IdPs whose
   email spaces overlap or recycle.
3. **PKCE + ID-token verification** as a hardening pass across all providers
   (the `CodeVerifier` field at `handlers_auth.go:63` is declared but unused
   today).
4. **Provider label map** in `CLIAuthProvidersResponse` so the CLI can show
   display names instead of raw IDs.
