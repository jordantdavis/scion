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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/scion/pkg/hubclient"
)

// OAuthProviderConfig holds OAuth credentials for a single provider.
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
}

// OAuthClientConfig holds OAuth provider configurations for a specific client type.
type OAuthClientConfig struct {
	Google OAuthProviderConfig
	GitHub OAuthProviderConfig
	Custom OAuthProviderConfig
}

// IsConfigured returns true if at least one OAuth provider is configured.
func (c *OAuthClientConfig) IsConfigured() bool {
	return c.Google.ClientID != "" || c.GitHub.ClientID != "" || c.Custom.ClientID != ""
}

// IsProviderConfigured returns true if the specified provider is configured.
func (c *OAuthClientConfig) IsProviderConfigured(provider string) bool {
	switch provider {
	case hubclient.OAuthProviderGoogle:
		return c.Google.ClientID != "" && c.Google.ClientSecret != ""
	case hubclient.OAuthProviderGitHub:
		return c.GitHub.ClientID != "" && c.GitHub.ClientSecret != ""
	case hubclient.OAuthProviderCustom:
		return c.Custom.ClientID != "" && c.Custom.ClientSecret != ""
	default:
		return false
	}
}

// GetProvider returns the provider config for the specified provider.
func (c *OAuthClientConfig) GetProvider(provider string) OAuthProviderConfig {
	switch provider {
	case hubclient.OAuthProviderGoogle:
		return c.Google
	case hubclient.OAuthProviderGitHub:
		return c.GitHub
	case hubclient.OAuthProviderCustom:
		return c.Custom
	default:
		return OAuthProviderConfig{}
	}
}

// OAuthCustomProviderConfig holds provider-level settings for the custom OAuth
// provider (mirrors the pkg/config version). Unlike Google/GitHub, the custom
// provider's endpoints, scopes, and claim mapping are configuration-driven
// rather than hardcoded, since it targets arbitrary corporate SSO providers.
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

// IsConfigured returns true if the required endpoint URLs are set. Credential
// presence (client ID/secret) is tracked separately via OAuthClientConfig.
func (c *OAuthCustomProviderConfig) IsConfigured() bool {
	return c.AuthorizeURL != "" && c.TokenURL != "" && c.UserinfoURL != ""
}

// EffectiveDisplayName returns DisplayName, defaulting to "SSO" if unset.
func (c *OAuthCustomProviderConfig) EffectiveDisplayName() string {
	if c.DisplayName == "" {
		return "SSO"
	}
	return c.DisplayName
}

// EffectiveScopes returns Scopes, defaulting to "openid email profile" if unset.
func (c *OAuthCustomProviderConfig) EffectiveScopes() string {
	if c.Scopes == "" {
		return "openid email profile"
	}
	return c.Scopes
}

// EffectiveEmailClaim returns EmailClaim, defaulting to "email" if unset.
func (c *OAuthCustomProviderConfig) EffectiveEmailClaim() string {
	if c.EmailClaim == "" {
		return "email"
	}
	return c.EmailClaim
}

// EffectiveNameClaim returns NameClaim, defaulting to "name" if unset.
func (c *OAuthCustomProviderConfig) EffectiveNameClaim() string {
	if c.NameClaim == "" {
		return "name"
	}
	return c.NameClaim
}

// EffectiveAvatarClaim returns AvatarClaim, defaulting to "picture" if unset.
func (c *OAuthCustomProviderConfig) EffectiveAvatarClaim() string {
	if c.AvatarClaim == "" {
		return "picture"
	}
	return c.AvatarClaim
}

// OAuthConfig holds configuration for all OAuth providers.
// Web, CLI, and Device use separate OAuth clients due to different redirect URI requirements.
type OAuthConfig struct {
	// Web OAuth client settings (for web frontend flows).
	Web OAuthClientConfig
	// CLI OAuth client settings (for CLI localhost callback flows).
	CLI OAuthClientConfig
	// Device OAuth client settings (for device authorization grant / headless flows).
	Device OAuthClientConfig
	// Custom provider-level settings (endpoint URLs, scopes, claim mapping).
	Custom OAuthCustomProviderConfig
}

// IsConfigured returns true if at least one OAuth provider is configured.
func (c *OAuthConfig) IsConfigured() bool {
	return c.Web.IsConfigured() || c.CLI.IsConfigured() || c.Device.IsConfigured()
}

// IsProviderConfigured returns true if the specified provider is configured
// for at least one client type.
func (c *OAuthConfig) IsProviderConfigured(provider string) bool {
	return c.Web.IsProviderConfigured(provider) || c.CLI.IsProviderConfigured(provider) || c.Device.IsProviderConfigured(provider)
}

// ValidateOAuthConfig checks custom-provider invariants at server start so a
// misconfigured corporate SSO fails fast instead of at login time.
func ValidateOAuthConfig(cfg *OAuthConfig) error {
	credsSet := cfg.Web.Custom.ClientID != "" || cfg.CLI.Custom.ClientID != "" || cfg.Device.Custom.ClientID != ""
	if !credsSet {
		return nil
	}
	// Ordered (not map) so that when multiple fields are invalid, the reported
	// field is deterministic across runs rather than depending on Go's
	// randomized map iteration order.
	fields := []struct {
		key      string
		val      string
		required bool
	}{
		{"oauth.custom.authorizeUrl", cfg.Custom.AuthorizeURL, true},
		{"oauth.custom.tokenUrl", cfg.Custom.TokenURL, true},
		{"oauth.custom.userinfoUrl", cfg.Custom.UserinfoURL, true},
		{"oauth.custom.deviceAuthorizationUrl", cfg.Custom.DeviceAuthorizationURL, false},
	}
	for _, f := range fields {
		if f.val == "" {
			if f.required {
				return fmt.Errorf("custom OAuth provider: %s is required when custom client credentials are set", f.key)
			}
			continue
		}
		u, err := url.Parse(f.val)
		if err != nil || u.Host == "" {
			return fmt.Errorf("custom OAuth provider: %s is not a valid URL: %q", f.key, f.val)
		}
		host := u.Hostname()
		isLocalHTTP := u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1")
		if u.Scheme != "https" && !isLocalHTTP {
			return fmt.Errorf("custom OAuth provider: %s must use https, or http on localhost/127.0.0.1 (got scheme %q in %q)", f.key, u.Scheme, f.val)
		}
	}
	if cfg.Device.Custom.ClientID != "" && cfg.Custom.DeviceAuthorizationURL == "" {
		return fmt.Errorf("custom OAuth provider: oauth.device.custom credentials set but oauth.custom.deviceAuthorizationUrl is empty")
	}
	return nil
}

// OAuthClientType represents the type of client (web or CLI).
type OAuthClientType = hubclient.OAuthClientType

const (
	// OAuthClientTypeWeb is for web browser-based OAuth flows.
	OAuthClientTypeWeb = hubclient.OAuthClientTypeWeb
	// OAuthClientTypeCLI is for CLI localhost callback OAuth flows.
	OAuthClientTypeCLI = hubclient.OAuthClientTypeCLI
	// OAuthClientTypeDevice is for device authorization grant (headless) flows.
	OAuthClientTypeDevice = hubclient.OAuthClientTypeDevice
)

func oauthProviderOrder() []string {
	return hubclient.OAuthProviderOrder()
}

// OAuthService handles OAuth operations for authentication.
type OAuthService struct {
	config     OAuthConfig
	httpClient *http.Client
}

// NewOAuthService creates a new OAuth service.
func NewOAuthService(config OAuthConfig) *OAuthService {
	return &OAuthService{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getClientConfig returns the appropriate OAuth client config for the given client type.
func (s *OAuthService) getClientConfig(clientType OAuthClientType) OAuthClientConfig {
	switch clientType {
	case OAuthClientTypeWeb:
		return s.config.Web
	case OAuthClientTypeCLI:
		return s.config.CLI
	case OAuthClientTypeDevice:
		return s.config.Device
	default:
		return OAuthClientConfig{}
	}
}

// IsProviderConfiguredForClient returns true if the specified provider is configured
// for the given client type.
func (s *OAuthService) IsProviderConfiguredForClient(clientType OAuthClientType, provider string) bool {
	cfg := s.getClientConfig(clientType)
	return cfg.IsProviderConfigured(provider)
}

// ConfiguredProvidersForClient returns the configured OAuth providers for the
// given client type in stable display order.
func (s *OAuthService) ConfiguredProvidersForClient(clientType OAuthClientType) []string {
	order := oauthProviderOrder()
	providers := make([]string, 0, len(order))
	for _, provider := range order {
		if s.IsProviderConfiguredForClient(clientType, provider) {
			providers = append(providers, provider)
		}
	}

	return providers
}

// DefaultProviderForClient returns the first configured OAuth provider for a
// client type, following the standard provider order.
func (s *OAuthService) DefaultProviderForClient(clientType OAuthClientType) string {
	if providers := s.ConfiguredProvidersForClient(clientType); len(providers) > 0 {
		return providers[0]
	}
	return "google"
}

// OAuthUserInfo contains user information retrieved from an OAuth provider.
type OAuthUserInfo struct {
	ID          string
	Email       string
	DisplayName string
	AvatarURL   string
	Provider    string
}

// Google OAuth endpoints
const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleUserURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GitHub OAuth endpoints
const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
	githubEmailURL = "https://api.github.com/user/emails"
)

// Device authorization endpoints
const (
	googleDeviceCodeURL = "https://oauth2.googleapis.com/device/code"
	githubDeviceCodeURL = "https://github.com/login/device/code"
)

// GetAuthorizationURL generates an OAuth authorization URL for the specified provider.
// Uses the default (CLI) client configuration for backward compatibility.
func (s *OAuthService) GetAuthorizationURL(provider, callbackURL, state string) (string, error) {
	return s.GetAuthorizationURLForClient(OAuthClientTypeCLI, provider, callbackURL, state)
}

// GetAuthorizationURLForClient generates an OAuth authorization URL for the specified
// provider and client type.
func (s *OAuthService) GetAuthorizationURLForClient(clientType OAuthClientType, provider, callbackURL, state string) (string, error) {
	cfg := s.getClientConfig(clientType)

	switch provider {
	case hubclient.OAuthProviderGoogle:
		return s.getGoogleAuthURLWithConfig(cfg.Google, callbackURL, state)
	case hubclient.OAuthProviderGitHub:
		return s.getGitHubAuthURLWithConfig(cfg.GitHub, callbackURL, state)
	case hubclient.OAuthProviderCustom:
		return s.getCustomAuthorizationURL(cfg.Custom, callbackURL, state)
	default:
		return "", fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// getGoogleAuthURL generates a Google OAuth authorization URL using the default config.
//
//nolint:unused // Kept for direct OAuth flow compatibility.
func (s *OAuthService) getGoogleAuthURL(callbackURL, state string) (string, error) {
	return s.getGoogleAuthURLWithConfig(s.config.CLI.Google, callbackURL, state)
}

// getGoogleAuthURLWithConfig generates a Google OAuth authorization URL with the given config.
func (s *OAuthService) getGoogleAuthURLWithConfig(cfg OAuthProviderConfig, callbackURL, state string) (string, error) {
	if cfg.ClientID == "" {
		return "", fmt.Errorf("google OAuth is not configured")
	}

	params := url.Values{
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {callbackURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
	}

	return googleAuthURL + "?" + params.Encode(), nil
}

// getGitHubAuthURL generates a GitHub OAuth authorization URL using the default config.
//
//nolint:unused // Kept for direct OAuth flow compatibility.
func (s *OAuthService) getGitHubAuthURL(callbackURL, state string) (string, error) {
	return s.getGitHubAuthURLWithConfig(s.config.CLI.GitHub, callbackURL, state)
}

// getGitHubAuthURLWithConfig generates a GitHub OAuth authorization URL with the given config.
func (s *OAuthService) getGitHubAuthURLWithConfig(cfg OAuthProviderConfig, callbackURL, state string) (string, error) {
	if cfg.ClientID == "" {
		return "", fmt.Errorf("GitHub OAuth is not configured")
	}

	params := url.Values{
		"client_id":    {cfg.ClientID},
		"redirect_uri": {callbackURL},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}

	return githubAuthURL + "?" + params.Encode(), nil
}

// getCustomAuthorizationURL generates a custom-provider OAuth authorization URL.
// Unlike Google/GitHub, the endpoint and scopes are configuration-driven
// (s.config.Custom) rather than hardcoded, since this targets arbitrary
// corporate SSO providers.
func (s *OAuthService) getCustomAuthorizationURL(cfg OAuthProviderConfig, callbackURL, state string) (string, error) {
	if cfg.ClientID == "" || !s.config.Custom.IsConfigured() {
		return "", fmt.Errorf("custom OAuth provider is not configured")
	}

	// Parse (rather than string-concatenate) so pre-existing query parameters
	// on operator-supplied authorize URLs survive — e.g. Azure AD B2C's
	// "?p=<policy>" tenant policy parameter.
	u, err := url.Parse(s.config.Custom.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("custom OAuth authorize URL is invalid: %w", err)
	}
	q := u.Query()
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", callbackURL)
	q.Set("response_type", "code")
	q.Set("scope", s.config.Custom.EffectiveScopes())
	q.Set("state", state)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ExchangeCode exchanges an authorization code for user information.
// Uses the default (CLI) client configuration for backward compatibility.
func (s *OAuthService) ExchangeCode(ctx context.Context, provider, code, callbackURL string) (*OAuthUserInfo, error) {
	return s.ExchangeCodeForClient(ctx, OAuthClientTypeCLI, provider, code, callbackURL)
}

// ExchangeCodeForClient exchanges an authorization code for user information
// using the specified client type's configuration.
func (s *OAuthService) ExchangeCodeForClient(ctx context.Context, clientType OAuthClientType, provider, code, callbackURL string) (*OAuthUserInfo, error) {
	cfg := s.getClientConfig(clientType)

	switch provider {
	case "google":
		return s.exchangeGoogleCodeWithConfig(ctx, cfg.Google, code, callbackURL)
	case "github":
		return s.exchangeGitHubCodeWithConfig(ctx, cfg.GitHub, code, callbackURL)
	case hubclient.OAuthProviderCustom:
		return s.exchangeCustomCodeWithConfig(ctx, cfg.Custom, code, callbackURL)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}
}

// exchangeGoogleCode exchanges a Google authorization code for user info.
//
//nolint:unused // Kept for direct OAuth flow compatibility.
func (s *OAuthService) exchangeGoogleCode(ctx context.Context, code, callbackURL string) (*OAuthUserInfo, error) {
	return s.exchangeGoogleCodeWithConfig(ctx, s.config.CLI.Google, code, callbackURL)
}

// exchangeGoogleCodeWithConfig exchanges a Google authorization code for user info using the given config.
func (s *OAuthService) exchangeGoogleCodeWithConfig(ctx context.Context, cfg OAuthProviderConfig, code, callbackURL string) (*OAuthUserInfo, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("google OAuth is not configured")
	}

	// Exchange code for access token
	tokenResp, err := s.exchangeCodeForToken(ctx, googleTokenURL, cfg.ClientID, cfg.ClientSecret, code, callbackURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange Google code: %w", err)
	}

	// Get user info
	userInfo, err := s.getGoogleUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get Google user info: %w", err)
	}

	return userInfo, nil
}

// exchangeGitHubCode exchanges a GitHub authorization code for user info.
//
//nolint:unused // Kept for direct OAuth flow compatibility.
func (s *OAuthService) exchangeGitHubCode(ctx context.Context, code, callbackURL string) (*OAuthUserInfo, error) {
	return s.exchangeGitHubCodeWithConfig(ctx, s.config.CLI.GitHub, code, callbackURL)
}

// exchangeGitHubCodeWithConfig exchanges a GitHub authorization code for user info using the given config.
func (s *OAuthService) exchangeGitHubCodeWithConfig(ctx context.Context, cfg OAuthProviderConfig, code, callbackURL string) (*OAuthUserInfo, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("GitHub OAuth is not configured")
	}

	// Exchange code for access token
	tokenResp, err := s.exchangeGitHubCodeForTokenWithConfig(ctx, cfg, code, callbackURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange GitHub code: %w", err)
	}

	// Get user info
	userInfo, err := s.getGitHubUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get GitHub user info: %w", err)
	}

	return userInfo, nil
}

// exchangeCustomCodeWithConfig exchanges a custom-provider authorization code for user info.
func (s *OAuthService) exchangeCustomCodeWithConfig(ctx context.Context, cfg OAuthProviderConfig, code, callbackURL string) (*OAuthUserInfo, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("custom OAuth provider is not configured")
	}

	// Exchange code for access token
	tokenResp, err := s.exchangeCodeForToken(ctx, s.config.Custom.TokenURL, cfg.ClientID, cfg.ClientSecret, code, callbackURL)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange custom code: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("custom token endpoint returned no access_token")
	}

	// Get user info
	userInfo, err := s.getCustomUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get custom user info: %w", err)
	}

	return userInfo, nil
}

// tokenResponse represents the response from an OAuth token endpoint.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

// exchangeCodeForToken exchanges an authorization code for an access token (Google).
func (s *OAuthService) exchangeCodeForToken(ctx context.Context, tokenURL, clientID, clientSecret, code, callbackURL string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Harmless for RFC-compliant servers; required by GitHub-style endpoints
	// that otherwise respond with application/x-www-form-urlencoded.
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// exchangeGitHubCodeForToken exchanges a GitHub authorization code for an access token.
//
//nolint:unused // Kept for direct OAuth flow compatibility.
func (s *OAuthService) exchangeGitHubCodeForToken(ctx context.Context, code, callbackURL string) (*tokenResponse, error) {
	return s.exchangeGitHubCodeForTokenWithConfig(ctx, s.config.CLI.GitHub, code, callbackURL)
}

// exchangeGitHubCodeForTokenWithConfig exchanges a GitHub authorization code for an access token using the given config.
func (s *OAuthService) exchangeGitHubCodeForTokenWithConfig(ctx context.Context, cfg OAuthProviderConfig, code, callbackURL string) (*tokenResponse, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {callbackURL},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		// GitHub sometimes returns error in the body
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("no access token in response: %s", string(body))
	}

	return &tokenResp, nil
}

// googleUserInfo represents the response from Google's userinfo endpoint.
type googleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// getGoogleUserInfo retrieves user information from Google.
func (s *OAuthService) getGoogleUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", googleUserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	var userInfo googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return &OAuthUserInfo{
		ID:          userInfo.ID,
		Email:       userInfo.Email,
		DisplayName: userInfo.Name,
		AvatarURL:   userInfo.Picture,
		Provider:    "google",
	}, nil
}

// githubUser represents the response from GitHub's user endpoint.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmail represents an email from GitHub's user/emails endpoint.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// getGitHubUserInfo retrieves user information from GitHub.
func (s *OAuthService) getGitHubUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	// Get user profile
	req, err := http.NewRequestWithContext(ctx, "GET", githubUserURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	var user githubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// If email is not public, fetch from emails endpoint
	email := user.Email
	if email == "" {
		email, err = s.getGitHubPrimaryEmail(ctx, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get user email: %w", err)
		}
	}

	displayName := user.Name
	if displayName == "" {
		displayName = user.Login
	}

	return &OAuthUserInfo{
		ID:          fmt.Sprintf("%d", user.ID),
		Email:       email,
		DisplayName: displayName,
		AvatarURL:   user.AvatarURL,
		Provider:    "github",
	}, nil
}

// getGitHubPrimaryEmail fetches the primary email from GitHub's emails endpoint.
func (s *OAuthService) getGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", githubEmailURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get emails: %s - %s", resp.Status, string(body))
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("failed to decode emails: %w", err)
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to any email
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}

// getCustomUserInfo retrieves user information from the configured custom
// provider's userinfo endpoint, mapping claims per s.config.Custom's
// configured (or defaulted) claim keys. Per the design spec, identity comes
// from this endpoint over TLS rather than ID-token/JWKS verification.
func (s *OAuthService) getCustomUserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.config.Custom.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("failed to get user info: %s - %s", resp.Status, string(body))
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	claim := func(key string) string {
		v, _ := claims[key].(string)
		return v
	}

	emailClaim := s.config.Custom.EffectiveEmailClaim()
	email := claim(emailClaim)
	if email == "" {
		return nil, fmt.Errorf("custom userinfo response missing email claim %q", emailClaim)
	}

	id := claim("sub")
	if id == "" {
		id = email
	}

	return &OAuthUserInfo{
		ID:          id,
		Email:       email,
		DisplayName: claim(s.config.Custom.EffectiveNameClaim()),
		AvatarURL:   claim(s.config.Custom.EffectiveAvatarClaim()),
		Provider:    hubclient.OAuthProviderCustom,
	}, nil
}

// DeviceCodeResponse holds the response from a device authorization request.
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// googleDeviceCodeResponse handles Google's non-standard field naming.
// Google returns "verification_url" instead of the RFC 8628 "verification_uri".
type googleDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURL         string `json:"verification_url"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceAuthError represents a non-success state from device token polling.
type DeviceAuthError struct {
	Code     string // "authorization_pending", "slow_down", "expired_token"
	Interval int    // updated interval for slow_down
}

func (e *DeviceAuthError) Error() string {
	return fmt.Sprintf("device auth: %s", e.Code)
}

// RequestDeviceCode initiates the device authorization flow with the provider.
func (s *OAuthService) RequestDeviceCode(ctx context.Context, clientType OAuthClientType, provider string) (*DeviceCodeResponse, error) {
	cfg := s.getClientConfig(clientType)

	switch provider {
	case "google":
		return s.requestGoogleDeviceCode(ctx, cfg.Google)
	case "github":
		return s.requestGitHubDeviceCode(ctx, cfg.GitHub)
	case hubclient.OAuthProviderCustom:
		if s.config.Custom.DeviceAuthorizationURL == "" {
			return nil, fmt.Errorf("provider %q does not support device-flow login", hubclient.OAuthProviderCustom)
		}
		return s.requestCustomDeviceCode(ctx, cfg.Custom)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider for device flow: %s", provider)
	}
}

func (s *OAuthService) requestGoogleDeviceCode(ctx context.Context, cfg OAuthProviderConfig) (*DeviceCodeResponse, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("google OAuth is not configured")
	}

	data := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {"openid email profile"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device code request failed: %s - %s", resp.Status, string(body))
	}

	// Google returns "verification_url" instead of the RFC 8628 "verification_uri"
	var gResult googleDeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&gResult); err != nil {
		return nil, fmt.Errorf("failed to decode device code response: %w", err)
	}

	return &DeviceCodeResponse{
		DeviceCode:              gResult.DeviceCode,
		UserCode:                gResult.UserCode,
		VerificationURI:         gResult.VerificationURL,
		VerificationURIComplete: gResult.VerificationURIComplete,
		ExpiresIn:               gResult.ExpiresIn,
		Interval:                gResult.Interval,
	}, nil
}

// requestCustomDeviceCode initiates the RFC 8628 device authorization flow
// against the operator-configured custom provider. Unlike Google
// (non-standard "verification_url") and GitHub (200 status with an error
// body), this targets a plain standards-compliant device authorization
// endpoint, so the shared DeviceCodeResponse type decodes directly.
func (s *OAuthService) requestCustomDeviceCode(ctx context.Context, cfg OAuthProviderConfig) (*DeviceCodeResponse, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("custom OAuth provider is not configured")
	}

	data := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {s.config.Custom.EffectiveScopes()},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Custom.DeviceAuthorizationURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("device code request failed: %s - %s", resp.Status, string(body))
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode device code response: %w", err)
	}

	return &result, nil
}

func (s *OAuthService) requestGitHubDeviceCode(ctx context.Context, cfg OAuthProviderConfig) (*DeviceCodeResponse, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("GitHub OAuth is not configured")
	}

	data := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {"read:user user:email"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", githubDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device code request failed: %s - %s", resp.Status, string(body))
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode device code response: %w", err)
	}

	return &result, nil
}

// PollDeviceToken polls the provider's token endpoint for the device flow result.
// Returns a tokenResponse on success, or a DeviceAuthError for pending/slow_down/expired states.
func (s *OAuthService) PollDeviceToken(ctx context.Context, clientType OAuthClientType, provider, deviceCode string) (*tokenResponse, error) {
	cfg := s.getClientConfig(clientType)

	switch provider {
	case "google":
		return s.pollGoogleDeviceToken(ctx, cfg.Google, deviceCode)
	case "github":
		return s.pollGitHubDeviceToken(ctx, cfg.GitHub, deviceCode)
	case hubclient.OAuthProviderCustom:
		return s.pollCustomDeviceToken(ctx, cfg.Custom, deviceCode)
	default:
		return nil, fmt.Errorf("unsupported OAuth provider for device flow: %s", provider)
	}
}

// deviceTokenErrorResponse represents an error response from a device token endpoint.
type deviceTokenErrorResponse struct {
	Error    string `json:"error"`
	Interval int    `json:"interval,omitempty"`
}

func (s *OAuthService) pollGoogleDeviceToken(ctx context.Context, cfg OAuthProviderConfig, deviceCode string) (*tokenResponse, error) {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"device_code":   {deviceCode},
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read device token response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tokenResp tokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}
		return &tokenResp, nil
	}

	// Parse error response
	var errResp deviceTokenErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return nil, fmt.Errorf("device token poll failed: %s - %s", resp.Status, string(body))
	}

	switch errResp.Error {
	case "authorization_pending", "slow_down", "expired_token":
		return nil, &DeviceAuthError{Code: errResp.Error, Interval: errResp.Interval}
	default:
		return nil, fmt.Errorf("device token poll failed: %s", errResp.Error)
	}
}

func (s *OAuthService) pollGitHubDeviceToken(ctx context.Context, cfg OAuthProviderConfig, deviceCode string) (*tokenResponse, error) {
	data := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read device token response: %w", err)
	}

	// GitHub returns 200 for all responses, using "error" field to indicate state
	var errCheck deviceTokenErrorResponse
	if err := json.Unmarshal(body, &errCheck); err == nil && errCheck.Error != "" {
		switch errCheck.Error {
		case "authorization_pending", "slow_down", "expired_token":
			return nil, &DeviceAuthError{Code: errCheck.Error, Interval: errCheck.Interval}
		default:
			return nil, fmt.Errorf("device token poll failed: %s", errCheck.Error)
		}
	}

	if resp.StatusCode == http.StatusOK {
		var tokenResp tokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}
		if tokenResp.AccessToken == "" {
			return nil, fmt.Errorf("no access token in response: %s", string(body))
		}
		return &tokenResp, nil
	}

	return nil, fmt.Errorf("device token poll failed: %s - %s", resp.Status, string(body))
}

// pollCustomDeviceToken polls the operator-configured custom provider's
// token endpoint per RFC 8628 section 3.4/3.5. authorization_pending,
// slow_down, and expired_token all map to *DeviceAuthError, the codebase's
// existing pending/terminal signal (see pollGoogleDeviceToken); any other
// "error" value (e.g. access_denied) is a plain terminal error.
func (s *OAuthService) pollCustomDeviceToken(ctx context.Context, cfg OAuthProviderConfig, deviceCode string) (*tokenResponse, error) {
	data := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.Custom.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("failed to read device token response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		var tokenResp tokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return nil, fmt.Errorf("failed to decode token response: %w", err)
		}
		if tokenResp.AccessToken == "" {
			return nil, fmt.Errorf("no access token in response: %s", string(body))
		}
		return &tokenResp, nil
	}

	var errResp deviceTokenErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return nil, fmt.Errorf("device token poll failed: %s - %s", resp.Status, string(body))
	}

	switch errResp.Error {
	case "authorization_pending", "slow_down", "expired_token":
		return nil, &DeviceAuthError{Code: errResp.Error, Interval: errResp.Interval}
	default:
		return nil, fmt.Errorf("device token poll failed: %s", errResp.Error)
	}
}
