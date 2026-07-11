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

package config

import (
	"net/url"
	"regexp"
	"strings"
)

// MaskedValue is the placeholder written in place of a secret-bearing DSN.
//
// It matches the masking convention already used across the codebase for
// sensitive settings: pkg/hub/admin_settings.go masks the database URL — along
// with dev/broker tokens and OAuth secrets — as "********" before returning
// them from the admin API (surfaced in the admin settings UI). Reusing the
// same token keeps log redaction consistent with how the very same value is
// treated in the UI, and satisfies .design/hosted/secrets.md §7.4: "Secret
// values MUST NOT appear in logs at any tier (Hub, Broker, Agent)."
const MaskedValue = "********"

// keywordPasswordPattern matches a `password=...` (or `password = ...`) token
// in a libpq keyword/value connection string, e.g.
// "host=h port=5432 user=u password=p dbname=db".
var keywordPasswordPattern = regexp.MustCompile(`(?i)password\s*=\s*\S+`)

// keywordPairPattern matches any `key=value` token, used only to sniff whether
// a string looks like a libpq keyword/value DSN.
var keywordPairPattern = regexp.MustCompile(`(?i)\b[a-z_]+\s*=\s*\S+`)

// RedactDSN returns a log-safe rendering of dsn for the given driver.
//
// Postgres DSNs may embed a password in either URL-form
// ("postgres://user:pass@host/db") or libpq keyword/value form
// ("host=h user=u password=p"). When a credential is present, RedactDSN
// replaces the ENTIRE DSN with MaskedValue ("********") — the same treatment
// the admin settings API gives the database URL (pkg/hub/admin_settings.go) —
// rather than a structured partial mask. This matches the project's masking
// convention and is safe because the host/database/query portions are not
// needed in logs (the driver is logged as a separate field).
//
// DSNs with no credential — passwordless URL-form, keyword-form without a
// password token, or non-postgres drivers such as sqlite file paths — are
// returned unchanged, since there is no secret to hide.
//
// If dsn looks like a postgres DSN but cannot be confidently classified,
// RedactDSN fails closed and returns MaskedValue rather than risk echoing a
// password.
func RedactDSN(driver, dsn string) string {
	if !isPostgresDriver(driver) {
		return dsn
	}

	if u, err := url.Parse(dsn); err == nil && isURLForm(u) {
		if _, hasPassword := u.User.Password(); hasPassword {
			return MaskedValue
		}
		return dsn // URL-form with no password: nothing secret to redact.
	}

	if keywordPasswordPattern.MatchString(dsn) {
		return MaskedValue
	}
	if isKeywordForm(dsn) {
		return dsn // keyword-form carrying no password token.
	}

	return MaskedValue // Unrecognized postgres DSN: fail closed.
}

func isPostgresDriver(driver string) bool {
	switch strings.ToLower(driver) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

// isURLForm reports whether u was parsed from a recognized postgres URL
// scheme. url.Parse succeeds on almost any input (including bare keyword-form
// DSNs, which it treats as an opaque path), so this guards against
// misclassifying a keyword-form string as a URL.
func isURLForm(u *url.URL) bool {
	switch strings.ToLower(u.Scheme) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

func isKeywordForm(dsn string) bool {
	return keywordPairPattern.MatchString(dsn)
}
