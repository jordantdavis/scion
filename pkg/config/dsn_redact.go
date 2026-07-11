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

// redactedPlaceholder is returned in place of any DSN whose password cannot
// be confidently located and stripped. Fail closed rather than risk leaking
// a credential in logs.
const redactedPlaceholder = "(redacted)"

// keywordPasswordPattern matches a `password=...` (or `password = ...`) token
// in a libpq keyword/value connection string, e.g.
// "host=h port=5432 user=u password=p dbname=db". The value runs until the
// next whitespace, matching libpq's own unquoted keyword/value parsing.
var keywordPasswordPattern = regexp.MustCompile(`(?i)(password\s*=\s*)(\S+)`)

// RedactDSN returns dsn with any embedded password replaced by "xxxxx", safe
// for logging. It understands both DSN forms accepted by lib/pq and
// pgx: URL-form ("postgres://user:pass@host/db") and libpq keyword/value
// form ("host=h user=u password=p").
//
// Non-postgres drivers (e.g. sqlite file paths, which carry no credential)
// are returned unchanged.
//
// For postgres/postgresql drivers, if dsn cannot be confidently parsed as
// either recognized form, RedactDSN fails closed and returns a fully-masked
// placeholder rather than risk returning a string that still contains the
// password.
func RedactDSN(driver, dsn string) string {
	if !isPostgresDriver(driver) {
		return dsn
	}

	if u, err := url.Parse(dsn); err == nil && isURLForm(u) {
		return u.Redacted()
	}

	if keywordPasswordPattern.MatchString(dsn) {
		return keywordPasswordPattern.ReplaceAllString(dsn, "${1}xxxxx")
	}

	// No recognizable password token: if the string otherwise looks like a
	// keyword-form DSN (has other "key=value" pairs) there is no password to
	// redact, so it's safe to return as-is. Otherwise fail closed.
	if isKeywordForm(dsn) {
		return dsn
	}

	return redactedPlaceholder
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

// keywordPairPattern matches any `key=value` token, used only to sniff
// whether a string looks like a libpq keyword/value DSN.
var keywordPairPattern = regexp.MustCompile(`(?i)\b[a-z_]+\s*=\s*\S+`)

func isKeywordForm(dsn string) bool {
	return keywordPairPattern.MatchString(dsn)
}
