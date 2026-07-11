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
	"fmt"
	"strings"
	"testing"
)

const testPassword = "s3cr3t-p@ss"

func TestRedactDSN(t *testing.T) {
	tests := []struct {
		name     string
		driver   string
		dsn      string
		wantExpr string // exact expected output, when deterministic
	}{
		{
			name:     "url form postgres scheme",
			driver:   "postgres",
			dsn:      "postgres://user:" + testPassword + "@host:5432/db?sslmode=require",
			wantExpr: "postgres://user:xxxxx@host:5432/db?sslmode=require",
		},
		{
			name:     "url form postgresql scheme",
			driver:   "postgres",
			dsn:      "postgresql://user:" + testPassword + "@host:5432/db",
			wantExpr: "postgresql://user:xxxxx@host:5432/db",
		},
		{
			name:     "keyword form",
			driver:   "postgres",
			dsn:      "host=h port=5432 user=u password=" + testPassword + " dbname=db sslmode=require",
			wantExpr: "host=h port=5432 user=u password=xxxxx dbname=db sslmode=require",
		},
		{
			name:     "keyword form with spaces around equals",
			driver:   "postgres",
			dsn:      "host=h user=u password = " + testPassword + " dbname=db",
			wantExpr: "host=h user=u password = xxxxx dbname=db",
		},
		{
			name:     "url with no password",
			driver:   "postgres",
			dsn:      "postgres://user@host:5432/db?sslmode=require",
			wantExpr: "postgres://user@host:5432/db?sslmode=require",
		},
		{
			name:   "sqlite path passthrough",
			driver: "sqlite",
			dsn:    "file:/var/lib/scion/hub.db?cache=shared",
			// sqlite has no credential; RedactDSN must not touch it.
			wantExpr: "file:/var/lib/scion/hub.db?cache=shared",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactDSN(tt.driver, tt.dsn)
			if got != tt.wantExpr {
				t.Errorf("RedactDSN(%q, %q) = %q, want %q", tt.driver, tt.dsn, got, tt.wantExpr)
			}
			if containsPassword(got) {
				t.Errorf("RedactDSN(%q, %q) = %q leaks password", tt.driver, tt.dsn, got)
			}
		})
	}
}

// TestRedactDSN_MalformedFailsClosed asserts that a postgres/postgresql DSN
// that cannot be confidently parsed as either URL-form or keyword-form is
// fully masked, never echoed back with the password intact.
func TestRedactDSN_MalformedFailsClosed(t *testing.T) {
	malformed := "totally not a dsn but has " + testPassword + " in it somewhere"

	got := RedactDSN("postgres", malformed)

	if containsPassword(got) {
		t.Fatalf("RedactDSN returned %q, which still contains the password", got)
	}
	if got != redactedPlaceholder {
		t.Errorf("RedactDSN(malformed) = %q, want fail-closed placeholder %q", got, redactedPlaceholder)
	}
}

// TestRedactDSN_PostgresqlDriverAlias exercises the "postgresql" driver name
// alias (as opposed to the "postgres" scheme) to ensure both drive the same
// redaction path.
func TestRedactDSN_PostgresqlDriverAlias(t *testing.T) {
	dsn := "postgres://user:" + testPassword + "@host/db"
	got := RedactDSN("postgresql", dsn)
	if containsPassword(got) {
		t.Fatalf("RedactDSN(%q) leaks password: %q", dsn, got)
	}
}

func TestDatabaseConfig_String(t *testing.T) {
	tests := []struct {
		name string
		cfg  DatabaseConfig
	}{
		{
			name: "postgres url form",
			cfg: DatabaseConfig{
				Driver: "postgres",
				URL:    "postgres://user:" + testPassword + "@host:5432/db?sslmode=require",
			},
		},
		{
			name: "postgres keyword form",
			cfg: DatabaseConfig{
				Driver: "postgres",
				URL:    "host=h user=u password=" + testPassword + " dbname=db",
			},
		},
		{
			name: "sqlite",
			cfg: DatabaseConfig{
				Driver: "sqlite",
				URL:    "file:/tmp/hub.db",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Exercise both the direct method and fmt's %s/%v dispatch,
			// since the leak sites use fmt/log with %s.
			for _, got := range []string{
				tt.cfg.String(),
				fmt.Sprintf("%s", tt.cfg),
				fmt.Sprintf("%v", tt.cfg),
			} {
				if containsPassword(got) {
					t.Errorf("DatabaseConfig rendering %q leaks password", got)
				}
			}
		})
	}
}

func containsPassword(s string) bool {
	return strings.Contains(s, testPassword)
}
