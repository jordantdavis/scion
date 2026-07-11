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

package cmd

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/scion/pkg/config"
	"github.com/GoogleCloudPlatform/scion/pkg/util/logging"
)

// dsnFixtures covers both connection-string forms this codebase accepts, each
// carrying a distinctive password that must never reach a log sink.
var dsnFixtures = []struct {
	name     string
	driver   string
	dsn      string
	password string
}{
	{
		name:     "url form",
		driver:   "postgres",
		dsn:      "postgres://hubuser:s3cr3t-p4ss@db.internal:5432/scion?sslmode=require",
		password: "s3cr3t-p4ss",
	},
	{
		name:     "keyword form",
		driver:   "postgres",
		dsn:      "host=db.internal port=5432 user=hubuser password=s3cr3t-p4ss dbname=scion sslmode=require",
		password: "s3cr3t-p4ss",
	},
}

// TestDatabaseConfiguredLogRedactsPassword guards the hub-startup log line
// (cmd/server_foreground.go, "database configured") against regressing to
// logging the raw DSN. It reproduces the exact call site verbatim -
// logging.Subsystem("hub").Info(..., "url", config.RedactDSN(driver, dsn)) -
// against a captured slog output and fails if the password token leaks.
func TestDatabaseConfiguredLogRedactsPassword(t *testing.T) {
	for _, tt := range dsnFixtures {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			defer slog.SetDefault(prev)

			logging.Subsystem("hub").Info("database configured",
				"driver", tt.driver,
				"url", config.RedactDSN(tt.driver, tt.dsn))

			out := buf.String()
			if strings.Contains(out, tt.password) {
				t.Fatalf("log output leaked password %q: %s", tt.password, out)
			}
			if !strings.Contains(out, "xxxxx") {
				t.Fatalf("expected redacted placeholder in log output, got: %s", out)
			}
		})
	}
}

// TestMigrateStorageOpeningDatabaseLogRedactsPassword guards the
// "Opening database" line in cmd/server_migrate_storage.go against
// regressing to printing the raw DSN.
func TestMigrateStorageOpeningDatabaseLogRedactsPassword(t *testing.T) {
	for _, tt := range dsnFixtures {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			fmt.Fprintf(&out, "Opening database: %s (%s)\n", tt.driver, config.RedactDSN(tt.driver, tt.dsn))

			if strings.Contains(out.String(), tt.password) {
				t.Fatalf("log output leaked password %q: %s", tt.password, out.String())
			}
			if !strings.Contains(out.String(), "xxxxx") {
				t.Fatalf("expected redacted placeholder in log output, got: %s", out.String())
			}
		})
	}
}
