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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/GoogleCloudPlatform/scion/pkg/config"
	"github.com/GoogleCloudPlatform/scion/pkg/hubclient"
	"github.com/spf13/cobra"
)

// hubSettingsCmd views the hub-level default settings. With no subcommand it
// prints the current settings (the "get" behavior); 'set' updates them.
//
// Hub settings are admin-only operations on the Hub and currently expose the
// hub-wide default GCP identity for new agents (mode + assigned service
// account). The hub default sits below project defaults in the precedence
// chain: explicit request -> project default -> hub default -> block.
var hubSettingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "View or update hub-level default settings (admin)",
	Long: `View or update Hub-wide default settings.

With no subcommand, prints the current Hub settings. Use 'set' to update them.

Hub settings currently control the Hub-wide default GCP identity applied to new
agents when neither the agent request nor its project specifies one:
  - mode: block, passthrough, or assign
  - service account: the hub-scoped SA id used when mode is "assign"

These commands require Hub administrator privileges.

Examples:
  scion hub settings
  scion hub settings --json
  scion hub settings set --gcp-identity-mode passthrough
  scion hub settings set --gcp-identity-mode assign --gcp-identity-service-account <sa-id>`,
	Args: cobra.NoArgs,
	RunE: runHubSettingsGet,
}

var hubSettingsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set hub-level default settings",
	Long: `Set Hub-wide default settings.

Only the flags you provide are changed; omitted settings are left unmodified.
Use --gcp-identity-mode to set the Hub default identity mode and, for "assign"
mode, --gcp-identity-service-account to reference a hub-scoped service account.

Examples:
  # Pass the caller's metadata through by default
  scion hub settings set --gcp-identity-mode passthrough

  # Assign a specific hub-scoped service account by default
  scion hub settings set --gcp-identity-mode assign --gcp-identity-service-account <sa-id>

  # Block GCP metadata by default (most secure)
  scion hub settings set --gcp-identity-mode block`,
	Args: cobra.NoArgs,
	RunE: runHubSettingsSet,
}

var (
	hubSettingsOutputJSON     bool
	hubSettingsGCPMode        string
	hubSettingsGCPServiceAcct string
)

func init() {
	hubCmd.AddCommand(hubSettingsCmd)
	hubSettingsCmd.AddCommand(hubSettingsSetCmd)

	hubSettingsCmd.Flags().BoolVar(&hubSettingsOutputJSON, "json", false, "Output in JSON format")

	hubSettingsSetCmd.Flags().StringVar(&hubSettingsGCPMode, "gcp-identity-mode", "",
		"Default GCP identity mode for new agents: block, passthrough, or assign")
	hubSettingsSetCmd.Flags().StringVar(&hubSettingsGCPServiceAcct, "gcp-identity-service-account", "",
		"Hub-scoped service account id to assign by default (required when mode is assign)")
	hubSettingsSetCmd.Flags().BoolVar(&hubSettingsOutputJSON, "json", false, "Output in JSON format")
}

// resolveHubClientForSettings creates a hub client for hub-level settings operations.
func resolveHubClientForSettings() (hubclient.Client, error) {
	resolvedPath, _, err := config.ResolveProjectPath(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve project path: %w", err)
	}

	settings, err := config.LoadSettings(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load settings: %w", err)
	}

	return getHubClient(settings)
}

func runHubSettingsGet(cmd *cobra.Command, args []string) error {
	client, err := resolveHubClientForSettings()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	settings, err := client.GetHubSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get hub settings: %w", err)
	}

	if hubSettingsOutputJSON || isJSONOutput() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(settings)
	}

	printHubSettings(settings)
	return nil
}

func runHubSettingsSet(cmd *cobra.Command, args []string) error {
	// Require at least one setting flag so 'set' with no flags is an error.
	modeChanged := cmd.Flags().Changed("gcp-identity-mode")
	saChanged := cmd.Flags().Changed("gcp-identity-service-account")
	if !modeChanged && !saChanged {
		return fmt.Errorf("no settings provided; specify --gcp-identity-mode and/or --gcp-identity-service-account")
	}

	if modeChanged {
		switch hubSettingsGCPMode {
		case "", "block", "passthrough", "assign":
		default:
			return fmt.Errorf("invalid --gcp-identity-mode %q (must be one of block, passthrough, assign)", hubSettingsGCPMode)
		}
	}

	client, err := resolveHubClientForSettings()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start from current settings so we only modify the flags provided.
	current, err := client.GetHubSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to load current hub settings: %w", err)
	}
	if current == nil {
		current = &hubclient.HubSettings{}
	}

	if modeChanged {
		current.DefaultGCPIdentityMode = hubSettingsGCPMode
	}
	if saChanged {
		current.DefaultGCPIdentityServiceAccountID = hubSettingsGCPServiceAcct
	}

	updated, err := client.UpdateHubSettings(ctx, current)
	if err != nil {
		return fmt.Errorf("failed to update hub settings: %w", err)
	}

	if hubSettingsOutputJSON || isJSONOutput() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(updated)
	}

	fmt.Println("Hub settings updated.")
	printHubSettings(updated)
	return nil
}

func printHubSettings(settings *hubclient.HubSettings) {
	fmt.Println("Hub Settings")
	fmt.Println("============")
	mode := settings.DefaultGCPIdentityMode
	if mode == "" {
		mode = "block"
	}
	fmt.Printf("Default GCP Identity Mode:            %s\n", mode)
	fmt.Printf("Default GCP Identity Service Account: %s\n", valueOrNone(settings.DefaultGCPIdentityServiceAccountID))
}
