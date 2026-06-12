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

// hubServiceAccountsCmd manages hub-scoped GCP service accounts.
//
// These are the hub-wide analog of 'scion project service-accounts'. They are
// registered against the Hub itself (scope=hub) rather than a single project,
// and are admin-only operations on the Hub. There is no --project flag.
var hubServiceAccountsCmd = &cobra.Command{
	Use:     "service-accounts",
	Aliases: []string{"sa"},
	Short:   "Manage hub-scoped GCP service accounts (admin)",
	Long: `Manage GCP service accounts registered at the Hub scope.

Hub-scoped service accounts are available to agents across all projects on the
Hub (subject to the hub default-identity settings) rather than being tied to a
single project. No key material is stored — the Hub impersonates the SA at
token-generation time. These commands require Hub administrator privileges.

Examples:
  scion hub service-accounts list
  scion hub service-accounts add agent-worker@my-project.iam.gserviceaccount.com --project my-project
  scion hub service-accounts verify <id>
  scion hub service-accounts remove <id>`,
}

var hubSAAddCmd = &cobra.Command{
	Use:   "add EMAIL",
	Short: "Register a hub-scoped GCP service account",
	Long: `Register a GCP service account at the Hub scope.

The Hub will verify it can impersonate this service account via the
IAM Credentials API. The Hub's own service account must have
roles/iam.serviceAccountTokenCreator on the target SA.

Examples:
  scion hub service-accounts add agent-worker@my-project.iam.gserviceaccount.com --project my-project
  scion hub service-accounts add agent-worker@my-project.iam.gserviceaccount.com --project my-project --name "Worker SA"`,
	Args: cobra.ExactArgs(1),
	RunE: runHubSAAdd,
}

var hubSAListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List hub-scoped GCP service accounts",
	Long: `List all GCP service accounts registered at the Hub scope.

Examples:
  scion hub service-accounts list
  scion hub service-accounts list --json`,
	Args: cobra.NoArgs,
	RunE: runHubSAList,
}

var hubSARemoveCmd = &cobra.Command{
	Use:     "remove ID",
	Aliases: []string{"rm", "delete"},
	Short:   "Remove a hub-scoped GCP service account registration",
	Long: `Remove a hub-scoped GCP service account registration.

This does not delete the service account in GCP — it only removes the
registration from the Hub.

Examples:
  scion hub service-accounts remove <id>`,
	Args: cobra.ExactArgs(1),
	RunE: runHubSARemove,
}

var hubSAVerifyCmd = &cobra.Command{
	Use:   "verify ID",
	Short: "Verify the Hub can impersonate a hub-scoped service account",
	Long: `Verify that the Hub can generate tokens for a hub-scoped service account.

This calls the IAM Credentials API to confirm the Hub's identity has
roles/iam.serviceAccountTokenCreator on the target SA.

Examples:
  scion hub service-accounts verify <id>`,
	Args: cobra.ExactArgs(1),
	RunE: runHubSAVerify,
}

var hubSAMintCmd = &cobra.Command{
	Use:   "mint",
	Short: "Mint a new hub-scoped GCP service account in the Hub's project",
	Long: `Create a new GCP service account in the Hub's own GCP project at the Hub scope.

The minted SA is permissionless by default — no IAM roles are granted.
The Hub automatically configures itself to impersonate the SA for token
generation. You can later grant IAM permissions on your own GCP projects.

Examples:
  scion hub service-accounts mint
  scion hub service-accounts mint --account-id my-pipeline
  scion hub service-accounts mint --account-id my-pipeline --name "My Pipeline SA"`,
	Args: cobra.NoArgs,
	RunE: runHubSAMint,
}

var (
	hubSAProjectID   string
	hubSADisplayName string
	hubSAMintID      string
	hubSAOutputJSON  bool
)

func init() {
	hubCmd.AddCommand(hubServiceAccountsCmd)
	hubServiceAccountsCmd.AddCommand(hubSAAddCmd)
	hubServiceAccountsCmd.AddCommand(hubSAListCmd)
	hubServiceAccountsCmd.AddCommand(hubSARemoveCmd)
	hubServiceAccountsCmd.AddCommand(hubSAVerifyCmd)
	hubServiceAccountsCmd.AddCommand(hubSAMintCmd)

	hubSAAddCmd.Flags().StringVar(&hubSAProjectID, "project", "", "GCP project ID (required)")
	hubSAAddCmd.Flags().StringVar(&hubSADisplayName, "name", "", "Display name for the service account")
	_ = hubSAAddCmd.MarkFlagRequired("project")

	hubSAMintCmd.Flags().StringVar(&hubSAMintID, "account-id", "", "Custom account ID (will be prefixed with scion-)")
	hubSAMintCmd.Flags().StringVar(&hubSADisplayName, "name", "", "Display name for the service account")

	hubSAListCmd.Flags().BoolVar(&hubSAOutputJSON, "json", false, "Output in JSON format")
}

// resolveHubClientForSA creates a hub client for hub-scoped SA operations.
// Unlike the project variant, no linked project is required — the operations
// target the Hub scope directly.
func resolveHubClientForSA() (hubclient.Client, error) {
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

func runHubSAAdd(cmd *cobra.Command, args []string) error {
	email := args[0]

	client, err := resolveHubClientForSA()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &hubclient.CreateGCPServiceAccountRequest{
		Email:       email,
		ProjectID:   hubSAProjectID,
		DisplayName: hubSADisplayName,
	}

	sa, err := client.HubGCPServiceAccounts().Create(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to register service account: %w", err)
	}

	if isJSONOutput() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sa)
	}

	fmt.Printf("Registered hub service account: %s\n", sa.Email)
	fmt.Printf("  ID:       %s\n", sa.ID)
	fmt.Printf("  Project:  %s\n", sa.ProjectID)
	if sa.DisplayName != "" {
		fmt.Printf("  Name:     %s\n", sa.DisplayName)
	}
	fmt.Printf("  Verified: %v\n", sa.Verified)

	return nil
}

func runHubSAList(cmd *cobra.Command, args []string) error {
	client, err := resolveHubClientForSA()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sas, err := client.HubGCPServiceAccounts().List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list service accounts: %w", err)
	}

	if hubSAOutputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sas)
	}

	if len(sas) == 0 {
		fmt.Println("No hub-scoped GCP service accounts registered.")
		fmt.Println("Use 'scion hub service-accounts add' to register one.")
		return nil
	}

	fmt.Printf("Hub GCP Service Accounts (%d):\n", len(sas))
	fmt.Printf("%-36s  %-45s  %-20s  %s\n", "ID", "EMAIL", "PROJECT", "VERIFIED")
	fmt.Printf("%-36s  %-45s  %-20s  %s\n",
		"------------------------------------",
		"---------------------------------------------",
		"--------------------",
		"--------")
	for _, sa := range sas {
		verified := "no"
		if sa.Verified {
			verified = "yes"
		}
		fmt.Printf("%-36s  %-45s  %-20s  %s\n",
			sa.ID,
			truncate(sa.Email, 45),
			truncate(sa.ProjectID, 20),
			verified)
	}

	return nil
}

func runHubSARemove(cmd *cobra.Command, args []string) error {
	saID := args[0]

	client, err := resolveHubClientForSA()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := client.HubGCPServiceAccounts().Delete(ctx, saID); err != nil {
		return fmt.Errorf("failed to remove service account: %w", err)
	}

	fmt.Printf("Removed hub service account %s\n", saID)
	return nil
}

func runHubSAMint(cmd *cobra.Command, args []string) error {
	client, err := resolveHubClientForSA()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req := &hubclient.MintGCPServiceAccountRequest{
		AccountID:   hubSAMintID,
		DisplayName: hubSADisplayName,
	}

	sa, err := client.HubGCPServiceAccounts().Mint(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to mint service account: %w", err)
	}

	if isJSONOutput() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sa)
	}

	fmt.Printf("Minted hub service account: %s\n", sa.Email)
	fmt.Printf("  ID:        %s\n", sa.ID)
	fmt.Printf("  Project:   %s\n", sa.ProjectID)
	if sa.DisplayName != "" {
		fmt.Printf("  Name:      %s\n", sa.DisplayName)
	}
	fmt.Printf("  Verified:  %v\n", sa.Verified)
	fmt.Printf("  Managed:   %v\n", sa.Managed)

	return nil
}

func runHubSAVerify(cmd *cobra.Command, args []string) error {
	saID := args[0]

	client, err := resolveHubClientForSA()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sa, err := client.HubGCPServiceAccounts().Verify(ctx, saID)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if isJSONOutput() {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sa)
	}

	fmt.Printf("Hub service account verified: %s\n", sa.Email)
	fmt.Printf("  ID:          %s\n", sa.ID)
	fmt.Printf("  Project:     %s\n", sa.ProjectID)
	fmt.Printf("  Verified:    %v\n", sa.Verified)
	fmt.Printf("  Verified At: %s\n", sa.VerifiedAt.Format(time.RFC3339))

	return nil
}
