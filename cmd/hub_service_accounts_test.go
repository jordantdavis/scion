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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func findSubcommand(parent *cobra.Command, use string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == use {
			return c
		}
	}
	return nil
}

func TestHubServiceAccountsWiredUnderHub(t *testing.T) {
	sa := findSubcommand(hubCmd, "service-accounts")
	require.NotNil(t, sa, "service-accounts should be attached to hub command")
	assert.Contains(t, sa.Aliases, "sa")

	// All five subcommands present.
	for _, name := range []string{"add", "list", "remove", "verify", "mint"} {
		assert.NotNil(t, findSubcommand(sa, name), "hub service-accounts should have %q subcommand", name)
	}
}

func TestHubServiceAccountsAddFlags(t *testing.T) {
	add := findSubcommand(hubServiceAccountsCmd, "add")
	require.NotNil(t, add)

	require.NotNil(t, add.Flags().Lookup("project"), "add should have --project flag")
	require.NotNil(t, add.Flags().Lookup("name"), "add should have --name flag")

	// --project is required.
	requiredAnnotation := add.Flags().Lookup("project").Annotations[cobra.BashCompOneRequiredFlag]
	assert.Equal(t, []string{"true"}, requiredAnnotation, "--project should be required")

	// ExactArgs(1): EMAIL.
	assert.Error(t, add.Args(add, []string{}))
	assert.NoError(t, add.Args(add, []string{"sa@p.iam.gserviceaccount.com"}))
}

func TestHubServiceAccountsMintFlags(t *testing.T) {
	mint := findSubcommand(hubServiceAccountsCmd, "mint")
	require.NotNil(t, mint)
	require.NotNil(t, mint.Flags().Lookup("account-id"))
	require.NotNil(t, mint.Flags().Lookup("name"))
	assert.NoError(t, mint.Args(mint, []string{}))
	assert.Error(t, mint.Args(mint, []string{"extra"}))
}

func TestHubServiceAccountsListFlags(t *testing.T) {
	list := findSubcommand(hubServiceAccountsCmd, "list")
	require.NotNil(t, list)
	assert.Contains(t, list.Aliases, "ls")
	require.NotNil(t, list.Flags().Lookup("json"))
}

func TestHubServiceAccountsRemoveVerifyArgs(t *testing.T) {
	remove := findSubcommand(hubServiceAccountsCmd, "remove")
	require.NotNil(t, remove)
	assert.Contains(t, remove.Aliases, "rm")
	assert.Error(t, remove.Args(remove, []string{}))
	assert.NoError(t, remove.Args(remove, []string{"id"}))

	verify := findSubcommand(hubServiceAccountsCmd, "verify")
	require.NotNil(t, verify)
	assert.Error(t, verify.Args(verify, []string{}))
	assert.NoError(t, verify.Args(verify, []string{"id"}))
}

func TestHubSettingsWiredUnderHub(t *testing.T) {
	settings := findSubcommand(hubCmd, "settings")
	require.NotNil(t, settings, "settings should be attached to hub command")

	set := findSubcommand(settings, "set")
	require.NotNil(t, set, "settings should have a set subcommand")

	require.NotNil(t, set.Flags().Lookup("gcp-identity-mode"))
	require.NotNil(t, set.Flags().Lookup("gcp-identity-service-account"))
	require.NotNil(t, settings.Flags().Lookup("json"))
}

func TestHubSettingsSetRejectsNoFlags(t *testing.T) {
	// With no flags changed, set should error before contacting the hub.
	set := &cobra.Command{Use: "set", RunE: runHubSettingsSet}
	set.Flags().StringVar(&hubSettingsGCPMode, "gcp-identity-mode", "", "")
	set.Flags().StringVar(&hubSettingsGCPServiceAcct, "gcp-identity-service-account", "", "")

	err := set.RunE(set, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no settings provided")
}

func TestHubSettingsSetRejectsInvalidMode(t *testing.T) {
	set := &cobra.Command{Use: "set", RunE: runHubSettingsSet}
	set.Flags().StringVar(&hubSettingsGCPMode, "gcp-identity-mode", "", "")
	set.Flags().StringVar(&hubSettingsGCPServiceAcct, "gcp-identity-service-account", "", "")
	require.NoError(t, set.Flags().Set("gcp-identity-mode", "bogus"))

	err := set.RunE(set, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --gcp-identity-mode")
}
