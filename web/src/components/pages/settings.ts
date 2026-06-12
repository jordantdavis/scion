/**
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Hub Resources page component
 *
 * Displays hub-scoped resources (environment variables, secrets) and the
 * global file-based resources (templates, harness configs). Structured to
 * mirror the project settings Resources section for consistency.
 */

import { LitElement, html, css, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';

import type { GCPServiceAccount } from '../../shared/types.js';
import { apiFetch, extractApiError } from '../../client/api.js';

import '../shared/env-var-list.js';
import '../shared/secret-list.js';
import '../shared/resource-list.js';
import '../shared/resource-import.js';
import '../shared/gcp-service-account-list.js';

/** Hub default-identity settings, matching GET/PUT /api/v1/hub/settings. */
interface HubSettings {
  defaultGcpIdentityMode?: string;
  defaultGcpIdentityServiceAccountId?: string;
}

@customElement('scion-page-settings')
export class ScionPageSettings extends LitElement {
  @state()
  private activeTab = 'env-vars';

  // Hub default GCP identity settings
  @state() private gcpIdentityMode = '';
  @state() private gcpIdentitySAID = '';
  @state() private gcpServiceAccounts: GCPServiceAccount[] = [];
  @state() private settingsLoading = true;
  @state() private settingsSaving = false;
  @state() private settingsError: string | null = null;
  @state() private settingsSaved = false;

  static override styles = css`
    :host {
      display: block;
    }

    .header {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 2rem;
    }

    .header sl-icon {
      color: var(--scion-primary, #3b82f6);
      font-size: 1.5rem;
    }

    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--scion-text, #1e293b);
      margin: 0;
    }

    .section {
      background: var(--scion-surface, #ffffff);
      border: 1px solid var(--scion-border, #e2e8f0);
      border-radius: var(--scion-radius-lg, 0.75rem);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }

    .section h2 {
      font-size: 1.125rem;
      font-weight: 600;
      color: var(--scion-text, #1e293b);
      margin: 0 0 0.25rem 0;
    }

    .section > p {
      font-size: 0.875rem;
      color: var(--scion-text-muted, #64748b);
      margin: 0 0 1rem 0;
    }

    .tab-intro {
      font-size: 0.875rem;
      color: var(--scion-text-muted, #64748b);
      margin: 0 0 1rem 0;
    }

    sl-tab-group {
      --indicator-color: var(--scion-primary, #3b82f6);
    }

    sl-tab-group::part(base) {
      background: transparent;
    }

    sl-tab-panel::part(base) {
      padding: 1.5rem 0 0 0;
    }

    .config-form {
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      max-width: 32rem;
    }

    .config-field {
      display: flex;
      flex-direction: column;
      gap: 0.375rem;
    }

    .config-field label {
      font-size: 0.875rem;
      font-weight: 600;
      color: var(--scion-text, #1e293b);
    }

    .field-help {
      font-size: 0.8125rem;
      color: var(--scion-text-muted, #64748b);
    }

    .settings-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-top: 0.5rem;
    }

    .settings-error {
      color: var(--sl-color-danger-700, #b91c1c);
      font-size: 0.8125rem;
    }

    .settings-saved {
      color: var(--sl-color-success-700, #15803d);
      font-size: 0.8125rem;
    }

    .subsection-intro {
      font-size: 0.875rem;
      color: var(--scion-text-muted, #64748b);
      margin: 0 0 1rem 0;
    }
  `;

  override connectedCallback(): void {
    super.connectedCallback();
    // Deep-link a specific tab via ?tab= (e.g. ?tab=templates), used by the
    // resource detail pages' "back" links.
    if (typeof window !== 'undefined') {
      const tab = new URLSearchParams(window.location.search).get('tab');
      if (tab) {
        this.activeTab = tab;
      }
    }
    void this.loadHubSettings();
  }

  private async loadHubSettings(): Promise<void> {
    this.settingsLoading = true;
    this.settingsError = null;
    try {
      const [settingsRes, saRes] = await Promise.all([
        apiFetch('/api/v1/hub/settings'),
        apiFetch('/api/v1/hub/gcp-service-accounts'),
      ]);

      if (!settingsRes.ok) {
        throw new Error(
          await extractApiError(
            settingsRes,
            `HTTP ${settingsRes.status}: ${settingsRes.statusText}`
          )
        );
      }
      const settings = (await settingsRes.json()) as HubSettings;
      this.gcpIdentityMode = settings.defaultGcpIdentityMode || '';
      this.gcpIdentitySAID = settings.defaultGcpIdentityServiceAccountId || '';

      if (saRes.ok) {
        const data = (await saRes.json()) as { items?: GCPServiceAccount[] } | GCPServiceAccount[];
        const items = Array.isArray(data) ? data : data.items || [];
        // Only verified accounts are eligible for assignment.
        this.gcpServiceAccounts = items.filter((sa) => sa.verified);
      }
    } catch (err) {
      console.error('Failed to load hub settings:', err);
      this.settingsError = err instanceof Error ? err.message : 'Failed to load hub settings';
    } finally {
      this.settingsLoading = false;
    }
  }

  private async saveHubSettings(): Promise<void> {
    this.settingsSaving = true;
    this.settingsError = null;
    this.settingsSaved = false;
    try {
      const body: HubSettings = {
        defaultGcpIdentityMode: this.gcpIdentityMode,
        defaultGcpIdentityServiceAccountId:
          this.gcpIdentityMode === 'assign' ? this.gcpIdentitySAID : '',
      };
      const res = await apiFetch('/api/v1/hub/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        throw new Error(await extractApiError(res, `HTTP ${res.status}: ${res.statusText}`));
      }
      const settings = (await res.json()) as HubSettings;
      this.gcpIdentityMode = settings.defaultGcpIdentityMode || '';
      this.gcpIdentitySAID = settings.defaultGcpIdentityServiceAccountId || '';
      this.settingsSaved = true;
    } catch (err) {
      console.error('Failed to save hub settings:', err);
      this.settingsError = err instanceof Error ? err.message : 'Failed to save hub settings';
    } finally {
      this.settingsSaving = false;
    }
  }

  /** Refresh a resource list (by element id) after an import. */
  private refreshList(id: string): void {
    const list = this.shadowRoot?.querySelector(`#${id}`) as
      | import('../shared/resource-list.js').ScionResourceList
      | null;
    void list?.load();
  }

  override render() {
    return html`
      <div class="header">
        <sl-icon name="gear"></sl-icon>
        <h1>Hub Resources</h1>
      </div>

      <div class="section">
        <h2>Resources</h2>
        <p>Hub-scoped resources available to all projects and agents.</p>

        <sl-tab-group
          @sl-tab-show=${(e: CustomEvent) => {
            this.activeTab = (e.detail as { name: string }).name;
          }}
        >
          <sl-tab slot="nav" panel="env-vars" ?active=${this.activeTab === 'env-vars'}
            >Environment Variables</sl-tab
          >
          <sl-tab slot="nav" panel="secrets" ?active=${this.activeTab === 'secrets'}
            >Secrets</sl-tab
          >
          <sl-tab slot="nav" panel="templates" ?active=${this.activeTab === 'templates'}
            >Templates</sl-tab
          >
          <sl-tab slot="nav" panel="harness-configs" ?active=${this.activeTab === 'harness-configs'}
            >Harness Configs</sl-tab
          >
          <sl-tab slot="nav" panel="gcp-sa" ?active=${this.activeTab === 'gcp-sa'}
            >GCP Service Accounts</sl-tab
          >

          <sl-tab-panel name="env-vars">
            <scion-env-var-list scope="hub" apiBasePath="/api/v1" compact></scion-env-var-list>
          </sl-tab-panel>

          <sl-tab-panel name="secrets">
            <scion-secret-list scope="hub" apiBasePath="/api/v1" compact></scion-secret-list>
          </sl-tab-panel>

          <sl-tab-panel name="templates">
            <p class="tab-intro">Global agent templates. Open one to browse and edit its files.</p>
            <scion-resource-import
              kind="template"
              scope="global"
              canImport
              @resource-changed=${() => this.refreshList('templates-list')}
            ></scion-resource-import>
            <scion-resource-list
              id="templates-list"
              kind="template"
              scope="global"
              detailBasePath="/settings"
              canClone
              canDelete
              @resource-changed=${() => this.refreshList('templates-list')}
            ></scion-resource-list>
          </sl-tab-panel>

          <sl-tab-panel name="harness-configs">
            <p class="tab-intro">
              Global harness configurations. Open one to browse and edit its files.
            </p>
            <scion-resource-import
              kind="harness-config"
              scope="global"
              canImport
              @resource-changed=${() => this.refreshList('harness-configs-list')}
            ></scion-resource-import>
            <scion-resource-list
              id="harness-configs-list"
              kind="harness-config"
              scope="global"
              detailBasePath="/settings"
              canClone
              canDelete
              @resource-changed=${() => this.refreshList('harness-configs-list')}
            ></scion-resource-list>
          </sl-tab-panel>

          <sl-tab-panel name="gcp-sa">
            ${this.renderGCPDefaultIdentity()}
            <scion-gcp-service-account-list
              hubScoped
              @sl-after-hide=${() => void this.loadHubSettings()}
            ></scion-gcp-service-account-list>
          </sl-tab-panel>
        </sl-tab-group>
      </div>
    `;
  }

  private renderGCPDefaultIdentity() {
    return html`
      <div class="config-form" style="margin-bottom: 2rem;">
        <p class="subsection-intro">
          The hub default GCP identity applies to all agents created through the hub when the
          agent's project does not set its own GCP identity default. A project that explicitly
          selects "Block" overrides this default.
        </p>

        <div class="config-field">
          <label>Default GCP Identity Mode</label>
          <sl-select
            value=${this.gcpIdentityMode || 'inherit'}
            ?disabled=${this.settingsLoading || this.settingsSaving}
            @sl-change=${(e: Event) => {
              const val = (e.target as HTMLSelectElement).value;
              this.gcpIdentityMode = val === 'inherit' ? '' : val;
              if (this.gcpIdentityMode !== 'assign') {
                this.gcpIdentitySAID = '';
              }
              this.settingsSaved = false;
            }}
          >
            <sl-option value="inherit">None (default to block)</sl-option>
            <sl-option value="block">Block</sl-option>
            <sl-option value="passthrough">Passthrough</sl-option>
            <sl-option value="assign">Assign Service Account</sl-option>
          </sl-select>
          <span class="field-help"
            >Controls GCP metadata server access for new agents. "Block" prevents access,
            "Passthrough" allows host identity, "Assign" binds a specific hub service account.</span
          >
        </div>

        ${this.gcpIdentityMode === 'assign'
          ? html`
              <div class="config-field">
                <label>Service Account</label>
                <sl-select
                  placeholder="Select a verified service account"
                  clearable
                  value=${this.gcpIdentitySAID}
                  ?disabled=${this.settingsLoading || this.settingsSaving}
                  @sl-change=${(e: Event) => {
                    this.gcpIdentitySAID = (e.target as HTMLSelectElement).value;
                    this.settingsSaved = false;
                  }}
                >
                  ${this.gcpServiceAccounts.length > 0
                    ? this.gcpServiceAccounts.map(
                        (sa) => html`
                          <sl-option value=${sa.id}>
                            ${sa.displayName || sa.email}
                            <small>(${sa.email})</small>
                          </sl-option>
                        `
                      )
                    : html`<sl-option value="" disabled
                        >No verified service accounts available</sl-option
                      >`}
                </sl-select>
                <span class="field-help"
                  >The hub-scoped GCP service account assigned to new agents by default. Only
                  verified accounts are shown.</span
                >
              </div>
            `
          : nothing}

        <div class="settings-actions">
          <sl-button
            variant="primary"
            ?loading=${this.settingsSaving}
            ?disabled=${this.settingsLoading || this.settingsSaving}
            @click=${() => void this.saveHubSettings()}
          >
            Save Default Identity
          </sl-button>
          ${this.settingsError
            ? html`<span class="settings-error">${this.settingsError}</span>`
            : this.settingsSaved
              ? html`<span class="settings-saved">Saved</span>`
              : nothing}
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'scion-page-settings': ScionPageSettings;
  }
}
