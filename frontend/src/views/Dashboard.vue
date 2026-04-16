<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <DashboardLayout
    :title="pageTitle"
    :active-tab="activeTab"
    :show-title="false"
    :show-development-warning="!orgSettings.require_pin && !loadingOrgSettings"
    @tab-change="handleTabChange"
    @logout="logout"
  >

    <!-- Notes sidebar (only show for Cloud credentials) -->
    <template #aside>
      <div v-if="activeTab === 'credentials'" class="notes-card">
        <h3>Cloud credentials</h3>
        <p>Add your AWS credentials to deploy applications to your own infrastructure.</p>
        <p>Your credentials are encrypted and stored securely.</p>
      </div>
    </template>

    <!-- Applications Tab -->
    <template v-if="activeTab === 'apps'">
      <!-- Loading state -->
      <div v-if="loadingApps" class="content-card">
        <div class="loading">Loading applications...</div>
      </div>

      <!-- App Detail View -->
      <div v-else-if="selectedApp" class="content-card app-detail-card">
        <nav class="breadcrumbs" aria-label="Breadcrumb">
          <button class="breadcrumb-link" @click="closeAppDetail">Applications</button>
          <span class="breadcrumb-separator">/</span>
          <span class="breadcrumb-current">{{ selectedApp.resource_name || 'Unnamed App' }}</span>
        </nav>

        <!-- Header with title -->
        <div class="app-detail-header">
          <div class="app-detail-header-left">
            <h2 class="app-detail-title">{{ selectedApp.resource_name || 'Unnamed App' }}</h2>
            <a
              v-if="selectedApp.public_ip"
              :href="getAppUrl(selectedApp)"
              target="_blank"
              class="app-open-icon-btn"
              title="Open app"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15 3 21 3 21 9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </a>
          </div>
          <button
            v-if="selectedApp.public_ip"
            @click="attestationApp = selectedApp"
            class="header-attestation-btn"
            title="Verify that this application is running exactly the code you expect inside a secure enclave."
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Verify attestation
          </button>
        </div>

        <!-- Two-column layout: Main content + Sidebar -->
        <div class="app-detail-layout">
          <!-- Main Content -->
          <div class="app-detail-main">
            <!-- Infrastructure Section -->
            <div class="app-detail-section">
              <div class="app-detail-grid app-detail-grid--3col">
                <!-- Row 1: Created, App ID (spans 2 cols) -->
                <div class="app-detail-item">
                  <span class="app-detail-label">Created</span>
                  <span class="app-detail-value">{{ formatDateOnly(selectedApp.created_at) }}, {{ formatTimeWithTimezone(selectedApp.created_at) }}</span>
                </div>
                <div class="app-detail-item app-detail-item--span2">
                  <span class="app-detail-label">App ID</span>
                  <div class="app-detail-value-with-copy">
                    <span class="app-detail-value">{{ selectedApp.id }}</span>
                    <button
                      class="copy-inline-btn"
                      @click="copyToClipboard(selectedApp.id, 'appId')"
                      :title="copiedField === 'appId' ? 'Copied!' : 'Copy to clipboard'"
                      :aria-label="copiedField === 'appId' ? 'Copied App ID' : 'Copy App ID to clipboard'"
                    >
                      <svg v-if="copiedField !== 'appId'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                      <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                    </button>
                  </div>
                </div>
                <!-- Row 2: Deployment, Region, Instance type -->
                <div class="app-detail-item">
                  <span class="app-detail-label tooltip-wrapper">
                    Deployment
                    <button type="button" class="tooltip-trigger" aria-label="Learn more about deployment types">
                      <img src="/assets/icons/info.svg" alt="" class="tooltip-icon" />
                    </button>
                    <span class="tooltip-content" role="tooltip">
                      <template v-if="isManaged(selectedApp)">
                        Workloads execute within the customer's infrastructure (on‑prem or cloud account) using customer‑owned credentials, while lifecycle management, configuration, and operational control of the service are performed by Caution.
                      </template>
                      <template v-else>
                        Workloads execute in Caution‑operated infrastructure. Provisioning, patching, monitoring, and security controls are administered entirely by Caution.
                      </template>
                    </span>
                  </span>
                  <span class="app-detail-value">{{ isManaged(selectedApp) ? 'Managed on-prem' : 'Fully managed' }}</span>
                </div>
                <div class="app-detail-item">
                  <span class="app-detail-label">Region</span>
                  <span class="app-detail-value">{{ selectedApp.region || 'Not set' }}</span>
                </div>
                <div class="app-detail-item">
                  <span class="app-detail-label">Instance type</span>
                  <span class="app-detail-value">{{ selectedApp.configuration?.instance_type || 'Not set' }}</span>
                </div>
                <!-- Row 3: Public IP, Domain -->
                <div class="app-detail-item">
                  <span class="app-detail-label">Public IP</span>
                  <div v-if="selectedApp.public_ip" class="app-detail-value-with-copy">
                    <span class="app-detail-value">{{ selectedApp.public_ip }}</span>
                    <button
                      class="copy-inline-btn"
                      @click="copyToClipboard(selectedApp.public_ip, 'publicIp')"
                      :title="copiedField === 'publicIp' ? 'Copied!' : 'Copy to clipboard'"
                      :aria-label="copiedField === 'publicIp' ? 'Copied IP address' : 'Copy IP address to clipboard'"
                    >
                      <svg v-if="copiedField !== 'publicIp'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                      <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                    </button>
                  </div>
                  <span v-else class="app-detail-value app-detail-muted">Not set</span>
                </div>
                <div class="app-detail-item app-detail-item--span2">
                  <span class="app-detail-label">Domain</span>
                  <div v-if="selectedApp.configuration?.domain" class="app-detail-value-with-copy">
                    <span class="app-detail-value">{{ selectedApp.configuration.domain }}</span>
                    <button
                      class="copy-inline-btn"
                      @click="copyToClipboard(selectedApp.configuration.domain, 'domain')"
                      :title="copiedField === 'domain' ? 'Copied!' : 'Copy to clipboard'"
                      :aria-label="copiedField === 'domain' ? 'Copied domain' : 'Copy domain to clipboard'"
                    >
                      <svg v-if="copiedField !== 'domain'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                      </svg>
                      <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                        <polyline points="20 6 9 17 4 12"></polyline>
                      </svg>
                    </button>
                  </div>
                  <span v-else class="app-detail-value app-detail-muted">Not set</span>
                </div>
              </div>
            </div>

          </div>

          <!-- Sidebar -->
          <aside class="app-detail-sidebar">
            <div class="sidebar-status">
              <span class="app-detail-label">Status</span>
              <span :class="['app-status-badge', `status-${selectedApp.state.toLowerCase()}`]">
                {{ selectedApp.state }}
              </span>
            </div>
            <div class="sidebar-meta">
              <div class="sidebar-meta-item">
                <span class="app-detail-label">vCPUs</span>
                <span class="app-detail-value">{{ selectedApp.configuration?.cpus || '-' }}</span>
              </div>
              <div class="sidebar-meta-item">
                <span class="app-detail-label">RAM</span>
                <span class="app-detail-value">{{ selectedApp.configuration?.memory_mb ? formatMemory(selectedApp.configuration.memory_mb) : '-' }}</span>
              </div>
            </div>
            <div v-if="selectedApp.state === 'running' && calculateAppMonthlyCost(selectedApp)" class="sidebar-cost">
              <span class="app-detail-label">Est. monthly cost</span>
              <span class="app-detail-value app-detail-value--cost">${{ calculateAppMonthlyCost(selectedApp) }}</span>
            </div>
          </aside>
        </div>

        <!-- AWS Infrastructure Details (only for managed on-prem apps) -->
        <div v-if="isManaged(selectedApp) && selectedApp.configuration?.managed_onprem" class="app-detail-section app-detail-section--fullwidth app-detail-section--borderless">
          <h3 class="app-detail-section-title">AWS Infrastructure</h3>
          <p class="app-detail-helper-text">Your AWS infrastructure for this deployment.</p>
          <div class="aws-details-grid">
            <div class="aws-detail-item">
              <span class="aws-detail-label">Account ID</span>
              <div class="aws-detail-value-row">
                <span class="aws-detail-value">{{ selectedApp.configuration.managed_onprem.aws_account_id || '-' }}</span>
                <button
                  v-if="selectedApp.configuration.managed_onprem.aws_account_id"
                  class="copy-inline-btn"
                  @click="copyToClipboard(selectedApp.configuration.managed_onprem.aws_account_id, 'awsAccountId')"
                  :title="copiedField === 'awsAccountId' ? 'Copied!' : 'Copy to clipboard'"
                  :aria-label="copiedField === 'awsAccountId' ? 'Copied AWS Account ID' : 'Copy AWS Account ID to clipboard'"
                >
                  <svg v-if="copiedField !== 'awsAccountId'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </button>
              </div>
            </div>
            <div class="aws-detail-item">
              <span class="aws-detail-label">Region</span>
              <span class="aws-detail-value">{{ selectedApp.configuration.managed_onprem.aws_region || selectedApp.region || 'Not set' }}</span>
            </div>
            <div class="aws-detail-item">
              <span class="aws-detail-label">VPC ID</span>
              <div class="aws-detail-value-row">
                <span class="aws-detail-value">{{ selectedApp.configuration.managed_onprem.vpc_id || '-' }}</span>
                <button
                  v-if="selectedApp.configuration.managed_onprem.vpc_id"
                  class="copy-inline-btn"
                  @click="copyToClipboard(selectedApp.configuration.managed_onprem.vpc_id, 'vpcId')"
                  :title="copiedField === 'vpcId' ? 'Copied!' : 'Copy to clipboard'"
                  :aria-label="copiedField === 'vpcId' ? 'Copied VPC ID' : 'Copy VPC ID to clipboard'"
                >
                  <svg v-if="copiedField !== 'vpcId'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </button>
              </div>
            </div>
            <div class="aws-detail-item">
              <span class="aws-detail-label">Deployment ID</span>
              <div class="aws-detail-value-row">
                <span class="aws-detail-value">{{ selectedApp.configuration.managed_onprem.deployment_id || '-' }}</span>
                <button
                  v-if="selectedApp.configuration.managed_onprem.deployment_id"
                  class="copy-inline-btn"
                  @click="copyToClipboard(selectedApp.configuration.managed_onprem.deployment_id, 'deploymentId')"
                  :title="copiedField === 'deploymentId' ? 'Copied!' : 'Copy to clipboard'"
                  :aria-label="copiedField === 'deploymentId' ? 'Copied Deployment ID' : 'Copy Deployment ID to clipboard'"
                >
                  <svg v-if="copiedField !== 'deploymentId'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                  </svg>
                  <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Builder Configuration -->
        <div class="app-detail-section app-detail-section--fullwidth app-detail-section--borderless">
          <h3 class="app-detail-section-title">Build instance</h3>
          <p class="app-detail-helper-text">Select the dedicated builder size for this app. Larger builders compile faster.</p>
          <div class="builder-size-options">
            <button
              v-for="opt in builderConfig.options"
              :key="opt.id"
              :class="['builder-size-btn', { 'builder-size-btn--active': builderConfig.builder_size === opt.id }]"
              @click="setBuilderSize(opt.id)"
            >
              <span class="builder-size-label">{{ opt.label }}</span>
              <span class="builder-size-specs">{{ opt.vcpus }} vCPU &middot; {{ opt.ram_gb }} GB RAM</span>
            </button>
          </div>
        </div>

        <!-- Deployment Section (full width, outside the two-column layout) -->
        <div v-if="selectedApp.git_url" class="app-detail-section app-detail-section--fullwidth app-detail-section--borderless">
          <h3 class="app-detail-section-title">Deploy via Git</h3>
          <p class="app-detail-helper-text">Add this Git remote, then push to deploy.</p>
          <div class="app-detail-command">
            <code>git remote add caution {{ selectedApp.git_url }}</code>
            <button
              class="copy-inline-btn"
              @click="copyToClipboard(`git remote add caution ${selectedApp.git_url}`, 'gitCmd')"
              :title="copiedField === 'gitCmd' ? 'Copied!' : 'Copy to clipboard'"
              :aria-label="copiedField === 'gitCmd' ? 'Copied git command' : 'Copy git command to clipboard'"
            >
              <svg v-if="copiedField !== 'gitCmd'" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
              </svg>
              <svg v-else width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            </button>
          </div>
        </div>

        <!-- Danger zone (outside the content card) -->
        <div class="app-detail-danger-zone app-detail-danger-zone--standalone">
          <h3 class="app-detail-section-title app-detail-section-title--danger">Danger zone</h3>
          <div class="app-detail-danger-content">
            <div class="app-detail-danger-item">
              <div class="app-detail-danger-info">
                <span class="app-detail-danger-title">Delete app</span>
                <span class="app-detail-danger-description">This will permanently delete the app and all data.</span>
              </div>
              <button @click="destroyApp(selectedApp.id, selectedApp.resource_name)" class="app-detail-action-btn app-detail-action-btn--danger">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <polyline points="3 6 5 6 21 6"/>
                  <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                </svg>
                Delete app
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Apps list (when user has apps) -->
      <div v-else-if="apps.length > 0" class="content-card">
        <div class="content-header content-header--with-search">
          <div class="content-header-text">
            <h2 class="content-header-title">Applications</h2>
            <p class="content-header-description">
              Applications running in secure enclaves.
            </p>
          </div>
          <div class="apps-search-container">
            <svg class="apps-search-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="11" cy="11" r="8"/>
              <path d="m21 21-4.34-4.34"/>
            </svg>
            <input
              v-model="appSearchQuery"
              type="text"
              class="apps-search-input"
              placeholder="Search apps..."
            />
          </div>
        </div>
        <div class="apps-table-container">
          <table class="apps-table">
            <thead>
              <tr>
                <th class="col-name">Name</th>
                <th class="col-status">Status</th>
                <th class="col-deployment">
                  <span class="tooltip-wrapper">
                    Deployment
                    <button type="button" class="tooltip-trigger" aria-label="Learn more about deployment types">
                      <img src="/assets/icons/info.svg" alt="" class="tooltip-icon" />
                    </button>
                    <span class="tooltip-content" role="tooltip">
                      <strong>Fully managed:</strong> Workloads execute in Caution‑operated infrastructure. Provisioning, patching, monitoring, and security controls are administered entirely by Caution.<br><br>
                      <strong>Managed on‑premises:</strong> Workloads execute within the customer's infrastructure (on‑prem or cloud account) using customer‑owned credentials, while lifecycle management, configuration, and operational control of the service are performed by Caution.
                    </span>
                  </span>
                </th>
                <th class="col-region">Region</th>
                <th class="col-attestation">Attestation</th>
                <th class="col-created">Created</th>
                <th class="col-chevron"></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="app in filteredApps" :key="app.id" class="apps-table-row" @click="openAppDetail(app)">
                <td class="app-name-cell">
                  <span class="app-name-text">{{ app.resource_name || "Unnamed App" }}</span>
                </td>
                <td class="app-status-cell">
                  <span :class="['app-status-badge', `status-${app.state.toLowerCase()}`]">
                    {{ app.state }}
                  </span>
                </td>
                <td class="app-type-cell">
                  <span :class="['app-type-badge', isManaged(app) ? 'type-managed' : 'type-hosted']">
                    {{ isManaged(app) ? 'Managed on-prem' : 'Fully managed' }}
                  </span>
                </td>
                <td class="app-region-cell">
                  <span v-if="app.region" class="region-code">{{ app.region }}</span>
                  <span v-else class="app-region-empty">Not set</span>
                </td>
                <td class="app-attestation-cell">
                  <button
                    v-if="app.public_ip"
                    @click.stop="attestationApp = app"
                    class="app-attestation-btn"
                    title="Verify attestation"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                    Verify
                  </button>
                  <span v-else class="app-attestation-empty">-</span>
                </td>
                <td class="app-created-cell">
                  <span v-if="app.created_at">{{ formatRelativeTime(app.created_at) }}</span>
                  <span v-else class="app-created-empty">-</span>
                </td>
                <td class="app-chevron-cell">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="9 18 15 12 9 6"/>
                  </svg>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Starter Screen (default home screen when no apps) -->
      <template v-else-if="apps.length === 0">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <div class="guide-intro-eyebrow">GET STARTED</div>
            <h2 class="guide-intro-title">Deploy your first app</h2>
            <p class="guide-intro-description">
              Follow the quickstart guide to deploy an application in a secure enclave using the Caution CLI.
            </p>

            <a href="https://docs.caution.co/quickstart/" target="_blank" rel="noopener noreferrer" class="btn-guide">
              Read the quickstart guide
            </a>
          </div>
        </div>
      </template>
    </template>

    <!-- Quick Start Guide Tab -->
    <template v-if="activeTab === 'guide'">
      <!-- Guide Intro Screen -->
      <template v-if="setupStep === 0">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <div class="guide-intro-eyebrow">QUICK START GUIDE</div>
            <h2 class="guide-intro-title">{{ apps.length === 0 ? 'Deploy your first application' : 'How to deploy an application' }}</h2>
            <p class="guide-intro-description">
              Learn how to use the Caution CLI to deploy your application in a secure enclave and verify exactly what code is running.
            </p>

            <button class="btn-guide" @click="setupStep = 1">
              Get started
            </button>
          </div>
        </div>
      </template>

      <!-- Step 1: Install CLI -->
      <template v-else-if="setupStep === 1">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 1. Install the Caution CLI</h2>
          </div>

          <div class="guide-layout guide-layout-step2">
            <div class="guide-content">
              <p class="quick-start-description">
                Install the Caution CLI to deploy and manage enclave applications from your terminal.
              </p>
              <p class="quick-start-description">
                You only need to do this once per environment.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'install' }"
                  @click="copyCode('install')"
                  :title="copiedBlock === 'install' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeInstall">
git clone https://codeberg.org/caution/platform
cd platform
make build-cli
./utils/install.sh</pre
                >
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 0">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot active" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 2">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 2: Clone & Authenticate -->
      <template v-else-if="setupStep === 2">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 2. Clone an application</h2>
          </div>

          <div class="guide-layout guide-layout-step2">
            <div class="guide-content">
              <p class="quick-start-description">
                Clone the application you want to deploy.</p>
                <p class="quick-start-description">You can use <a href="https://codeberg.org/caution" target="_blank" rel="noopener noreferrer" class="guide-link">one of our demos</a> or your own repository.
              </p>
              <p class="quick-start-description">
                Authenticate with your security key and register your SSH key.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'clone' }"
                  @click="copyCode('clone')"
                  :title="copiedBlock === 'clone' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeClone"><span class="code-command">git clone https://codeberg.org/caution/hello-world-enclave</span>
<span class="code-command">cd hello-world-enclave</span>

<span class="code-command">caution login</span>
<span class="code-comment"># Tap your security key when prompted</span>

<span class="code-command">caution ssh-keys add --from-agent</span>
<span class="code-comment"># Or provide a key file such as ~/.ssh/id_ed25519.pub</span></pre
                >
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 1">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot active" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 3">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 3: Initialize -->
      <template v-else-if="setupStep === 3">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 3. Initialize project</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Run <code>caution init</code> to capture and lock the build environment for reproducible enclave builds.
              </p>
              <p class="quick-start-description">
                This creates a lockfile that records your system's build environment, ensuring that your enclave can be reproduced bit-for-bit by anyone.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'init' }"
                  @click="copyCode('init')"
                  :title="copiedBlock === 'init' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeInit">caution init</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 2">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot active" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 4">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 4: Deploy -->
      <template v-else-if="setupStep === 4">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 4. Deploy to enclave</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Push your application with <code>git push caution main</code> to deploy it.
              </p>
              <p class="quick-start-description">
                Caution builds a reproducible enclave image and provisions the TEE.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'deploy' }"
                  @click="copyCode('deploy')"
                  :title="copiedBlock === 'deploy' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeDeploy">git push caution main</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 3">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot active" @click="setupStep = 4"></button>
              <button class="progress-dot" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 5">
              <span class="btn-text">Next</span>
              <img
                src="/assets/chevron-right.svg"
                alt=""
                style="width: 20px; height: 20px; margin-left: 8px;"
              />
            </button>
          </div>
        </div>
      </template>

      <!-- Step 5: Verify -->
      <template v-else-if="setupStep === 5">
        <div class="content-card quick-start-inline">
          <div class="step-header">
            <h2 class="step-title">Step 5. Verify what runs in the enclave</h2>
          </div>

          <div class="guide-layout guide-layout-balanced">
            <div class="guide-content">
              <p class="quick-start-description">
                Run <code>caution verify --reproduce</code> to rebuild the image, compare hashes, and confirm exactly what code is running inside the enclave.
              </p>
              <p class="quick-start-description">
                Independent verification confirms the deployed enclave matches your source code.
              </p>
            </div>
            <div class="guide-code">
              <div class="code-block code-block-short">
                <button
                  class="copy-btn"
                  :class="{ copied: copiedBlock === 'verify' }"
                  @click="copyCode('verify')"
                  :title="copiedBlock === 'verify' ? 'Copied' : 'Copy to clipboard'"
                >
                  <img src="/assets/copy.svg" alt="Copy" class="copy-icon" />
                  <span class="copy-btn-text">Copied</span>
                </button>
                <pre ref="codeVerify">caution verify --reproduce</pre>
              </div>
            </div>
          </div>

          <div class="guide-navigation">
            <button class="btn-continue" @click="setupStep = 4">
              <img
                src="/assets/chevron-left.svg"
                alt=""
                style="width: 20px; height: 20px; margin-right: 8px;"
              />
              <span class="btn-text">Back</span>
            </button>
            <div class="progress-dots">
              <button class="progress-dot" @click="setupStep = 1"></button>
              <button class="progress-dot" @click="setupStep = 2"></button>
              <button class="progress-dot" @click="setupStep = 3"></button>
              <button class="progress-dot" @click="setupStep = 4"></button>
              <button class="progress-dot active" @click="setupStep = 5"></button>
            </div>
            <button class="btn-continue" @click="setupStep = 6">
              <span class="btn-text">Done</span>
            </button>
          </div>
        </div>
      </template>

      <!-- Completion Screen -->
      <template v-else-if="setupStep === 6">
        <div class="content-card guide-intro">
          <div class="guide-intro-content">
            <h2 class="guide-completion-title">You're ready to deploy with Caution</h2>
            <p class="guide-completion-description">
              You've completed the quick start guide.
              Use these steps to deploy and verify applications using the Caution CLI.
            </p>

            <button class="btn-guide" @click="handleTabChange('apps')">
              Go to applications
            </button>
          </div>
        </div>
      </template>
    </template>

    <!-- SSH Keys Tab -->
    <div v-if="activeTab === 'ssh'" class="content-card content-card--dashboard-tab">
      <!-- Show form when adding a key -->
      <template v-if="showAddKeyForm">
        <h3 class="form-section-title">Add new SSH key</h3>
        <p class="form-section-description">
          Add SSH keys to push code to your applications via git.
        </p>
        <div class="form-group">
          <label class="form-label" for="keyName">Key name</label>
          <input
            id="keyName"
            v-model="newKeyName"
            type="text"
            class="form-input"
            :disabled="addingKey"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="publicKey">Public key</label>
          <div class="form-input-wrapper">
            <textarea
              id="publicKey"
              v-model="newPublicKey"
              class="form-textarea"
              placeholder="Begins with 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-ed25519', 'sk-ecdsa-sha2-nistp256@openssh.com', or 'sk-ssh-ed25519@openssh.com'"
              rows="3"
              :disabled="addingKey"
            ></textarea>
            <div class="form-message-container">
              <div v-if="error && showAddKeyForm" class="message message--error">
                {{ error }}
              </div>
            </div>
          </div>
        </div>
        <div class="form-actions">
          <button
            @click="addKey"
            class="btn-primary"
            :disabled="addingKey || !newPublicKey.trim()"
          >
            {{ addingKey ? "Adding..." : "Add SSH key" }}
          </button>
          <button
            @click="showAddKeyForm = false; newKeyName = ''; newPublicKey = ''; error = null"
            class="btn-secondary"
            :disabled="addingKey"
          >
            Cancel
          </button>
        </div>
      </template>

      <!-- Show list when not adding a key -->
      <template v-else>
        <div class="content-header">
          <div class="content-header-text">
            <h2 class="content-header-title">SSH keys</h2>
            <p class="content-header-description">
              SSH keys for pushing code via Git. Remove any you don't recognize.
            </p>
          </div>
          <button
            class="btn-primary"
            @click="showAddKeyForm = true"
          >
            Add SSH key
          </button>
        </div>

        <!-- SSH Keys List -->
        <div class="items-list ssh-keys-list">
          <div v-if="loadingKeys" class="list-item-empty">Loading SSH keys...</div>
          <div v-else-if="sshKeys.length === 0" class="list-item-empty">
            No SSH keys yet. Add one to deploy via Git.
          </div>
          <div v-else>
            <div v-for="key in sshKeys" :key="key.fingerprint" class="ssh-key-item">
              <div class="ssh-key-icon">
                <img src="/assets/icons/ssh--inact.svg" alt="" />
              </div>
              <div class="ssh-key-info">
                <div class="ssh-key-title">{{ key.name || "Unnamed Key" }}</div>
                <div class="ssh-key-fingerprint">{{ key.fingerprint }}</div>
                <div class="ssh-key-meta">
                  <span class="ssh-key-date">Added on {{ formatDate(key.created_at) }}</span>
                </div>
                <div class="ssh-key-meta">
                  <span class="ssh-key-usage">{{ formatLastUsed(key.last_used_at) }}</span>
                  <span class="ssh-key-separator">|</span>
                  <span class="ssh-key-access">Read/write</span>
                </div>
              </div>
              <button
                @click="deleteKey(key.fingerprint)"
                class="ssh-key-delete"
                :disabled="deletingKey === key.fingerprint"
              >
                <svg v-if="deletingKey === key.fingerprint" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                  <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                </svg>
                {{ deletingKey === key.fingerprint ? "Deleting..." : "Delete" }}
              </button>
            </div>
          </div>
        </div>
      </template>
    </div>

    <!-- Security Tab -->
    <div v-if="activeTab === 'security'" class="content-card content-card--dashboard-tab">
      <div class="content-header">
        <div class="content-header-text">
          <h2 class="content-header-title">Security settings</h2>
          <p class="content-header-description">
            Configure authentication requirements for your organization.
          </p>
        </div>
        <button
          class="btn-primary"
          @click="addPasskey"
          :disabled="addingPasskey"
        >
          <svg v-if="addingPasskey" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
            <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
          </svg>
          {{ addPasskeyButtonLabel }}
        </button>
      </div>

      <div class="security-auth-panel">
        <div class="security-settings security-settings--inline">
          <div v-if="loadingOrgSettings" class="list-item-empty">Loading security settings...</div>
          <div v-else>
            <div class="security-setting-item">
              <div class="security-setting-info">
                <h3 class="security-setting-title">Require PIN/biometric for authentication</h3>
                <p class="security-setting-description">
                  When enabled, users must verify their identity with a PIN or biometric (fingerprint, face)
                  when logging in or signing sensitive operations. This provides stronger security but may
                  not be supported by all passkeys.
                </p>
              </div>
              <div class="security-setting-control">
                <label class="toggle-switch">
                  <input
                    type="checkbox"
                    :checked="orgSettings.require_pin"
                    @change="toggleRequirePin"
                    :disabled="updatingOrgSettings"
                  />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>

            <div v-if="orgSettingsError" class="message message--error">
              {{ orgSettingsError }}
            </div>
          </div>
        </div>

        <div class="security-passkeys">
          <div v-if="passkeyFlowStage" class="passkey-flow-card" role="status" aria-live="polite">
            <div class="passkey-flow-steps">
              <div
                class="passkey-flow-step"
                :class="{
                  'passkey-flow-step--active': passkeyFlowStage === 'approve',
                  'passkey-flow-step--done': passkeyFlowStage === 'register'
                }"
              >
                <span class="passkey-flow-step-number">1</span>
                <div class="passkey-flow-step-copy">
                  <strong>Approve with current authenticator</strong>
                  <span>Use the same authenticator you used to sign in.</span>
                </div>
              </div>
              <div
                class="passkey-flow-step"
                :class="{ 'passkey-flow-step--active': passkeyFlowStage === 'register' }"
              >
                <span class="passkey-flow-step-number">2</span>
                <div class="passkey-flow-step-copy">
                  <strong>Register the new authenticator</strong>
                  <span>Only tap the new key after step 1 succeeds.</span>
                </div>
              </div>
            </div>
            <p class="passkey-flow-message">{{ passkeyFlowMessage }}</p>
          </div>

          <div v-if="loadingPasskeys" class="list-item-empty">Loading authenticators...</div>
          <div v-else-if="passkeys.length === 0" class="list-item-empty">
            No authenticators found for this account.
          </div>
          <div v-else class="passkey-list">
            <div v-for="passkey in passkeys" :key="passkey.id" class="passkey-item">
              <div class="passkey-info">
                <div class="passkey-header">
                  <div>
                    <div class="passkey-title">{{ formatPasskeyTitle(passkey) }}</div>
                  </div>
                  <div class="passkey-badges">
                    <span class="passkey-badge">{{ passkey.kind }}</span>
                    <span v-if="passkey.is_current_session" class="passkey-badge passkey-badge--current">
                      Current session
                    </span>
                  </div>
                </div>

                <div class="passkey-meta">
                  <span>Added {{ formatDate(passkey.created_at) }}</span>
                  <span v-if="passkey.last_used_at">Last used {{ formatLastUsed(passkey.last_used_at) }}</span>
                  <span v-else>Not used recently</span>
                  <span v-if="formatPasskeyTransports(passkey.transports)">
                    {{ formatPasskeyTransports(passkey.transports) }}
                  </span>
                </div>
              </div>

              <button
                class="btn-danger btn-small"
                @click="deletePasskey(passkey)"
                :disabled="removingPasskey === passkey.id || passkeys.length <= 1"
              >
                <svg v-if="removingPasskey === passkey.id" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                  <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                </svg>
                {{ removingPasskey === passkey.id ? "Removing..." : "Remove" }}
              </button>
            </div>
          </div>

        </div>
      </div>
    </div>

    <!-- Key Services Tab -->
    <div v-if="activeTab === 'keys'" class="content-card content-card--dashboard-tab">
      <div class="content-header">
        <div class="content-header-text">
          <h2 class="content-header-title">Key services</h2>
          <p class="content-header-description">
            Manage quorum bundles created via <code>caution secret new</code>.
          </p>
        </div>
      </div>

      <div class="items-list">
        <div v-if="loadingBundles" class="loading">Loading bundles...</div>
        <div v-else-if="quorumBundles.length === 0" class="list-item-empty">
          <p class="list-item-empty-copy">
            No quorum bundles yet. Use <code>caution secret new</code> to create one.
          </p>
        </div>
        <div v-else>
          <div v-for="bundle in quorumBundles" :key="bundle.id" class="bundle-card">
            <div class="bundle-header">
              <div class="item-info">
                <div v-if="editingBundleName === bundle.id" class="bundle-name-edit">
                  <input
                    v-model="editBundleNameValue"
                    class="bundle-name-input"
                    placeholder="Bundle name"
                    @keyup.enter="saveBundleName(bundle.id)"
                    @keyup.escape="cancelEditBundleName()"
                  />
                  <button class="btn-sm btn-primary" @click="saveBundleName(bundle.id)">Save</button>
                  <button class="btn-sm btn-secondary" @click="cancelEditBundleName()">Cancel</button>
                </div>
                <div v-else class="bundle-name-display">
                  <span class="item-name">{{ bundle.name || truncateId(bundle.id) }}</span>
                  <button class="btn-icon" @click="startEditBundleName(bundle)" title="Rename bundle">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                  </button>
                </div>
                <span v-if="bundle.name" class="item-meta-id">{{ truncateId(bundle.id) }}</span>
                <span class="item-meta">Created {{ formatDate(bundle.created_at) }}</span>
              </div>
              <div class="item-actions">
                <button
                  @click="deleteBundle(bundle.id)"
                  class="btn-danger"
                  :disabled="deletingBundle === bundle.id"
                >
                  <svg v-if="deletingBundle === bundle.id" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                    <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                  </svg>
                  {{ deletingBundle === bundle.id ? "Deleting..." : "Delete" }}
                </button>
              </div>
            </div>
            <div class="bundle-labels">
              <span v-for="(v, k) in (bundle.labels || {})" :key="k" class="bundle-label-tag">
                {{ k }}: {{ v }}
                <button class="label-remove-btn" @click="removeLabel(bundle.id, k)" title="Remove label">&times;</button>
              </span>
              <button v-if="addingLabelTo !== bundle.id" class="bundle-label-add" @click="startAddLabel(bundle.id)">+ Add label</button>
              <span v-else class="label-add-form">
                <input v-model="newLabelKey" class="label-input" placeholder="key" @keyup.escape="cancelAddLabel()" />
                <input v-model="newLabelValue" class="label-input" placeholder="value" @keyup.enter="saveLabel(bundle.id)" @keyup.escape="cancelAddLabel()" />
                <button class="btn-sm btn-primary" @click="saveLabel(bundle.id)">Add</button>
                <button class="btn-sm btn-secondary" @click="cancelAddLabel()">Cancel</button>
              </span>
            </div>
            <div class="bundle-details" v-if="bundle.data">
              <div class="bundle-detail-row" v-if="bundleKeyHashes[bundle.id]">
                <span class="bundle-label">Public key hash</span>
                <code class="bundle-hash">{{ bundleKeyHashes[bundle.id] }}</code>
              </div>
              <div class="bundle-actions">
                <button
                  v-if="bundle.data.secret_recipient_public_key"
                  class="btn-sm btn-download"
                  @click="downloadFile(bundle.data.secret_recipient_public_key, truncateId(bundle.id) + '_public_key.asc')"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Public key
                </button>
                <button
                  v-if="bundle.data.shardfile"
                  class="btn-sm btn-download"
                  @click="downloadFile(bundle.data.shardfile, truncateId(bundle.id) + '_shardfile.asc')"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  Shard file
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete SSH Key Confirmation Modal -->
    <div v-if="showDeleteModal" class="modal-overlay" @click="cancelDelete">
      <div class="modal-content" @click.stop>
        <h3 class="modal-title">Delete SSH key</h3>
        <p class="modal-message">Are you sure you want to delete this SSH key? This action cannot be undone.</p>
        <div class="modal-actions">
          <button @click="cancelDelete" class="btn-secondary">Cancel</button>
          <button @click="confirmDelete" class="btn-danger">Delete</button>
        </div>
      </div>
    </div>

    <!-- Delete App Confirmation Modal -->
    <div v-if="showDestroyModal" class="modal-overlay" @click="cancelDestroy">
      <div class="modal-content" @click.stop>
        <h3 class="modal-title">Delete application</h3>
        <p class="modal-message">Are you sure you want to delete "{{ appToDestroy?.name }}"? This will stop the enclave and delete all data.</p>
        <p class="modal-message modal-message--subtle modal-message--with-icon">
          <img src="/assets/icons/icons__apps/hourglass.svg" alt="" class="modal-time-icon" />
          This may take a few minutes to complete.
        </p>
        <div class="modal-actions">
          <button @click="cancelDestroy" class="btn-secondary">Cancel</button>
          <button @click="confirmDestroy" class="btn-danger">Delete</button>
        </div>
      </div>
    </div>

    <!-- Billing Tab -->
    <div v-if="activeTab === 'settings'" class="content-card">
      <div class="content-header">
        <div class="content-header-text">
          <h2 class="content-header-title">Settings</h2>
          <p class="content-header-description">
            Manage your account email and billing.
          </p>
        </div>
      </div>

      <!-- Email Section -->
      <div class="billing-section">
        <h3 class="billing-section-title">Legal</h3>
        <div class="legal-settings-card">
          <div class="legal-settings-row">
            <div class="legal-settings-copy">
              <div class="legal-settings-name">Terms of Service</div>
              <div class="legal-settings-meta">
                <span>{{ getLegalStatusLabel(legalStatus?.terms_of_service) }}</span>
              </div>
            </div>
            <a href="https://caution.co/terms.html" target="_blank" rel="noopener noreferrer" class="legal-settings-link">
              <span>Review</span>
              <svg class="legal-settings-link-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M15 3h6v6"/>
                <path d="M10 14 21 3"/>
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              </svg>
            </a>
          </div>
          <div class="legal-settings-row">
            <div class="legal-settings-copy">
              <div class="legal-settings-name">Privacy Notice</div>
              <div class="legal-settings-meta">
                <span>{{ getLegalStatusLabel(legalStatus?.privacy_notice) }}</span>
              </div>
            </div>
            <a href="https://caution.co/privacy.html" target="_blank" rel="noopener noreferrer" class="legal-settings-link">
              <span>Review</span>
              <svg class="legal-settings-link-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M15 3h6v6"/>
                <path d="M10 14 21 3"/>
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
              </svg>
            </a>
          </div>
        </div>
      </div>

      <!-- Email Section -->
      <div class="billing-section">
        <h3 class="billing-section-title">Email</h3>
        <div class="email-settings">
          <div v-if="!editingEmail" class="email-display">
            <span v-if="userEmail" class="email-current">{{ userEmail }}</span>
            <span v-else class="email-not-set">No email set</span>
            <button @click="startEditEmail" class="btn-secondary btn-small">{{ userEmail ? 'Change' : 'Set email' }}</button>
          </div>
          <div v-else class="email-edit">
            <input
              v-model="emailInput"
              type="email"
              placeholder="you@example.com"
              class="email-input"
              @keyup.enter="saveEmail"
            />
            <div class="email-edit-actions">
              <button @click="saveEmail" :disabled="savingEmail" class="btn-primary btn-small">
                {{ savingEmail ? 'Saving...' : 'Save' }}
              </button>
              <button @click="editingEmail = false" class="btn-secondary btn-small">Cancel</button>
            </div>
            <div v-if="emailError" class="card-error">{{ emailError }}</div>
          </div>
          <p v-if="userEmail && emailVerified === false" class="email-unverified-warning">Email not verified — check your inbox for a verification link.</p>
          <p class="email-hint">Used for invoice and payment notifications.</p>
        </div>
      </div>

      <!-- Prepaid Credits -->
      <div class="billing-section">
        <h3 class="billing-section-title" style="margin-top: 2rem;">Prepaid credits</h3>
        <div class="credits-balance-card">
          <div class="credits-balance-row">
            <div class="credits-balance-info">
              <span class="credits-balance-amount">{{ creditBalance.balance_display }}</span>
              <span class="credits-balance-label">credit balance</span>
            </div>
            <button @click="showAddCreditsModal = true" class="btn-primary btn-small">Add credits</button>
          </div>
          <p class="credits-hint">Credits are deducted in real-time as your deployments run. Minimum $5 required to deploy.</p>
          <div class="redeem-code-row">
            <input
              v-model="redeemCode"
              type="text"
              class="redeem-code-input"
              placeholder="Enter credit code"
              :disabled="redeemingCode"
              @keyup.enter="redeemCreditCode"
            />
            <button
              @click="redeemCreditCode"
              class="btn-primary btn-small"
              :disabled="redeemingCode || !redeemCode.trim()"
            >
              {{ redeemingCode ? 'Redeeming...' : 'Redeem' }}
            </button>
          </div>
        </div>

        <!-- Auto Top-up -->
        <div class="auto-topup-card">
          <div class="auto-topup-header">
            <div>
              <strong>Auto top-up</strong>
              <p class="credits-hint" style="margin-top: 0.25rem;">Automatically recharge when your balance gets low.</p>
            </div>
            <label class="toggle-switch">
              <input type="checkbox" v-model="autoTopup.enabled" @change="onAutoTopupToggle" :disabled="savingAutoTopup" />
              <span class="toggle-slider"></span>
            </label>
          </div>
          <div v-if="autoTopup.enabled" class="auto-topup-settings">
            <div class="auto-topup-field">
              <label class="auto-topup-label">Top-up to</label>
              <div class="auto-topup-input-row">
                <span class="auto-topup-currency">$</span>
                <input type="number" v-model.number="autoTopup.amount_dollars" min="10" step="5" class="auto-topup-input" :disabled="savingAutoTopup" />
              </div>
              <span class="auto-topup-hint">Triggers when balance drops below 5% of this amount (min $10)</span>
            </div>
            <button @click="saveAutoTopup" class="btn-primary btn-small" :disabled="savingAutoTopup || autoTopup.amount_dollars < 10" style="margin-top: 0.5rem;">
              {{ savingAutoTopup ? 'Saving...' : 'Save' }}
            </button>
            <span v-if="autoTopupError" class="auto-topup-error">{{ autoTopupError }}</span>
          </div>
        </div>
      </div>

      <!-- Subscription Section -->
      <div class="billing-section">
        <h3 class="billing-section-title" style="margin-top: 2rem;">Managed on-premises subscription</h3>
        <div v-if="subscription" class="subscription-card">
          <div class="subscription-info">
            <div class="subscription-tier-name">{{ subscription.tier_name }}</div>
            <span :class="['subscription-status', `status-${subscription.status}`]">{{ subscription.status }}</span>
          </div>
          <div class="subscription-details">
            <div class="subscription-detail-item">
              <span class="subscription-detail-label">Price</span>
              <span class="subscription-detail-value">${{ (subscription.price_cents_per_cycle / 100).toLocaleString() }}/mo</span>
            </div>
            <div class="subscription-detail-item">
              <span class="subscription-detail-label">vCPUs</span>
              <span class="subscription-detail-value">Up to {{ subscription.max_vcpus }}</span>
            </div>
            <div class="subscription-detail-item">
              <span class="subscription-detail-label">Enclaves</span>
              <span class="subscription-detail-value">{{ subscription.max_apps }}</span>
            </div>
            <div class="subscription-detail-item">
              <span class="subscription-detail-label">Started</span>
              <span class="subscription-detail-value">{{ formatDate(subscription.started_at) }}</span>
            </div>
          </div>
          <div class="subscription-actions">
            <button @click="showSelectPlanModal = true" class="btn-secondary btn-small">Change plan</button>
            <button @click="cancelSubscription" class="btn-secondary btn-small btn-danger-text">Cancel</button>
          </div>
        </div>
        <div v-else class="subscription-empty">
          <p>No active managed on-premises subscription.</p>
          <button @click="showSelectPlanModal = true" class="btn-primary btn-small">Choose a plan</button>
        </div>
      </div>

      <!-- Billing Section -->
      <h3 class="billing-section-title" style="margin-top: 2rem;">Billing</h3>

      <!-- Current Period Summary -->
      <div class="billing-summary">
        <div class="billing-period">
          <span class="billing-period-label">Current period</span>
          <span class="billing-period-dates">{{ currentBillingPeriod }}</span>
        </div>
        <div class="billing-total">
          <span class="billing-total-label">Total debits</span>
          <span class="billing-total-amount">${{ billingData.totalCost?.toFixed(2) || '0.00' }}</span>
        </div>
        <div class="billing-total">
          <span class="billing-total-label">Projected by period end</span>
          <span class="billing-total-amount billing-projected">${{ billingData.projectedCost?.toFixed(2) || '0.00' }}</span>
        </div>
      </div>

      <!-- Usage Breakdown -->
      <div class="billing-section">
        <h3 class="billing-section-title">Managed Resource Usage Breakdown</h3>
        <div v-if="loadingBilling" class="list-item-empty">Loading billing data...</div>
        <div v-else-if="billingData.items?.length === 0" class="list-item-empty">
          No usage this billing period.
        </div>
        <div v-else class="billing-table">
          <div class="billing-table-header">
            <span class="billing-col-resource">Resource</span>
            <span class="billing-col-usage">Usage</span>
            <span class="billing-col-rate">Rate</span>
            <span class="billing-col-cost">Cost</span>
          </div>
          <div v-for="item in billingData.items" :key="item.id" class="billing-table-row">
            <span class="billing-col-resource">
              <span class="billing-resource-name">{{ item.resourceName }}</span>
              <span class="billing-resource-type">{{ item.resourceType }}</span>
            </span>
            <span class="billing-col-usage">{{ formatBillingUsage(item.usage, item.unit) }} {{ item.unit }}</span>
            <span class="billing-col-rate">${{ item.rate }}/{{ item.unit }}</span>
            <span class="billing-col-cost">${{ item.cost.toFixed(2) }}</span>
          </div>
        </div>
      </div>

      <div class="billing-section">
        <h3 class="billing-section-title">Subscription Spend</h3>
        <div v-if="loadingBilling" class="list-item-empty">Loading billing data...</div>
        <div v-else-if="billingData.subscriptionItems?.length === 0" class="list-item-empty">
          No subscription charges this billing period.
        </div>
        <div v-else class="billing-table">
          <div class="billing-table-header">
            <span class="billing-col-resource">Subscription</span>
            <span class="billing-col-usage">Usage</span>
            <span class="billing-col-rate">Rate</span>
            <span class="billing-col-cost">Cost</span>
          </div>
          <div v-for="item in billingData.subscriptionItems" :key="item.id" class="billing-table-row">
            <span class="billing-col-resource">
              <span class="billing-resource-name">{{ item.resourceName }}</span>
              <span class="billing-resource-type">{{ item.resourceType }}</span>
            </span>
            <span class="billing-col-usage">{{ formatBillingUsage(item.usage, item.unit) }} {{ item.unit }}</span>
            <span class="billing-col-rate">${{ item.rate }}/{{ item.unit }}</span>
            <span class="billing-col-cost">${{ item.cost.toFixed(2) }}</span>
          </div>
        </div>
      </div>

      <!-- Payment Methods -->
      <div class="billing-section">
        <h3 class="billing-section-title">Payment methods</h3>
        <div v-if="paymentMethods.length > 0" class="payment-methods-list">
          <div v-for="pm in paymentMethods" :key="pm.id" class="payment-method-card">
            <div class="payment-method-info">
              <span class="payment-method-type">{{ pm.card_brand || pm.type }}</span>
              <span class="payment-method-details">{{ pm.last4 ? `•••• ${pm.last4}` : pm.email }}</span>
              <span v-if="pm.is_primary" class="payment-method-badge">Primary</span>
            </div>
            <div class="payment-method-actions">
              <button v-if="!pm.is_primary" @click="setPrimaryPaymentMethod(pm.id)" class="btn-secondary btn-small">Set as primary</button>
              <button @click="removePaymentMethod(pm.id)" class="btn-secondary btn-small btn-danger-text">Remove</button>
            </div>
          </div>
        </div>
        <div v-if="paymentMethods.length === 0" class="payment-method-empty">
          <p>No payment method on file.</p>
        </div>
        <button @click="showAddPaymentModal = true" class="btn-secondary" style="margin-top: 0.75rem;">Add payment method</button>
      </div>

      <!-- Invoices -->
      <div class="billing-section">
        <h3 class="billing-section-title">Invoices</h3>
        <div v-if="loadingInvoices" class="list-item-empty">Loading invoices...</div>
        <div v-else-if="invoices.length === 0" class="list-item-empty">
          No invoices yet.
        </div>
        <div v-else class="invoices-list">
          <div v-for="invoice in invoices" :key="invoice.id" class="invoice-item">
            <div class="invoice-info">
              <span class="invoice-number">{{ invoice.number }}</span>
              <span class="invoice-date">{{ formatDate(invoice.date) }}</span>
            </div>
            <div class="invoice-amount">
              <span :class="['invoice-status', `status-${invoice.status}`]">{{ invoice.status }}</span>
              <span class="invoice-total">${{ (invoice.amount_cents / 100).toFixed(2) }}</span>
            </div>
            <a v-if="invoice.pdf_url" :href="invoice.pdf_url" target="_blank" class="btn-secondary btn-small">
              Download PDF
            </a>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Payment Method Modal -->
    <div v-if="showAddPaymentModal" class="modal-overlay" @click="showAddPaymentModal = false">
      <div class="modal-content modal-content--wide" @click.stop>
        <h3 class="modal-title">Add payment method</h3>

        <!-- Paddle Checkout Container -->
        <div class="paddle-checkout-container"></div>

        <div v-if="cardError" class="card-error">{{ cardError }}</div>

        <div class="modal-actions">
          <button @click="showAddPaymentModal = false" class="btn-secondary">Cancel</button>
        </div>

        <p class="card-privacy-notice">
          Payments are processed securely by
          <a href="https://www.paddle.com" target="_blank" rel="noopener">Paddle</a>,
          our merchant of record.
        </p>
      </div>
    </div>

    <!-- Add Credits Modal -->
    <div v-if="showAddCreditsModal" class="modal-overlay" @click="showAddCreditsModal = false">
      <div class="modal-content" @click.stop>
        <h3 class="modal-title">Add prepaid credits</h3>
        <p class="modal-description">Purchase credits at a volume discount. Credits never expire and are applied automatically at billing time.</p>

        <div class="credit-packages">
          <button
            v-for="(pkg, index) in creditPackages"
            :key="index"
            class="credit-package-card"
            :class="{ 'credit-package-card--selected': selectedPackage === index }"
            @click="selectedPackage = index"
          >
            <span class="credit-package-pay">Pay {{ pkg.purchase_display }}</span>
            <span class="credit-package-get">Get {{ pkg.credit_display }} in credits</span>
            <span class="credit-package-bonus">{{ pkg.bonus_percent }}% bonus</span>
          </button>
        </div>

        <div v-if="creditPurchaseError" class="card-error">{{ creditPurchaseError }}</div>

        <div class="modal-actions">
          <button
            v-if="selectedPackage !== null"
            @click="openCreditCheckout"
            class="btn-primary"
            :disabled="purchasingCredits"
          >
            {{ purchasingCredits ? 'Processing...' : 'Purchase with card on file' }}
          </button>
          <button @click="closeCreditsModal" class="btn-secondary">Cancel</button>
        </div>

        <p class="card-privacy-notice">
          Payments are processed securely by
          <a href="https://www.paddle.com" target="_blank" rel="noopener">Paddle</a>,
          our merchant of record.
        </p>
      </div>
    </div>

    <!-- Select Plan Modal -->
    <div v-if="showSelectPlanModal" class="modal-overlay" @click="showSelectPlanModal = false">
      <div class="modal-content modal-content--wide" @click.stop>
        <h3 class="modal-title">Choose a plan</h3>
        <p class="modal-description">Select a managed on-premises subscription tier.</p>

        <div class="tier-cards">
          <button
            v-for="tier in subscriptionTiers"
            :key="tier.id"
            class="tier-card"
            :class="{ 'tier-card--selected': selectedTier?.id === tier.id }"
            @click="selectedTier = tier"
          >
            <span class="tier-card-name">{{ tier.name }}</span>
            <span class="tier-card-price">{{ formatTierPrice(tier) }}<span class="tier-card-period">/mo</span></span>
            <span class="tier-card-limits">{{ tier.enclaves }} {{ tier.enclaves === 1 ? 'enclave' : 'enclaves' }} &middot; {{ tier.vcpu }} vCPUs &middot; {{ tier.ram_gb }} GB RAM</span>
          </button>
        </div>

        <div v-if="subscribeError" class="card-error">{{ subscribeError }}</div>

        <div class="modal-actions">
          <button
            v-if="selectedTier"
            @click="doSubscribe"
            class="btn-primary"
            :disabled="subscribing"
          >
            {{ subscribing ? 'Processing...' : 'Subscribe now' }}
          </button>
          <button @click="showSelectPlanModal = false; subscribeError = ''" class="btn-secondary">Cancel</button>
        </div>
      </div>
    </div>

    <!-- Cloud Credentials Tab -->
    <div v-if="activeTab === 'credentials'" class="content-card">
      <h2 class="content-card-title">Cloud credentials</h2>
      <div class="form-section">
        <h3 class="form-section-title">Add AWS Credentials</h3>
        <p class="quick-start-description">
          Add AWS credentials to deploy applications to your own infrastructure.
        </p>
        <div class="form-group">
          <label class="form-label" for="credName">Name</label>
          <input
            id="credName"
            v-model="newCredName"
            type="text"
            class="form-input"
            placeholder="e.g., Production AWS"
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="awsAccessKeyId">Access Key ID</label>
          <input
            id="awsAccessKeyId"
            v-model="newCredAwsKeyId"
            type="text"
            class="form-input"
            placeholder="AKIA..."
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label class="form-label" for="awsSecretKey">Secret Access Key</label>
          <input
            id="awsSecretKey"
            v-model="newCredAwsSecret"
            type="password"
            class="form-input"
            placeholder="Enter secret access key"
            :disabled="addingCred"
          />
        </div>
        <div class="form-group">
          <label
            style="
              display: flex;
              align-items: center;
              gap: 8px;
              cursor: pointer;
            "
          >
            <input
              type="checkbox"
              v-model="newCredIsDefault"
              :disabled="addingCred"
            />
            Set as default
          </label>
        </div>
        <button
          @click="addCredential"
          class="btn-primary"
          :disabled="
            addingCred ||
            !newCredName.trim() ||
            !newCredAwsKeyId.trim() ||
            !newCredAwsSecret.trim()
          "
        >
          {{ addingCred ? "Adding..." : "Add Credential" }}
        </button>
      </div>

      <div class="items-list">
        <div v-if="loadingCreds" class="loading">Loading credentials...</div>
        <div v-else-if="credentials.length === 0" class="empty-state">
          No AWS credentials added yet
        </div>
        <div v-else>
          <div v-for="cred in credentials" :key="cred.id" class="list-item">
            <div class="item-info">
              <div style="display: flex; align-items: center; gap: 8px">
                <span class="item-name">{{ cred.name }}</span>
                <span
                  v-if="cred.is_default"
                  class="item-badge item-badge--default"
                  >Default</span
                >
              </div>
              <code class="item-meta">{{ cred.identifier }}</code>
            </div>
            <div class="item-actions">
              <button
                v-if="!cred.is_default"
                @click="setDefaultCredential(cred.id)"
                class="btn-secondary"
                :disabled="settingDefault === cred.id"
              >
                {{ settingDefault === cred.id ? "..." : "Set Default" }}
              </button>
              <button
                @click="deleteCredential(cred.id, cred.name)"
                class="btn-danger"
                :disabled="deletingCred === cred.id"
              >
                <svg v-if="deletingCred === cred.id" class="spinner" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                  <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                </svg>
                {{ deletingCred === cred.id ? "Deleting..." : "Delete" }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <AttestationModal
      v-if="attestationApp"
      :resource-id="attestationApp.id"
      :public-ip="attestationApp.public_ip"
      :app-name="attestationApp.resource_name || 'App'"
      @close="attestationApp = null"
    />

    <!-- Toast notification -->
    <Transition name="toast">
      <div v-if="toast" class="toast" :class="`toast--${toast.type}`" @click="dismissToast">
        <span class="toast-message">{{ toast.message }}</span>
        <button class="toast-dismiss" aria-label="Dismiss">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M1 1L13 13M1 13L13 1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </button>
      </div>
    </Transition>
  </DashboardLayout>
</template>

<script>
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import DashboardLayout from "../components/DashboardLayout.vue";
import AttestationModal from "../components/AttestationModal.vue";
import { authFetch } from "../composables/useWebAuthn.js";

async function sha256Hex(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export default {
  name: "Dashboard",
  props: {
    legalBlocked: {
      type: Boolean,
      default: false,
    },
  },
  components: {
    DashboardLayout,
    AttestationModal,
  },
  setup(props) {
    const DASHBOARD_TAB_HASHES = {
      apps: "",
      ssh: "ssh",
      keys: "keys",
      security: "security",
      settings: "settings",
      credentials: "credentials",
      guide: "guide",
    };
    const DASHBOARD_HASH_TO_TAB = Object.entries(DASHBOARD_TAB_HASHES).reduce(
      (acc, [tab, hash]) => {
        if (hash) {
          acc[hash] = tab;
        }
        return acc;
      },
      {}
    );
    const error = ref(null);
    const activeTab = ref("apps");
    const setupStep = ref(0);

    // Code block refs and copy state
    const codeInstall = ref(null);
    const codeClone = ref(null);
    const codeInit = ref(null);
    const codeDeploy = ref(null);
    const codeVerify = ref(null);
    const copiedBlock = ref(null);

    const copyCode = async (blockName) => {
      const codeRefs = {
        install: codeInstall,
        clone: codeClone,
        init: codeInit,
        deploy: codeDeploy,
        verify: codeVerify,
      };
      const codeRef = codeRefs[blockName];
      if (!codeRef?.value) return;

      try {
        await navigator.clipboard.writeText(codeRef.value.textContent);
        copiedBlock.value = blockName;
        setTimeout(() => {
          copiedBlock.value = null;
        }, 1200);
      } catch (err) {
        console.error("Failed to copy:", err);
      }
    };

    // Apps state
    const apps = ref([]);
    const loadingApps = ref(true);
    const destroyingApp = ref(null);
    const attestationApp = ref(null);
    const selectedApp = ref(null);
    const showDestroyModal = ref(false);
    const appToDestroy = ref(null);
    const copiedAppId = ref(null);
    const copiedField = ref(null);
    const appSearchQuery = ref('');
    const builderConfig = ref({ builder_size: 'small', options: [] });

    const filteredApps = computed(() => {
      if (!appSearchQuery.value.trim()) {
        return apps.value;
      }
      const query = appSearchQuery.value.toLowerCase().trim();
      return apps.value.filter(app =>
        app.resource_name?.toLowerCase().includes(query) ||
        app.id?.toLowerCase().includes(query) ||
        app.region?.toLowerCase().includes(query) ||
        app.state?.toLowerCase().includes(query) ||
        app.public_ip?.toLowerCase().includes(query) ||
        app.configuration?.domain?.toLowerCase().includes(query) ||
        app.configuration?.instance_type?.toLowerCase().includes(query)
      );
    });

    const openAppDetail = async (app) => {
      selectedApp.value = app;
      loadBuilderConfig(app.id);
    };

    const loadBuilderConfig = async (resourceId) => {
      try {
        const response = await authFetch(`/api/resources/${resourceId}/builder-config`);
        if (response.ok) {
          builderConfig.value = await response.json();
        }
      } catch (e) {
        // Builder config not available — leave defaults
      }
    };

    const setBuilderSize = async (size) => {
      if (!selectedApp.value) return;
      try {
        const response = await authFetch(`/api/resources/${selectedApp.value.id}/builder-config`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ builder_size: size }),
        });
        if (response.ok) {
          builderConfig.value.builder_size = size;
          showToast(`Builder size set to ${size}`, 'success');
        }
      } catch (e) {
        showToast('Failed to update builder size', 'error');
      }
    };

    const closeAppDetail = () => {
      selectedApp.value = null;
      copiedField.value = null;
    };

    const copyToClipboard = async (text, fieldName) => {
      try {
        await navigator.clipboard.writeText(text);
        copiedField.value = fieldName;
        showToast('Copied to clipboard', 'success');
        setTimeout(() => {
          copiedField.value = null;
        }, 2000);
      } catch (err) {
        console.error('Failed to copy:', err);
        showToast('Failed to copy to clipboard', 'error');
      }
    };

    const truncateGitUrl = (url) => {
      if (!url) return '';
      // Extract the meaningful part (e.g., the UUID portion)
      // Format: git@localhost:768aafe8-b21b-4c17-ba53-33af3a11bd84.git
      const match = url.match(/([a-f0-9-]{36})\.git$/i);
      if (match) {
        const uuid = match[1];
        const prefix = url.replace(match[0], '');
        // Show prefix + truncated UUID
        return `${prefix}${uuid.substring(0, 8)}...${uuid.substring(uuid.length - 4)}.git`;
      }
      // Fallback: truncate if too long
      if (url.length > 50) {
        return url.substring(0, 40) + '...' + url.substring(url.length - 10);
      }
      return url;
    };

    // SSH Keys state
    const sshKeys = ref([]);
    const loadingKeys = ref(true);
    const addingKey = ref(false);
    const deletingKey = ref(null);
    const showAddKeyForm = ref(false);
    const newKeyName = ref("");
    const newPublicKey = ref("");
    const showDeleteModal = ref(false);
    const keyToDelete = ref(null);

    // Toast notification state
    const toast = ref(null);
    const toastTimeout = ref(null);

    const showToast = (message, type = 'success') => {
      // Clear any existing timeout
      if (toastTimeout.value) {
        clearTimeout(toastTimeout.value);
      }
      toast.value = { message, type };
      // Auto-dismiss: errors stay longer (10s) than success messages (4s)
      const duration = type === 'error' ? 10000 : 4000;
      toastTimeout.value = setTimeout(() => {
        toast.value = null;
      }, duration);
    };

    const dismissToast = () => {
      if (toastTimeout.value) {
        clearTimeout(toastTimeout.value);
      }
      toast.value = null;
    };

    // Credentials state
    const credentials = ref([]);
    const loadingCreds = ref(true);
    const addingCred = ref(false);
    const deletingCred = ref(null);
    const settingDefault = ref(null);
    const newCredName = ref("");
    const newCredAwsKeyId = ref("");
    const newCredAwsSecret = ref("");
    const newCredIsDefault = ref(false);

    // Quorum bundles state
    const quorumBundles = ref([]);
    const loadingBundles = ref(true);
    const deletingBundle = ref(null);
    const bundleKeyHashes = ref({});
    const editingBundleName = ref(null);
    const editBundleNameValue = ref('');
    const addingLabelTo = ref(null);
    const newLabelKey = ref('');
    const newLabelValue = ref('');

    // Organization settings state
    const orgSettings = ref({ require_pin: false });
    const loadingOrgSettings = ref(true);
    const updatingOrgSettings = ref(false);
    const orgSettingsError = ref(null);
    const currentOrgId = ref(null);
    const passkeys = ref([]);
    const loadingPasskeys = ref(true);
    const addingPasskey = ref(false);
    const removingPasskey = ref(null);
    const passkeyFlowStage = ref(null);
    const addPasskeyButtonLabel = computed(() => {
      if (!addingPasskey.value) return "Add passkey";
      if (passkeyFlowStage.value === "approve") return "Approve current authenticator...";
      if (passkeyFlowStage.value === "register") return "Register new authenticator...";
      return "Working...";
    });
    const passkeyFlowMessage = computed(() => {
      if (passkeyFlowStage.value === "approve") {
        return "Browser prompt 1 of 2: approve this account change with the authenticator you are already signed in with.";
      }
      if (passkeyFlowStage.value === "register") {
        return "Browser prompt 2 of 2: now tap, insert, or use the new authenticator you want to add.";
      }
      return "";
    });

    const loadOrgSettings = async () => {
      // only display loading text if we have no org settings
      if (Object.keys(orgSettings.value).length == 0) {
        loadingOrgSettings.value = true;
      }
      orgSettingsError.value = null;

      try {
        // First get the user's primary organization
        const orgsResponse = await authFetch("/api/organizations");
        if (!orgsResponse.ok) {
          if (orgsResponse.status === 401) {
            window.location.href = "/login";
            return;
          }
          throw new Error("Failed to load organizations");
        }

        const orgs = await orgsResponse.json();
        if (orgs.length === 0) {
          loadingOrgSettings.value = false;
          return;
        }

        currentOrgId.value = orgs[0].id;

        // Then get the org settings
        const settingsResponse = await authFetch(`/api/organizations/${currentOrgId.value}/settings`);
        if (settingsResponse.ok) {
          orgSettings.value = await settingsResponse.json();
        } else {
          throw new Error("Failed to load security settings");
        }
      } catch (err) {
        orgSettingsError.value = err.message || "Failed to load security settings";
      } finally {
        loadingOrgSettings.value = false;
      }
    };

    const readResponseError = async (response, fallback) => {
      const text = await response.text().catch(() => "");
      if (!text) return fallback;
      try {
        const parsed = JSON.parse(text);
        return parsed.error || parsed.message || text;
      } catch {
        return text;
      }
    };

    const buildSignedHeaders = async (method, path, body = "") => {
      const bodyHash = await sha256Hex(body);
      const challengeRes = await authFetch("/auth/sign-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method,
          path,
          body_hash: bodyHash,
        }),
      });

      if (!challengeRes.ok) {
        throw new Error(await readResponseError(challengeRes, "Failed to authenticate request"));
      }

      const { publicKey, challenge_id } = await challengeRes.json();

      publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
      if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map((cred) => ({
          ...cred,
          id: base64UrlToArrayBuffer(cred.id),
        }));
      }

      const credential = await navigator.credentials.get({ publicKey });
      const credentialResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64Url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: arrayBufferToBase64Url(
            credential.response.authenticatorData
          ),
          clientDataJSON: arrayBufferToBase64Url(
            credential.response.clientDataJSON
          ),
          signature: arrayBufferToBase64Url(credential.response.signature),
          userHandle: credential.response.userHandle
            ? arrayBufferToBase64Url(credential.response.userHandle)
            : null,
        },
      };

      const fido2Response = btoa(JSON.stringify(credentialResponse))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

      return {
        "X-Fido2-Challenge-Id": challenge_id,
        "X-Fido2-Response": fido2Response,
      };
    };

    const loadPasskeys = async () => {
      if (passkeys.value.length === 0) {
        loadingPasskeys.value = true;
      }

      try {
        const response = await authFetch("/passkeys");

        if (response.ok) {
          passkeys.value = await response.json();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          passkeys.value = [];
          showToast(await readResponseError(response, "Failed to load authenticators"), "error");
        }
      } catch (err) {
        passkeys.value = [];
        showToast("Failed to connect to server", "error");
      } finally {
        loadingPasskeys.value = false;
      }
    };

    const transportLabel = (transport) => {
      const labels = {
        internal: "Device",
        hybrid: "Phone",
        usb: "USB",
        nfc: "NFC",
        ble: "Bluetooth",
      };
      return labels[transport] || transport;
    };

    const formatPasskeyTransports = (transports = []) => {
      if (!transports.length) return "";
      return transports.map(transportLabel).join(" · ");
    };

    const truncatePasskeyId = (credentialId) => {
      if (!credentialId) return "";
      if (credentialId.length <= 18) return credentialId;
      return `${credentialId.slice(0, 10)}...${credentialId.slice(-6)}`;
    };

    const formatPasskeyTitle = (passkey) => {
      const suffix = passkey.credential_id ? truncatePasskeyId(passkey.credential_id) : "";
      return suffix ? `${passkey.kind} ${suffix}` : passkey.kind;
    };

    const addPasskey = async () => {
      if (!window.PublicKeyCredential) {
        showToast("This browser does not support passkeys", "error");
        return;
      }

      addingPasskey.value = true;
      passkeyFlowStage.value = "approve";

      try {
        const beginBody = "{}";
        let signedHeaders;
        try {
          signedHeaders = await buildSignedHeaders("POST", "/passkeys/register/begin", beginBody);
        } catch (signErr) {
          if (signErr.name === "NotAllowedError") {
            return;
          }
          throw signErr;
        }
        const beginResponse = await authFetch("/passkeys/register/begin", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...signedHeaders,
          },
          body: beginBody,
        });

        if (!beginResponse.ok) {
          throw new Error(await readResponseError(beginResponse, "Failed to start passkey registration"));
        }

        const beginData = await beginResponse.json();
        const publicKey = beginData.publicKey;
        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
        publicKey.user.id = base64UrlToArrayBuffer(publicKey.user.id);
        passkeyFlowStage.value = "register";

        if (publicKey.excludeCredentials) {
          publicKey.excludeCredentials = publicKey.excludeCredentials.map((cred) => ({
            type: cred.type,
            id: base64UrlToArrayBuffer(cred.id),
            ...(cred.transports && cred.transports.length > 0
              ? { transports: cred.transports }
              : {}),
          }));
        }

        let credential;
        try {
          credential = await navigator.credentials.create({ publicKey });
        } catch (credError) {
          const duplicateHint = `${credError.name || ""} ${credError.message || ""}`.toLowerCase();
          if (
            credError.name === "InvalidStateError" ||
            duplicateHint.includes("already registered") ||
            duplicateHint.includes("excluded credential") ||
            duplicateHint.includes("credential is excluded")
          ) {
            throw new Error("This authenticator is already registered with an account on this platform.");
          }
          if (credError.name === "NotAllowedError") {
            return;
          }
          throw credError;
        }

        if (!credential) {
          throw new Error("No authenticator response received.");
        }

        const finishResponse = await authFetch("/passkeys/register/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            id: credential.id,
            rawId: arrayBufferToBase64Url(credential.rawId),
            type: credential.type,
            response: {
              attestationObject: arrayBufferToBase64Url(
                credential.response.attestationObject
              ),
              clientDataJSON: arrayBufferToBase64Url(
                credential.response.clientDataJSON
              ),
            },
            session: beginData.session,
            transports: typeof credential.response.getTransports === "function"
              ? credential.response.getTransports()
              : [],
          }),
        });

        if (!finishResponse.ok) {
          throw new Error(await readResponseError(finishResponse, "Failed to add authenticator"));
        }

        await loadPasskeys();
        showToast("Authenticator added");
      } catch (err) {
        showToast(err.message || "Failed to add authenticator", "error");
      } finally {
        addingPasskey.value = false;
        passkeyFlowStage.value = null;
      }
    };

    const deletePasskey = async (passkey) => {
      if (passkeys.value.length <= 1) {
        showToast("Keep at least one authenticator on your account", "error");
        return;
      }
      if (!confirm(`Remove ${formatPasskeyTitle(passkey)}?`)) {
        return;
      }

      removingPasskey.value = passkey.id;

      try {
        const deletePath = `/passkeys/${passkey.id}`;
        const signedHeaders = await buildSignedHeaders("DELETE", deletePath, "");
        const response = await authFetch(deletePath, {
          method: "DELETE",
          headers: signedHeaders,
        });

        if (response.ok || response.status === 204) {
          if (passkey.is_current_session) {
            showToast("Authenticator removed. Sign in again to continue.");
            window.location.href = "/login";
            return;
          }
          await loadPasskeys();
          showToast("Authenticator removed");
        } else {
          showToast(await readResponseError(response, "Failed to remove authenticator"), "error");
        }
      } catch (err) {
        if (err.name === "NotAllowedError") {
          showToast("Authenticator approval was cancelled or timed out", "error");
        } else {
          showToast(err.message || "Failed to remove authenticator", "error");
        }
      } finally {
        removingPasskey.value = null;
      }
    };

    const toggleRequirePin = async () => {
      if (!currentOrgId.value) return;

      updatingOrgSettings.value = true;
      orgSettingsError.value = null;

      const newValue = !orgSettings.value.require_pin;

      try {
        // Step 1: Create request body and hash it
        const body = JSON.stringify({ require_pin: newValue });
        const bodyHash = await sha256Hex(body);

        // Step 2: Request signing challenge
        const challengeRes = await authFetch("/auth/sign-request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            method: "PATCH",
            path: `/organizations/${currentOrgId.value}/settings`,
            body_hash: bodyHash,
          }),
        });

        if (!challengeRes.ok) {
          const data = await challengeRes.json().catch(() => ({}));
          throw new Error(data.error || "Failed to authenticate request");
        }

        const { publicKey, challenge_id } = await challengeRes.json();

        // Step 3: Convert challenge data
        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => ({
              ...cred,
              id: base64UrlToArrayBuffer(cred.id),
            })
          );
        }

        // Step 4: Get user signature
        const credential = await navigator.credentials.get({ publicKey });

        const credentialResponse = {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64Url(
              credential.response.authenticatorData
            ),
            clientDataJSON: arrayBufferToBase64Url(
              credential.response.clientDataJSON
            ),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64Url(credential.response.userHandle)
              : null,
          },
        };

        const fido2Response = btoa(JSON.stringify(credentialResponse))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");

        // Step 5: Send signed request
        const response = await authFetch(`/api/organizations/${currentOrgId.value}/settings`, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "X-Fido2-Challenge-Id": challenge_id,
            "X-Fido2-Response": fido2Response,
          },
          body: body,
        });

        if (response.ok) {
          orgSettings.value = await response.json();
          showToast(newValue ? "PIN requirement enabled" : "PIN requirement disabled");
        } else {
          const data = await response.json().catch(() => ({}));
          orgSettingsError.value = data.error || "Failed to update settings";
          showToast(orgSettingsError.value, 'error');
        }
      } catch (err) {
        orgSettingsError.value = err.message || "Failed to connect to server";
        showToast(orgSettingsError.value, 'error');
      } finally {
        updatingOrgSettings.value = false;
      }
    };

    // Billing state
    const billingData = ref({ totalCost: 0, projectedCost: 0, items: [], subscriptionItems: [] });
    const loadingBilling = ref(false);
    const invoices = ref([]);
    const loadingInvoices = ref(false);
    const paymentMethods = ref([]);
    const showAddPaymentModal = ref(false);
    const cardError = ref('');

    // Credits state
    const creditBalance = ref({ balance_cents: 0, balance_display: '$0.00' });
    const creditPackages = ref([]);
    const showAddCreditsModal = ref(false);
    const selectedPackage = ref(null);
    const purchasingCredits = ref(false);
    const creditPurchaseError = ref('');
    const creditCheckoutOpen = ref(false);
    const redeemCode = ref('');
    const redeemingCode = ref(false);

    // Auto top-up state
    const autoTopup = ref({ enabled: false, amount_dollars: 0 });
    const savingAutoTopup = ref(false);
    const autoTopupError = ref('');

    // Subscription state
    const subscription = ref(null);
    const subscriptionTiers = ref([]);
    const showSelectPlanModal = ref(false);
    const selectedTier = ref(null);
    const subscribing = ref(false);
    const subscribeError = ref('');

    // Email settings
    const userEmail = ref('');
    const emailVerified = ref(null);
    const legalStatus = ref(null);
    const editingEmail = ref(false);
    const emailInput = ref('');
    const savingEmail = ref(false);
    const emailError = ref('');

    const currentBillingPeriod = computed(() => {
      const now = new Date();
      const start = new Date(now.getFullYear(), now.getMonth(), 1);
      const end = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      const formatter = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' });
      return `${formatter.format(start)} - ${formatter.format(end)}, ${now.getFullYear()}`;
    });

    const formatBillingUsage = (usage, unit) => {
      if (unit !== 'hours') {
        return usage ?? 0;
      }

      const numericUsage = Number(usage ?? 0);
      if (!Number.isFinite(numericUsage)) {
        return usage ?? 0;
      }

      return numericUsage.toFixed(2);
    };

    const pageTitle = computed(() => {
      return "";
    });

    const loadApps = async () => {
      // only display loading text if we have no apps
      if (apps.value.length === 0) {
        loadingApps.value = true;
      }

      try {
        const response = await authFetch("/api/resources");

        if (response.ok) {
          apps.value = await response.json();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to load apps", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        loadingApps.value = false;
      }
    };

    const destroyApp = (id, name) => {
      appToDestroy.value = { id, name: name || `App #${id}` };
      showDestroyModal.value = true;
    };

    const confirmDestroy = async () => {
      if (!appToDestroy.value) return;

      const { id, name } = appToDestroy.value;
      destroyingApp.value = id;
      showDestroyModal.value = false;

      // Show info toast while destroying
      showToast(`Destroying "${name}"... This may take a few minutes.`, 'info');

      try {
        const response = await authFetch(`/api/resources/${id}`, {
          method: "DELETE",
        });

        if (response.ok || response.status === 204) {
          showToast(`App "${name}" destroyed`);
          await loadApps();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to destroy app", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        destroyingApp.value = null;
        appToDestroy.value = null;
      }
    };

    const cancelDestroy = () => {
      showDestroyModal.value = false;
      appToDestroy.value = null;
    };

    const loadKeys = async () => {
      // only display loading text if we have no ssh keys
      if (sshKeys.value.length === 0) {
        loadingKeys.value = true;
      }

      try {
        const response = await authFetch("/ssh-keys");

        if (response.ok) {
          const data = await response.json();
          sshKeys.value = data.keys || [];
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          sshKeys.value = [];
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to load SSH keys", 'error');
        }
      } catch (err) {
        sshKeys.value = [];
        showToast("Failed to connect to server", 'error');
      } finally {
        loadingKeys.value = false;
      }
    };

    const loadBilling = async () => {
      // only display loading text if we have no billing data
      if (billingData.value.items.length === 0) {
        loadingBilling.value = true;
      }

      try {
        const response = await authFetch("/api/billing/usage");

        if (response.ok) {
          const data = await response.json();
          billingData.value = {
            totalCost: data.total_cost ?? 0,
            projectedCost: data.projected_cost ?? 0,
            billingPeriodStart: data.billing_period_start ?? '',
            billingPeriodEnd: data.billing_period_end ?? '',
            items: (data.items || []).map(item => ({
              id: item.id || item.resource_id,
              resourceName: item.resource_name ?? item.resource_id,
              resourceType: item.resource_type ?? 'compute',
              usage: item.quantity ?? 0,
              unit: item.unit ?? 'hours',
              rate: item.rate ?? '0.00',
              cost: item.cost ?? 0,
              projectedCost: item.projected_cost ?? 0,
            })),
            subscriptionItems: (data.subscription_items || []).map(item => ({
              id: item.id || item.subscription_id,
              resourceName: item.resource_name ?? item.tier ?? 'Subscription',
              resourceType: item.resource_type ?? 'subscription',
              usage: item.quantity ?? 0,
              unit: item.unit ?? 'hours',
              rate: item.rate ?? '0.00',
              cost: item.cost ?? 0,
              projectedCost: item.projected_cost ?? 0,
            })),
          };
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          // API might not exist yet, use placeholder data from apps
          billingData.value = calculateBillingFromApps();
        }
      } catch (err) {
        // Fallback: calculate billing from running apps
        billingData.value = calculateBillingFromApps();
      } finally {
        loadingBilling.value = false;
      }
    };

    const calculateBillingFromApps = () => {
      // Base AWS rates (from metering/calculator.rs)
      const baseRates = {
        'm5.xlarge': 0.192,
        'm5.2xlarge': 0.384,
        'c5.xlarge': 0.17,
        'c6i.xlarge': 0.17,
        'c6a.xlarge': 0.153,
        'default': 0.20,
      };

      // Margin for verifiable compute (55% markup)
      const marginPercent = 55;

      // const runningApps = apps.value.filter(app => app.state === 'running');
      const items = apps.map(app => {
        const hoursRunning = app.created_at
          ? Math.ceil((Date.now() - new Date(app.created_at).getTime()) / (1000 * 60 * 60))
          : 0;

        const instanceType = app.configuration?.instance_type || 'default';
        const baseRate = baseRates[instanceType] || baseRates['default'];
        const hourlyRate = baseRate * (1 + marginPercent / 100);
        const cost = hoursRunning * hourlyRate;

        return {
          id: app.id,
          resourceName: app.resource_name || 'Unnamed App',
          resourceType: 'Compute',
          usage: hoursRunning,
          unit: 'hours',
          rate: hourlyRate.toFixed(2),
          cost: cost,
        };
      });
      return {
        totalCost: items.reduce((sum, item) => sum + item.cost, 0),
        projectedCost: items.reduce((sum, item) => sum + item.cost, 0),
        items,
        subscriptionItems: [],
      };
    };

    const getAppEstimatedMonthlyCost = (app) => {
      // Get the hourly rate from billing data if available
      const billingItem = billingData.value.items?.find(item => item.id === app.id);
      if (billingItem && billingItem.rate) {
        const hourlyRate = parseFloat(billingItem.rate);
        const hoursPerMonth = 730;
        return (hourlyRate * hoursPerMonth).toFixed(2);
      }

      // Fallback: show estimated_monthly_cost from resource if available
      if (app.estimated_monthly_cost) {
        return app.estimated_monthly_cost.toFixed(2);
      }

      return null;
    };

    // Alias for template
    const calculateAppMonthlyCost = getAppEstimatedMonthlyCost;

    const loadInvoices = async () => {
      // only display loading text if we have no invoices
      if (invoices.value.length === 0) {
        loadingInvoices.value = true;
      }

      try {
        const response = await authFetch("/api/billing/invoices");

        if (response.ok) {
          const data = await response.json();
          invoices.value = data.invoices || [];
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          invoices.value = [];
        }
      } catch (err) {
        invoices.value = [];
      } finally {
        loadingInvoices.value = false;
      }
    };

    const loadUserEmail = async () => {
      try {
        const response = await authFetch("/api/users/me");
        if (response.ok) {
          const data = await response.json();
          userEmail.value = data.email || '';
        }
      } catch (err) {
        // ignore
      }
      try {
        const statusRes = await authFetch("/api/user/status");
        if (statusRes.ok) {
          const status = await statusRes.json();
          emailVerified.value = status.email_verified;
          legalStatus.value = status.legal || null;
        }
      } catch (err) {
        // ignore
      }
    };

    const startEditEmail = () => {
      emailInput.value = userEmail.value;
      emailError.value = '';
      editingEmail.value = true;
    };

    const saveEmail = async () => {
      const email = emailInput.value.trim();
      if (!email) {
        emailError.value = 'Email is required';
        return;
      }
      savingEmail.value = true;
      emailError.value = '';
      try {
        const response = await authFetch("/api/users/me", {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        if (response.ok) {
          const data = await response.json();
          userEmail.value = data.email || email;
          emailVerified.value = false;
          editingEmail.value = false;
          showToast('Verification email sent — check your inbox');
        } else {
          const data = await response.json().catch(() => ({}));
          emailError.value = data.error || 'Failed to update email';
        }
      } catch (err) {
        emailError.value = 'Failed to connect to server';
      } finally {
        savingEmail.value = false;
      }
    };

    const loadPaymentMethods = async () => {
      try {
        const response = await authFetch("/api/billing/payment-methods");

        if (response.ok) {
          const data = await response.json();
          paymentMethods.value = data.payment_methods || [];
        } else {
          paymentMethods.value = [];
        }
      } catch (err) {
        paymentMethods.value = [];
      }
    };

    const initPaddleCheckout = async () => {
      // Load Paddle.js if not already loaded
      if (!window.Paddle) {
        const script = document.createElement('script');
        script.src = 'https://cdn.paddle.com/paddle/v2/paddle.js';
        script.onload = () => openPaddleCheckout();
        script.onerror = () => {
          cardError.value = 'Failed to load payment form. Please refresh and try again.';
        };
        document.body.appendChild(script);
      } else {
        openPaddleCheckout();
      }
    };

    const openPaddleCheckout = async () => {
      if (!window.Paddle) {
        cardError.value = 'Payment form not available.';
        return;
      }

      try {
        // Get client token and customer ID from our backend
        const tokenResponse = await authFetch('/api/billing/paddle/client-token');

        if (!tokenResponse.ok) {
          throw new Error('Failed to initialize payment form');
        }

        const { client_token, paddle_customer_id, setup_price_id } = await tokenResponse.json();

        const isSandbox = import.meta.env.VITE_PADDLE_SANDBOX === 'true';

        // Set sandbox environment before initializing
        if (isSandbox) {
          window.Paddle.Environment.set('sandbox');
        }

        // Initialize Paddle
        window.Paddle.Initialize({
          token: client_token,
          eventCallback: async (event) => {
            if (event.name === 'checkout.completed') {
              const data = event.data;
              // Transaction data intentionally not logged
              // Notify our backend about the completed transaction
              try {
                const payment = data.payment || {};
                const card = payment.method_details?.card || {};
                const response = await authFetch('/api/billing/paddle/transaction-completed', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    transaction_id: data.transaction_id,
                    payment_method_id: payment.payment_method_id || payment.stored_payment_method_id || null,
                    card_last4: card.last4 || null,
                    card_brand: card.type || null,
                  }),
                });

                if (response.ok) {
                  showToast('Payment method saved successfully');
                  showAddPaymentModal.value = false;
                  await loadPaymentMethods();
                } else {
                  cardError.value = 'Failed to save payment method. Please try again.';
                }
              } catch (err) {
                console.error('Transaction completed callback error:', err);
                cardError.value = 'Failed to save payment method. Please try again.';
              }
            }
          },
        });

        // Open inline checkout
        if (!setup_price_id) {
          throw new Error('Paddle setup price not configured. Contact support.');
        }

        const checkoutSettings = {
          settings: {
            displayMode: 'inline',
            frameTarget: 'paddle-checkout-container',
            frameInitialHeight: 450,
            frameStyle: 'width: 100%; background-color: transparent; border: none;',
          },
          items: [{ priceId: setup_price_id, quantity: 1 }],
        };

        if (paddle_customer_id) {
          checkoutSettings.customer = { id: paddle_customer_id };
        } else if (userEmail.value) {
          checkoutSettings.customer = { email: userEmail.value };
        }

        window.Paddle.Checkout.open(checkoutSettings);
      } catch (err) {
        console.error('Failed to initialize Paddle checkout:', err);
        cardError.value = 'Failed to initialize payment form. Please try again.';
      }
    };

    const removePaymentMethod = async (id) => {
      if (!confirm('Are you sure you want to remove this payment method?')) return;

      try {
        const response = await authFetch(`/api/billing/payment-methods/${id}`, {
          method: 'DELETE',
        });

        if (response.ok || response.status === 204) {
          await loadPaymentMethods();
          showToast('Payment method removed');
        } else {
          showToast('Failed to remove payment method', 'error');
        }
      } catch (err) {
        showToast('Failed to remove payment method', 'error');
      }
    };

    const setPrimaryPaymentMethod = async (id) => {
      try {
        const response = await authFetch(`/api/billing/payment-methods/${id}/set-primary`, {
          method: 'POST',
        });

        if (response.ok) {
          await loadPaymentMethods();
          showToast('Primary payment method updated');
        } else {
          showToast('Failed to update primary payment method', 'error');
        }
      } catch (err) {
        showToast('Failed to update primary payment method', 'error');
      }
    };

    const loadCreditBalance = async () => {
      try {
        const response = await authFetch('/api/billing/credits/balance');
        if (response.ok) {
          creditBalance.value = await response.json();
        }
      } catch (err) {
        // silently fail — balance stays at $0.00
      }
    };

    const loadCreditPackages = async () => {
      try {
        const response = await authFetch('/api/billing/credits/packages');
        if (response.ok) {
          const data = await response.json();
          creditPackages.value = data.packages || [];
        }
      } catch (err) {
        // silently fail
      }
    };

    const loadAutoTopup = async () => {
      try {
        const response = await authFetch('/api/billing/auto-topup');
        if (response.ok) {
          const data = await response.json();
          autoTopup.value = { enabled: data.enabled, amount_dollars: data.amount_dollars || 0 };
        }
      } catch (err) {
        // silently fail
      }
    };

    const saveAutoTopup = async () => {
      autoTopupError.value = '';
      if (autoTopup.value.enabled && autoTopup.value.amount_dollars < 10) {
        autoTopupError.value = 'Minimum top-up target is $10';
        return;
      }
      savingAutoTopup.value = true;
      try {
        const response = await authFetch('/api/billing/auto-topup', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabled: autoTopup.value.enabled,
            amount_dollars: autoTopup.value.enabled ? autoTopup.value.amount_dollars : 0,
          }),
        });
        if (response.ok) {
          const data = await response.json();
          autoTopup.value = { enabled: data.enabled, amount_dollars: data.amount_dollars };
          showToast('Auto top-up settings saved');
        } else {
          const err = await response.text();
          autoTopupError.value = err || 'Failed to save';
          // Revert toggle if it was a toggle change
          await loadAutoTopup();
        }
      } catch (err) {
        autoTopupError.value = 'Failed to save auto top-up settings';
        await loadAutoTopup();
      } finally {
        savingAutoTopup.value = false;
      }
    };

    // Only auto-save when disabling (no config needed); when enabling, let user set amount first
    const onAutoTopupToggle = () => {
      if (!autoTopup.value.enabled) {
        saveAutoTopup();
      }
    };

    // Balance polling — refresh every 30s when settings tab is active
    let balancePollingInterval = null;
    const startBalancePolling = () => {
      stopBalancePolling();
      balancePollingInterval = setInterval(loadCreditBalance, 30000);
    };
    const stopBalancePolling = () => {
      if (balancePollingInterval) {
        clearInterval(balancePollingInterval);
        balancePollingInterval = null;
      }
    };

    const loadSubscription = async () => {
      try {
        const response = await authFetch('/api/billing/subscription');
        if (response.ok) {
          const data = await response.json();
          subscription.value = data.subscription || null;
        }
      } catch (err) {
        // silently fail
      }
    };

    const loadSubscriptionTiers = async () => {
      try {
        const response = await authFetch('/api/billing/subscription/tiers');
        if (response.ok) {
          const data = await response.json();
          subscriptionTiers.value = data.tiers || [];
        }
      } catch (err) {
        // silently fail
      }
    };

    const formatTierPrice = (tier) => {
      const cents = tier.price_cents_per_cycle || 0;
      return `$${(cents / 100).toLocaleString()}`;
    };

    const doSubscribe = async () => {
      if (!selectedTier.value) return;
      subscribing.value = true;
      subscribeError.value = '';
      try {
        const response = await authFetch('/api/billing/subscription/subscribe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            tier_id: selectedTier.value.id,
          }),
        });
        if (response.ok) {
          showToast('Subscription activated!');
          showSelectPlanModal.value = false;
          await loadSubscription();
          await loadCreditBalance();
        } else if (response.status === 402) {
          subscribeError.value = 'Add credits first.';
        } else if (response.status === 409) {
          subscribeError.value = 'You already have an active subscription.';
        } else {
          const text = await response.text().catch(() => '');
          subscribeError.value = text || 'Subscription failed. Please try again.';
        }
      } catch (err) {
        subscribeError.value = 'Failed to connect to server.';
      } finally {
        subscribing.value = false;
      }
    };

    const cancelSubscription = async () => {
      if (!confirm('Cancel your subscription immediately?')) return;
      try {
        const response = await authFetch('/api/billing/subscription/cancel', { method: 'POST' });
        if (response.ok) {
          showToast('Subscription canceled');
          await loadSubscription();
        } else {
          showToast('Failed to cancel subscription', 'error');
        }
      } catch (err) {
        showToast('Failed to connect to server', 'error');
      }
    };

    const redeemCreditCode = async () => {
      if (!redeemCode.value.trim()) return;
      redeemingCode.value = true;
      try {
        const response = await authFetch('/api/billing/credits/redeem', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: redeemCode.value.trim() }),
        });
        if (response.ok) {
          const result = await response.json();
          const dollars = (result.amount_cents / 100).toFixed(2);
          showToast(`$${dollars} in credits added to your account!`);
          redeemCode.value = '';
          await loadCreditBalance();
        } else {
          const text = await response.text().catch(() => '');
          showToast(text || 'Invalid or already redeemed code', 'error');
        }
      } catch (err) {
        showToast('Failed to redeem code', 'error');
      }
      redeemingCode.value = false;
    };

    const closeCreditsModal = () => {
      showAddCreditsModal.value = false;
      selectedPackage.value = null;
      creditPurchaseError.value = '';
      creditCheckoutOpen.value = false;
    };

    const openCreditCheckout = async () => {
      if (selectedPackage.value === null) return;

      creditPurchaseError.value = '';
      purchasingCredits.value = true;

      try {
        // Try server-side charge using card on file
        const response = await authFetch('/api/billing/credits/purchase', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package_index: selectedPackage.value }),
        });

        if (response.ok) {
          const result = await response.json();
          creditBalance.value = {
            balance_cents: result.balance_cents,
            balance_display: result.balance_display,
          };
          showToast('Credits added successfully!');
          closeCreditsModal();
        } else if (response.status === 402) {
          // No payment method on file
          creditPurchaseError.value = 'Please add a payment method first, then come back to purchase credits.';
        } else {
          const errData = await response.text().catch(() => '');
          creditPurchaseError.value = `Payment failed: ${errData || 'Please try again.'}`;
        }
      } catch (err) {
        creditPurchaseError.value = 'Failed to process payment. Please try again.';
      } finally {
        purchasingCredits.value = false;
      }
    };

    const addKey = async () => {
      if (!newPublicKey.value.trim()) return;

      addingKey.value = true;
      error.value = null;

      try {
        const body = JSON.stringify({
          public_key: newPublicKey.value.trim(),
          name: newKeyName.value.trim() || null,
        });
        const bodyHash = await sha256Hex(body);

        const challengeRes = await authFetch("/auth/sign-request", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            method: "POST",
            path: "/ssh-keys",
            body_hash: bodyHash,
          }),
        });

        if (!challengeRes.ok) {
          const data = await challengeRes.json().catch(() => ({}));
          throw new Error(
            data.error ||
            "Failed to authenticate request. Please try again."
          );
        }

        const { publicKey, challenge_id } = await challengeRes.json();

        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => ({
              ...cred,
              id: base64UrlToArrayBuffer(cred.id),
            })
          );
        }

        const credential = await navigator.credentials.get({ publicKey });

        const credentialResponse = {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64Url(
              credential.response.authenticatorData
            ),
            clientDataJSON: arrayBufferToBase64Url(
              credential.response.clientDataJSON
            ),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64Url(credential.response.userHandle)
              : null,
          },
        };

        const fido2Response = btoa(JSON.stringify(credentialResponse))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");

        const response = await authFetch("/ssh-keys", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Fido2-Challenge-Id": challenge_id,
            "X-Fido2-Response": fido2Response,
          },
          body: body,
        });

        if (response.ok) {
          const data = await response.json();
          const keyName = newKeyName.value.trim() || 'SSH key';
          newKeyName.value = "";
          newPublicKey.value = "";
          showAddKeyForm.value = false;
          await loadKeys();
          showToast(`${keyName} added`);
        } else {
          const data = await response.json().catch(() => ({}));
          error.value = data.error || "Failed to add SSH key";
        }
      } catch (err) {
        if (err.name === "NotAllowedError") {
          error.value =
            "Security key authentication was cancelled or timed out";
        } else {
          error.value = err.message || "Failed to add SSH key";
        }
      } finally {
        addingKey.value = false;
      }
    };

    const deleteKey = (fingerprint) => {
      keyToDelete.value = fingerprint;
      showDeleteModal.value = true;
    };

    const confirmDelete = async () => {
      if (!keyToDelete.value) return;

      deletingKey.value = keyToDelete.value;
      showDeleteModal.value = false;

      try {
        const deletePath = `/ssh-keys/${encodeURIComponent(keyToDelete.value)}`;
        const body = "";
        const bodyHash = await sha256Hex(body);

        // Step 1: Request signing challenge
        const challengeRes = await authFetch("/auth/sign-request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            method: "DELETE",
            path: deletePath,
            body_hash: bodyHash,
          }),
        });

        if (!challengeRes.ok) {
          const data = await challengeRes.json().catch(() => ({}));
          throw new Error(data.error || "Failed to authenticate request");
        }

        const { publicKey, challenge_id } = await challengeRes.json();

        // Step 2: Convert challenge data
        publicKey.challenge = base64UrlToArrayBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(
            (cred) => ({
              ...cred,
              id: base64UrlToArrayBuffer(cred.id),
            })
          );
        }

        // Step 3: Get user signature
        const credential = await navigator.credentials.get({ publicKey });

        const credentialResponse = {
          id: credential.id,
          rawId: arrayBufferToBase64Url(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: arrayBufferToBase64Url(
              credential.response.authenticatorData
            ),
            clientDataJSON: arrayBufferToBase64Url(
              credential.response.clientDataJSON
            ),
            signature: arrayBufferToBase64Url(credential.response.signature),
            userHandle: credential.response.userHandle
              ? arrayBufferToBase64Url(credential.response.userHandle)
              : null,
          },
        };

        const fido2Response = btoa(JSON.stringify(credentialResponse))
          .replace(/\+/g, "-")
          .replace(/\//g, "_")
          .replace(/=/g, "");

        // Step 4: Send signed delete request
        const response = await authFetch(deletePath, {
          method: "DELETE",
          headers: {
            "X-Fido2-Challenge-Id": challenge_id,
            "X-Fido2-Response": fido2Response,
          },
        });

        if (response.ok || response.status === 204) {
          showToast("SSH key deleted");
          await loadKeys();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to delete SSH key", 'error');
        }
      } catch (err) {
        if (err.name === "NotAllowedError") {
          showToast("Security key authentication was cancelled or timed out", 'error');
        } else {
          showToast(err.message || "Failed to connect to server", 'error');
        }
      } finally {
        deletingKey.value = null;
        keyToDelete.value = null;
      }
    };

    const cancelDelete = () => {
      showDeleteModal.value = false;
      keyToDelete.value = null;
    };

    const loadCredentials = async () => {
      // only display loading text if we have no credentials
      if (credentials.value.length === 0) {
        loadingCreds.value = true;
      }

      try {
        const response = await authFetch("/api/credentials");

        if (response.ok) {
          credentials.value = await response.json();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to load credentials", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        loadingCreds.value = false;
      }
    };

    const loadBundles = async () => {
      // only display loading text if we have no bundles
      if (quorumBundles.value.length === 0) {
        loadingBundles.value = true;
      }

      try {
        const response = await authFetch("/api/quorum-bundles");

        if (response.ok) {
          quorumBundles.value = await response.json();
          computeBundleHashes();
        } else if (response.status === 401) {
          window.location.href = "/login";
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to load quorum bundles", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        loadingBundles.value = false;
      }
    };

    const deleteBundle = async (id) => {
      if (!confirm("Are you sure you want to delete this quorum bundle?")) return;

      deletingBundle.value = id;

      try {
        const response = await authFetch(`/api/quorum-bundles/${id}`, {
          method: "DELETE",
        });

        if (response.ok || response.status === 204) {
          showToast("Quorum bundle deleted");
          await loadBundles();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to delete quorum bundle", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        deletingBundle.value = null;
      }
    };

    const computeBundleHashes = async () => {
      for (const bundle of quorumBundles.value) {
        if (bundle.data?.secret_recipient_public_key) {
          try {
            const encoded = new TextEncoder().encode(bundle.data.secret_recipient_public_key);
            const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            bundleKeyHashes.value[bundle.id] = hashHex.substring(0, 16);
          } catch {
            // skip hash computation on error
          }
        }
      }
    };

    const startEditBundleName = (bundle) => {
      editingBundleName.value = bundle.id;
      editBundleNameValue.value = bundle.name || '';
    };

    const saveBundleName = async (bundleId) => {
      try {
        const response = await authFetch(`/api/quorum-bundles/${bundleId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: editBundleNameValue.value }),
        });

        if (response.ok) {
          showToast("Bundle renamed");
          editingBundleName.value = null;
          await loadBundles();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to rename bundle", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      }
    };

    const cancelEditBundleName = () => {
      editingBundleName.value = null;
      editBundleNameValue.value = '';
    };

    const startAddLabel = (bundleId) => {
      addingLabelTo.value = bundleId;
      newLabelKey.value = '';
      newLabelValue.value = '';
    };

    const cancelAddLabel = () => {
      addingLabelTo.value = null;
      newLabelKey.value = '';
      newLabelValue.value = '';
    };

    const saveLabel = async (bundleId) => {
      if (!newLabelKey.value.trim()) return;
      const bundle = quorumBundles.value.find(b => b.id === bundleId);
      if (!bundle) return;

      const labels = { ...(bundle.labels || {}), [newLabelKey.value.trim()]: newLabelValue.value.trim() };

      try {
        const response = await authFetch(`/api/quorum-bundles/${bundleId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ labels }),
        });

        if (response.ok) {
          showToast("Label added");
          cancelAddLabel();
          await loadBundles();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to add label", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      }
    };

    const removeLabel = async (bundleId, key) => {
      const bundle = quorumBundles.value.find(b => b.id === bundleId);
      if (!bundle) return;

      const labels = { ...(bundle.labels || {}) };
      delete labels[key];

      try {
        const response = await authFetch(`/api/quorum-bundles/${bundleId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ labels }),
        });

        if (response.ok) {
          showToast("Label removed");
          await loadBundles();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to remove label", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      }
    };

    const downloadFile = (content, filename) => {
      const blob = new Blob([content], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    };

    const addCredential = async () => {
      if (
        !newCredName.value.trim() ||
        !newCredAwsKeyId.value.trim() ||
        !newCredAwsSecret.value.trim()
      )
        return;

      addingCred.value = true;

      try {
        const body = {
          platform: "aws",
          name: newCredName.value.trim(),
          access_key_id: newCredAwsKeyId.value.trim(),
          secret_access_key: newCredAwsSecret.value.trim(),
          is_default: newCredIsDefault.value,
        };

        const response = await authFetch("/api/credentials", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(body),
        });

        if (response.ok) {
          showToast("AWS credential added");
          newCredName.value = "";
          newCredAwsKeyId.value = "";
          newCredAwsSecret.value = "";
          newCredIsDefault.value = false;
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to add credential", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        addingCred.value = false;
      }
    };

    const deleteCredential = async (id, name) => {
      if (!confirm(`Are you sure you want to delete "${name}"?`)) return;

      deletingCred.value = id;

      try {
        const response = await authFetch(`/api/credentials/${id}`, {
          method: "DELETE",
        });

        if (response.ok || response.status === 204) {
          showToast("Credential deleted");
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to delete credential", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        deletingCred.value = null;
      }
    };

    const setDefaultCredential = async (id) => {
      settingDefault.value = id;

      try {
        const response = await authFetch(`/api/credentials/${id}/default`, {
          method: "POST",
        });

        if (response.ok) {
          showToast("Default credential updated");
          await loadCredentials();
        } else {
          const data = await response.json().catch(() => ({}));
          showToast(data.error || "Failed to set default credential", 'error');
        }
      } catch (err) {
        showToast("Failed to connect to server", 'error');
      } finally {
        settingDefault.value = null;
      }
    };

    const logout = async () => {
      try {
        const response = await authFetch('/auth/logout', { method: 'POST' });
        if (!response.ok) {
          showToast('Logout failed. Please try again.', 'error');
          return;
        }
        window.location.href = "/login";
      } catch (err) {
        console.error('Logout API call failed:', err);
        showToast('Could not reach server. Please try again.', 'error');
      }
    };

    const getTabFromLocation = () => {
      const hash = window.location.hash.replace(/^#/, "");
      return DASHBOARD_HASH_TO_TAB[hash] || "apps";
    };

    const syncDashboardLocation = (tab, { replace = false } = {}) => {
      if (window.location.pathname !== "/" && window.location.pathname !== "/dashboard") return;

      const hash = DASHBOARD_TAB_HASHES[tab] ?? "";
      const nextUrl = hash ? `/#${hash}` : "/";
      const currentUrl = `${window.location.pathname}${window.location.hash}`;

      if (currentUrl === nextUrl) return;

      const method = replace ? "replaceState" : "pushState";
      window.history[method]({}, "", nextUrl);
    };

    const loadTabData = (newTab, previousTab) => {
      if (newTab === "apps") {
        setupStep.value = 0;
        selectedApp.value = null;
        loadApps();
      } else if (newTab === "guide") {
        setupStep.value = 0;
      } else if (newTab === "ssh") {
        showAddKeyForm.value = false;
        newKeyName.value = "";
        newPublicKey.value = "";
        error.value = null;
        loadKeys();
      } else if (newTab === "security") {
        loadPasskeys();
        loadOrgSettings();
      } else if (newTab === "credentials") {
        loadCredentials();
      } else if (newTab === "keys") {
        loadBundles();
      } else if (newTab === "settings") {
        loadUserEmail();
        loadBilling();
        loadInvoices();
        loadPaymentMethods();
        loadCreditBalance();
        loadCreditPackages();
        loadAutoTopup();
        loadSubscription();
        loadSubscriptionTiers();
        startBalancePolling();
      }

      // Stop polling when leaving settings tab
      if (previousTab === "settings" && newTab !== "settings") {
        stopBalancePolling();
      }
    };

    const handleTabChange = (newTab, options = {}) => {
      const normalizedTab = Object.prototype.hasOwnProperty.call(DASHBOARD_TAB_HASHES, newTab)
        ? newTab
        : "apps";
      const previousTab = activeTab.value;

      if (previousTab === normalizedTab) {
        if (options.syncHistory !== false) {
          syncDashboardLocation(normalizedTab, {
            replace: options.replaceHistory === true,
          });
        }
        return;
      }

      activeTab.value = normalizedTab;
      if (props.legalBlocked) {
        return;
      }
      loadTabData(normalizedTab, previousTab);

      if (options.syncHistory !== false) {
        syncDashboardLocation(normalizedTab, {
          replace: options.replaceHistory === true,
        });
      }
    };

    const formatKeyType = (keyType) => {
      if (!keyType) return 'Unknown';
      // Normalize common SSH key type names
      const typeMap = {
        'ssh-ed25519': 'ED25519',
        'ssh-rsa': 'RSA',
        'ecdsa-sha2-nistp256': 'ECDSA P-256',
        'ecdsa-sha2-nistp384': 'ECDSA P-384',
        'ecdsa-sha2-nistp521': 'ECDSA P-521',
        'sk-ssh-ed25519@openssh.com': 'ED25519-SK',
        'sk-ecdsa-sha2-nistp256@openssh.com': 'ECDSA-SK',
      };
      return typeMap[keyType.toLowerCase()] || keyType.toUpperCase();
    };

    const parseDate = (dateValue) => {
      if (!dateValue) return null;
      // Handle array format from Rust's time crate: [year, day_of_year, hour, min, sec, nanosec]
      if (Array.isArray(dateValue)) {
        const [year, ordinal, hour = 0, min = 0, sec = 0] = dateValue;
        const date = new Date(Date.UTC(year, 0, ordinal, hour, min, sec));
        return date;
      }
      // Handle Rust time::OffsetDateTime string output like:
      // 2026-04-10 18:10:27.062269084 +00:00:00
      if (typeof dateValue === 'string') {
        const rustTimeMatch = dateValue.match(
          /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?) ([+-]\d{2}:\d{2})(?::\d{2})$/
        );
        if (rustTimeMatch) {
          const [, datePart, timePart, offsetPart] = rustTimeMatch;
          return new Date(`${datePart}T${timePart}${offsetPart}`);
        }
      }
      // Handle string dates - if no timezone specified, assume UTC
      if (typeof dateValue === 'string' && !dateValue.includes('Z') && !dateValue.includes('+')) {
        return new Date(dateValue + 'Z');
      }
      return new Date(dateValue);
    };

    const formatDate = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return 'Unknown';
      const options = { year: 'numeric', month: 'short', day: 'numeric' };
      return date.toLocaleDateString('en-US', options);
    };

    const formatDateTime = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return 'Unknown';
      const dateOptions = { year: 'numeric', month: 'short', day: 'numeric' };
      const timeOptions = { hour: 'numeric', minute: '2-digit', hour12: true };
      const datePart = date.toLocaleDateString('en-US', dateOptions);
      const timePart = date.toLocaleTimeString('en-US', timeOptions);
      return `${datePart} at ${timePart}`;
    };

    const formatDateTimeFull = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return 'Unknown';
      const dateOptions = { year: 'numeric', month: 'short', day: 'numeric' };
      const timeOptions = { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true };
      const datePart = date.toLocaleDateString('en-US', dateOptions);
      const timePart = date.toLocaleTimeString('en-US', timeOptions);
      return `${datePart} at ${timePart}`;
    };

    const formatDateOnly = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return 'Unknown';
      const dateOptions = { year: 'numeric', month: 'short', day: 'numeric' };
      return date.toLocaleDateString('en-US', dateOptions);
    };

    const formatTimeOnly = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return '';
      const timeOptions = { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true };
      return date.toLocaleTimeString('en-US', timeOptions);
    };

    const formatTimeWithTimezone = (dateString) => {
      const date = parseDate(dateString);
      if (!date || isNaN(date.getTime())) return '';
      const timeOptions = { hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true, timeZoneName: 'short' };
      return date.toLocaleTimeString('en-US', timeOptions);
    };

    const formatLastUsed = (dateValue) => {
      if (!dateValue) return 'Never used';
      const date = parseDate(dateValue);
      if (!date || isNaN(date.getTime())) return 'Never used';

      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / (1000 * 60));
      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (diffMins < 1) return 'Last used just now';
      if (diffMins < 60) return `Last used ${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
      if (diffHours < 24) return `Last used ${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
      if (diffDays === 1) return 'Last used yesterday';
      if (diffDays < 7) return `Last used ${diffDays} days ago`;
      if (diffDays < 30) {
        const weeks = Math.floor(diffDays / 7);
        return `Last used ${weeks} week${weeks === 1 ? '' : 's'} ago`;
      }
      if (diffDays < 365) {
        const months = Math.floor(diffDays / 30);
        return `Last used ${months} month${months === 1 ? '' : 's'} ago`;
      }
      const years = Math.floor(diffDays / 365);
      return `Last used ${years} year${years === 1 ? '' : 's'} ago`;
    };

    const formatRelativeTime = (dateValue) => {
      if (!dateValue) return '';
      const date = parseDate(dateValue);
      if (!date || isNaN(date.getTime())) return '';

      const now = new Date();
      const diffMs = now - date;
      const diffMins = Math.floor(diffMs / (1000 * 60));
      const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

      if (diffMins < 1) return 'just now';
      if (diffMins < 60) return `${diffMins}m ago`;
      if (diffHours < 24) return `${diffHours}h ago`;
      if (diffDays < 7) return `${diffDays}d ago`;
      if (diffDays < 30) {
        const weeks = Math.floor(diffDays / 7);
        return `${weeks}w ago`;
      }
      // For older deployments, show the actual date
      return formatDate(dateValue);
    };

    const startGuide = () => {
      handleTabChange("guide");
      setupStep.value = 1;
    };

    const formatMemory = (memoryMb) => {
      if (!memoryMb) return '';
      if (memoryMb >= 1024) {
        const gb = memoryMb / 1024;
        return gb % 1 === 0 ? `${gb} GB` : `${gb.toFixed(1)} GB`;
      }
      return `${memoryMb} MB`;
    };

    const isManaged = (app) => {
      return app.configuration?.managed_onprem != null;
    };

    const getAppUrl = (app) => {
      if (app.configuration?.domain) {
        return `https://${app.configuration.domain}`;
      }
      if (app.public_ip) {
        return `http://${app.public_ip}:8080`;
      }
      return '#';
    };

    const getRegionFlag = (region) => {
      if (!region) return '';
      // Map AWS regions to country flags
      const regionFlags = {
        // US regions
        'us-east-1': '🇺🇸',
        'us-east-2': '🇺🇸',
        'us-west-1': '🇺🇸',
        'us-west-2': '🇺🇸',
        // Europe
        'eu-west-1': '🇮🇪',
        'eu-west-2': '🇬🇧',
        'eu-west-3': '🇫🇷',
        'eu-central-1': '🇩🇪',
        'eu-central-2': '🇨🇭',
        'eu-north-1': '🇸🇪',
        'eu-south-1': '🇮🇹',
        'eu-south-2': '🇪🇸',
        // Asia Pacific
        'ap-northeast-1': '🇯🇵',
        'ap-northeast-2': '🇰🇷',
        'ap-northeast-3': '🇯🇵',
        'ap-southeast-1': '🇸🇬',
        'ap-southeast-2': '🇦🇺',
        'ap-southeast-3': '🇮🇩',
        'ap-southeast-4': '🇦🇺',
        'ap-south-1': '🇮🇳',
        'ap-south-2': '🇮🇳',
        'ap-east-1': '🇭🇰',
        // South America
        'sa-east-1': '🇧🇷',
        // Canada
        'ca-central-1': '🇨🇦',
        'ca-west-1': '🇨🇦',
        // Middle East
        'me-south-1': '🇧🇭',
        'me-central-1': '🇦🇪',
        // Africa
        'af-south-1': '🇿🇦',
        // Israel
        'il-central-1': '🇮🇱',
      };
      return regionFlags[region.toLowerCase()] || '🌐';
    };

    const truncateId = (id) => {
      if (!id) return '';
      // Show first 8 characters of UUID
      return id.substring(0, 8);
    };

    const copyAppId = async (id) => {
      try {
        await navigator.clipboard.writeText(id);
        copiedAppId.value = id;
        setTimeout(() => {
          copiedAppId.value = null;
        }, 2000);
      } catch (err) {
        console.error('Failed to copy ID:', err);
      }
    };

    // Keyboard shortcuts for guide navigation
    const handleKeyDown = (event) => {
      // Only handle keyboard shortcuts when in guide tab (starter screen 0 or steps 1-6)
      if (activeTab.value !== "guide" || setupStep.value < 0 || setupStep.value > 6) {
        return;
      }

      // Don't trigger shortcuts if user is typing in an input field
      if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") {
        return;
      }

      // Arrow Left or 'b' key - go back
      if ((event.key === "ArrowLeft" || event.key === "b") && setupStep.value > 1) {
        event.preventDefault();
        setupStep.value = setupStep.value - 1;
      }
      // Arrow Right or 'n' key - go next (or begin guide from starter screen)
      else if (event.key === "ArrowRight" || event.key === "n") {
        event.preventDefault();
        if (setupStep.value === 0) {
          setupStep.value = 1; // Begin guide from starter screen
        } else if (setupStep.value < 6) {
          setupStep.value = setupStep.value + 1;
        }
      }
    };

    // Refresh active tab data when browser tab regains focus
    const handleVisibilityChange = () => {
      if (document.hidden || props.legalBlocked) return;
      if (activeTab.value === "apps") {
        loadApps();
      } else if (activeTab.value === "ssh") {
        loadKeys();
      } else if (activeTab.value === "credentials") {
        loadCredentials();
      } else if (activeTab.value === "security") {
        loadPasskeys();
        loadOrgSettings();
      } else if (activeTab.value === "keys") {
        loadBundles();
      } else if (activeTab.value === "settings") {
        loadCreditBalance();
        loadBilling();
        loadPaymentMethods();
        loadSubscription();
      }
    };

    const handleHistoryNavigation = () => {
      handleTabChange(getTabFromLocation(), { syncHistory: false });
    };

    const getLegalStatusLabel = (documentStatus) => {
      if (documentStatus?.accepted_at) {
        return `Accepted on ${formatDateTimeFull(documentStatus.accepted_at)}`;
      }

      if (documentStatus?.requires_action) {
        return 'Acceptance required';
      }

      return 'Acceptance recorded before tracking';
    };

    onMounted(async () => {
      const initialTab = getTabFromLocation();
      activeTab.value = initialTab;

      // Add keyboard event listener
      window.addEventListener("keydown", handleKeyDown);
      document.addEventListener("visibilitychange", handleVisibilityChange);
      window.addEventListener("popstate", handleHistoryNavigation);
      window.addEventListener("hashchange", handleHistoryNavigation);

      await Promise.all([loadApps(), loadKeys(), loadCredentials(), loadBundles(), loadOrgSettings(), loadPasskeys()]);

      if (initialTab === "settings") {
        loadUserEmail();
        loadBilling();
        loadInvoices();
        loadPaymentMethods();
        loadCreditBalance();
        loadCreditPackages();
        loadAutoTopup();
        loadSubscription();
        loadSubscriptionTiers();
        startBalancePolling();
      }

      syncDashboardLocation(initialTab, { replace: true });
    });

    onUnmounted(() => {
      window.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("popstate", handleHistoryNavigation);
      window.removeEventListener("hashchange", handleHistoryNavigation);
      stopBalancePolling();
    });

    watch(
      () => props.legalBlocked,
      (isBlocked, wasBlocked) => {
        if (isBlocked || !wasBlocked) {
          return;
        }

        if (activeTab.value === "apps") {
          loadApps();
        } else if (activeTab.value === "ssh") {
          loadKeys();
        } else if (activeTab.value === "credentials") {
          loadCredentials();
        } else if (activeTab.value === "keys") {
          loadBundles();
        } else if (activeTab.value === "settings") {
          loadUserEmail();
          loadBilling();
          loadInvoices();
          loadPaymentMethods();
          loadCreditBalance();
          loadCreditPackages();
          loadAutoTopup();
          loadSubscription();
          loadSubscriptionTiers();
          startBalancePolling();
        }

        loadOrgSettings();
      }
    );

    // Keep selectedApp in sync when apps list is refreshed
    watch(apps, (newApps) => {
      if (selectedApp.value) {
        const updated = newApps.find(app => app.id === selectedApp.value.id);
        selectedApp.value = updated || null;
      }
    });

    // Initialize Paddle checkout when payment modal opens
    watch(showAddPaymentModal, (isOpen) => {
      if (isOpen) {
        cardError.value = '';
        // Wait for DOM to update then initialize Paddle checkout
        setTimeout(() => initPaddleCheckout(), 100);
      }
    });

    return {
      error,
      activeTab,
      pageTitle,
      setupStep,
      codeInstall,
      codeClone,
      codeInit,
      codeDeploy,
      codeVerify,
      copiedBlock,
      copyCode,
      apps,
      filteredApps,
      appSearchQuery,
      loadingApps,
      destroyingApp,
      attestationApp,
      selectedApp,
      openAppDetail,
      closeAppDetail,
      builderConfig,
      setBuilderSize,
      copiedField,
      copyToClipboard,
      truncateGitUrl,
      showDestroyModal,
      appToDestroy,
      destroyApp,
      confirmDestroy,
      cancelDestroy,
      sshKeys,
      loadingKeys,
      addingKey,
      deletingKey,
      showAddKeyForm,
      newKeyName,
      newPublicKey,
      showDeleteModal,
      keyToDelete,
      toast,
      showToast,
      dismissToast,
      addKey,
      deleteKey,
      confirmDelete,
      cancelDelete,
      quorumBundles,
      loadingBundles,
      deletingBundle,
      deleteBundle,
      bundleKeyHashes,
      editingBundleName,
      editBundleNameValue,
      startEditBundleName,
      saveBundleName,
      cancelEditBundleName,
      addingLabelTo,
      newLabelKey,
      newLabelValue,
      startAddLabel,
      cancelAddLabel,
      saveLabel,
      removeLabel,
      downloadFile,
      credentials,
      loadingCreds,
      addingCred,
      deletingCred,
      settingDefault,
      newCredName,
      newCredAwsKeyId,
      newCredAwsSecret,
      newCredIsDefault,
      addCredential,
      deleteCredential,
      setDefaultCredential,
      passkeys,
      loadingPasskeys,
      addingPasskey,
      passkeyFlowStage,
      addPasskeyButtonLabel,
      passkeyFlowMessage,
      removingPasskey,
      addPasskey,
      deletePasskey,
      formatPasskeyTitle,
      formatPasskeyTransports,
      truncatePasskeyId,
      orgSettings,
      loadingOrgSettings,
      updatingOrgSettings,
      orgSettingsError,
      toggleRequirePin,
      billingData,
      loadingBilling,
      currentBillingPeriod,
      formatBillingUsage,
      loadBilling,
      invoices,
      loadingInvoices,
      loadInvoices,
      paymentMethods,
      showAddPaymentModal,
      cardError,
      removePaymentMethod,
      setPrimaryPaymentMethod,
      creditBalance,
      creditPackages,
      showAddCreditsModal,
      autoTopup,
      savingAutoTopup,
      autoTopupError,
      saveAutoTopup,
      onAutoTopupToggle,
      selectedPackage,
      purchasingCredits,
      creditPurchaseError,
      loadCreditBalance,
      loadCreditPackages,
      openCreditCheckout,
      closeCreditsModal,
      redeemCode,
      redeemingCode,
      redeemCreditCode,
      subscription,
      subscriptionTiers,
      showSelectPlanModal,
      selectedTier,
      subscribing,
      subscribeError,
      loadSubscription,
      loadSubscriptionTiers,
      formatTierPrice,
      doSubscribe,
      cancelSubscription,
      userEmail,
      emailVerified,
      legalStatus,
      editingEmail,
      emailInput,
      savingEmail,
      emailError,
      startEditEmail,
      saveEmail,
      calculateAppMonthlyCost,
      logout,
      handleTabChange,
      formatKeyType,
      formatDate,
      formatDateTime,
      formatDateTimeFull,
      getLegalStatusLabel,
      formatDateOnly,
      formatTimeOnly,
      formatTimeWithTimezone,
      formatLastUsed,
      formatRelativeTime,
      formatMemory,
      isManaged,
      getAppUrl,
      getRegionFlag,
      truncateId,
      copyAppId,
      copiedAppId,
      startGuide,
    };
  },
};
</script>

<style scoped>
/* Guide intro/starter screen */
.guide-intro {
  min-height: 500px;
  display: flex;
  flex-direction: column;
}

.content-card--dashboard-tab {
  min-height: 500px;
  display: flex;
  flex-direction: column;
}

.content-card--dashboard-tab .items-list {
  flex: 1;
  min-height: 0;
}

.content-card--dashboard-tab .list-item-empty {
  min-height: 100%;
}

.guide-intro-content {
  text-align: center;
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.guide-intro-eyebrow {
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: #666;
  margin-bottom: 16px;
}

.guide-intro-title {
  font-size: clamp(1.5rem, 3vw, 2.25rem);
  font-weight: 600;
  color: #0f0f0f;
  line-height: 1.2;
}

.guide-intro-description {
  font-size: clamp(1.05rem, 2vw, 1.095rem);
  color: rgba(15, 15, 15, 0.875);
  margin: 0 auto;
  line-height: 1.6;
  max-width: 550px;
  margin: 32px auto;
}

.guide-completion-title {
  font-size: clamp(1.5rem, 3vw, 2.25rem);
  font-weight: 600;
  color: #0f0f0f;
  line-height: 1.3;
  margin: 0;
}

.guide-completion-description {
  font-size: 1.1rem;
  color: rgba(15, 15, 15, 0.75);
  margin: 24px auto 36px auto;
  line-height: 1.6;
  max-width: 500px;
}

.guide-intro-meta {
  display: flex;
  justify-content: center;
  gap: 56px;
  padding: 12px;
  flex-wrap: wrap;
}

.intro-meta-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.95rem;
  color: #666;
}

.intro-meta-icon {
  font-size: 1.125rem;
}

.intro-meta-icon-svg {
  width: 18px;
  height: 18px;
  stroke: #666;
  flex-shrink: 0;
}

.guide-intro-actions {
  display: flex;
  justify-content: center;
  gap: 16px;
  align-items: center;
}

/* Quick start inline cards with fixed height */
.quick-start-inline {
  min-height: 500px;
  display: flex;
  flex-direction: column;
  position: relative;
}

/* Step header */
.step-header {
  margin-bottom: 56px;
  flex-shrink: 0;
}

.step-title {
  font-size: clamp(1.35rem, 3vw, 2rem);
  font-weight: 600;
  color: #0f0f0f;
  margin: 0;
  line-height: 1.2;
  text-align: left;
}

.step-metadata {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.step-time,
.step-prereq {
  font-size: 0.875rem;
  color: #666;
}

.step-time::before {
  content: "⏱ ";
  opacity: 0.7;
}

.step-prereq::before {
  content: "📋 ";
  opacity: 0.7;
}

/* Guide link styling */
.guide-link {
  color: #0f0f0f;
  font-weight: 500;
  text-decoration: underline dotted;
  transition: all 0.2s ease;
}

.guide-link:hover,
.guide-link:active {
  color: #f048b5;
}

/* Tooltip styling */
.tooltip-wrapper {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.tooltip-trigger {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  padding: 2px;
  margin: 0;
  cursor: help;
  border-radius: 50%;
  transition: background-color 0.15s ease;
}

.tooltip-trigger:focus {
  outline: 2px solid #0f0f0f;
  outline-offset: 2px;
}

.tooltip-trigger:focus:not(:focus-visible) {
  outline: none;
}

.tooltip-trigger:focus-visible {
  outline: 2px solid #0f0f0f;
  outline-offset: 2px;
}

.tooltip-icon {
  width: 15px;
  height: 15px;
  opacity: 0.45;
  transition: opacity 0.2s ease;
}

.tooltip-wrapper:hover .tooltip-icon,
.tooltip-trigger:focus .tooltip-icon {
  opacity: 1;
}

.tooltip-content {
  position: absolute;
  bottom: calc(100% + 8px);
  left: 20px;
  transform: translateX(0);
  background: #161616;
  background-color: #161616;
  color: white;
  padding: 12px 16px;
  border-radius: 8px;
  border: 1px solid #161616;
  font-size: 0.95rem;
  font-weight: 400;
  line-height: 1.5;
  text-transform: none;
  width: 550px;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.2s ease, visibility 0.2s ease, transform 0.2s ease;
  z-index: 9999;
  pointer-events: none;
}

.tooltip-wrapper:hover .tooltip-content,
.tooltip-trigger:focus + .tooltip-content,
.tooltip-trigger:focus-within + .tooltip-content {
  opacity: 1;
  visibility: visible;
  transform: translateX(0) scale(1.02);
}

.tooltip-title {
  display: block;
  font-weight: 600;
  margin-bottom: 6px;
  color: #f048b5;
  font-size: 0.85em;
  letter-spacing: 0.5px;
}

/* Two-column guide layout */
.guide-layout {
  display: grid;
  grid-template-columns: 0.8fr 1fr;
  gap: 48px;
  align-items: start;
  flex: 1;
  min-height: 0;
}

.guide-layout-step2 {
  grid-template-columns: 0.65fr 1.35fr;
}

.guide-layout-balanced {
  grid-template-columns: 0.8fr 1fr;
}

.guide-content {
  width: 100%;
  min-width: 0;
}

.guide-code {
  width: 100%;
  min-width: 0;
}

/* Guide navigation */
.guide-navigation {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: auto;
  padding-top: 24px;
  flex-shrink: 0;
}

.btn-exit {
  opacity: 0.6;
}

.btn-exit:hover {
  opacity: 1;
}

.keyboard-hint {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-left: 8px;
  padding: 2px 6px;
  font-size: 0.75rem;
  font-weight: 500;
  color: #666;
  background: rgba(0, 0, 0, 0.05);
  border: 1px solid rgba(0, 0, 0, 0.1);
  border-radius: 4px;
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  min-width: 24px;
  line-height: 1;
}

.btn-continue .keyboard-hint {
  margin-left: 8px;
}

/* Code syntax highlighting */
.code-command {
  color: #e0e0e0;
}

.code-comment {
  color: #7c7c7c;
  font-style: italic;
}

/* Responsive layout for mobile/tablet */
@media (max-width: 968px) {
  .guide-layout {
    grid-template-columns: 1fr;
    gap: 32px;
  }

  .step-header {
    margin-bottom: 32px;
  }
}

/* Modal styles */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: white;
  border-radius: 16px;
  padding: 32px;
  max-width: 600px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  position: relative;
}

.modal-close {
  position: absolute;
  top: 16px;
  right: 16px;
  background: none;
  border: none;
  font-size: 24px;
  cursor: pointer;
  color: #666;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
}

.modal-close:hover {
  background: #f5f5f5;
  color: #333;
}

/* Toast notification */
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  border-radius: 10px;
  background: #0f0f0f;
  color: white;
  font-size: 0.95rem;
  font-weight: 500;
  box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
  cursor: pointer;
  z-index: 1100;
}

.toast--success {
  background: #0f0f0f;
}

.toast--error {
  background: #dc3545;
}

.toast--info {
  background: #1e40af;
}

.toast-message {
  flex: 1;
}

.toast-dismiss {
  background: none;
  border: none;
  color: rgba(255, 255, 255, 0.6);
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: color 0.15s ease;
}

.toast-dismiss:hover {
  color: white;
}

/* Toast animation */
.toast-enter-active {
  animation: toast-in 0.3s ease-out;
}

.toast-leave-active {
  animation: toast-out 0.2s ease-in;
}

@keyframes toast-in {
  from {
    opacity: 0;
    transform: translateY(16px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes toast-out {
  from {
    opacity: 1;
    transform: translateY(0);
  }
  to {
    opacity: 0;
    transform: translateY(16px);
  }
}

/* Spinner animation */
.spinner {
  animation: spin 1s linear infinite;
  margin-right: 6px;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

/* Breadcrumbs */
.breadcrumbs {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 20px;
  font-size: 0.9rem;
}

.breadcrumb-link {
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 500;
  color: #666;
  cursor: pointer;
  transition: color 0.15s ease;
}

.breadcrumb-link:hover {
  color: #0f0f0f;
}

.breadcrumb-separator {
  color: #ccc;
  font-weight: 400;
}

.breadcrumb-current {
  color: #333;
  font-weight: 500;
}

/* App Name Button */
.app-name-btn {
  background: none;
  border: none;
  padding: 0;
  font-family: inherit;
  font-size: clamp(1rem, 2vw, 1.095rem);
  font-weight: 600;
  color: inherit;
  text-align: left;
  cursor: pointer;
  transition: color 0.15s ease;
}

.app-name-btn:hover {
  color: #f048b5;
}

/* App Detail View */

/* Header section */
.app-detail-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 48px;
}

.app-detail-header-left {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.app-detail-title {
  font-size: clamp(1.5rem, 3vw, 2rem);
  font-weight: 600;
  color: #0f0f0f;
  margin: 0;
  line-height: 1.2;
}

.app-open-icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  background: transparent;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  color: #888;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
  flex-shrink: 0;
}

.app-open-icon-btn:hover {
  background: #0f0f0f;
  border-color: #0f0f0f;
  color: #fff;
}

.app-open-icon-btn svg {
  display: block;
}

/* Header Attestation Button (Primary CTA) - matches .btn-primary styling */
.header-attestation-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px 12px 18px;
  background: #0f0f0f;
  border: none;
  border-radius: 8px;
  font-family: inherit;
  font-size: clamp(0.95rem, 2vw, 1.05rem);
  font-weight: 500;
  color: #fff;
  cursor: pointer;
  transition: background-color 0.15s ease;
  flex-shrink: 0;
}

.header-attestation-btn:hover {
  background: #333;
}

.header-attestation-btn svg {
  color: #fff;
}

/* Highlighted deployment type text */
.highlight-hosted {
  background: #f3e8ff;
  color: #7c3aed;
  font-weight: 500;
  padding: 3px 6px;
  border-radius: 4px;
  font-size: clamp(0.9rem, 2vw, 1rem);
}

.highlight-managed {
  background: #dbeafe;
  color: #2563eb;
  font-weight: 500;
  padding: 3px 6px;
  border-radius: 4px;
  font-size: clamp(0.9rem, 2vw, 1rem);
}

.app-detail-header-actions {
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.app-detail-header-actions .btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  text-decoration: none;
}

/* Two-column layout */
.app-detail-layout {
  display: grid;
  grid-template-columns: 0.915fr auto;
  gap: 42px;
  align-items: start;
}

.app-detail-main {
  min-width: 0;
}

/* Sidebar */
.app-detail-sidebar {
  position: sticky;
  top: 24px;
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.sidebar-attestation {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}

.sidebar-attestation-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 16px 21px 16px 18px;
  background: transparent;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  font-size: 1.025rem;
  font-weight: 500;
  color: #555;
  cursor: pointer;
  transition: all 0.15s ease;
}

.sidebar-attestation-btn:hover {
  background: #0f0f0f;
  border-color: #0f0f0f;
  color: #fff;
}

.sidebar-attestation-btn svg {
  color: #888;
  transition: color 0.15s ease;
}

.sidebar-attestation-btn:hover svg {
  color: #fff;
}

.sidebar-status {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.sidebar-status .app-status-badge {
  width: fit-content;
}

.sidebar-meta {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.sidebar-meta-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.sidebar-cost {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding-top: 12px;
  margin-top: 12px;
  border-top: 1px solid #e5e7eb;
}

.app-detail-value--cost {
  font-size: 1.25rem;
  font-weight: 600;
  color: #059669;
}

.sidebar-section {
  padding-bottom: 20px;
  margin-bottom: 20px;
  border-bottom: 1px solid #f0f0f0;
}

.sidebar-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.sidebar-section-title {
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #888;
  margin: 0 0 12px 0;
}

.sidebar-info-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.sidebar-info-item {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 0.9rem;
  color: #333;
}

.sidebar-info-item svg {
  flex-shrink: 0;
  color: #888;
}

.sidebar-info-item--copyable {
  position: relative;
}

.sidebar-info-item--copyable .copy-inline-btn {
  margin-left: auto;
}

.sidebar-info-mono {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
}

/* Sidebar Info Blocks */
.sidebar-info-block {
  padding-bottom: 16px;
  margin-bottom: 16px;
  border-bottom: 1px solid #f0f0f0;
}

.sidebar-info-block:last-of-type {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.sidebar-info-label {
  display: block;
  font-size: 0.95rem;
  font-weight: 500;
  color: #333;
  margin-bottom: 4px;
}

.sidebar-info-value {
  display: block;
  font-size: 0.95rem;
  color: #0f0f0f;
  font-weight: 500;
}

.sidebar-info-value.sidebar-info-mono {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
}

/* Inline sidebar info rows */
.sidebar-info-list-inline {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.sidebar-info-row {
  display: flex;
  align-items: baseline;
  gap: 6px;
  font-size: 1rem;
  line-height: 1.4;
}

.sidebar-info-inline-label {
  color: #666;
  white-space: nowrap;
}

.sidebar-info-inline-value {
  color: #666;
}

.sidebar-info-inline-value.sidebar-info-mono {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.85rem;
}

.sidebar-info-value-secondary {
  display: block;
  font-size: 0.9rem;
  color: #666;
  margin-top: 2px;
}

.sidebar-info-value-with-copy {
  display: flex;
  align-items: center;
  gap: 8px;
}

.sidebar-info-value-with-copy .copy-inline-btn {
  flex-shrink: 0;
}

/* Sidebar Actions */
.sidebar-actions {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sidebar-action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 10px 12px;
  font-size: 0.9rem;
  font-weight: 500;
  font-family: inherit;
  color: #333;
  background: #fafafa;
  border: 1px solid #e8e8e8;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.sidebar-action-btn:hover:not(:disabled) {
  background: #f0f0f0;
  border-color: #ddd;
}

.sidebar-action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.sidebar-action-btn svg {
  flex-shrink: 0;
  color: #666;
}

.sidebar-action-btn--start:not(:disabled) {
  color: #166534;
  background: #f0fdf4;
  border-color: #bbf7d0;
}

.sidebar-action-btn--start:hover:not(:disabled) {
  background: #dcfce7;
}

.sidebar-action-btn--start svg {
  color: #166534;
}

.sidebar-action-btn--stop:not(:disabled) {
  color: #92400e;
  background: #fffbeb;
  border-color: #fde68a;
}

.sidebar-action-btn--stop:hover:not(:disabled) {
  background: #fef3c7;
}

.sidebar-action-btn--stop svg {
  color: #92400e;
}

.sidebar-action-btn--primary {
  color: #fff;
  background: #0f0f0f;
  border-color: #0f0f0f;
  text-decoration: none;
}

.sidebar-action-btn--primary:hover {
  background: #333;
  border-color: #333;
}

.sidebar-action-btn--primary svg {
  color: #fff;
}

.sidebar-action-btn--danger {
  color: #dc3545;
  background: #fff;
  border-color: #f5c6cb;
}

.sidebar-action-btn--danger:hover:not(:disabled) {
  background: #fff5f5;
  border-color: #dc3545;
}

.sidebar-action-btn--danger svg {
  color: #dc3545;
}

.sidebar-actions-divider {
  height: 1px;
  background: #f0f0f0;
  margin: 8px 0;
}

/* Content sections */
.app-detail-main .app-detail-section-title:first-child {
  margin-top: 0;
}

.app-detail-section {
  margin: 0 0 24px 0;
  padding: 28px;
  border: 1px solid #f0f0f0;
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0, 0, 0, 0.06);
}

.app-detail-section:last-child {
  margin-bottom: 0;
}

.app-detail-section--fullwidth {
  margin-top: 48px;
}

.app-detail-section--borderless {
  background: none;
  border: none;
  padding: 0;
  box-shadow: none;
}

.app-detail-section-title {
  font-size: clamp(1.15rem, 2vw, 1.35rem);
  font-weight: 500;
  color: #0f0f0f;
  margin: 24px 0 12px 0;
}

.app-detail-section-title:first-child {
  margin-top: 0;
}

.app-detail-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 36px;
}

/* 2-column grid variant */
.app-detail-grid--2col {
  grid-template-columns: 1fr 1.8fr;
  gap: 28px 48px;
}

/* 3-column grid variant */
.app-detail-grid--3col {
  grid-template-columns: 1.15fr 0.925fr 0.925fr;
  gap: 28px 36px;
}

.app-detail-item--span2 {
  grid-column: span 2;
}

.app-detail-item {
  display: flex;
  flex-direction: column;
}

.app-detail-item-full {
  grid-column: 1 / -1;
}

.app-detail-label {
  font-size: clamp(1rem, 2vw, 1.05rem);
  font-weight: 500;
  color: #222;
  letter-spacing: 0.3px;
  margin-bottom: 2px;
}

.app-detail-value {
  font-size: clamp(1rem, 2vw, 1.05rem);
  color: #666;
  word-break: break-all;
  font-weight: 400;
}

.app-detail-mono {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
}

.app-detail-uppercase {
  text-transform: uppercase;
}

.app-detail-truncate {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
}

/* Copy button inline */
.app-detail-value-with-copy {
  display: flex;
  align-items: center;
  gap: 8px;
}

.copy-inline-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  padding: 4px;
  color: #999;
  cursor: pointer;
  border-radius: 4px;
  transition: all 0.15s ease;
  flex-shrink: 0;
}

.copy-inline-btn:hover {
  background: #f0f0f0;
  color: #333;
}

.copy-inline-btn svg {
  display: block;
}

/* Git URL display */
.app-detail-git-url {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.app-detail-git-url-header {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.app-detail-helper-text {
  font-size: clamp(1rem, 2vw, 1.05rem);
  color: #666;
  margin: 0;
  line-height: 1.4;
}

.app-detail-git-url .app-detail-value-with-copy {
  background: #f8f8f8;
  padding: 12px 14px;
  border-radius: 6px;
  border: 1px solid #e8e8e8;
}

.app-detail-git-url .app-detail-value {
  flex: 1;
  min-width: 0;
  word-break: break-all;
}

.app-detail-command {
  display: flex;
  align-items: center;
  gap: 12px;
  background: #f6f8fa;
  border-radius: 8px;
  padding: 12px 16px;
  margin-top: 12px;
}

.app-detail-command code {
  flex: 1;
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.95rem;
  color: #333;
  word-break: break-all;
}

.app-detail-command .copy-inline-btn {
  flex-shrink: 0;
  color: #999;
}

.app-detail-command .copy-inline-btn:hover {
  background: #e0e0e0;
  color: #333;
}

/* AWS Infrastructure Details grid */
.aws-details-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px 32px;
  background: #f6f8fa;
  border-radius: 8px;
  padding: 20px 24px;
  margin-top: 12px;
}

.aws-detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.aws-detail-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: #666;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.aws-detail-value {
  font-size: 0.95rem;
  color: #333;
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  word-break: break-all;
}

.aws-detail-value-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.aws-detail-value-row .copy-inline-btn {
  flex-shrink: 0;
  color: #999;
}

.aws-detail-value-row .copy-inline-btn:hover {
  background: #e0e0e0;
  color: #333;
}

/* Actions section */
.app-detail-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.app-detail-action-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px 12px 14px;
  background: #f5f5f5;
  border: 1px solid #e8e8e8;
  border-radius: 8px;
  font-family: inherit;
  font-size: 0.95rem;
  font-weight: 500;
  color: #333;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.15s ease;
}

.app-detail-action-btn:hover {
  background: #eee;
  border-color: #ddd;
}

.app-detail-action-btn--start {
  background: #f0fdf4;
  border-color: #bbf7d0;
  color: #16a34a;
}

.app-detail-action-btn--start:hover:not(:disabled) {
  background: #dcfce7;
  border-color: #86efac;
}

.app-detail-action-btn--stop {
  background: #fefce8;
  border-color: #fef08a;
  color: #ca8a04;
}

.app-detail-action-btn--stop:hover:not(:disabled) {
  background: #fef9c3;
  border-color: #fde047;
}

.app-detail-action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.app-detail-action-btn--danger {
  background: #fff5f5;
  border-color: #ffcdd2;
  color: #dc3545;
}

.app-detail-action-btn--danger:hover {
  background: #ffebee;
  border-color: #ef9a9a;
}

.app-detail-action-btn--danger svg {
  position: relative;
  top: 2px;
}

/* Danger Zone */
.app-detail-danger-zone {
  background: #fffbfb;
  border: 1px solid #fee2e2;
  border-radius: 12px;
  padding: 20px;
  margin-top: 32px;
}

.app-detail-danger-zone--standalone {
  background: none;
  border: none;
  border-radius: 0;
  padding: 0;
  margin-top: 48px;
}

.app-detail-danger-zone .app-detail-section-title {
  margin-top: 0;
  margin-bottom: 16px;
}

.app-detail-section-title--danger {
  color: #dc3545;
}

.app-detail-danger-content {
  margin-top: 0;
  background: #fffbfb;
  border: 1px solid #fee2e2;
  border-radius: 8px;
  padding: 20px;
}

.app-detail-danger-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 20px;
}

.app-detail-danger-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
}

.app-detail-danger-title {
  font-size: clamp(1rem, 2vw, 1.05rem);
  font-weight: 600;
  color: #333;
}

.app-detail-danger-description {
  font-size: clamp(1rem, 2vw, 1.05rem);
  color: #666;
  line-height: 1.4;
}

/* Responsive adjustments */
@media (max-width: 900px) {
  .app-detail-layout {
    grid-template-columns: 1fr;
    gap: 24px;
  }

  .app-detail-sidebar {
    position: static;
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    padding-top: 24px;
    border-top: 1px solid #f0f0f0;
  }

  .sidebar-section {
    border-bottom: none;
    padding-bottom: 0;
    margin-bottom: 0;
  }
}

@media (max-width: 768px) {
  .app-detail-header {
    flex-wrap: wrap;
  }

  .app-detail-grid {
    grid-template-columns: 1fr;
  }

  .app-detail-item--span2 {
    grid-column: auto;
  }
}

@media (max-width: 600px) {
  .app-detail-sidebar {
    grid-template-columns: 1fr;
  }
}

/* Security Warning Banner */
.security-warning-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  background: #fef3c7;
  border: 1px solid #f59e0b;
  border-radius: 8px;
  margin-bottom: 20px;
  color: #92400e;
  font-size: 14px;
}

.security-warning-banner svg {
  flex-shrink: 0;
  color: #f59e0b;
}

.security-warning-link {
  background: none;
  border: none;
  color: #d97706;
  text-decoration: underline;
  cursor: pointer;
  font-size: inherit;
  padding: 0;
}

.security-warning-link:hover {
  color: #b45309;
}

/* Security Settings */
.security-settings {
  display: flex;
  flex-direction: column;
  gap: 24px;
  margin-top: 24px;
}

.security-setting-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  padding: 20px;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}

.security-auth-panel {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.security-settings--inline {
  margin-top: 0;
}

.security-passkeys {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.passkey-flow-card {
  margin-bottom: 0;
  padding: 16px 18px;
  border: 1px solid #d1d5db;
  border-radius: 12px;
  background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
}

.passkey-flow-steps {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.passkey-flow-step {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.75);
  border: 1px solid transparent;
}

.passkey-flow-step--active {
  border-color: #111827;
  background: #ffffff;
  box-shadow: 0 6px 18px rgba(15, 23, 42, 0.06);
}

.passkey-flow-step--done {
  border-color: #bbf7d0;
  background: #f0fdf4;
}

.passkey-flow-step-number {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 999px;
  background: #e5e7eb;
  color: #111827;
  font-size: 13px;
  font-weight: 700;
  flex-shrink: 0;
}

.passkey-flow-step--active .passkey-flow-step-number {
  background: #111827;
  color: #ffffff;
}

.passkey-flow-step--done .passkey-flow-step-number {
  background: #16a34a;
  color: #ffffff;
}

.passkey-flow-step-copy {
  display: flex;
  flex-direction: column;
  gap: 3px;
  font-size: 13px;
  color: #4b5563;
}

.passkey-flow-step-copy strong {
  color: #111827;
  font-size: 14px;
}

.passkey-flow-message {
  margin: 12px 0 0;
  font-size: 13px;
  color: #4b5563;
}

.passkey-list {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.passkey-add-action {
  margin-top: 0;
}

.ssh-keys-action {
  margin-top: 16px;
  align-self: flex-start;
}

.passkey-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 20px;
  padding: 18px 20px;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
}

.passkey-info {
  min-width: 0;
  flex: 1;
}

.passkey-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.passkey-title {
  font-size: 15px;
  font-weight: 600;
  color: #111827;
}

.passkey-badges {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.passkey-badge {
  padding: 4px 10px;
  border-radius: 999px;
  background: #e5e7eb;
  color: #374151;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}

.passkey-badge--current {
  background: #dcfce7;
  color: #166534;
}

.passkey-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 12px;
  font-size: 13px;
  color: #6b7280;
}

@media (max-width: 700px) {
  .passkey-item,
  .passkey-header {
    flex-direction: column;
  }

  .passkey-flow-card {
    padding: 14px;
  }

  .passkey-badges {
    justify-content: flex-start;
  }
}

/* Billing Styles */
.billing-summary {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  background: #f8f9fa;
  border-radius: 8px;
  margin-bottom: 2rem;
}

.billing-period {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.billing-period-label {
  font-size: 0.75rem;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.billing-period-dates {
  font-size: 1rem;
  font-weight: 500;
  color: #1f2937;
}

.billing-total {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 0.25rem;
}

.billing-total-label {
  font-size: 0.75rem;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.billing-total-amount {
  font-size: 1.75rem;
  font-weight: 600;
  color: #1f2937;
}

.billing-total-amount.billing-projected {
  color: #6b7280;
}

.billing-section {
  margin-bottom: 2rem;
}

.billing-section-title {
  font-size: 1rem;
  font-weight: 600;
  color: #1f2937;
  margin-bottom: 1rem;
}

.billing-table {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  overflow: hidden;
}

.billing-table-header {
  display: grid;
  grid-template-columns: 2fr 1fr 1fr 1fr;
  padding: 0.75rem 1rem;
  background: #f9fafb;
  border-bottom: 1px solid #e5e7eb;
  font-size: 0.75rem;
  font-weight: 600;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.billing-table-row {
  display: grid;
  grid-template-columns: 2fr 1fr 1fr 1fr;
  padding: 1rem;
  border-bottom: 1px solid #e5e7eb;
  align-items: center;
}

.billing-table-row:last-child {
  border-bottom: none;
}

.billing-col-resource {
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
}

.billing-resource-name {
  font-weight: 500;
  color: #1f2937;
}

.billing-resource-type {
  font-size: 0.75rem;
  color: #6b7280;
}

.billing-col-usage,
.billing-col-rate,
.billing-col-cost {
  font-size: 0.875rem;
  color: #374151;
}

.billing-col-cost {
  font-weight: 500;
}

.billing-info {
  padding: 1.5rem;
  background: #f8f9fa;
  border-radius: 8px;
}

.billing-pricing-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
}

.billing-pricing-item {
  display: flex;
  justify-content: space-between;
  padding: 0.75rem;
  background: white;
  border-radius: 6px;
  border: 1px solid #e5e7eb;
}

.billing-pricing-resource {
  font-size: 0.875rem;
  color: #374151;
}

.billing-pricing-rate {
  font-size: 0.875rem;
  font-weight: 500;
  color: #1f2937;
}

.billing-pricing-note {
  font-size: 0.875rem;
  color: #6b7280;
  margin-bottom: 1rem;
}

/* Payment method styles */
.payment-methods-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.payment-method-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem;
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}

.payment-method-badge {
  font-size: 0.75rem;
  font-weight: 500;
  color: #059669;
  background: #ecfdf5;
  padding: 0.125rem 0.5rem;
  border-radius: 9999px;
}

.payment-method-actions {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.btn-danger-text {
  color: #dc2626;
}

.btn-danger-text:hover {
  color: #b91c1c;
}

.security-setting-info {
  flex: 1;
}

.security-setting-title {
  font-size: 16px;
  font-weight: 600;
  color: #111827;
  margin: 0 0 8px 0;
}

.security-setting-description {
  max-width: 750px;
  font-size: 14px;
  color: #6b7280;
  margin: 0;
  line-height: 1.5;
}

.security-setting-control {
  flex-shrink: 0;
}

/* Toggle Switch */
.toggle-switch {
  position: relative;
  display: inline-block;
  width: 48px;
  height: 26px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.toggle-slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #d1d5db;
  transition: 0.3s;
  border-radius: 26px;
}

.toggle-slider:before {
  position: absolute;
  content: "";
  height: 20px;
  width: 20px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: 0.3s;
  border-radius: 50%;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.toggle-switch input:checked + .toggle-slider {
  background-color: #10b981;
}

.toggle-switch input:checked + .toggle-slider:before {
  transform: translateX(22px);
}

.toggle-switch input:disabled + .toggle-slider {
  opacity: 0.5;
  cursor: not-allowed;
}

/* Quorum bundle cards */
.bundle-card {
  padding: 16px 20px;
  border-bottom: 1px solid #eee;
}

.bundle-card:last-child {
  border-bottom: none;
}

.bundle-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.bundle-details {
  padding-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.bundle-detail-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.bundle-label {
  font-size: 0.8rem;
  color: #666;
}

.bundle-hash {
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
  font-size: 0.8rem;
  color: #333;
  background: #f5f5f5;
  padding: 2px 6px;
  border-radius: 3px;
}

.bundle-actions {
  display: flex;
  gap: 8px;
}

.btn-download {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  font-size: 0.8rem;
  color: #555;
  background: #fff;
  border: 1px solid #ccc;
  border-radius: 4px;
  cursor: pointer;
}
.btn-download:hover {
  border-color: #999;
  color: #333;
  background: #f8f8f8;
}

.bundle-name-display {
  display: flex;
  align-items: center;
  gap: 6px;
}

.bundle-name-edit {
  display: flex;
  align-items: center;
  gap: 6px;
}

.bundle-name-input {
  padding: 4px 8px;
  font-size: 0.9rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  outline: none;
  width: 200px;
}

.bundle-name-input:focus {
  border-color: #666;
}

.item-meta-id {
  font-size: 0.75rem;
  color: #999;
  font-family: ui-monospace, "SF Mono", Monaco, "Cascadia Code", monospace;
}

.btn-icon {
  background: none;
  border: none;
  cursor: pointer;
  padding: 2px;
  color: #999;
  display: flex;
  align-items: center;
}

.btn-icon:hover {
  color: #333;
}

.bundle-labels {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding-top: 8px;
}

.bundle-label-tag {
  font-size: 0.75rem;
  background: #f0f0f0;
  color: #555;
  padding: 2px 8px;
  border-radius: 10px;
  border: 1px solid #e0e0e0;
  display: inline-flex;
  align-items: center;
  gap: 2px;
}

.label-remove-btn {
  background: none;
  border: none;
  cursor: pointer;
  color: #999;
  font-size: 0.85rem;
  padding: 0 2px;
  margin-left: 2px;
  line-height: 1;
}
.label-remove-btn:hover { color: #dc3545; }

.bundle-label-add {
  font-size: 0.75rem;
  color: #999;
  background: none;
  border: 1px dashed #ccc;
  border-radius: 10px;
  padding: 2px 8px;
  cursor: pointer;
}
.bundle-label-add:hover { color: #333; border-color: #999; }

.label-add-form {
  display: flex;
  align-items: center;
  gap: 4px;
}

.label-input {
  padding: 2px 6px;
  font-size: 0.75rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  width: 80px;
}
.label-input:focus { border-color: #666; outline: none; }

.btn-sm {
  padding: 4px 10px;
  font-size: 0.8rem;
  border-radius: 4px;
  cursor: pointer;
}

.payment-method-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.payment-method-type {
  font-weight: 500;
  color: #1f2937;
  text-transform: capitalize;
}

.payment-method-details {
  font-size: 0.875rem;
  color: #6b7280;
}

.payment-method-empty {
  padding: 1.5rem;
  background: #f9fafb;
  border: 1px dashed #d1d5db;
  border-radius: 8px;
  text-align: center;
}

.payment-method-empty p {
  color: #6b7280;
  margin-bottom: 1rem;
}

/* Invoice styles */
.invoices-list {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  overflow: hidden;
}

.invoice-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem;
  border-bottom: 1px solid #e5e7eb;
  background: white;
}

.invoice-item:last-child {
  border-bottom: none;
}

.invoice-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.invoice-number {
  font-weight: 500;
  color: #1f2937;
}

.invoice-date {
  font-size: 0.875rem;
  color: #6b7280;
}

.invoice-amount {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.invoice-status {
  font-size: 0.75rem;
  font-weight: 500;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  text-transform: capitalize;
}

.invoice-status.status-paid {
  background: #d1fae5;
  color: #065f46;
}

.invoice-status.status-pending {
  background: #fef3c7;
  color: #92400e;
}

.invoice-status.status-overdue {
  background: #fee2e2;
  color: #991b1b;
}

.invoice-total {
  font-weight: 500;
  color: #1f2937;
}

/* Card form styles */
.card-form {
  margin-bottom: 1rem;
}

.card-form-row {
  margin-bottom: 1rem;
}

.card-form-row--split {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.card-form-col {
  min-width: 0;
}

.card-form-label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #374151;
  margin-bottom: 0.5rem;
}

.card-field {
  height: 42px;
  padding: 0.5rem 0.75rem;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  background: white;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.card-field:focus-within {
  border-color: #0f0f0f;
  box-shadow: 0 0 0 3px rgba(15, 15, 15, 0.1);
}

.card-error {
  padding: 0.75rem;
  margin-bottom: 1rem;
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 6px;
  color: #dc2626;
  font-size: 0.875rem;
}

.card-privacy-notice {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid #e5e7eb;
  font-size: 0.75rem;
  color: #6b7280;
  text-align: center;
}

.card-privacy-notice a {
  color: #4b5563;
  text-decoration: underline;
}

.btn-small {
  padding: 0.375rem 0.75rem;
  font-size: 0.8125rem;
}

/* Estimated cost in app detail */
.app-estimated-cost {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: #fef3c7;
  border-radius: 6px;
  margin-top: 1rem;
}

.app-estimated-cost-label {
  font-size: 0.875rem;
  color: #92400e;
}

.app-estimated-cost-value {
  font-size: 0.875rem;
  font-weight: 600;
  color: #92400e;
}

@media (max-width: 768px) {
  .billing-summary {
    flex-direction: column;
    gap: 1rem;
    align-items: flex-start;
  }

  .billing-total {
    align-items: flex-start;
  }

  .billing-table-header,
  .billing-table-row {
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem;
  }

  .billing-pricing-grid {
    grid-template-columns: 1fr;
  }
}

/* Email settings */
.legal-settings-card {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 0.5rem 0;
}

.legal-settings-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem 1.1rem;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  background: #f9fafb;
}

.legal-settings-copy {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.legal-settings-name {
  font-size: 0.95rem;
  font-weight: 600;
  color: #111827;
}

.legal-settings-meta {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
  font-size: 0.82rem;
  color: #6b7280;
}

.legal-settings-link {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  color: #111827;
  font-size: 0.9rem;
  font-weight: 500;
  text-decoration: none;
  white-space: nowrap;
}

.legal-settings-link:hover {
  color: var(--color-pink);
}

.legal-settings-link-icon {
  width: 0.95rem;
  height: 0.95rem;
  opacity: 0.95;
  transition: opacity 0.2s ease;
}

.legal-settings-link:hover .legal-settings-link-icon {
  opacity: 1;
}

.email-settings {
  padding: 0.5rem 0;
}

.email-display {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.email-current {
  font-size: 0.95rem;
  color: var(--color-text);
}

.email-not-set {
  font-size: 0.95rem;
  color: var(--color-text-muted, #888);
  font-style: italic;
}

.email-edit {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  max-width: 400px;
}

.email-input {
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--color-border, #ddd);
  border-radius: 6px;
  font-size: 0.95rem;
  background: var(--color-bg, #fff);
  color: var(--color-text);
}

.email-input:focus {
  outline: none;
  border-color: var(--color-primary, #000);
}

.email-edit-actions {
  display: flex;
  gap: 0.5rem;
}

.email-unverified-warning {
  font-size: 0.8rem;
  color: #e8a735;
  margin-top: 0.5rem;
}

.email-hint {
  font-size: 0.8rem;
  color: var(--color-text-muted, #888);
  margin-top: 0.5rem;
}

/* Prepaid Credits */
.credits-balance-card {
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  border-radius: 8px;
  padding: 1rem 1.25rem;
}

.credits-balance-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.credits-balance-info {
  display: flex;
  align-items: baseline;
  gap: 0.5rem;
}

.credits-balance-amount {
  font-size: 1.5rem;
  font-weight: 700;
  color: #15803d;
}

.credits-balance-label {
  font-size: 0.875rem;
  color: #4b5563;
}

.credits-hint {
  font-size: 0.8rem;
  color: #6b7280;
  margin-top: 0.5rem;
}

.redeem-code-row {
  display: flex;
  gap: 0.5rem;
  margin-top: 0.75rem;
}

.redeem-code-input {
  flex: 1;
  padding: 0.4rem 0.6rem;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 0.875rem;
  font-family: monospace;
  max-width: 240px;
}

.redeem-code-input:focus {
  outline: none;
  border-color: var(--color-primary, #000);
}

/* Auto Top-up */
.auto-topup-card {
  margin-top: 1rem;
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 1rem 1.25rem;
}
.auto-topup-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.toggle-switch {
  position: relative;
  display: inline-block;
  width: 44px;
  height: 24px;
  flex-shrink: 0;
}
.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.toggle-slider {
  position: absolute;
  cursor: pointer;
  inset: 0;
  background-color: #d1d5db;
  border-radius: 24px;
  transition: 0.2s;
}
.toggle-slider::before {
  content: "";
  position: absolute;
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: #fff;
  border-radius: 50%;
  transition: 0.2s;
}
.toggle-switch input:checked + .toggle-slider {
  background-color: #22c55e;
}
.toggle-switch input:checked + .toggle-slider::before {
  transform: translateX(20px);
}
.auto-topup-settings {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid #e5e7eb;
}
.auto-topup-field {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}
.auto-topup-label {
  font-size: 0.85rem;
  font-weight: 500;
  color: #374151;
}
.auto-topup-input-row {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}
.auto-topup-currency {
  font-size: 0.95rem;
  color: #374151;
  font-weight: 500;
}
.auto-topup-input {
  width: 100px;
  padding: 0.35rem 0.5rem;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 0.9rem;
}
.auto-topup-hint {
  font-size: 0.75rem;
  color: #9ca3af;
}
.auto-topup-error {
  display: block;
  margin-top: 0.35rem;
  font-size: 0.8rem;
  color: #ef4444;
}

.credit-packages {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin: 1rem 0;
}

.credit-package-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 1.25rem;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  background: #fff;
  cursor: pointer;
  transition: border-color 0.15s, background-color 0.15s;
  text-align: left;
}

.credit-package-card:hover {
  border-color: #a7f3d0;
  background: #f0fdf4;
}

.credit-package-card--selected {
  border-color: #16a34a;
  background: #f0fdf4;
  box-shadow: 0 0 0 1px #16a34a;
}

.credit-package-pay {
  font-weight: 600;
  font-size: 1rem;
  color: #111827;
}

.credit-package-get {
  font-size: 0.875rem;
  color: #4b5563;
}

.credit-package-bonus {
  font-size: 0.8125rem;
  font-weight: 600;
  color: #16a34a;
  background: #dcfce7;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.modal-description {
  font-size: 0.875rem;
  color: #6b7280;
  margin-bottom: 0.5rem;
}

/* Subscription */
.subscription-card {
  background: #f9fafb;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: 1rem;
}

.subscription-info {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.subscription-tier-name {
  font-weight: 600;
  font-size: 1.125rem;
  color: #111827;
}

.subscription-status {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  text-transform: capitalize;
}

.subscription-status.status-active {
  background: #dcfce7;
  color: #16a34a;
}

.subscription-status.status-past_due {
  background: #fef3c7;
  color: #d97706;
}

.subscription-status.status-canceled {
  background: #f3f4f6;
  color: #6b7280;
}

.subscription-details {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.subscription-detail-item {
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
}

.subscription-detail-label {
  font-size: 0.75rem;
  color: #6b7280;
}

.subscription-detail-value {
  font-size: 0.875rem;
  color: #111827;
  font-weight: 500;
}

.subscription-cancel-notice {
  font-size: 0.8125rem;
  color: #d97706;
  background: #fffbeb;
  border: 1px solid #fef3c7;
  border-radius: 4px;
  padding: 0.5rem;
  margin-bottom: 0.75rem;
}

.subscription-actions {
  display: flex;
  gap: 0.5rem;
}

.subscription-empty {
  color: #6b7280;
  font-size: 0.875rem;
}

.subscription-empty p {
  margin-bottom: 0.75rem;
}

.tier-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.tier-card {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
  padding: 1rem;
  border: 2px solid #e5e7eb;
  border-radius: 8px;
  background: #fff;
  cursor: pointer;
  transition: border-color 0.15s;
  text-align: left;
}

.tier-card:hover {
  border-color: #9ca3af;
}

.tier-card--selected {
  border-color: #111827;
  background: #f9fafb;
}

.tier-card-name {
  font-weight: 600;
  font-size: 0.9375rem;
  color: #111827;
}

.tier-card-price {
  font-weight: 700;
  font-size: 1.125rem;
  color: #111827;
}

.tier-card-period {
  font-weight: 400;
  font-size: 0.8125rem;
  color: #6b7280;
}

.tier-card-limits {
  font-size: 0.8125rem;
  color: #6b7280;
}

/* Builder size selector */
.builder-size-options {
  display: flex;
  gap: 0.75rem;
}
.builder-size-btn {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.25rem;
  padding: 0.75rem 1rem;
  border: 1px solid #d1d5db;
  border-radius: 0.5rem;
  background: #fff;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}
.builder-size-btn:hover {
  border-color: #9ca3af;
}
.builder-size-btn--active {
  border-color: #111827;
  background: #f9fafb;
}
.builder-size-label {
  font-weight: 600;
  font-size: 0.875rem;
  color: #111827;
}
.builder-size-specs {
  font-size: 0.75rem;
  color: #6b7280;
}
</style>
