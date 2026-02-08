<!-- SPDX-FileCopyrightText: 2025 Caution SEZC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial -->

<template>
  <DashboardLayout
    :title="pageTitle"
    :active-tab="activeTab"
    :show-title="false"
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

    <!-- Security Warning Banner (non-dismissible) -->
    <div v-if="!orgSettings.require_pin && !loadingOrgSettings" class="security-warning-banner">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M12 8v4"/>
        <circle cx="12" cy="16" r="1"/>
      </svg>
      <span>
        <strong>Development mode:</strong> PIN verification is disabled.
        <button class="security-warning-link" @click="handleTabChange('security')">
          Enable PIN requirement
        </button>
        for production use.
      </span>
    </div>

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
            <h2 class="content-header-title">Your applications</h2>
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
    <div v-if="activeTab === 'ssh'" class="content-card">
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
        <!-- Header with title and Add button -->
        <div class="content-header">
          <div class="content-header-text">
            <h2 class="content-header-title">Your SSH keys</h2>
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
        <div class="items-list">
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
    <div v-if="activeTab === 'security'" class="content-card">
      <div class="content-header">
        <div class="content-header-text">
          <h2 class="content-header-title">Security settings</h2>
          <p class="content-header-description">
            Configure authentication requirements for your organization.
          </p>
        </div>
      </div>

      <div v-if="loadingOrgSettings" class="list-item-empty">Loading security settings...</div>
      <div v-else class="security-settings">
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
import { ref, computed, onMounted, onUnmounted } from "vue";
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
  components: {
    DashboardLayout,
    AttestationModal,
  },
  setup() {
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

    const openAppDetail = (app) => {
      selectedApp.value = app;
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

    // Organization settings state
    const orgSettings = ref({ require_pin: false });
    const loadingOrgSettings = ref(true);
    const updatingOrgSettings = ref(false);
    const orgSettingsError = ref(null);
    const currentOrgId = ref(null);

    const loadOrgSettings = async () => {
      loadingOrgSettings.value = true;
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

    const pageTitle = computed(() => {
      return "";
    });

    const loadApps = async () => {
      loadingApps.value = true;

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
      loadingKeys.value = true;

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
      loadingCreds.value = true;

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

    const handleTabChange = (newTab) => {
      activeTab.value = newTab;
      if (newTab === "apps") {
        setupStep.value = 0;
        selectedApp.value = null;
      } else if (newTab === "guide") {
        setupStep.value = 0;
      } else if (newTab === "ssh") {
        showAddKeyForm.value = false;
        newKeyName.value = "";
        newPublicKey.value = "";
        error.value = null;
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
      activeTab.value = "guide";
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

    onMounted(async () => {
      // Add keyboard event listener
      window.addEventListener("keydown", handleKeyDown);

      await Promise.all([loadApps(), loadKeys(), loadCredentials(), loadOrgSettings()]);
    });

    onUnmounted(() => {
      // Clean up keyboard event listener
      window.removeEventListener("keydown", handleKeyDown);
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
      orgSettings,
      loadingOrgSettings,
      updatingOrgSettings,
      orgSettingsError,
      toggleRequirePin,
      logout,
      handleTabChange,
      formatKeyType,
      formatDate,
      formatDateTime,
      formatDateTimeFull,
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
  height: 500px;
  display: flex;
  flex-direction: column;
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
</style>
