# SAMICIOUS MICROFINANCE Settings Architecture Audit

## Scope and current implementation

The application is a single-page, browser-first application centered in `index.html`, with a server-side security gateway under `server/`. Data access is routed through the frontend `callRpc()` wrapper to `/api/rpc`, while the server delegates approved operations to Supabase RPCs. The frontend includes an IndexedDB-shaped data model and an offline/synchronization layer, but the current source also contains centralized security hardening, session storage controls, and server authorization.

## Roles identified

The primary role catalog includes Administrator, Branch Manager, Loan Manager, Teller, Cashier, Susu Collector, Loan Officer, Auditor, and Developer. Additional operational role aliases and persisted-role extensions include Customer Service Officer, Accounts Officer, Recovery Officer, Operations Officer, Compliance Officer, Accountant, HR/Staff Manager, Customer Service, Teller/Cashier, and Susu/Field Officer. Dashboard normalization maps aliases such as Administrator/CEO, Staff Manager, HR Manager, Teller/Cashier, and Field/Susu Collector to canonical roles.

The frontend permission model is centralized in `PERMISSIONS` and `ROLE_PERMISSIONS`. Administrator receives every permission except SMS configuration; Developer has a distinct read-only/technical set plus SMS configuration; business roles receive explicit operational permissions. Credential management is intentionally Administrator-only in the frontend model, and the server gateway separately enforces Administrator-only RPCs and users-table mutation.

## Dashboards, navigation, and existing settings-related components

The page registry `PAGES` defines dashboard, notifications, customers, savings, loans, loan top-up, loan repayment, EOD closing and reconciliation, cash position monitoring, till closing, vault settlement, system EOD processing, branches, staff, administrator credentials, staff credential management, credential revocation, administrator transaction notifications, savings products, customer portfolio/risk, household relationships, document vault, reports, audit trail, policy settings, sync, SMS configuration, and related operational pages. Navigation is flat and role-filtered by both role and permission.

Existing settings-like components include Administrator Credentials, Staff Credential Management, Credential Revocation, Policy Settings, Sync/Data Sync, SMS Configuration, and the general Settings page/route where present. Developer Information and About/acknowledgement content already exist in the developer menu and documentation-style areas. Notifications include normal in-app notifications, an Administrator Transaction Notification Dashboard, archived notification records, and notification badges. Help/Support/User Guide/FAQ-like content exists in the application’s informational/developer sections and should be reused rather than duplicated.

## Security, audit, offline, and synchronization findings

Authentication uses the existing login/session architecture with server-side password verification, session tokens, session epoch invalidation, revoked-account checks, and periodic session-validity enforcement. Server authorization lives in `server/authz.mjs`; the security gateway audits denied protected RPC attempts and fails closed for unknown RPC names. Credential hashes are kept server-side and normal users-table responses are redacted.

Audit support includes general activity logging, security audit records, credential audit events, administrator transaction notifications, and sync logs. The application has IndexedDB-backed data access, online/offline event handlers, a sync queue, auto-sync, manual sync, sync status indicators, and persistent sync state. Browser storage hardening moves authentication state into session storage and blocks serialized credential material from browser storage. The existing UI uses CSS custom properties, responsive cards/tables, badges, modals, notes, section headers, and mobile-first enhancement helpers.

## Initial architecture direction

The centralized Settings foundation should be additive: introduce a role-filtered Settings page with a responsive category navigation and card sections, then deep-link or embed the existing Administrator Credentials, Policy Settings, Sync, SMS Configuration, Help/Support, Developer Information, and About components. New settings permissions should be represented in the existing `PERMISSIONS` and server authorization model. Settings reads/writes should use existing RPC/data access patterns and be audited without storing secrets. Frontend visibility must be paired with server-side authorization for sensitive categories such as Security, Password Management, Login & Session, Offline/Synchronization configuration, Privacy, and Developer controls.

## Detailed page and UI-shell findings

The flat page registry contains the following functional families: Overview (Dashboard, Notifications), Customer Management (Customers, Customer Portfolio, Customer Risk, Household Relationships, Document Vault), Savings & Cash (Savings Accounts, Savings Products, Fixed/Term Deposits, Cash Holding Limits, Withdrawal Risk Alerts), Loan Management (Loans, Loan Top-Up, Loan Repayment), Operations & Closing (EOD Closing, Cash Position Monitoring, Till Closing, Vault Settlement, System EOD Processing), Administration & Security (Branches, Staff, three credential pages, Policy Settings, Data Sync), Reports & Compliance (Reports, Daily Reports, Audit Trail), and Developer-only SMS Configuration.

The existing `settings` route is labeled **Policy Settings** and is registered to `renderSettings`, but the source audit did not find a concrete `renderSettings` implementation in the inspected renderer definitions. This indicates a missing or incomplete Settings foundation rather than a fully centralized module. The new implementation should therefore provide the missing renderer while preserving the existing Policy Settings intent and integrating the already-working security, credential, sync, notification, developer, and informational surfaces.

The app shell is a dark left sidebar with brand name, module search, role summary, grouped navigation, a Developer submenu, session identity, sync status, Developer Information, and logout. The main content area has a top bar with hamburger, page title, spacer, date, and dynamic page containers. Existing primitives include cards, grids, section headers, badges, notes, tables, modals, buttons, toast notifications, CSS custom properties, and responsive mobile enhancements.

The settings foundation should add one centralized Settings page under the existing `settings` route, with a mobile-first category rail/list and a content panel. Existing specialized pages can remain available through navigation while the new Settings page provides organized entry points and safe summaries. Sensitive controls should be conditionally rendered by frontend permission and additionally protected at the server RPC/data layer.
