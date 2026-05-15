<#
.SYNOPSIS
    Managed Identity Authentication — Module 3
    Portfolio Project: NHI Governance with Microsoft Entra ID

.DESCRIPTION
    Demonstrates Non-Human Identity authentication using Azure Managed Identities.
    Unlike App Registrations (Modules 1 & 2), Managed Identities require zero
    credential management — no secrets, no certificates, no rotation.

    This script contains two implementations:
    1. IMDS-based auth  — runs INSIDE an Azure resource (VM, Function, Container)
    2. Graph-based audit — inventories Managed Identities in the tenant

.ARCHITECTURE NOTE
    Managed Identity authentication requires an Azure-hosted resource.
    The IMDS endpoint (169.254.169.254) is only accessible from within
    Azure infrastructure. This is by design — a security boundary that
    prevents external credential theft.

.GDPR COMPLIANCE
    Art. 32  — No credentials to intercept, leak, or rotate
    Art. 25  — Privacy by Design: identity lifecycle managed by platform
    Art. 5(f) — Confidentiality: credentials never exist as retrievable values

.ENVIRONMENT NOTE
    Full IMDS authentication requires an Azure subscription with an active
    compute resource. The audit function works in any Entra ID P2 tenant.
#>

# ============================================================
# IMPLEMENTATION A: IMDS Authentication (Azure-hosted resources)
# ============================================================
# This function would run INSIDE a VM, Function App, or Container
# with Managed Identity enabled. No credentials required in code.

function Get-ManagedIdentityToken {
    param(
        [string]$Resource = "https://graph.microsoft.com/",

        # For User-assigned MI: specify the Client ID
        # For System-assigned MI: leave empty
        [string]$ClientId = ""
    )

    # Instance Metadata Service endpoint
    # Only accessible from within Azure infrastructure
    # External access is blocked at the network level — security by design
    $IMDSEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

    $QueryParams = "api-version=2018-02-01&resource=$Resource"
    if ($ClientId) {
        # User-assigned MI: specify which identity to use
        # A resource can have multiple User-assigned MIs
        $QueryParams += "&client_id=$ClientId"
    }

    try {
        $TokenResponse = Invoke-RestMethod `
            -Uri     "$IMDSEndpoint?$QueryParams" `
            -Headers @{ Metadata = "true" } `
            -Method  GET `
            -ErrorAction Stop

        Write-Host "Token obtained via Managed Identity" -ForegroundColor Green
        Write-Host "  Resource:   $Resource"
        Write-Host "  Token type: $($TokenResponse.token_type)"
        Write-Host "  Expires:    $([DateTimeOffset]::FromUnixTimeSeconds($TokenResponse.expires_on).LocalDateTime)"
        Write-Host "  Method:     Managed Identity — zero credentials in code" -ForegroundColor Cyan

        return $TokenResponse.access_token

    } catch {
        # Expected error outside Azure infrastructure
        if ($_.Exception.Message -match "Unable to connect" -or
            $_.Exception.Message -match "actively refused") {
            Write-Warning "IMDS endpoint not reachable — script is running outside Azure infrastructure."
            Write-Warning "Deploy to an Azure VM or Function App with Managed Identity enabled to use this function."
        } else {
            Write-Error "Unexpected error: $($_.Exception.Message)"
        }
        return $null
    }
}

# ============================================================
# IMPLEMENTATION B: Tenant Audit (works in any Entra ID tenant)
# ============================================================
# Inventories all Managed Identities in the tenant.
# Critical for NHI governance — most orgs have no visibility
# into which Managed Identities exist and what they can access.

function Get-ManagedIdentityInventory {

    Write-Host "=== Managed Identity Inventory ===" -ForegroundColor Cyan
    Write-Host "Scanning tenant for Managed Identities..." -ForegroundColor Cyan

    # Retrieve all Service Principals of type ManagedIdentity
    $ManagedIdentities = Get-MgServicePrincipal -All |
        Where-Object { $_.ServicePrincipalType -eq "ManagedIdentity" }

    if (-not $ManagedIdentities) {
        Write-Host "No Managed Identities found in tenant." -ForegroundColor Yellow
        Write-Host "Note: Managed Identities require Azure resources to exist." -ForegroundColor Yellow
        return
    }

    Write-Host "Found $($ManagedIdentities.Count) Managed Identity/ies:" -ForegroundColor Green

    foreach ($MI in $ManagedIdentities) {

        Write-Host "`n--- $($MI.DisplayName) ---" -ForegroundColor Cyan
        Write-Host "  Object ID:  $($MI.Id)"
        Write-Host "  App ID:     $($MI.AppId)"
        Write-Host "  Type:       $($MI.ServicePrincipalType)"

        # Check assigned permissions
        $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MI.Id `
                    -ErrorAction SilentlyContinue

        if ($AppRoles) {
            Write-Host "  Permissions assigned:" -ForegroundColor Yellow
            foreach ($Role in $AppRoles) {
                Write-Host "    → ResourceId: $($Role.ResourceId) | RoleId: $($Role.AppRoleId)"
            }
        } else {
            Write-Host "  Permissions: None assigned" -ForegroundColor Green
        }
    }
}

# ============================================================
# MAIN EXECUTION
# ============================================================

Write-Host "=== Managed Identity Module ===" -ForegroundColor Cyan
Write-Host "Comparing authentication methods:" -ForegroundColor Cyan
Write-Host ""
Write-Host "Module 1 — Client Secret:    credential transmitted on every request"
Write-Host "Module 2 — Certificate:      signature transmitted, key stays local"
Write-Host "Module 3 — Managed Identity: NO credential exists — platform manages all"
Write-Host ""

# Attempt IMDS authentication (will gracefully fail outside Azure)
Write-Host "--- Testing IMDS Authentication ---" -ForegroundColor Cyan
$Token = Get-ManagedIdentityToken -Resource "https://graph.microsoft.com/"

if ($Token) {
    # If running inside Azure with MI enabled
    $Headers = @{ Authorization = "Bearer $Token" }
    $Context = Invoke-RestMethod `
        -Uri     "https://graph.microsoft.com/v1.0/organization" `
        -Headers $Headers
    Write-Host "Graph API call successful via Managed Identity" -ForegroundColor Green
} else {
    Write-Host "IMDS not available — running outside Azure infrastructure" -ForegroundColor Yellow
    Write-Host "This is expected behavior in a local development environment" -ForegroundColor Yellow
}

Write-Host ""

# Audit tenant for existing Managed Identities
Write-Host "--- Auditing Tenant Managed Identities ---" -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.Read.All" -TenantId "25de3db3-c870-4699-be4e-bc4322e9d249"
Get-ManagedIdentityInventory
