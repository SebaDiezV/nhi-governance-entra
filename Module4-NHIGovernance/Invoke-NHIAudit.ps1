#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Users

<#
.SYNOPSIS
    NHI Governance Audit Script — Module 4
    Portfolio Project: NHI Governance with Microsoft Entra ID

.DESCRIPTION
    Automated audit of all Non-Human Identities in the tenant.
    Produces a governance report covering:
    - Credential health (secrets vs certificates, expiry status)
    - Permission risk assessment (high-risk API permissions)
    - Ownership gaps (App Registrations without assigned owners)
    - Inactive NHI detection (zombie applications)
    - GDPR data processing mapping (Art. 30 RoPA support)

.GDPR COMPLIANCE
    Art. 30  — Records of Processing: inventory of NHI accessing personal data
    Art. 32  — Technical measures: identifies credential and permission risks
    Art. 25  — Privacy by Design: flags NHI violating least privilege
    Art. 5(1)(f) — Confidentiality: detects expired/expiring credentials

.OUTPUTS
    - Console report with color-coded risk levels
    - CSV export for audit evidence and RoPA documentation

.NOTES
    Requires: Microsoft Graph PowerShell SDK
    Permissions: Application.Read.All, Directory.Read.All
#>

param(
    [string]$TenantId    = "YOUR-TENANT-ID-HERE",
    # Days threshold for secret expiry warnings
    [int]$ExpiryWarningDays = 30,
    # Days threshold for inactive NHI detection
    [int]$InactiveDays      = 90,
    # Export results to CSV
    [switch]$ExportCsv
)

# ============================================================
# REGION 1: INITIALIZATION
# ============================================================

$script:LogTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir       = Join-Path $PSScriptRoot "logs"
$script:LogFile      = Join-Path $script:LogDir "nhi-audit_$($script:LogTimestamp).log"
$script:ReportPath   = Join-Path $PSScriptRoot "nhi-audit-report_$($script:LogTimestamp).csv"

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

# Risk classification for Graph API permissions
# These permissions grant access to personal data — GDPR Art. 30 relevance
# HIGH: can read/write sensitive data across entire tenant
# MEDIUM: can read data but not modify
# LOW: limited scope or non-personal data
$PermissionRiskMap = @{
    # Critical — full tenant data access
    "Directory.ReadWrite.All"     = "CRITICAL"
    "Directory.Read.All"          = "HIGH"
    "Mail.ReadWrite"              = "CRITICAL"
    "Mail.Read"                   = "HIGH"
    "User.ReadWrite.All"          = "HIGH"
    "User.Read.All"               = "HIGH"
    "Group.ReadWrite.All"         = "HIGH"
    "Group.Read.All"              = "MEDIUM"
    "Files.ReadWrite.All"         = "HIGH"
    "Files.Read.All"              = "MEDIUM"
    "MailboxSettings.ReadWrite"   = "MEDIUM"
    "Calendars.ReadWrite"         = "MEDIUM"
    "Contacts.ReadWrite"          = "MEDIUM"
    "People.Read.All"             = "MEDIUM"
    "AuditLog.Read.All"           = "MEDIUM"
    "Policy.ReadWrite.All"        = "HIGH"
    "RoleManagement.ReadWrite.All"= "CRITICAL"
    "Application.ReadWrite.All"   = "CRITICAL"
    # GDPR-specific: direct personal data access
    "User.Read"                   = "LOW"
    "profile"                     = "LOW"
    "openid"                      = "LOW"
}

# Permissions that indicate GDPR data processing
# Any NHI with these permissions is a data processor under GDPR Art. 30
$GDPRDataPermissions = @(
    "User.Read.All", "User.ReadWrite.All",
    "Mail.Read", "Mail.ReadWrite",
    "Contacts.ReadWrite", "People.Read.All",
    "Files.Read.All", "Files.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "Calendars.ReadWrite", "MailboxSettings.ReadWrite"
)

# ============================================================
# REGION 2: LOGGING & DISPLAY
# ============================================================

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR","CRITICAL")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $LogEntry  = "[$Timestamp] [$Level] $Message"
    $Color = switch ($Level) {
        "SUCCESS"  { "Green"   }
        "WARNING"  { "Yellow"  }
        "ERROR"    { "Red"     }
        "CRITICAL" { "Magenta" }
        default    { "Cyan"    }
    }
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $script:LogFile -Value $LogEntry -Encoding UTF8
}

function Write-RiskAlert {
    param([string]$AppName, [string]$Risk, [string]$Detail)
    $Icon = switch ($Risk) {
        "CRITICAL" { "🔴" } "HIGH" { "🟠" }
        "MEDIUM"   { "🟡" } default { "🟢" }
    }
    Write-AuditLog "$Icon [$Risk] $AppName — $Detail" -Level $(
        if ($Risk -eq "CRITICAL") { "CRITICAL" }
        elseif ($Risk -eq "HIGH") { "ERROR" }
        elseif ($Risk -eq "MEDIUM") { "WARNING" }
        else { "INFO" }
    )
}

# ============================================================
# REGION 3: DATA COLLECTION
# ============================================================

function Get-AllAppRegistrations {
    # Retrieve all App Registrations with their key properties
    # We expand owners to identify orphaned apps (no owner = governance gap)
    Write-AuditLog "Retrieving all App Registrations from tenant..."

    $Apps = Get-MgApplication -All `
        -Property "id,appId,displayName,createdDateTime,
                   passwordCredentials,keyCredentials,
                   requiredResourceAccess,signInAudience" |
        Select-Object *

    Write-AuditLog "Found $($Apps.Count) App Registration(s)" -Level "SUCCESS"
    return $Apps
}

function Get-AppOwners {
    param([string]$AppObjectId)
    try {
        $Owners = Get-MgApplicationOwner -ApplicationId $AppObjectId -ErrorAction Stop
        return $Owners
    } catch {
        return @()
    }
}

function Get-ServicePrincipalPermissions {
    param([string]$AppId)
    # Get the Service Principal for this App Registration
    # SP holds the actual granted permissions (after admin consent)
    try {
        $SP = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction Stop
        if (-not $SP) { return @() }

        $Assignments = Get-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue
        return $Assignments
    } catch {
        return @()
    }
}

function Get-PermissionDisplayName {
    param([string]$ResourceId, [string]$AppRoleId)
    # Resolve permission GUIDs to human-readable names
    # Graph API returns GUIDs — we need names for the audit report
    try {
        $ResourceSP = Get-MgServicePrincipal -ServicePrincipalId $ResourceId `
                      -ErrorAction SilentlyContinue
        if ($ResourceSP) {
            $Role = $ResourceSP.AppRoles | Where-Object { $_.Id -eq $AppRoleId }
            if ($Role) { return $Role.Value }
        }
    } catch {}
    return $AppRoleId  # fallback to GUID if resolution fails
}

# ============================================================
# REGION 4: RISK ASSESSMENT FUNCTIONS
# ============================================================

function Get-CredentialHealth {
    param($App)
    # Analyze credential posture of an App Registration
    # Returns a structured object with health indicators

    $Now    = Get-Date
    $Health = @{
        HasSecret      = $false
        HasCertificate = $false
        ExpiredCreds   = @()
        ExpiringCreds  = @()
        CredType       = "None"
        CredRisk       = "LOW"
    }

    # Check Client Secrets (passwordCredentials)
    foreach ($Secret in $App.PasswordCredentials) {
        $Health.HasSecret = $true
        $DaysUntilExpiry  = ($Secret.EndDateTime - $Now).Days

        if ($DaysUntilExpiry -lt 0) {
            # Already expired — but still listed means it wasn't cleaned up
            $Health.ExpiredCreds += "Secret '$($Secret.DisplayName)' expired $([Math]::Abs($DaysUntilExpiry)) days ago"
        } elseif ($DaysUntilExpiry -le $ExpiryWarningDays) {
            $Health.ExpiringCreds += "Secret '$($Secret.DisplayName)' expires in $DaysUntilExpiry days"
        }
    }

    # Check Certificates (keyCredentials)
    foreach ($Cert in $App.KeyCredentials) {
        $Health.HasCertificate = $true
        $DaysUntilExpiry       = ($Cert.EndDateTime - $Now).Days

        if ($DaysUntilExpiry -lt 0) {
            $Health.ExpiredCreds += "Certificate '$($Cert.DisplayName)' expired $([Math]::Abs($DaysUntilExpiry)) days ago"
        } elseif ($DaysUntilExpiry -le $ExpiryWarningDays) {
            $Health.ExpiringCreds += "Certificate '$($Cert.DisplayName)' expires in $DaysUntilExpiry days"
        }
    }

    # Determine credential type and risk
    # Having both secret AND certificate is unnecessary surface area
    if ($Health.HasCertificate -and $Health.HasSecret) {
        $Health.CredType = "Both (Certificate + Secret)"
        $Health.CredRisk = "MEDIUM"  # secret is redundant — should be removed
    } elseif ($Health.HasCertificate) {
        $Health.CredType = "Certificate"
        $Health.CredRisk = "LOW"
    } elseif ($Health.HasSecret) {
        $Health.CredType = "Secret Only"
        $Health.CredRisk = "HIGH"  # secrets are riskier than certificates
    } else {
        $Health.CredType = "No Credentials"
        $Health.CredRisk = "INFO"  # may be valid (MI or federated)
    }

    return $Health
}

function Get-PermissionRisk {
    param([array]$PermissionNames)
    # Returns the highest risk level across all permissions
    $HighestRisk = "LOW"
    $RiskyPerms  = @()

    foreach ($Perm in $PermissionNames) {
        if ($PermissionRiskMap.ContainsKey($Perm)) {
            $Risk = $PermissionRiskMap[$Perm]
            $RiskyPerms += "$Perm ($Risk)"

            # Track highest risk level
            if ($Risk -eq "CRITICAL") { $HighestRisk = "CRITICAL" }
            elseif ($Risk -eq "HIGH" -and $HighestRisk -ne "CRITICAL") { $HighestRisk = "HIGH" }
            elseif ($Risk -eq "MEDIUM" -and $HighestRisk -notin @("CRITICAL","HIGH")) { $HighestRisk = "MEDIUM" }
        }
    }
    return @{ HighestRisk = $HighestRisk; RiskyPermissions = $RiskyPerms }
}

function Test-GDPRDataProcessor {
    param([array]$PermissionNames)
    # Determines if this NHI processes personal data under GDPR
    # Returns true if any permission grants access to personal data
    foreach ($Perm in $PermissionNames) {
        if ($GDPRDataPermissions -contains $Perm) { return $true }
    }
    return $false
}

# ============================================================
# REGION 5: MAIN AUDIT FUNCTION
# ============================================================

function Invoke-NHIGovernanceAudit {

    $AuditResults = @()
    $Stats = @{
        Total           = 0
        SecretOnly      = 0
        CertOnly        = 0
        BothCreds       = 0
        NoCreds         = 0
        ExpiredCreds    = 0
        ExpiringCreds   = 0
        NoOwner         = 0
        CriticalRisk    = 0
        HighRisk        = 0
        GDPRProcessors  = 0
    }

    $Apps = Get-AllAppRegistrations
    $Stats.Total = $Apps.Count

    # Get Microsoft Graph Service Principal once — reused for permission resolution
    $GraphSP = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'" `
               -ErrorAction SilentlyContinue

    Write-AuditLog "--- Starting NHI Risk Assessment ---" -Level "INFO"

    foreach ($App in $Apps) {

        Write-AuditLog "Analyzing: $($App.DisplayName)"

        # --- Credential Health ---
        $CredHealth = Get-CredentialHealth -App $App

        # --- Ownership ---
        $Owners    = Get-AppOwners -AppObjectId $App.Id
        $HasOwner  = $Owners.Count -gt 0
        $OwnerList = if ($HasOwner) {
            ($Owners | ForEach-Object {
                (Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue)?.UserPrincipalName
            } | Where-Object { $_ }) -join "; "
        } else { "NO OWNER" }

        # --- Permissions ---
        $GrantedPermissions = Get-ServicePrincipalPermissions -AppId $App.AppId
        $PermissionNames    = @()

        foreach ($Assignment in $GrantedPermissions) {
            if ($GraphSP -and $Assignment.ResourceId -eq $GraphSP.Id) {
                $PermName = Get-PermissionDisplayName `
                    -ResourceId $Assignment.ResourceId `
                    -AppRoleId  $Assignment.AppRoleId
                $PermissionNames += $PermName
            }
        }

        $PermRisk      = Get-PermissionRisk -PermissionNames $PermissionNames
        $IsGDPRProcessor = Test-GDPRDataProcessor -PermissionNames $PermissionNames

        # --- Age / Zombie Detection ---
        $AppAge    = (Get-Date) - $App.CreatedDateTime
        $IsOld     = $AppAge.Days -gt $InactiveDays

        # --- Update Statistics ---
        switch ($CredHealth.CredType) {
            "Secret Only"              { $Stats.SecretOnly++ }
            "Certificate"              { $Stats.CertOnly++ }
            "Both (Certificate + Secret)" { $Stats.BothCreds++ }
            "No Credentials"           { $Stats.NoCreds++ }
        }
        if ($CredHealth.ExpiredCreds.Count -gt 0)  { $Stats.ExpiredCreds++ }
        if ($CredHealth.ExpiringCreds.Count -gt 0) { $Stats.ExpiringCreds++ }
        if (-not $HasOwner)                         { $Stats.NoOwner++ }
        if ($PermRisk.HighestRisk -eq "CRITICAL")  { $Stats.CriticalRisk++ }
        if ($PermRisk.HighestRisk -eq "HIGH")       { $Stats.HighRisk++ }
        if ($IsGDPRProcessor)                       { $Stats.GDPRProcessors++ }

        # --- Risk Alerts ---
        if (-not $HasOwner) {
            Write-RiskAlert -AppName $App.DisplayName -Risk "HIGH" `
                -Detail "No owner assigned — orphaned NHI"
        }
        if ($CredHealth.CredRisk -in @("HIGH","CRITICAL")) {
            Write-RiskAlert -AppName $App.DisplayName -Risk $CredHealth.CredRisk `
                -Detail "Credential type: $($CredHealth.CredType)"
        }
        foreach ($Expired in $CredHealth.ExpiredCreds) {
            Write-RiskAlert -AppName $App.DisplayName -Risk "CRITICAL" `
                -Detail $Expired
        }
        foreach ($Expiring in $CredHealth.ExpiringCreds) {
            Write-RiskAlert -AppName $App.DisplayName -Risk "HIGH" `
                -Detail $Expiring
        }
        if ($PermRisk.HighestRisk -in @("CRITICAL","HIGH")) {
            Write-RiskAlert -AppName $App.DisplayName -Risk $PermRisk.HighestRisk `
                -Detail "High-risk permissions: $($PermRisk.RiskyPermissions -join ', ')"
        }
        if ($IsGDPRProcessor) {
            Write-AuditLog "📋 [GDPR] $($App.DisplayName) — processes personal data (Art. 30 RoPA)" -Level "WARNING"
        }

        # --- Build Result Object ---
        $AuditResults += [PSCustomObject]@{
            DisplayName          = $App.DisplayName
            AppId                = $App.AppId
            ObjectId             = $App.Id
            CreatedDate          = $App.CreatedDateTime.ToString("yyyy-MM-dd")
            AgeInDays            = [int]$AppAge.Days
            CredentialType       = $CredHealth.CredType
            CredentialRisk       = $CredHealth.CredRisk
            ExpiredCredentials   = $CredHealth.ExpiredCreds -join " | "
            ExpiringCredentials  = $CredHealth.ExpiringCreds -join " | "
            HasOwner             = $HasOwner
            Owners               = $OwnerList
            PermissionRisk       = $PermRisk.HighestRisk
            HighRiskPermissions  = $PermRisk.RiskyPermissions -join " | "
            IsGDPRDataProcessor  = $IsGDPRProcessor
            GDPRPermissions      = ($PermissionNames | Where-Object { $GDPRDataPermissions -contains $_ }) -join " | "
            AllPermissions       = $PermissionNames -join " | "
        }

        Start-Sleep -Milliseconds 300  # respect Graph API rate limits
    }

    return @{ Results = $AuditResults; Stats = $Stats }
}

# ============================================================
# REGION 6: REPORT GENERATION
# ============================================================

function Write-AuditSummary {
    param($Stats, $Results)

    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "  NHI GOVERNANCE AUDIT REPORT" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan

    Write-Host "`n📊 INVENTORY SUMMARY" -ForegroundColor White
    Write-Host "  Total NHI (App Registrations): $($Stats.Total)"
    Write-Host "  Secret only (HIGH risk):        $($Stats.SecretOnly)" -ForegroundColor $(if ($Stats.SecretOnly -gt 0) { "Red" } else { "Green" })
    Write-Host "  Certificate only (LOW risk):    $($Stats.CertOnly)" -ForegroundColor Green
    Write-Host "  Both credentials (MEDIUM risk): $($Stats.BothCreds)" -ForegroundColor Yellow
    Write-Host "  No credentials:                 $($Stats.NoCreds)"

    Write-Host "`n🔑 CREDENTIAL HEALTH" -ForegroundColor White
    Write-Host "  Expired credentials:            $($Stats.ExpiredCreds)" -ForegroundColor $(if ($Stats.ExpiredCreds -gt 0) { "Red" } else { "Green" })
    Write-Host "  Expiring within $ExpiryWarningDays days:         $($Stats.ExpiringCreds)" -ForegroundColor $(if ($Stats.ExpiringCreds -gt 0) { "Yellow" } else { "Green" })

    Write-Host "`n👤 OWNERSHIP" -ForegroundColor White
    Write-Host "  Orphaned NHI (no owner):        $($Stats.NoOwner)" -ForegroundColor $(if ($Stats.NoOwner -gt 0) { "Red" } else { "Green" })

    Write-Host "`n⚠️  PERMISSION RISK" -ForegroundColor White
    Write-Host "  Critical risk permissions:      $($Stats.CriticalRisk)" -ForegroundColor $(if ($Stats.CriticalRisk -gt 0) { "Magenta" } else { "Green" })
    Write-Host "  High risk permissions:          $($Stats.HighRisk)" -ForegroundColor $(if ($Stats.HighRisk -gt 0) { "Red" } else { "Green" })

    Write-Host "`n📋 GDPR COMPLIANCE (Art. 30)" -ForegroundColor White
    Write-Host "  NHI processing personal data:   $($Stats.GDPRProcessors)" -ForegroundColor $(if ($Stats.GDPRProcessors -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  These NHI must be documented in your Records of Processing Activities (RoPA)"

    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan

    # Log summary
    Write-AuditLog "=== AUDIT SUMMARY ===" -Level "INFO"
    Write-AuditLog "Total NHI: $($Stats.Total) | Secret-only: $($Stats.SecretOnly) | Cert-only: $($Stats.CertOnly)" -Level "INFO"
    Write-AuditLog "Expired creds: $($Stats.ExpiredCreds) | Expiring: $($Stats.ExpiringCreds)" -Level $(if ($Stats.ExpiredCreds -gt 0) { "ERROR" } else { "INFO" })
    Write-AuditLog "No owner: $($Stats.NoOwner) | Critical risk: $($Stats.CriticalRisk) | GDPR processors: $($Stats.GDPRProcessors)" -Level "INFO"
}

# ============================================================
# REGION 7: MAIN EXECUTION
# ============================================================

Write-AuditLog "=== NHI GOVERNANCE AUDIT STARTED ===" -Level "INFO"
Write-AuditLog "Tenant: $TenantId" -Level "INFO"
Write-AuditLog "Expiry warning threshold: $ExpiryWarningDays days" -Level "INFO"
Write-AuditLog "GDPR Art. 30 mapping: ENABLED" -Level "INFO"

$RequiredScopes = @(
    "Application.Read.All",    # Read all App Registrations and Service Principals
    "Directory.Read.All"       # Read owners and directory objects
)

try {
    Connect-MgGraph -TenantId $TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Authenticated as: $((Get-MgContext).Account)" -Level "SUCCESS"
} catch {
    Write-AuditLog "FATAL: Cannot connect to Graph: $_" -Level "ERROR"
    exit 1
}

# Run audit
$AuditData = Invoke-NHIGovernanceAudit

# Display summary report
Write-AuditSummary -Stats $AuditData.Stats -Results $AuditData.Results

# Export to CSV if requested
if ($ExportCsv) {
    $AuditData.Results | Export-Csv -Path $script:ReportPath -NoTypeInformation -Encoding UTF8
    Write-AuditLog "Report exported to: $script:ReportPath" -Level "SUCCESS"
    Write-Host "`n📄 CSV report saved to: $script:ReportPath" -ForegroundColor Green
}

Write-AuditLog "=== AUDIT COMPLETED ===" -Level "INFO"
Write-AuditLog "Full log: $($script:LogFile)" -Level "INFO"

Disconnect-MgGraph
Write-AuditLog "Graph session disconnected." -Level "INFO"