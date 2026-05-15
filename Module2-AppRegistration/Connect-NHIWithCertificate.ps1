<#
.SYNOPSIS
    Certificate-based NHI Authentication — Module 2
    Portfolio Project: NHI Governance with Microsoft Entra ID

.DESCRIPTION
    Demonstrates secure Non-Human Identity authentication using
    certificate-based client assertions instead of Client Secrets.
    
    The private key never leaves the local certificate store.
    Only a cryptographic signature is transmitted to Entra ID.

.SECURITY NOTE
    This script requires the certificate private key to be present
    in the current user's certificate store (Cert:\CurrentUser\My).
    Never export or store the private key outside the certificate store.

.GDPR COMPLIANCE
    Art. 32 — Technical measures: certificate auth eliminates
              the risk of credential interception or accidental exposure
    Art. 5(1)(f) — Confidentiality: private key never transmitted

.PARAMETER Thumbprint
    SHA1 thumbprint of the certificate in Cert:\CurrentUser\My

.PARAMETER TenantId
    Entra ID Tenant ID

.PARAMETER ClientId
    Application (client) ID of the App Registration

.EXAMPLE
    .\Connect-NHIWithCertificate.ps1 `
        -Thumbprint "YOUR-CERT-THUMBPRINT" `
        -TenantId "YOUR-TENANT-ID" `
        -ClientId "YOUR-CLIENT-ID"
#>

param(
    [Parameter(Mandatory)]
    [string]$Thumbprint,

    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId
)

# ============================================================
# REGION 1: CERTIFICATE RETRIEVAL
# ============================================================

function Get-NHICertificate {
    param([string]$Thumbprint)

    $Cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue

    if (-not $Cert) {
        Write-Error "Certificate with thumbprint '$Thumbprint' not found in Cert:\CurrentUser\My"
        exit 1
    }

    if (-not $Cert.HasPrivateKey) {
        Write-Error "Certificate found but has no private key. Cannot sign assertions."
        exit 1
    }

    if ($Cert.NotAfter -lt (Get-Date)) {
        Write-Warning "Certificate has expired on $($Cert.NotAfter). Authentication may fail."
    }

    $DaysUntilExpiry = ($Cert.NotAfter - (Get-Date)).Days
    if ($DaysUntilExpiry -le 30) {
        Write-Warning "Certificate expires in $DaysUntilExpiry days. Plan rotation now."
    }

    Write-Host "Certificate loaded:" -ForegroundColor Cyan
    Write-Host "  Subject:    $($Cert.Subject)"
    Write-Host "  Thumbprint: $($Cert.Thumbprint)"
    Write-Host "  Expires:    $($Cert.NotAfter) ($DaysUntilExpiry days remaining)"

    return $Cert
}

# ============================================================
# REGION 2: JWT BUILDER
# ============================================================
# OAuth2 certificate authentication requires a signed JWT assertion.
# This function builds and signs the JWT using the certificate's
# private key — which never leaves the certificate store.

function New-ClientAssertion {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$TenantId,
        [string]$ClientId
    )

    # Helper: encode string to Base64URL (URL-safe Base64 without padding)
    function ConvertTo-Base64URL {
        param([string]$Text)
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return [System.Convert]::ToBase64String($Bytes) `
            -replace '\+','-' -replace '/','_' -replace '='
    }

    # JWT Header
    # x5t: Base64URL-encoded SHA1 thumbprint
    # Entra ID uses this to look up the correct public key
    $ThumbprintBytes = [System.Convert]::FromHexString($Certificate.Thumbprint)
    $x5t = [System.Convert]::ToBase64String($ThumbprintBytes) `
           -replace '\+','-' -replace '/','_' -replace '='

    $Header = @{
        alg = "RS256"  # RSA with SHA-256
        typ = "JWT"
        x5t = $x5t
    } | ConvertTo-Json -Compress

    # JWT Payload — standard OAuth2 client assertion claims
    $Now = [System.DateTimeOffset]::UtcNow
    $Payload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [System.Guid]::NewGuid().ToString()  # unique ID prevents replay attacks
        nbf = $Now.ToUnixTimeSeconds()
        exp = $Now.AddMinutes(5).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $B64Header  = ConvertTo-Base64URL -Text $Header
    $B64Payload = ConvertTo-Base64URL -Text $Payload

    # Sign with private key — key never leaves certificate store
    $DataToSign = "$B64Header.$B64Payload"
    $RSA        = $Certificate.PrivateKey -as [System.Security.Cryptography.RSA]
    $Signature  = $RSA.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($DataToSign),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $B64Signature = [System.Convert]::ToBase64String($Signature) `
                    -replace '\+','-' -replace '/','_' -replace '='

    return "$B64Header.$B64Payload.$B64Signature"
}

# ============================================================
# REGION 3: TOKEN REQUEST
# ============================================================

function Get-NHIAccessToken {
    param(
        [string]$ClientAssertion,
        [string]$TenantId,
        [string]$ClientId
    )

    $TokenBody = @{
        grant_type            = "client_credentials"
        client_id             = $ClientId
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $ClientAssertion
        scope                 = "https://graph.microsoft.com/.default"
    }

    try {
        $Response = Invoke-RestMethod `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -Method POST `
            -Body $TokenBody `
            -ErrorAction Stop

        Write-Host "Token obtained successfully" -ForegroundColor Green
        Write-Host "  Type:       $($Response.token_type)"
        Write-Host "  Expires in: $($Response.expires_in) seconds"
        Write-Host "  Method:     Certificate — no secret transmitted" -ForegroundColor Green

        return $Response.access_token

    } catch {
        Write-Error "Token request failed: $($_.Exception.Message)"
        exit 1
    }
}

# ============================================================
# REGION 4: MAIN EXECUTION
# ============================================================

Write-Host "=== NHI Certificate Authentication ===" -ForegroundColor Cyan
Write-Host "App: $ClientId"
Write-Host "Tenant: $TenantId"
Write-Host ""

# Step 1: Load certificate
$Certificate = Get-NHICertificate -Thumbprint $Thumbprint

# Step 2: Build signed JWT assertion
Write-Host "`nBuilding client assertion JWT..." -ForegroundColor Cyan
$ClientAssertion = New-ClientAssertion `
    -Certificate $Certificate `
    -TenantId    $TenantId `
    -ClientId    $ClientId

# Step 3: Request access token
Write-Host "Requesting access token from Entra ID..." -ForegroundColor Cyan
$AccessToken = Get-NHIAccessToken `
    -ClientAssertion $ClientAssertion `
    -TenantId        $TenantId `
    -ClientId        $ClientId

# Step 4: Verify with a Graph API call
Write-Host "`nVerifying access via Graph API..." -ForegroundColor Cyan
$Headers = @{ Authorization = "Bearer $AccessToken" }

$Users = Invoke-RestMethod `
    -Uri     "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers $Headers

Write-Host "`nUsers retrieved via certificate auth:" -ForegroundColor Green
$Users.value | Select-Object displayName, userPrincipalName |
    Format-Table -AutoSize

Write-Host "=== Authentication complete ===" -ForegroundColor Cyan
Write-Host "Private key remained in local certificate store throughout." -ForegroundColor Green