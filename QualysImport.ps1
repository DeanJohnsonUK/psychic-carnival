#Requires -Version 5.1

<#
.SYNOPSIS
    Qualys to NinjaOne Vulnerability Ingestor.

.DESCRIPTION
    Synchronizes Qualys vulnerability data to NinjaOne. Uses Qualys API v4.0 for
    legacy XML endpoints and QPS REST 2.0 for the Asset Management search endpoint.
    Compatible with PowerShell 5.1 and PowerShell 7.

    NINJAONE CUSTOM FIELD VS VARIABLE MAPPING:
    The 'Field Name' in your NinjaOne Dashboard must match the key names below exactly.
    Any of the overridable fields can also be set as environment variables by the same
    name, which is the fallback when not running inside a NinjaOne agent context.

    [MANDATORY AUTHENTICATION - set these as Secure Custom Fields in NinjaOne]
    - QualysImportClientID  : OAuth2 Client ID for the NinjaOne API.
    - QualysImportSecret    : OAuth2 Client Secret for the NinjaOne API.
    - QualysAPIUser         : Qualys service account username.
    - QualysAPIPass         : Qualys service account password.

    [RUNTIME CONFIGURATION - these override the script parameter defaults if set]
    - ScanGroupID           : (Text/Int) Scan group name (e.g. "Global Qualys Import") or numeric ID.
                               Resolved automatically via API. Default: "Global Qualys Import"
    - TestMode              : (Checkbox) Skip final upload. Default: True
    - EnableDebugLimit      : (Checkbox) Cap host count for testing. Default: False
    - DebugLimit            : (Integer)  Host cap when EnableDebugLimit is on. Default: 200
    - StorageMode           : (Dropdown) "Memory" or "Disk". Default: "Memory"
      Memory: builds the upload payload in RAM as a byte stream, no temp file written.
      Disk:   writes a temp CSV first, then streams it for upload.
      In TestMode, the main CSV is always written to disk regardless of StorageMode.
    - OutputPath            : (Text) Directory path for output CSV files. Default: "C:\WINDOWS\TEMP"

    [OUTPUT FILES - written to the configured OutputPath directory]
    - qualys_sync_yyyyMMdd-HHmm.csv       : Main export uploaded to NinjaOne. One row per
                                             vulnerability per MAC address. Columns: Device,
                                             MAC, CVE, Severity, Title. In TestMode this file
                                             is written to disk for review but not uploaded.
    - qualys_sync_no_mac_yyyyMMdd-HHmm.csv : Hosts with zero valid MAC addresses. These are
                                             excluded from the main export as they cannot be
                                             reliably matched in NinjaOne. Includes an
                                             InvalidMacObserved column distinguishing hosts
                                             that sent malformed MAC data from those with no
                                             MAC data recorded at all. Always written to disk
                                             when populated, regardless of TestMode.
    - qualys_sync_invalid_mac_yyyyMMdd-HHmm.csv : Data quality report. Lists every host that had
                                             any format-invalid MAC values, even if that host
                                             also had valid MACs and made it into the main
                                             export. Columns: HostID, InvalidMACs, ValidMACs,
                                             RoutedToMainCSV. Never uploaded to NinjaOne.

    [WRITTEN BY SCRIPT - create this field so the script can record sync state]
    - LastQualysSync        : (DateTime/Text) Written on successful ingestion only (not in TestMode).
                               Records the timestamp of the last completed upload in
                               "yyyy-MM-dd HH:mm" format. Create as a Device custom field
                               (not Organisation) with Script access set to Write or Read/Write
                               on the role assigned to the device running this script. If the
                               field does not exist or script access is not granted, the update
                               fails non-fatally with a warning and the rest of the script is
                               unaffected.

    DATA PIPELINE FLOW DIAGRAM:

    +-------------------------------------------------------+
    |          Step 0: Context, Credentials & Auth          |
    +-------------------------------------------------------+
                               |
                               v
    +-------------------------------------------------------+
    |          Step 1 (Pass 1): Qualys Active Detections    |
    |  - Paginates via Qualys WARNING/URL token (falls back |
    |    to id_min increment with cursor-stall guard)       |
    |  - QIDs & host IDs extracted per-page into HashSets   |
    |  - Conditional early break if EnableDebugLimit is on  |
    +-------------------------------------------------------+
           |                                       |
           v (Unique Host IDs)                     v (Unique QIDs)
    +-------------------------------+   +-------------------------------+
    |   Step 2 (Pass 0): MAC Lookup |   |   Step 3 (Pass 2): KB Lookup  |
    |  - Chunks host IDs by 200     |   |  - Chunks QIDs by 100         |
    |  - Queries Asset Management   |   |  - Resolves CVEs & Titles     |
    |  - Validates MAC format       |   |                               |
    |  - Retains invalid for review |   |                               |
    +-------------------------------+   +-------------------------------+
                               |
                               v
    +-------------------------------------------------------+
    |                Step 4: Data Consolidation             |
    |  - Joins Host + MAC address(es) + CVE data            |
    |  - Branches per host on validated MAC count:          |
    |      0 MACs   -> "no MAC" dataset (separate file)     |
    |      1 MAC    -> one row per vulnerability            |
    |      2+ MACs  -> fan-out: vuln rows repeated per MAC  |
    +-------------------------------------------------------+
                |
                +----------------------------------+
                |                                  |
                v                                  v
    +-----------------------+       +--------------------------+
    |  Main Dataset         |       |  No-MAC Dataset          |
    |  (>=1 valid MAC)      |       |  (0 valid MACs - always  |
    |                       |       |   written to disk for    |
    |                       |       |   manual review)         |
    +-----------------------+       +--------------------------+
                |
                v
       /------------------\
      <  Is TestMode On?   >
       \------------------/
           /         \
         Yes           No
          v             v
    +----------+   /-----------------------\
    | Write to |  <   Check StorageMode     >
    | disk CSV |   \-----------------------/
    | (review) |        /           \
    +----------+   'Memory'        'Disk'
                      /                 \
                     v                   v
            +--------------+   +------------------+
            | MemoryStream |   | Temp CSV on disk |
            +--------------+   +------------------+
                      \                 /
                       +-------+-------+
                               |
                               v
                  +---------------------------+
                  | Step 5: NinjaOne Ingest   |
                  | (Multipart POST upload)   |
                  | Updates LastQualysSync    |
                  | custom field on success   |
                  +---------------------------+

.PARAMETER TestMode
    When true, skips the final NinjaOne upload and writes the main CSV to disk instead
    for manual review. Defaults to True.

.PARAMETER EnableDebugLimit
    When true, stops Pass 1 early once $DebugLimit hosts have been collected. Useful
    for testing without processing the full inventory. Defaults to False.

.PARAMETER DebugLimit
    Maximum number of hosts to collect when EnableDebugLimit is active. Defaults to 200.

.PARAMETER StorageMode
    Controls how the upload payload is staged. 'Memory' streams directly from RAM
    (no temp file). 'Disk' writes a temp CSV first then streams from that file.
    In TestMode this parameter has no effect - a disk CSV is always written.
    Defaults to 'Memory'.

.PARAMETER OutputPath
    Directory path where all output CSV files will be written. Defaults to "C:\WINDOWS\TEMP".
    Can be overridden via NinjaOne custom field or environment variable.

.AUTHOR
    Dean Johnson

.NOTES
    Version: 7.7.5
    Release Notes:
      06/23/26 - BUG FIXES AND ENHANCEMENTS (v7.7.4 -> v7.7.5):
                 * FIXED: LastQualysSync custom field now properly detects NinjaOne
                   agent context using Ninja-Property-Get "systemDeviceId" instead of
                   relying solely on $env:NINJA_DEVICE_ID which is not reliably set.
                 * FIXED: All output CSV files now write to the same configurable
                   directory (OutputPath parameter, default "C:\WINDOWS\TEMP") instead
                   of being split between $env:TEMP and hardcoded paths.
                 * ENHANCED: Added OutputPath parameter that can be overridden via
                   NinjaOne custom field or environment variable.
                 * ENHANCED: Output filenames now include date in yyyyMMdd format
                   in addition to time (e.g., qualys_sync_20260623-1225.csv).
      06/23/26 - DOCUMENTATION ONLY: Added output CSV file and LastQualysSync
                 documentation to .DESCRIPTION. No code changes.
      06/23/26 - DOCUMENTATION ONLY: Added LastQualysSync to the custom field
                 requirements block in .DESCRIPTION. No code changes.
      06/22/26 - SCAN GROUP ID AUTO-RESOLUTION (v7.7.3 -> v7.7.4):
                 * $Global:ScanGroupID now accepts either a numeric ID or a human-
                   readable name (e.g. "Global Qualys Import"). After authentication, the
                   script calls GET /v2/vulnerability/scan-groups to resolve a name
                   to its numeric ID automatically. If the name has no match, the
                   script exits immediately and lists all available scan groups with
                   their IDs so the correct value can be confirmed without needing
                   to browse the NinjaOne UI or API docs manually.
                 * If $Global:ScanGroupID is already a valid non-zero integer it is
                   used directly, skipping the lookup entirely.
                 * The pre-flight inline validation in the upload block is removed -
                   resolution now happens right after auth so the script fails fast
                   before Pass 1/0/2 spend their full runtime on a bad config.
      06/22/26 - SCAN GROUP ID TYPE CORRECTED (v7.7.2 -> v7.7.3):
                 * $Global:ScanGroupID default changed from the descriptive string
                   "Global Qualys Import" to a numeric placeholder (0). The NinjaOne
                   vulnerability upload endpoint requires an integer scan group ID
                   in the URL path - passing a string name produces HTTP 400
                   "scan-group-id incorrect type". The numeric ID is found in
                   NinjaOne under Administration -> Apps -> API documentation ->
                   Vulnerability Management -> Fetch all scan groups.
                 * Added a pre-flight integer validation of $Global:ScanGroupID
                   before the upload attempt, with a clear actionable error message,
                   so a misconfigured ID fails immediately rather than after
                   Pass 1/0/2 have already spent their full runtime.
      06/22/26 - AM API BATCH SIZE & TIMEOUT CORRECTED (v7.7.1 -> v7.7.2):
                 * Reduced $MacChunkSize from 500 back to 200. The qwebHostId IN (...)
                   query against the Qualys AM API scales non-linearly with ID count -
                   500-ID batches consistently exceeded the 90s HttpClient timeout before
                   returning a response. 200-ID batches were confirmed working at 20-25s
                   each in prior runs. The round-trip count increase (38 vs ~16 batches)
                   is the lesser cost compared to every batch silently failing.
                 * Increased AM API TimeoutSec from 90 to 120 to add headroom against
                   transient latency spikes even at the smaller batch size.
      06/22/26 - NINJAONE INGESTION ENDPOINT CORRECTED (v7.7.0 -> v7.7.1):
                 * Import URL updated: /v2/vulnerability-management/scan-groups/{id}/import
                   is a 404 on current NinjaOne clusters. Correct path is
                   /v2/vulnerability/scan-groups/{id}/upload (scan group ID remains
                   in the URL path - the form body claim from other sources was not
                   supported by NinjaOne's own published sample scripts).
                 * Multipart form field name corrected: "file" -> "csv" to match
                   the field name NinjaOne's current upload endpoint expects.
      06/22/26 - BUG FIXES AND FEATURE RESTORATION (v7.6.8 -> v7.7.0):
                 * Restored @(...) wrapper on $HostMacs and $HostInvalidMacs
                   assignments in Step 4. Without it, a single-element array
                   returned from the if/else block is unwrapped to a bare string
                   by PowerShell's if-block return semantics - the fix originally
                   introduced in v7.5.1 had been dropped.
                 * Restored the dedicated $QualysAmHeaders header set (clone of
                   $QualysHeaders with Content-Type: text/xml added) for the AM
                   API POST endpoint. $QualysHeaders never included Content-Type
                   since it's only needed for POST bodies, and the AM API requires
                   it to correctly parse the XML ServiceRequest body.
                 * Restored null guard on CVE_LIST in Pass 2. Without it,
                   accessing .ID on @($null)[0] throws a null reference exception
                   for any vulnerability that has no associated CVE.
                 * Restored CVE non-empty filter on detection rows. Rows without a
                   CVE are excluded from both output files since NinjaOne's importer
                   requires the CVE field to be populated.
                 * Restored DNS->IP fallback for the Device field in consolidation.
                   Hosts with no DNS name now fall back to their IP address.
                 * Restored "Qualys QID XXXXX: " prefix on the Title field.
                 * Restored Pass 1 id_min fallback pagination with cursor-stall and
                   non-numeric-ID guards. WARNING/URL-only pagination stops after
                   any page that lacks the token, which includes the last real page
                   in some Qualys API configurations.
                 * Restored Pass 1 error handling - catch { break } was silently
                   treating all API failures as end-of-results. Now fatal.
                 * Restored the full no-MAC CSV output with InvalidMacObserved
                   column and all associated $InvalidMacLookupTable logic.
                 * Restored MAC fan-out summary statistics.
                 * Restored per-page Pass 1 progress logging.
                 * Restored per-batch Pass 0 result logging.
                 * Restored hasMoreRecords warning in Pass 0.
                 * Restored AM API responseCode error check in Pass 0.
                 * Restored elapsed time log line.
                 * Implemented StorageMode='Disk' path (was previously a stub
                   that silently fell through to Memory mode regardless).
                 * TestMode now always writes the main CSV to disk for review,
                   regardless of StorageMode.
                 * Fixed Get-ConfigValue: [switch] parameters are now explicitly
                   cast to [bool] at call sites so the $DefaultValue -is [bool]
                   type check inside the function fires correctly.
                 * Kept all good additions from v7.6.8: Get-ConfigValue,
                   Set-NinjaCustomField, DeviceId/LastQualysSync field update,
                   memory-based upload, and the StorageMode parameter.
      06/18/26 - PERFORMANCE OPTIMIZATIONS:
                 * Pass 1 prefers WARNING/URL pagination token with id_min fallback.
                 * Per-page HashSet extraction of QIDs and host IDs.
                 * Pass 0 MAC batch size increased from 200 to 500.
      06/18/26 - MAC FAN-OUT, VALIDATION & INVALID MAC RETENTION.
      06/17/26 - API 4.0, debug limit decoupling, ASCII diagram, Code 2007 check.
    Context: Hybrid (Local or NinjaOne Agent)

.LICENSE
    This software is licensed under the Mozilla Public License 2.0 (MPL-2.0)
    with the following additional permission and restriction:

    ADDITIONAL PERMISSION:
      - You may use, modify, and distribute this software for commercial or
        non-commercial purposes, provided that any modified versions of the
        original files remain licensed under MPL-2.0.

    ADDITIONAL RESTRICTION:
      - You may NOT sell this software, or any portion of its source code,
        as a standalone product. You may, however, include it within a
        commercial service or product, provided the source files covered by
        MPL-2.0 remain open and available under the same licence.

    ATTRIBUTION REQUIREMENT:
      The original author credit "Dean Johnson – (scripts@deanjohnson.co.uk)"
      must be preserved in all copies, forks, substantial portions, and
      derivative works of this software. This notice may not be removed,
      altered, or obscured.

    DISCLAIMER:
      This software is provided "AS IS" without warranty of any kind.
      The author shall not be liable for any damages or claims arising
      from the use of this software.

    Full MPL-2.0 text:
      https://www.mozilla.org/MPL/2.0/

#>

[CmdletBinding()]
param(
    [switch]$TestMode         = $true,
    [switch]$EnableDebugLimit = $false,
    [int]$DebugLimit          = 200,
    [ValidateSet('Memory', 'Disk')]
    [string]$StorageMode      = 'Memory',
    [string]$OutputPath       = 'C:\WINDOWS\TEMP'
)

# --- 0. SECURITY & GLOBAL PREP ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Global:ScanGroupID   = "Global Qualys Import"  # Name or numeric ID - resolved automatically after auth
$Global:NinjaInstance = "eu"
$Global:QualysBaseUrl = "https://qualysapi.qg1.apps.qualys.co.uk"
$Global:ApiVersion    = "4.0"
$ScriptStartTime      = Get-Date

# --- 1. FUNCTIONS ---

function Get-LogTime { "[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + "]" }

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]$Message,
        [string]$Color = "White",
        [switch]$Detail   # When set, line is suppressed in NinjaOne agent context
    )
    if ($Detail -and $script:IsNinjaContext) { return }
    Write-Host "$(Get-LogTime) $Message" -ForegroundColor $Color
}

function Get-ConfigValue {
    <#
    .SYNOPSIS
        Reads a configuration value from NinjaOne custom fields or environment variables,
        falling back to the provided default if neither is set. Type-safe: converts the
        returned string to match the type of the default value.
    #>
    param([string]$Key, [object]$DefaultValue)
    $Override = $null

    # Only attempt Ninja-Property-Get when we know we are in a Ninja agent context.
    # Unlike credentials, these are optional overrides - if unavailable, defaults are used.
    # Calling unconditionally causes "Unable to find the specified field" stdout noise for
    # every field that hasn't been created as a custom field in NinjaOne.
    # 2>$null suppresses that stderr output for a cleaner log.
    if ($script:IsNinjaContext) {
        try { $Override = Ninja-Property-Get $Key 2>$null } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($Override) -or $Override -eq "null") {
        $Override = [System.Environment]::GetEnvironmentVariable($Key)
    }
    if ([string]::IsNullOrWhiteSpace($Override) -or $Override -eq "null") {
        return $DefaultValue
    }

    # Type-coerce the string value to match the expected type of the default
    if ($DefaultValue -is [bool]) {
        $BoolResult = $false
        if ([bool]::TryParse($Override, [ref]$BoolResult)) { return $BoolResult }
        return $DefaultValue
    }
    if ($DefaultValue -is [int]) {
        $IntResult = 0
        if ([int]::TryParse($Override, [ref]$IntResult)) { return $IntResult }
        return $DefaultValue
    }
    return $Override
}


function Set-NinjaCustomField {
    <#
    .SYNOPSIS
        Updates a custom field value for the current device via the NinjaOne REST API.
        Fails non-fatally with a warning if the field doesn't exist or the update fails.
    #>
    param(
        [Parameter(Mandatory=$true)]$DeviceId,
        [Parameter(Mandatory=$true)]$FieldName,
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)]$Headers
    )
    try {
        $Uri  = "https://$Global:NinjaInstance.ninjarmm.com/v2/device/$DeviceId/fields"
        $Body = @{ fields = @{ $FieldName = $Value } } | ConvertTo-Json
        Invoke-RestMethod -Uri $Uri -Method Patch -Headers $Headers -Body $Body -ContentType "application/json" | Out-Null
        Write-Log "[+] NinjaOne Custom Field '$FieldName' updated for device $DeviceId." -Color Green
    } catch {
        Write-Log "[!] Failed to update Custom Field '$FieldName': $($_.Exception.Message)" -Color Yellow
    }
}

function Get-QualysData {
    <#
    .SYNOPSIS
        Performs a GET request against the Qualys API and returns a parsed XmlDocument.
        Surfaces Qualys-specific error codes embedded in the response body (e.g. code
        2007 for IP whitelist failures) rather than letting them masquerade as success.
    #>
    param([Parameter(Mandatory=$true)]$Url, [Parameter(Mandatory=$true)]$Headers)
    try {
        $Response = Invoke-WebRequest -Uri $Url -Method Get -Headers $Headers -UseBasicParsing -ErrorAction Stop
        [xml]$XmlRes = $Response.Content
        $ErrorCode = $XmlRes.SelectSingleNode("//CODE")
        if ($ErrorCode -and $ErrorCode.InnerText -eq "2007") {
            Write-Log "CRITICAL: IP ACCESS DENIED (Code 2007). Your IP is not whitelisted in Qualys." -Color Red
            throw "IP_NOT_WHITELISTED"
        }
        return $XmlRes
    } catch {
        if ($_.Exception.Message -ne "IP_NOT_WHITELISTED") {
            Write-Log "CRITICAL API ERROR: $($_.Exception.Message)" -Color Red
            if ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Log "Server Response Body: $($reader.ReadToEnd())" -Color Yellow
            }
        }
        throw $_
    }
}

function Get-XmlNodeText ($Node) {
    # Safely extracts the inner text of an XML node without leaking type names.
    if ($null -eq $Node) { return "" }
    if ($Node.InnerText) { return $Node.InnerText.Trim() }
    return "$Node".Trim()
}

function Test-ValidMacAddress {
    # Strict format check: six hex octet pairs joined by a consistent separator
    # (all colons or all hyphens). Mixed separators are rejected.
    param([string]$Mac)
    if ([string]::IsNullOrWhiteSpace($Mac)) { return $false }
    return ($Mac -match '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$') -or
           ($Mac -match '^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$')
}

function Format-MacAddress {
    # Normalizes a validated MAC to uppercase colon-separated form for consistent output.
    param([string]$Mac)
    return ($Mac -replace '-', ':').ToUpper()
}

# --- 2. CONTEXT & CREDENTIALS ---

Write-Log "--- Step 0: Context & Variable Resolution ---" -Color Cyan

# Determine if we're in a NinjaOne context and get device ID
# $env:NINJA_DEVICE_ID is the most reliable indicator across NinjaOne deployments.
# Fall back to credential access check if the env var isn't set.
$DeviceId = $null
$script:IsNinjaContext = $false

if ($env:NINJA_DEVICE_ID) {
    $DeviceId = $env:NINJA_DEVICE_ID
    $script:IsNinjaContext = $true
    Write-Log "[i] Running in NinjaOne agent context on device $DeviceId" -Color Gray
} else {
    # Fall back: if we can access NinjaOne credentials, we're in agent context
    # but the NINJA_DEVICE_ID environment variable isn't set in this deployment.
    # 2>$null suppresses the "Unable to find the specified field" stderr message
    # that Ninja-Property-Get emits when a field doesn't exist.
    try {
        $testCred = Ninja-Property-Get "QualysImportClientID" 2>$null
        if ($testCred -and $testCred -ne "null") {
            $script:IsNinjaContext = $true
            Write-Log "[i] Running in NinjaOne agent context - device ID not available from environment" -Color Gray
        } else {
            Write-Log "[i] Not running in NinjaOne agent context" -Color Gray
        }
    } catch {
        Write-Log "[i] Not running in NinjaOne agent context" -Color Gray
    }
}

# NinjaOne custom fields and environment variables override script parameter defaults.
# [switch] params are explicitly cast to [bool] so Get-ConfigValue's type check fires.
$Global:ScanGroupID = Get-ConfigValue "ScanGroupID"      $Global:ScanGroupID
$TestMode           = Get-ConfigValue "TestMode"         ([bool]$TestMode)
$EnableDebugLimit   = Get-ConfigValue "EnableDebugLimit" ([bool]$EnableDebugLimit)
$DebugLimit         = Get-ConfigValue "DebugLimit"       $DebugLimit
$StorageMode        = Get-ConfigValue "StorageMode"      $StorageMode
$OutputPath         = Get-ConfigValue "OutputPath"       $OutputPath

# Ensure output path exists
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
        Write-Log "[i] Created output directory: $OutputPath" -Color Gray
    } catch {
        Write-Log "[FATAL] Cannot create output directory '$OutputPath': $($_.Exception.Message)" -Color Red
        exit 1
    }
}

$DebugStatus = if ($EnableDebugLimit) { "Enabled (limit: $DebugLimit)" } else { "Disabled" }
Write-Log "[i] ScanGroupID='$Global:ScanGroupID' | TestMode=$TestMode | StorageMode=$StorageMode | DebugLimit=$DebugStatus | OutputPath=$OutputPath" -Color Gray

function Get-NinjaCredential {
    # Retrieves a single credential value from a NinjaOne Organisation secure custom field.
    # Always attempts Ninja-Property-Get directly (no context pre-check) - this mirrors the
    # pattern used by working NinjaOne scripts. $env:NINJA_DEVICE_ID is not reliably set in
    # all NinjaOne scripting execution environments, so guarding on it causes the call to be
    # skipped silently. If Ninja-Property-Get is unavailable (local run), it throws and we
    # fall back to the environment variable. NinjaOne returns the literal string "null" when
    # a field is empty or unset - treated the same as a missing value.
    param([string]$FieldName, [string]$EnvFallback)
    $Value = $null
    try {
        $Value = Ninja-Property-Get $FieldName
    } catch {
        # Not in a Ninja agent context, or command unavailable - fall through to env var
    }
    # Fall back to environment variable if Ninja-Property-Get was unavailable or returned nothing
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "null") {
        $Value = $EnvFallback
    }
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "null") {
        Write-Log "[!] Credential field '$FieldName' is empty or unset. Ensure the Organisation secure custom field exists, has a value, and Script access is set to Read or Read/Write." -Color Red
        return $null
    }
    return $Value
}

$N_ClientID     = Get-NinjaCredential "QualysImportClientID" $env:QualysImportClientID
$N_ClientSecret = Get-NinjaCredential "QualysImportSecret"   $env:QualysImportSecret
$Q_User         = Get-NinjaCredential "QualysAPIUser"        $env:QualysAPIUser
$Q_Pass         = Get-NinjaCredential "QualysAPIPass"        $env:QualysAPIPass

if (-not ($N_ClientID -and $N_ClientSecret -and $Q_User -and $Q_Pass)) {
    Write-Log "[FATAL] One or more credentials could not be resolved. See field warnings above." -Color Red
    exit 1
}

# --- 3. AUTHENTICATION & HEADERS ---

try {
    $AuthBody = "grant_type=client_credentials&client_id=$N_ClientID&client_secret=$N_ClientSecret&scope=monitoring management"
    $TokenRes = Invoke-RestMethod -Uri "https://$Global:NinjaInstance.ninjarmm.com/ws/oauth/token" `
                -Method Post -Body $AuthBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    $NinjaHeaders = @{ "Authorization" = "Bearer $($TokenRes.access_token)"; "Accept" = "application/json" }
} catch {
    Write-Log "[FATAL] NinjaOne token request failed. Verify credentials. Error: $_" -Color Red
    exit 1
}

$QualysAuth    = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("${Q_User}:${Q_Pass}"))
$QualysHeaders = @{
    "Authorization"    = "Basic $QualysAuth"
    "X-Requested-With" = "curl"
    "User-Agent"       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# --- 3.5: RESOLVE NUMERIC SCAN GROUP ID ---
# Accepts either a human-readable name ("Global Qualys Import") or a raw integer.
# Resolution happens here - right after auth - so a bad value fails immediately
# before the three API passes spend their full runtime on a misconfiguration.

$ScanGroupIdInt = 0
if ([int]::TryParse("$Global:ScanGroupID", [ref]$ScanGroupIdInt) -and $ScanGroupIdInt -gt 0) {
    Write-Log "[i] Using numeric scan group ID directly: $ScanGroupIdInt" -Color Gray
} else {
    Write-Log "[i] ScanGroupID '$Global:ScanGroupID' is not numeric - resolving name via NinjaOne API..." -Color Gray
    try {
        $ScanGroupsResponse = Invoke-RestMethod `
            -Uri "https://$Global:NinjaInstance.ninjarmm.com/v2/vulnerability/scan-groups" `
            -Method Get -Headers $NinjaHeaders -ErrorAction Stop

        # Try the most likely field names NinjaOne may use for the display name.
        $NameFields = @('name', 'displayName', 'groupName', 'description', 'scanGroupName')
        $MatchedField = $null
        $Match = $null
        foreach ($Field in $NameFields) {
            $Candidate = $ScanGroupsResponse | Where-Object { $_.$Field -eq $Global:ScanGroupID }
            if ($Candidate) { $Match = $Candidate; $MatchedField = $Field; break }
        }

        if ($Match) {
            $ScanGroupIdInt = [int]$Match.id
            Write-Log "[+] Resolved '$Global:ScanGroupID' to scan group ID: $ScanGroupIdInt (matched on field: '$MatchedField')" -Color Green
        } else {
            # Dump all fields of every returned item so the correct name field is visible
            $Available = ($ScanGroupsResponse | ForEach-Object {
                "  ID $($_.id): $($_ | ConvertTo-Json -Compress)"
            }) -join "`n"
            Write-Log "[FATAL] No scan group matching '$Global:ScanGroupID' found. Full scan group list:`n$Available" -Color Red
            exit 1
        }
    } catch {
        Write-Log "[FATAL] Failed to retrieve scan groups from NinjaOne API. Error: $($_.Exception.Message)" -Color Red
        exit 1
    }
}

# The Asset Management QPS REST endpoint requires Content-Type: text/xml on POST
# bodies. The base $QualysHeaders intentionally omits this since it's only valid
# for POST, not for the GET-based detection and KB endpoints.
$QualysAmHeaders = $QualysHeaders.Clone()
$QualysAmHeaders["Content-Type"] = "text/xml"

# --- 4. PASS 1: FETCH DETECTIONS (PAGINATED) ---

Write-Log "--- Step 1: Pass 1 - Fetching Active Detections ---" -Color Cyan

$AllRawHosts = [System.Collections.Generic.List[object]]::new()
$QIDSet      = [System.Collections.Generic.HashSet[string]]::new()
$HostIDSet   = [System.Collections.Generic.HashSet[string]]::new()
$IdMin       = 0
$NextUrl     = $null
$MoreResults = $true
$PageNumber  = 0
$PageSize    = 1000

while ($MoreResults) {
    $PageNumber++
    $DetectUri = if ($NextUrl) { $NextUrl } else {
        "$Global:QualysBaseUrl/api/$Global:ApiVersion/fo/asset/host/vm/detection/?action=list&status=New,Active,Re-Opened&truncation_limit=$PageSize&id_min=$IdMin"
    }

    try {
        $DetectXml = Get-QualysData -Url $DetectUri -Headers $QualysHeaders
    } catch {
        Write-Log "[FATAL] Pass 1 failed on page $PageNumber. API rejected the request. Error: $_" -Color Red
        exit 1
    }

    $CurrentBatch = $DetectXml.SelectNodes("//HOST")

    if ($null -eq $CurrentBatch -or $CurrentBatch.Count -eq 0) {
        Write-Log "[i] Page $PageNumber returned no hosts - end of results." -Color Gray
        $MoreResults = $false
        continue
    }

    # Extract QIDs and host IDs per-page while the XmlDocument is still in scope,
    # rather than reconstructing them from the full host list afterwards. This avoids
    # the O(n) cost of querying the combined array and removes a fragile dependency
    # on PowerShell's implicit collection-forwarding behavior.
    foreach ($HostElement in $CurrentBatch) {
        $AllRawHosts.Add($HostElement)
        $HostIdText = Get-XmlNodeText $HostElement.SelectSingleNode("ID")
        if ($HostIdText -match '^\d+$') { [void]$HostIDSet.Add($HostIdText) }
        foreach ($QidNode in $HostElement.SelectNodes("DETECTION_LIST/DETECTION/QID")) {
            $QidText = Get-XmlNodeText $QidNode
            if ($QidText -match '^\d+$') { [void]$QIDSet.Add($QidText) }
        }
    }

    Write-Log "[i] Page $PageNumber : fetched $($CurrentBatch.Count) hosts ($($AllRawHosts.Count) total so far)..." -Color Gray -Detail

    # Prefer Qualys's own WARNING/URL continuation token - the authoritative "more
    # pages exist" signal for this API. Fall back to an id_min increment only if the
    # token is absent, and guard against a non-numeric or non-advancing cursor to
    # prevent infinite loops if the API behaves unexpectedly.
    $WarningUrlNode = $DetectXml.SelectSingleNode("//WARNING/URL")
    if ($WarningUrlNode -and -not [string]::IsNullOrWhiteSpace($WarningUrlNode.InnerText)) {
        $NextUrl = $WarningUrlNode.InnerText.Trim()
    } else {
        $NextUrl      = $null
        $LastHostText = Get-XmlNodeText $CurrentBatch[$CurrentBatch.Count - 1].SelectSingleNode("ID")
        $LastHostNum  = 0
        if (-not [int]::TryParse($LastHostText, [ref]$LastHostNum)) {
            Write-Log "[!] Could not parse last host ID ('$LastHostText') to advance cursor. Stopping Pass 1 here - data collected so far will still be processed." -Color Red
            $MoreResults = $false; continue
        }
        if ($LastHostNum -lt $IdMin) {
            Write-Log "[!] Pagination cursor did not advance (last ID $LastHostNum < id_min $IdMin). Stopping to avoid a stalled loop." -Color Red
            $MoreResults = $false; continue
        }
        $IdMin = $LastHostNum + 1
        # A page shorter than the requested size is a reliable end-of-results signal -
        # avoids one extra empty-page round trip just to confirm we are done.
        if ($CurrentBatch.Count -lt $PageSize) { $MoreResults = $false }
    }

    if ($EnableDebugLimit -and $AllRawHosts.Count -ge $DebugLimit) {
        Write-Log "[!] Debug limit reached ($DebugLimit hosts). Terminating Pass 1 early as requested." -Color Yellow
        $MoreResults = $false
    }
}

if ($AllRawHosts.Count -eq 0) { Write-Log "[i] No active vulnerabilities or hosts found." -Color Gray; exit 0 }

$RawHosts       = $AllRawHosts
$UniqueQIDArray = @($QIDSet)
$UniqueHostIDs  = @($HostIDSet)

if ($UniqueQIDArray.Count -eq 0) { Write-Log "[i] Hosts found but no valid QIDs extracted from their detections." -Color Gray; exit 0 }

Write-Log "[+] Pass 1 complete. $($UniqueQIDArray.Count) unique QIDs across $($UniqueHostIDs.Count) hosts." -Color Green

# --- 5. PASS 0: TARGETED MAC ADDRESS LOOKUP ---

Write-Log "--- Step 2: Pass 0 - Building Targeted MAC Address Lookup Table ---" -Color Cyan

# $MacLookupTable        : HostID -> string[] of valid, normalized MAC addresses
# $InvalidMacLookupTable : HostID -> string[] of raw, format-invalid MAC values
#                          (retained for surfacing in the no-MAC CSV, not discarded)
$MacLookupTable        = @{}
$InvalidMacLookupTable = @{}
$MacChunkSize          = 200   # Batch size for qwebHostId IN (...) queries
$InvalidMacCount       = 0     # Running total of format-invalid values seen

for ($i = 0; $i -lt $UniqueHostIDs.Count; $i += $MacChunkSize) {
    $LastIndex    = [Math]::Min(($i + $MacChunkSize - 1), ($UniqueHostIDs.Count - 1))
    $IdChunk      = $UniqueHostIDs[$i..$LastIndex]
    $IdChunkStr   = $IdChunk -join ','

    Write-Log "[i] MAC batch: entries $($i + 1) to $($LastIndex + 1) of $($UniqueHostIDs.Count)..." -Color Gray -Detail

    $Body = @"
<ServiceRequest>
    <filters>
        <Criteria field="qwebHostId" operator="IN">$IdChunkStr</Criteria>
    </filters>
    <preferences>
        <limitResults>1000</limitResults>
    </preferences>
</ServiceRequest>
"@

    try {
        # Note: $QualysAmHeaders (not $QualysHeaders) - the AM POST endpoint requires Content-Type: text/xml
        $AssetRaw = Invoke-RestMethod -Uri "$Global:QualysBaseUrl/qps/rest/2.0/search/am/hostasset" `
                    -Method Post -Headers $QualysAmHeaders -Body $Body -TimeoutSec 120
    } catch {
        Write-Log "[!] AM API batch $($i+1)-$($LastIndex+1) request failed: $($_.Exception.Message). Skipping batch." -Color Red
        continue
    }
    $AssetXml = [xml]$AssetRaw

    # Surface AM API-level errors explicitly. Without this check, a non-SUCCESS
    # response (auth failure, rate limit, IP restriction, etc.) silently looks
    # like a batch that returned 0 assets.
    $ResponseCodeNode = $AssetXml.SelectSingleNode("//*[local-name()='responseCode']")
    if ($ResponseCodeNode -and $ResponseCodeNode.InnerText -ne "SUCCESS") {
        $ErrNode = $AssetXml.SelectSingleNode("//*[local-name()='errorMessage']")
        $ErrDetail = if ($ErrNode) { $ErrNode.InnerText } else { "(no further detail in response)" }
        Write-Log "[!] AM API non-SUCCESS for batch $($i+1)-$($LastIndex+1): '$($ResponseCodeNode.InnerText)' - $ErrDetail" -Color Red
        continue
    }

    # Warn if the API signals there are more records than the 1000 limitResults returned.
    # This should not occur for a correctly-sized chunk (200 IDs with 1000 headroom), but
    # if it does, some MAC addresses in this batch will be silently missing.
    # Reducing $MacChunkSize to 400 or lower will resolve this warning if seen.
    $HasMoreNode = $AssetXml.SelectSingleNode("//*[local-name()='hasMoreRecords']")
    if ($HasMoreNode -and $HasMoreNode.InnerText -eq "true") {
        Write-Log "[!] AM batch $($i+1)-$($LastIndex+1) has more records than requested (limitResults=1000). Some MACs may be missing - consider reducing `$MacChunkSize." -Color Yellow
    }

    $HostAssets  = $AssetXml.SelectNodes("//*[local-name()='HostAsset']")
    $ChunkMapped = 0
    foreach ($Asset in $HostAssets) {
        $IdNode     = $Asset.SelectSingleNode(".//*[local-name()='qwebHostId']")
        $InternalId = if ($IdNode) { $IdNode.InnerText.Trim() } else { $null }
        if (-not $InternalId) { continue }

        $ValidMacs   = @()
        $InvalidMacs = @()

        # Select macAddress elements directly across all interface types (both
        # HostAssetInterface and NetworkInterface) without needing to enumerate
        # the parent interface wrapper first.
        foreach ($MacNode in $Asset.SelectNodes(".//*[local-name()='macAddress']")) {
            $Candidate = $MacNode.InnerText.Trim()
            if (Test-ValidMacAddress $Candidate) {
                $ValidMacs += Format-MacAddress $Candidate
            } else {
                $InvalidMacs += $Candidate
                $InvalidMacCount++
            }
        }

        # Stored as an array (not a joined string) so Step 4 can fan out one row
        # per MAC for hosts with more than one valid address.
        $UniqueMacs = @($ValidMacs | Select-Object -Unique)
        if ($UniqueMacs.Count -gt 0) {
            $MacLookupTable[$InternalId] = $UniqueMacs
            $ChunkMapped++
        }

        if ($InvalidMacs.Count -gt 0) {
            # Merge any invalid MACs from this asset into the running list for this
            # host ID. @(...) ensures we always merge arrays, not concatenate strings,
            # even if the existing entry was previously a single-element that got
            # unwrapped from its array by PS assignment.
            $ExistingInvalid = @(if ($InvalidMacLookupTable.ContainsKey($InternalId)) { $InvalidMacLookupTable[$InternalId] } else { @() })
            $InvalidMacLookupTable[$InternalId] = @($ExistingInvalid + $InvalidMacs | Select-Object -Unique)
        }
    }
    Write-Log "[i] Batch complete: $($HostAssets.Count) assets found, $ChunkMapped with at least one valid MAC." -Color Gray -Detail
}

Write-Log "[+] MAC lookup complete. $($MacLookupTable.Count) of $($UniqueHostIDs.Count) hosts mapped." -Color Green
if ($InvalidMacCount -gt 0) {
    Write-Log "[!] $InvalidMacCount format-invalid MAC value(s) excluded from matching but retained in the no-MAC CSV for review." -Color Yellow
}

# --- 6. PASS 2: TARGETED KB LOOKUP ---

Write-Log "--- Step 3: Pass 2 - Targeted KB Lookup ---" -Color Cyan
$KVMap = @{}

for ($i = 0; $i -lt $UniqueQIDArray.Count; $i += 100) {
    $LastIndex = [Math]::Min(($i + 99), ($UniqueQIDArray.Count - 1))
    $ChunkIds  = ($UniqueQIDArray[$i..$LastIndex]) -join ','

    Write-Log "[i] KB batch: entries $($i + 1) to $($LastIndex + 1) of $($UniqueQIDArray.Count)..." -Color Gray -Detail

    try {
        $KBXml = Get-QualysData -Url "$Global:QualysBaseUrl/api/$Global:ApiVersion/fo/knowledge_base/vuln/?action=list&ids=$ChunkIds" -Headers $QualysHeaders
    } catch {
        Write-Log "[!] KB batch $($i+1)-$($LastIndex+1) failed: $($_.Exception.Message). QIDs in this batch will have no CVE/Title data." -Color Red
        continue
    }

    foreach ($vuln in @($KBXml.KNOWLEDGE_BASE_VULN_LIST_OUTPUT.RESPONSE.VULN_LIST.VULN)) {
        if (-not $vuln.QID) { continue }
        $QIDKey = Get-XmlNodeText $vuln.QID

        # Guard against null CVE_LIST before accessing .CVE - some Qualys KB entries
        # have no associated CVE and will throw a null reference without this check.
        $CveString   = if ($vuln.CVE_LIST -and $vuln.CVE_LIST.CVE) { Get-XmlNodeText (@($vuln.CVE_LIST.CVE)[0].ID) } else { "" }
        $TitleString = if ($vuln.TITLE) { Get-XmlNodeText $vuln.TITLE } else { "" }

        $KVMap[$QIDKey] = @{ CVE = $CveString; Title = $TitleString }
    }
}
Write-Log "[+] KB lookup complete. $($KVMap.Count) QIDs mapped to CVE/Title data." -Color Green

# --- 7. DATA CONSOLIDATION ---

Write-Log "--- Step 4: Consolidating Data ---" -Color Cyan

$CSVDataList               = [System.Collections.Generic.List[object]]::new()
$NoMacCSVDataList          = [System.Collections.Generic.List[object]]::new()
$NoMacHostCount            = 0
$NoMacHostsWithInvalidData = 0
$MultiMacHostCount         = 0
$TotalFanOutRowsAdded      = 0

foreach ($hostNode in $RawHosts) {
    $DNS        = Get-XmlNodeText $hostNode.SelectSingleNode("DNS")
    $IP         = Get-XmlNodeText $hostNode.SelectSingleNode("IP")
    # Fall back to IP when DNS is not populated so Device is never blank
    $DeviceName = if (-not [string]::IsNullOrWhiteSpace($DNS)) { $DNS } else { $IP }
    $InternalID = Get-XmlNodeText $hostNode.SelectSingleNode("ID")

    # @(...) forces the if/else result into a true array regardless of element count.
    # Without it, a single-element array is unwrapped to a bare string by PowerShell's
    # if-block return semantics. That causes $HostMacs[0] to character-index the string
    # (returning e.g. "E" from "E0:1D:...") rather than returning the full MAC address.
    $HostMacs        = @(if ($InternalID -and $MacLookupTable.ContainsKey($InternalID))        { $MacLookupTable[$InternalID] }        else { @() })
    $HostInvalidMacs = @(if ($InternalID -and $InvalidMacLookupTable.ContainsKey($InternalID)) { $InvalidMacLookupTable[$InternalID] } else { @() })

    # Build detection rows first without a MAC assigned, then apply the MAC strategy
    # below based on how many valid addresses this host has.
    $HostDetectionRows = [System.Collections.Generic.List[object]]::new()
    foreach ($detection in $hostNode.SelectNodes("DETECTION_LIST/DETECTION")) {
        $QID    = Get-XmlNodeText $detection.SelectSingleNode("QID")
        $KbInfo = $KVMap[$QID]

        # Exclude rows with no CVE - NinjaOne's importer requires the CVE field
        if ($KbInfo -and -not [string]::IsNullOrWhiteSpace($KbInfo.CVE)) {
            $HostDetectionRows.Add([PSCustomObject]@{
                Device   = $DeviceName
                CVE      = $KbInfo.CVE
                Severity = Get-XmlNodeText $detection.SelectSingleNode("SEVERITY")
                Title    = "Qualys QID $($QID): $($KbInfo.Title)"
            })
        }
    }

    if ($HostDetectionRows.Count -eq 0) { continue }

    if ($HostMacs.Count -eq 0) {
        # No valid MAC - route to separate CSV for manual review rather than the main
        # export. InvalidMacObserved surfaces any malformed values Qualys returned,
        # distinguishing "bad data was sent" from "no data was sent at all".
        $NoMacHostCount++
        $InvalidMacStr = ""
        if ($HostInvalidMacs.Count -gt 0) {
            $NoMacHostsWithInvalidData++
            $InvalidMacStr = $HostInvalidMacs -join '; '
        }
        foreach ($Row in $HostDetectionRows) {
            $NoMacCSVDataList.Add([PSCustomObject]@{
                Device             = $Row.Device
                MAC                = ""
                InvalidMacObserved = $InvalidMacStr
                CVE                = $Row.CVE
                Severity           = $Row.Severity
                Title              = $Row.Title
            })
        }
    }
    elseif ($HostMacs.Count -eq 1) {
        foreach ($Row in $HostDetectionRows) {
            $CSVDataList.Add([PSCustomObject]@{
                Device = $Row.Device; MAC = $HostMacs[0]
                CVE = $Row.CVE; Severity = $Row.Severity; Title = $Row.Title
            })
        }
    }
    else {
        # Multiple valid MACs: fan out. Each output row carries exactly one MAC address,
        # so a host with N vulnerabilities and K MACs produces N*K rows total.
        $MultiMacHostCount++
        $TotalFanOutRowsAdded += ($HostMacs.Count - 1) * $HostDetectionRows.Count
        foreach ($Mac in $HostMacs) {
            foreach ($Row in $HostDetectionRows) {
                $CSVDataList.Add([PSCustomObject]@{
                    Device = $Row.Device; MAC = $Mac
                    CVE = $Row.CVE; Severity = $Row.Severity; Title = $Row.Title
                })
            }
        }
    }
}

Write-Log "[+] Consolidation complete. $($CSVDataList.Count) main rows | $($NoMacCSVDataList.Count) no-MAC rows." -Color Green
if ($MultiMacHostCount -gt 0) {
    Write-Log "[i] $MultiMacHostCount host(s) had multiple valid MACs; $TotalFanOutRowsAdded additional row(s) added by fan-out." -Color Gray
}
if ($NoMacHostCount -gt 0) {
    $NoMacNoData = $NoMacHostCount - $NoMacHostsWithInvalidData
    Write-Log "[!] $NoMacHostCount host(s) had no valid MAC: $NoMacHostsWithInvalidData with malformed MAC data, $NoMacNoData with no MAC data at all." -Color Yellow
}

# --- 8. OUTPUT & INGESTION ---

Write-Log "--- Step 5: Output & Ingestion ---" -Color Cyan

# Generate timestamp with both date and time for filenames
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmm'
$NoMacPath      = Join-Path $OutputPath "qualys_sync_no_mac_$Timestamp.csv"
$InvalidMacPath = Join-Path $OutputPath "qualys_sync_invalid_mac_$Timestamp.csv"

# The no-MAC file is always written to disk when there is data to review,
# regardless of TestMode or StorageMode - it is never uploaded to NinjaOne.
if ($NoMacCSVDataList.Count -gt 0) {
    $NoMacCSVDataList | Select-Object Device, MAC, InvalidMacObserved, CVE, Severity, Title |
        Export-Csv -Path $NoMacPath -NoTypeInformation -Encoding UTF8
    Write-Log "[!] No-MAC hosts written to: $NoMacPath" -Color Yellow
}

# Write a data quality CSV for every host that had any format-invalid MAC values,
# even if that host also had valid MACs and made it into the main export.
# This is separate from the no-MAC CSV - it flags data hygiene issues regardless
# of whether the host was successfully matched.
$InvalidMacQualityList = [System.Collections.Generic.List[object]]::new()
foreach ($HostId in $InvalidMacLookupTable.Keys) {
    $ValidMacs   = @(if ($MacLookupTable.ContainsKey($HostId)) { $MacLookupTable[$HostId] } else { @() })
    $InvalidMacs = @($InvalidMacLookupTable[$HostId])
    $InvalidMacQualityList.Add([PSCustomObject]@{
        HostID           = $HostId
        InvalidMACs      = $InvalidMacs -join '; '
        ValidMACs        = $ValidMacs -join '; '
        RoutedToMainCSV  = ($ValidMacs.Count -gt 0)
    })
}
if ($InvalidMacQualityList.Count -gt 0) {
    $InvalidMacQualityList | Export-Csv -Path $InvalidMacPath -NoTypeInformation -Encoding UTF8
    Write-Log "[!] $($InvalidMacQualityList.Count) host(s) had format-invalid MAC value(s) - data quality report: $InvalidMacPath" -Color Yellow
}

if ($TestMode) {
    # TestMode always writes the main CSV to disk for review, regardless of StorageMode.
    $TempPath = Join-Path $OutputPath "qualys_sync_$Timestamp.csv"
    $CSVDataList | Select-Object Device, MAC, CVE, Severity, Title |
        Export-Csv -Path $TempPath -NoTypeInformation -Encoding UTF8
    Write-Log "[*] TEST MODE: Upload skipped. Main CSV saved for review: $TempPath ($($CSVDataList.Count) rows)" -Color Yellow
} else {
    # System.Net.Http is not auto-loaded in PS5.1 / .NET Framework - must be explicitly
    # referenced before using HttpClient, MultipartFormDataContent, etc.
    Add-Type -AssemblyName System.Net.Http

    $ImportUrl = "https://$Global:NinjaInstance.ninjarmm.com/v2/vulnerability/scan-groups/$ScanGroupIdInt/upload"
    $FileStream = $null
    $HttpClient = $null

    try {
        $CsvLines = $CSVDataList | Select-Object Device, MAC, CVE, Severity, Title | ConvertTo-Csv -NoTypeInformation
        $CsvBytes = [System.Text.Encoding]::UTF8.GetBytes(($CsvLines -join "`r`n"))

        $MultipartContent = New-Object System.Net.Http.MultipartFormDataContent
        $HttpClient       = New-Object System.Net.Http.HttpClient
        foreach ($h in $NinjaHeaders.GetEnumerator()) { $HttpClient.DefaultRequestHeaders.Add($h.Key, $h.Value) }

        if ($StorageMode -eq 'Disk') {
            # Disk mode: write bytes to a temp file and stream from it. Useful when
            # available RAM on the agent host is a concern for large payloads.
            $TempPath  = Join-Path $OutputPath "qualys_sync_$Timestamp.csv"
            [System.IO.File]::WriteAllBytes($TempPath, $CsvBytes)
            Write-Log "[i] Disk mode: staging CSV at $TempPath before upload." -Color Gray
            $FileStream  = [System.IO.File]::OpenRead($TempPath)
            $FileContent = New-Object System.Net.Http.StreamContent($FileStream)
            $MultipartContent.Add($FileContent, "csv", (Split-Path $TempPath -Leaf))
        } else {
            # Memory mode (default): stream directly from a byte array. Faster and
            # leaves no temp file on the agent disk.
            $MemStream   = New-Object System.IO.MemoryStream(,$CsvBytes)
            $FileContent = New-Object System.Net.Http.StreamContent($MemStream)
            $MultipartContent.Add($FileContent, "csv", "qualys_sync_$Timestamp.csv")
        }

        $UploadTask = $HttpClient.PostAsync($ImportUrl, $MultipartContent)
        $UploadTask.Wait()
        $Response = $UploadTask.Result

        if ($Response.IsSuccessStatusCode) {
            Write-Log "[+] SUCCESS: $($CSVDataList.Count) rows ingested into NinjaOne scan group '$Global:ScanGroupID'." -Color Green
            # Update LastQualysSync custom field using Ninja-Property-Set
            # (available in NinjaOne agent context without needing device ID)
            if ($script:IsNinjaContext) {
                try {
                    $syncTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
                    Ninja-Property-Set "LastQualysSync" $syncTimestamp 2>$null
                    Write-Log "[+] NinjaOne Custom Field 'LastQualysSync' updated to $syncTimestamp" -Color Green
                } catch {
                    Write-Log "[!] Failed to update LastQualysSync via Ninja-Property-Set: $($_.Exception.Message)" -Color Yellow
                    Write-Log "[i] Ensure the 'LastQualysSync' custom field exists with Write access for this script role" -Color Gray
                }
            } else {
                Write-Log "[i] Not in NinjaOne agent context - skipping LastQualysSync field update." -Color Gray
            }
        } else {
            $ResponseBody = $Response.Content.ReadAsStringAsync().Result
            throw "NinjaOne API rejected upload: HTTP $($Response.StatusCode). Body: $ResponseBody"
        }



    } catch {
        Write-Log "[FATAL] Ingestion failed: $($_.Exception.Message)" -Color Red
    } finally {
        if ($FileStream) { $FileStream.Close(); $FileStream.Dispose() }
        if ($HttpClient) { $HttpClient.Dispose() }
    }
}

$Elapsed = (Get-Date) - $ScriptStartTime
Write-Log "--- Script Execution Complete (Elapsed: $($Elapsed.ToString('hh\:mm\:ss'))) ---" -Color Cyan
