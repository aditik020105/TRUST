# ==============================================================================
# TRUST Platform - DDoS Protection Attack Simulation Script (PowerShell / Windows)
# ==============================================================================
# Demonstrates that the backend DDoS protection system mitigates high-volume
# concurrent request floods and keeps the server stable and healthy.
# ==============================================================================

param(
    [string]$TargetUrl = "http://localhost:3001",
    [int]$NumRequests = 100
)

$AttackEndpoint = "$TargetUrl/api/evidence"
$HealthEndpoint = "$TargetUrl/health"
$AttackerIp = "198.51.100." + (Get-Random -Minimum 10 -Maximum 220)

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          TRUST Platform - DDoS Attack Simulation & Defense Test      " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Target URL:        $TargetUrl"
Write-Host "Attack Target:     $AttackEndpoint"
Write-Host "Flood Magnitude:   $NumRequests concurrent requests"
Write-Host "Attacker IP:       $AttackerIp (simulated via X-Forwarded-For)"
Write-Host "Health Endpoint:   $HealthEndpoint"
Write-Host "----------------------------------------------------------------------"

# 1. Pre-flight Check
Write-Host -NoNewline "Checking backend connectivity... "
try {
    $pre = Invoke-WebRequest -Uri $HealthEndpoint -UseBasicParsing -TimeoutSec 4
    if ($pre.StatusCode -eq 200) {
        Write-Host "[ONLINE] (HTTP 200)" -ForegroundColor Green
    } else {
        Write-Host "[FAILED] (HTTP $($pre.StatusCode))" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[FAILED] - Cannot connect to $TargetUrl" -ForegroundColor Red
    Write-Host "Please start the backend before running: cd trust-backend; npm run dev"
    exit 1
}

# 2. Launch Concurrent Request Flood
Write-Host ""
Write-Host "[PHASE 1] Launching flood of $NumRequests requests from IP $AttackerIp..." -ForegroundColor Yellow
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$count200 = 0
$count429 = 0
$countOther = 0
$sample429Message = ""

# Send requests in rapid parallel batches
1..$NumRequests | ForEach-Object -Parallel {
    param($url, $ip)
    try {
        $headers = @{ "X-Forwarded-For" = $ip }
        $res = Invoke-WebRequest -Uri $url -Headers $headers -UseBasicParsing -TimeoutSec 6 -ErrorAction Stop
        return [PSCustomObject]@{ Status = $res.StatusCode; Body = $res.Content }
    } catch {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $reader.ReadToEnd()
            return [PSCustomObject]@{ Status = $code; Body = $body }
        } else {
            return [PSCustomObject]@{ Status = 0; Body = $_.Exception.Message }
        }
    }
} -ArgumentList $AttackEndpoint, $AttackerIp -ThrottleLimit 30 | ForEach-Object {
    if ($_.Status -eq 200) {
        $count200++
    } elseif ($_.Status -eq 429) {
        $count429++
        if (-not $sample429Message) {
            $sample429Message = $_.Body
        }
    } else {
        $countOther++
    }
}

$sw.Stop()
Write-Host "Flood completed in $($sw.ElapsedMilliseconds) ms" -ForegroundColor Green

# 3. Post-Attack Survivability Check
Write-Host ""
Write-Host "[PHASE 2] Verifying server survivability and legitimate traffic..." -ForegroundColor Yellow

$healthStatus = 0
$healthBody = ""
try {
    $h = Invoke-RestMethod -Uri $HealthEndpoint -UseBasicParsing -TimeoutSec 4
    $healthStatus = 200
    $healthBody = ($h | ConvertTo-Json -Compress)
} catch {
    $healthStatus = 500
}

$cleanIp = "192.168.1.99"
$cleanStatus = 0
try {
    $c = Invoke-WebRequest -Uri $AttackEndpoint -Headers @{ "X-Forwarded-For" = $cleanIp } -UseBasicParsing -TimeoutSec 4
    $cleanStatus = $c.StatusCode
} catch {
    if ($_.Exception.Response) {
        $cleanStatus = [int]$_.Exception.Response.StatusCode
    }
}

$percentMitigated = 0
if ($NumRequests -gt 0) {
    $percentMitigated = [math]::Round(($count429 * 100) / $NumRequests)
}

# 4. Report
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "                  DDoS ATTACK MITIGATION REPORT                       " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Total Requests Fired:        $NumRequests"
Write-Host "Requests Allowed (HTTP 200): $count200" -ForegroundColor $(if ($count200 -gt 0) { "Green" } else { "Gray" })
Write-Host "Requests Blocked (HTTP 429): $count429" -ForegroundColor Yellow
if ($countOther -gt 0) {
    Write-Host "Other Responses:             $countOther" -ForegroundColor Red
}
Write-Host "Mitigation Rate:             $percentMitigated%" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------------------"
Write-Host "Server Health Status:        " -NoNewline
if ($healthStatus -eq 200) {
    Write-Host "STABLE & RESPONDING (HTTP 200)" -ForegroundColor Green
    Write-Host "Health Response:             $healthBody"
} else {
    Write-Host "UNRESPONSIVE / FAILED (HTTP $healthStatus)" -ForegroundColor Red
}

Write-Host "Legitimate User (Clean IP):  " -NoNewline
if ($cleanStatus -eq 200 -or $cleanStatus -eq 401) {
    Write-Host "UNBLOCKED (Zero Cross-IP Impact)" -ForegroundColor Green
} else {
    Write-Host "HTTP $cleanStatus" -ForegroundColor Yellow
}

if ($sample429Message) {
    Write-Host "----------------------------------------------------------------------"
    Write-Host "Sample Mitigation Payload (HTTP 429):"
    Write-Host "  $sample429Message" -ForegroundColor Yellow
}
Write-Host "======================================================================" -ForegroundColor Cyan

# 5. Final Verdict
if ($count429 -gt 0 -and $healthStatus -eq 200) {
    Write-Host ""
    Write-Host "[TEST PASSED] DDoS flood attack was successfully mitigated!" -ForegroundColor Green
    Write-Host "Firewall jailed the attacker and throttled $count429 / $NumRequests requests while the server stayed 100% healthy." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host ""
    Write-Host "[TEST FAILED] Protection was not triggered or server crashed." -ForegroundColor Red
    Write-Host ""
    exit 1
}

