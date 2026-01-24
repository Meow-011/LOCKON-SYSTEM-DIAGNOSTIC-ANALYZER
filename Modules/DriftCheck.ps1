
function Invoke-LockonDriftCheck {
    param (
        [Object]$Config,
        [Hashtable]$RunResults
    )
    
    $ModuleResults = @{}
    $DriftCheck = @{ Status = "INFO"; Message = "Skipped"; Data = @{} }

    # Only run if explicitly requested or part of full scan (Check ID 16)
    if (Should-RunCheck "16") {
        Write-SectionHeader "Drift Detection (Baseline Comparison)"
        $DriftCheck = @{ Status = "PASS"; Message = ""; Data = @() }

        # Compare current state with Baseline from Centralized Config
        $BaselinePath = $Config.ResolvedPaths.Baseline
        
        # Fallback
        if (-not $BaselinePath) {
            $BaselinePath = Join-Path $PSScriptRoot "config_baseline.json"
            if (-not (Test-Path $BaselinePath)) {
                $BaselinePath = Join-Path (Split-Path $PSScriptRoot -Parent) "config_baseline.json"
            }
        }

        if (Test-Path $BaselinePath) {
            try {
                $Baseline = Get-Content $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
                $Drifts = @()

                # --- 1. OS Version Check ---
                if ($Baseline.OsVersion -and $RunResults.OsInfo.Data.DisplayVersion) {
                    if ($RunResults.OsInfo.Data.DisplayVersion -ne $Baseline.OsVersion) {
                        $Drifts += "OS Version changed (Expected: $($Baseline.OsVersion), Found: $($RunResults.OsInfo.Data.DisplayVersion))"
                    }
                }

                # --- 2. Local Admins Count ---
                # Compare number of admins if available
                if ($Baseline.AdminCount -and $RunResults.LocalAdmins.Data) {
                    $CurrentCount = $RunResults.LocalAdmins.Data.Count
                    if ($CurrentCount -ne $Baseline.AdminCount) {
                        $Drifts += "Admin Count changed (Expected: $($Baseline.AdminCount), Found: $CurrentCount)"
                    }
                }

                # --- 3. Antivirus Status ---
                if ($Baseline.AntivirusStatus -and $RunResults.Antivirus.Status) {
                     if ($RunResults.Antivirus.Status -ne $Baseline.AntivirusStatus) {
                         $Drifts += "Antivirus Status changed (Expected: $($Baseline.AntivirusStatus), Found: $($RunResults.Antivirus.Status))"
                     }
                }

                # --- 4. Risky Ports Count ---
                if ($Baseline.RiskyPortsCount -and ($RunResults.ListeningPortsTCP -or $RunResults.ListeningPortsUDP)) {
                    $CurrentRisky = 0
                    if ($RunResults.ListeningPortsTCP.Data.FoundRisky) { $CurrentRisky += $RunResults.ListeningPortsTCP.Data.FoundRisky.Count }
                    if ($RunResults.ListeningPortsUDP.Data.FoundRisky) { $CurrentRisky += $RunResults.ListeningPortsUDP.Data.FoundRisky.Count }
                    
                    if ($CurrentRisky -gt $Baseline.RiskyPortsCount) {
                         $Drifts += "Risky Ports increased (Baseline: $($Baseline.RiskyPortsCount), Found: $CurrentRisky)"
                    }
                }

                if ($Drifts.Count -gt 0) {
                    $DriftCheck.Status = "WARN"
                    $DriftCheck.Message = "System Drift Detected: $($Drifts -join '; ')"
                    $DriftCheck.Data = $Drifts
                    Write-HostWarn "  [!] Baseline Drift: $($Drifts -join '; ')"
                } else {
                    $DriftCheck.Message = "System matches baseline configuration."
                    Write-HostPass "  [+] No baseline drift detected."
                }

            } catch {
                $DriftCheck.Status = "INFO"
                $DriftCheck.Message = "Error comparing baseline: $($_.Exception.Message)"
                Write-HostWarn $DriftCheck.Message
            }
        } else {
            $DriftCheck.Status = "INFO"
            $DriftCheck.Message = "No baseline configuration found (config_baseline.json). Skip."
            Write-HostInfo "  [i] No baseline found."
        }
    }
    
    $ModuleResults.DriftAnalysis = $DriftCheck
    return $ModuleResults
}
