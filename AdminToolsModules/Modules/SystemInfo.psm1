function Get-AdminHostInfo {
    <#
    .SYNOPSIS
        Gets detailed information about the local system
    
    .DESCRIPTION
        Retrieves comprehensive system information including OS details, hardware configuration,
        memory, CPU, disks, network, and security settings. Supports multiple detail levels.
    
    .PARAMETER DetailLevel
        Specifies the level of detail to return. Basic returns OS info only, Detailed adds hardware
        information, Full includes security and update information.
        
        Valid values: Basic, Detailed, Full
        Default: Basic
    
    .PARAMETER Show
        Displays formatted output to console instead of returning objects
    
    .EXAMPLE
        Get-AdminHostInfo -DetailLevel Basic
        
        Returns basic system information for local computer
    
    .EXAMPLE  
        Get-AdminHostInfo -DetailLevel Full -Show
        
        Displays full system information in formatted output
    
    .OUTPUTS
        PSCustomObject. Returns system information objects
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [ValidateSet("Basic", "Detailed", "Full")]
        [string]$DetailLevel = "Basic",

        [switch]$Show
    )
    
    process {
        try {
            $os = Get-CimInstance Win32_OperatingSystem

            $BasicInfo = [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                User         = $env:USERNAME
                Os           = $os.Caption
                Version      = $os.Version
                Uptime       = (Get-Date) - $os.LastBootUpTime
                Domain       = $env:USERDOMAIN
                Timestamp    = Get-Date
            }

            if ($DetailLevel -eq "Basic") {
                if (-not $Show) {
                    return $BasicInfo
                } else {
                    Write-AdminLog -Message "Function 'Get-AdminHostInfo' with flag -Basic or without it, was used." -Level INFO -FunctionName 'Get-AdminHostInfo'
                    Write-Host "=== System Information ===" -ForegroundColor Cyan
                    Write-Host "OS:" -ForegroundColor Yellow
                    $BasicInfo | Format-List | Out-String | Write-Host
                    return
                }
            }

            $memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
            $disks = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3}
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            $network = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }

            $DetailInfo = [PSCustomObject]@{
                Memory = [PSCustomObject]@{
                    TotalmemoryGB = [math]::Round($memory.Sum / 1GB, 2)
                    FreeMemoryGB  = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
                }
                CPU = [PSCustomObject]@{
                    CpuName       = $cpu.Name
                    CpuCores      = $cpu.NumberOfCores
                }
                Disks = $disks | ForEach-Object {
                    [PSCustomObject]@{
                        Drive = $_.DeviceID
                        SizeGB = [math]::Round($_.Size / 1GB, 2)
                        FreeGB = [math]::Round($_.FreeSpace / 1GB, 2)
                    }
                }
                Network = [PSCustomObject]@{
                    Network      = $network #Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }
                    IPAddresses  = ($network.IPAddress | Where-Object {$_ -ne $null}) -join ', '
                    MACAddress   = ($network.MACAddress | Where-Object {$_ -ne $null}) -join ', '
                }
            }
            if ($DetailLevel -eq "Detailed") {
                if (-not $Show) {
                    return [PSCustomObject]@{
                        OS = $BasicInfo
                        Sys = $DetailInfo
                    }
                } else {
                    Write-AdminLog -Message "Function 'Get-AdminHostInfo' with flag -Detailed was used." -Level INFO -FunctionName 'Get-AdminHostInfo'
                    Write-Host "=== System Information ===" -ForegroundColor Cyan
                    Write-Host "OS:" -ForegroundColor Yellow
                    $BasicInfo | Format-List | Out-String | Write-Host
                    Write-Host "Sys:" -ForegroundColor Yellow
                    $DetailInfo.Memory | Format-List | Out-String | Write-Host
                    $DetailInfo.CPU | Format-List | Out-String | Write-Host
                    $DDetailInfo.Disks | Format-List | Out-String | Write-Host
                    Write-Host "Network:" -ForegroundColor Yellow
                    $DetailInfo.Network | Format-List | Out-String | Write-Host
                    return
                }
            }
            if ($DetailLevel -eq "Full") {
                $updates = Get-HotFix | Select-Object -First 5 | ForEach-Object {"$($_.HotFixID)-$($_.Description)" }
                $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
                $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled}

                $fullInfo = [PSCustomObject]@{
                    Updates = $updates -join "`n"
                    Antivirus   = if ($antivirus) {$antivirus.displayName -join ', '} else { "Not detected"}
                    Firewall    =  if ($firewall) {$firewall.Name -join ', '} else {"Not configured"}
                }
            }
            if (-not $Show) {
                return [PSCustomObject]@{
                    OS = $BasicInfo
                    Sys = $DetailInfo
                    Admin = $fullInfo
                }
            } else {
                Write-AdminLog -Message "Function 'Get-AdminHostInfo' with flag -Full was used." -Level INFO -FunctionName 'Get-AdminHostInfo'
                Write-Host "=== System Information ===" -ForegroundColor Cyan
                Write-Host "OS:" -ForegroundColor Yellow
                $basicInfo | Format-List | Out-String | Write-Host
                Write-Host "Sys:" -ForegroundColor Yellow
                $DetailInfo.Memory | Format-List | Out-String | Write-Host
                $DetailInfo.CPU | Format-List | Out-String | Write-Host
                $DDetailInfo.Disks | Format-List | Out-String | Write-Host
                Write-Host "Network:" -ForegroundColor Yellow
                $DetailInfo.Network | Format-List | Out-String | Write-Host
                Write-Host "Admin:" -ForegroundColor Yellow
                $fullInfo | Format-List | Out-String | Write-Host
                return
            }

        }
        catch {
            Write-AdminLog -Message "Error $($_.Exception.Message)" -Level ERROR -FunctionName 'Get-AdminHostInfo'
            throw "Error $($_.Exception.Message)"
            return [PSCustomObject]@{
                Succes = $false
                Error = $_.Exception.Message
            }
        }
    }
    
}
