function Invoke-AdminRemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Scriptblock,

        [pscredential]$Credential,

        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 32,

        [ValidateSet("Continue", "Stop", "SilentlyContinue")]
        [string]$fErrorAction = "Stop"
    )
    
    begin {
        $results = @()
    }
    
    process {
        foreach ($computer in $ComputerName) {
            try {
                $result = Invoke-Command -ComputerName $computer `
                -ScriptBlock $Scriptblock `
                -Credential $Credential `
                -ErrorAction $fErrorAction `
                -ThrottleLimit $ThrottleLimit

                Write-AdminLog -Message "Command '$Scriptblock' was completed on computer '$computer'." -Level INFO -FunctionName 'Invoke-AdminRemoteCommand'

                $endTime = Get-Date
                
                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Succeess     = $true
                    Output       = $result
                    Error        = $null
                    Timestamp    = $endTime
                }
                
            }
            catch {
                Write-AdminLog -Message "Error on computer '$computer' : $($_.Exception.Message)." -Level ERROR -FunctionName 'Invoke-AdminRemoteCommand'

                $endTime = Get-Date

                $results += [PSCustomObject]@{
                    ComputerName = $computer
                    Succeess     = $false
                    Output       = $null
                    Error        = $_.Exception.Message
                    Timestamp    = $endTime
                }
            }
        }
    }
    
    end {
        return $results
    }
}

function Get-AdminRemoteInfo {
    [CmdletBinding()]
    param (
        [ValidateSet("Basic", "Detailed", "Full")]
        [string]$DetailLevel = "Basic",

        [switch]$Show,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$ComputerName,

        [pscredential]$Credential,

        [ValidateSet("Continue", "Stop", "SilentlyContinue")]
        [string]$fErrorAction = "Stop",

        [ValidateRange(1, 64)]
        [int]$ThrottleLimit = 32
    )
    
    process {
        foreach ($computer in $ComputerName) {
            try {
                $scriptBlock = {
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
                            Write-AdminLog -Message "Function 'Get-AdminRemoteInfo' with flag -Basic or without it, was used." -Level INFO -FunctionName 'Get-AdminRemoteInfo'
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
                            Network      = $network
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
                            Write-AdminLog -Message "Function 'Get-AdminRemoteInfo' with flag -Detailed was used." -Level INFO -FunctionName 'Get-AdminRemoteInfo'
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
                        Write-AdminLog -Message "Function 'Get-AdminRemoteInfo' with flag -Full was used." -Level INFO -FunctionName 'Get-AdminRemoteInfo'
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

                $invokeParams = @{
                    ComputerName = $computer
                    ScriptBlock  = $scriptBlock
                    ArgumentList = $DetailLevel, $Show
                    ErrorAction  = $fErrorAction
                    ThrottleLimit = $ThrottleLimit
                }

                if ($Credential) {
                    $invokeParams.Credential = $Credential
                }

                return Invoke-Command @invokeParams
            }
            catch {
                Write-AdminLog -Message "Error $($_.Exception.Message)" -Level ERROR -FunctionName 'Get-AdminRemoteInfo'
                throw "Error $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Succes = $false
                    Error = $_.Exception.Message
                    ComputerName = if ($ComputerName) {$ComputerName} else {$env:COMPUTERNAME}
                }
            }
        }
    }
}