#Module System-Info
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
            $network = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -ne $null}

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

#=====================================================
#Module Service-Control

function Start-AdminService {
    <#
    .SYNOPSIS
        Starts a Windows service with additional administrative features
    
    .DESCRIPTION
        Starts the specified Windows service. If the service is already running and -Force is specified,
        restarts the service. Includes logging and error handling.
    
    .PARAMETER Name
        Specifies the service name. This parameter is mandatory.
    
    .PARAMETER Force
        Forces the service to restart if it is already running
    
    .EXAMPLE
        Start-AdminService -Name "Spooler"
        
        Starts the Print Spooler service
    
    .EXAMPLE
        Start-AdminService -Name "WinRM" -Force
        
        Restarts the Windows Remote Management service even if it's running
    
    .INPUTS
        String. You can pipe service names to this function.
    
    .OUTPUTS
        None. Writes output to console and log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Force
    )
    begin {
        $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue

        if (-not $Service) {
            Write-AdminLog -Message "Service '$Name' not found." -Level WARNING -FunctionName 'Start-AdminService'
            throw "Service '$Name' not found."
        }
    }
    process {
        if ($Service.Status -eq "Running") {
            if ($Force) {
                Restart-Service -Name $Name -Force
                Write-AdminLog -Message "Service $Name was already running. Restarted due to -Force." -Level INFO -FunctionName 'Start-AdminService'
                Write-Host "Service $Name was already running. Restarted due to -Force."
            } else {
                Write-AdminLog -Message "Service $Name was already running." -Level INFO -FunctionName 'Start-AdminService'
                Write-Host "Service $Name is already running."
            }
        } else {
            Start-Service -Name $Name
            Write-AdminLog -Message "Service $Name has been started." -Level INFO -FunctionName 'Start-AdminService'
            Write-Host "Service $Name has been started."
        }
    }
}


function Stop-AdminService {
    <#
    .SYNOPSIS
        Stops a Windows service with administrative features
    
    .DESCRIPTION
        Stops the specified Windows service. Includes logging and error handling.
    
    .PARAMETER Name
        Specifies the service name. This parameter is mandatory.
    
    .PARAMETER Force
        Forces the service to stop even if it has dependent services
    
    .EXAMPLE
        Stop-AdminService -Name "SomeService"
        
        Stops the specified service
    
    .EXAMPLE
        Stop-AdminService -Name "AnotherService" -Force
        
        Forcefully stops the service
    
    .INPUTS
        String. You can pipe service names to this function.
    
    .OUTPUTS
        None. Writes output to console and log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Force
    )
    begin {
        $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $Service) {
            Write-AdminLog -Message "Service '$Name' not found" -Level WARNING -FunctionName 'Stop-AdminService'
            throw "Service '$Name' not found"
        }
    }
    process {
        if ($Service.Status -eq "Stopped") {
            if ($Force) {
                Stop-Service -Name $Name -Force
                Write-AdminLog -Message "Service '$Name' has been stopped (Forced)." -Level INFO -FunctionName 'Stop-AdminService'
                Write-Host "Service '$Name' has been stopped (Forced)."
            } else {
                Write-Host "Service '$Name' already stopped."
            }
        } else {
            Stop-Service -Name $Name
            Write-AdminLog -Message "Service '$Name' has been stopped." -Level INFO -FunctionName 'Stop-AdminService'
            Write-Host "Service '$Name' has been stopped."
        }
    }
}

function Restart-AdminService {
    <#
    .SYNOPSIS
        Restarts a Windows service with administrative features
    
    .DESCRIPTION
        Restarts the specified Windows service. If the service is stopped, starts it.
        Includes logging and error handling.
    
    .PARAMETER Name
        Specifies the service name. This parameter is mandatory.
    
    .PARAMETER Force
        Forces the service to restart even if it has dependent services
    
    .EXAMPLE
        Restart-AdminService -Name "Spooler"
        
        Restarts the Print Spooler service
    
    .EXAMPLE
        Restart-AdminService -Name "WinRM" -Force
        
        Forcefully restarts the Windows Remote Management service
    
    .INPUTS
        String. You can pipe service names to this function.
    
    .OUTPUTS
        None. Writes output to console and log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Force
    )
    
    begin {
        $Service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $Service) {
            Write-AdminLog -Message "Service '$Name' not found." -Level WARNING -FunctionName 'Restart-AdminService'
            throw "Service $Name not found."
        }
    }
    process {
        if ($Service.Status -eq "Running") {
            if ($Force) {
                Restart-Service -Name $Name -Force
                Write-AdminLog -Message "Service '$Name' has been restarted (Forced)." -Level DEBUG -FunctionName 'Restart-AdminService'
                Write-Host "Service '$Name' has been restarted (Forced)."
            } else {
                Restart-Service -Name $Name
                Write-AdminLog -Message "Service '$Name' has been restarted." -Level DEBUG -FunctionName 'Restart-AdminService'
                Write-Host "Service '$Name' has been restarted."
            }
        } else {
            Start-Service -Name $Name
            Write-AdminLog -Message "Service '$Name' was stopped, starting." -Level DEBUG -FunctionName 'Restart-AdminService'
            Write-Host "Service '$Name' was stopped, starting."
        }
    }
}

function Watch-AdminService {
    <#
    .SYNOPSIS
        Monitors a Windows service and automatically restarts it if it stops
    
    .DESCRIPTION
        Sets up event-based monitoring for a Windows service. If the service stops,
        it will be automatically restarted. Includes force option and stop monitoring capability.
    
    .PARAMETER Name
        Specifies the service name to monitor. This parameter is mandatory.
    
    .PARAMETER Force
        Forces the service restart when using automatic recovery
    
    .PARAMETER StopWatch
        Stops the monitoring for the specified service
    
    .EXAMPLE
        Watch-AdminService -Name "CriticalService"
        
        Starts monitoring the critical service
    
    .EXAMPLE
        Watch-AdminService -Name "ImportantService" -Force
        
        Starts monitoring with forceful restart
    
    .EXAMPLE
        Watch-AdminService -Name "SomeService" -StopWatch
        
        Stops monitoring the service
    
    .INPUTS
        String. You can pipe service names to this function.
    
    .OUTPUTS
        None. Sets up event monitoring in the background.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [switch]$Force,

        [switch]$StopWatch
    )
    begin {
            $Service = Get-Service -Name $Name
        $id = "WatchService_$Name"

        if (-not $Service) {
            Write-AdminLog -Message "Service '$Name' not found" -Level WARNING -FunctionName 'Watch-AdminService'
            throw "Service '$Name' not found"
        }
    }
    process {
        if ($StopWatch) {
            Unregister-Event -SourceIdentifier $id
            Write-AdminLog -Message "Watch-Service monitoring for '$Name' was successfully stopped." -Level DEBUG -FunctionName 'Watch-AdminService'
            Write-Host "Watch-Service monitoring for '$Name' was successfully stopped."
            return
        }

        Register-ObjectEvent -InputObject $Service -EventName "StatusChanged" -SourceIdentifier $id -Action {
            $Current = Get-Service -Name $Service.Name

            if ($Current.Status -eq "Stopped") {
                if ($Force) {
                    Restart-Service -Name $Current.Name -Force
                    Write-AdminLog -Message "Service $($Current.Name) was stopped and restarted automatically (forced)." -Level DEBUG -FunctionName 'Watch-AdminService'
                    Write-Host "Service $($Current.Name) was stopped and restarted automatically (forced)."
            } else {
                Start-Service -Name $Current.Name
                Write-AdminLog -Message "Service $($Current.Name) was stopped and restarted automatically." -Level DEBUG -FunctionName 'Watch-AdminService'
                Write-Host "Service $($Current.Name) was stopped and restarted automatically."
                }
            }
        Write-Verbose "Detected service $($Current.Name) stop, taking action restart service $($Current.Name)."
        }
    }
}

#=====================================================
#Module Process-Control
function Get-AdminAllProcesses {
    <#
    .SYNOPSIS
        Gets information about running processes with administrative features
    
    .DESCRIPTION
        Retrieves detailed information about currently running processes.
        Can sort by CPU or memory usage and limit results to top processes.
    
    .PARAMETER Top
        Specifies the number of top processes to return. Default is 10.
    
    .PARAMETER SortByCPU
        Sorts processes by CPU usage instead of memory usage
    
    .EXAMPLE
        Get-AdminAllProcesses
        
        Returns top 10 processes by memory usage
    
    .EXAMPLE
        Get-AdminAllProcesses -Top 5 -SortByCPU
        
        Returns top 5 processes by CPU usage
    
    .OUTPUTS
        PSCustomObject. Returns process information objects
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    param (
        [int]$Top = 10,
        [switch]$SortByCPU
    )
    $processes = Get-Process

    if ($SortByCPU) {
        $processes = $processes | Sort-Object -Property CPU -Descending
    } else {
        $processes = $processes | Sort-Object -Property Ws -Descending
    }

    $processes | Select-Object -First $Top Name, Id,
    @{Name="MemoryMB";Expression={[math]::Round($_.WS / 1MB, 2)}},
    @{Name="CPUTime";Expression={if ($_.CPU) {"{0:N2}" -f $_.CPU} else {0}}}

    Write-AdminLog -Message "Function 'Get-AdminAllProcesses' was used." -Level INFO -FunctionName 'Get-AdminAllProcesses'
}    


function Stop-AdminProcess {
    <#
    .SYNOPSIS
        Stops a running process with administrative features
    
    .DESCRIPTION
        Stops the specified process by name. Includes force option and error handling.
    
    .PARAMETER Name
        Specifies the process name. This parameter is mandatory.
    
    .PARAMETER Force
        Forces the process to terminate immediately
    
    .EXAMPLE
        Stop-AdminProcess -Name "NotRespondingApp"
        
        Stops the not responding application
    
    .EXAMPLE
        Stop-AdminProcess -Name "MaliciousProcess" -Force
        
        Forcefully terminates the malicious process
    
    .INPUTS
        String. You can pipe process names to this function.
    
    .OUTPUTS
        None. Writes output to console and log.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    param (

        [Parameter(Mandatory = $true, Position=0)]
        [string]$Name,

        [switch]$Force
    )
    
    $proc = Get-AdminProcess -Name $Name -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-AdminLog -Message "Process '$Name' not found." -Level WARNING -FunctionName 'Get-AdminProcess'
        throw "Process '$Name' not found"
    }
    try {
        Stop-Process -Id $proc.Id -Force:$Force
        Write-AdminLog -Message "Process '$Name' stopped." -Level INFO -FunctionName 'Get-AdminProcess'
        Write-Host "Process '$Name' stopped"
    }
    catch {
        Write-AdminLog -Message "Cannot stop process '$Name': $_ ." -Level ERROR -FunctionName 'Get-AdminProcess'
        Write-Warning "Cannot stop process '$Name': $_"
    }
}


function Start-AdminProcessByName {
    <#
    .SYNOPSIS
        Starts a process by specifying the executable path
    
    .DESCRIPTION
        Starts a new process from the specified executable path.
        Supports arguments and wait option for synchronous execution.
    
    .PARAMETER Path
        Specifies the path to the executable. This parameter is mandatory.
    
    .PARAMETER Arguments
        Specifies arguments to pass to the process
    
    .PARAMETER Wait
        Waits for the process to complete before continuing
    
    .EXAMPLE
        Start-AdminProcessByName -Path "C:\Program Files\MyApp\app.exe"
        
        Starts the application from specified path
    
    .EXAMPLE
        Start-AdminProcessByName -Path "script.ps1" -Arguments "-Verbose" -Wait
        
        Starts PowerShell script with arguments and waits for completion
    
    .INPUTS
        String. You can pipe file paths to this function.
    
    .OUTPUTS
        None. Starts the specified process.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    param (

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string[]]$Arguments,

        [switch]$Wait
    )

    if (-not(Test-Path $Path)) {
        Write-AdminLog -Message "File '$path' not found." -Level WARNING -FunctionName 'Start-AdminProcessByName'
        throw "File '$path' not found."
    }
    Start-Process -FilePath $Path -ArgumentList $Arguments -Wait:$Wait
    Write-AdminLog -Message "Process '$Path' Started." -Level INFO -FunctionName 'Start-AdminProcessByName'
    Write-Host "Process '$Path' Started."
    
}

#=====================================================
#Module User-Management
function Get-AdminAllUsers {
    <#
    .SYNOPSIS
        Gets information about local users
    
    .DESCRIPTION
        Retrieves information about all local users or filters by enabled/disabled state.
    
    .PARAMETER state
        Filters users by their enabled state: All, Enabled, or Disabled
    
    .EXAMPLE
        Get-AdminAllUsers
        
        Returns all local users
    
    .EXAMPLE
        Get-AdminAllUsers -State Enabled
        
        Returns only enabled users
    
    .OUTPUTS
        PSCustomObject. Returns user information objects
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [ValidateSet("All","Enabled","Disabled")]
        [string]$state = "All"
    )
    $users = Get-LocalUser

    if ($state -eq "Enabled") {
        $users = $users | Where-Object {$_.Enabled -eq $true}
    } elseif ($state -eq "Disabled") {
        $users = $users | Where-Object {$_.Enabled -eq $false}
    }
    Write-AdminLog -Message "Function 'Get-AdminAllUsers' was used." -Level INFO -FunctionName 'Get-AdminAllUsers'
    return $users | Select-Object Name, Enabled, Description
}

function New-AdminUser {
    <#
    .SYNOPSIS
        Creates a new local user account
    
    .DESCRIPTION
        Creates a new local user account with specified name and optional group memberships.
        Includes password prompt and automatic logging.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .PARAMETER Groups
        Specifies groups to add the user to
    
    .EXAMPLE
        New-AdminUser -Name "john.doe" -Groups @("Users", "RemoteDesktopUsers")
        
        Creates new user and adds to specified groups
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Creates user account and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,

        
        [string[]]$Groups = @()
    )
    
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
        Write-Warning "User $Name already exists"
        return
    }

    $Password = Read-Host "Enter Password for $Name" -AsSecureString

    New-LocalUser -Name $Name -Password $Password -FullName $Name -Description "created by AdminTools"

    foreach ($group in $Groups) {
        Add-LocalGroupMember -Group $group -Member $Name
    }
    Write-AdminLog -Message "User created: $Name" -Level INFO -FunctionName 'New-AdminUser'
    Write-Host "User $Name created successfully"
}

function Set-AdminUserState {
    <#
    .SYNOPSIS
        Enables or disables a local user account
    
    .DESCRIPTION
        Changes the enabled state of a local user account. Includes validation and logging.
    
    .PARAMETER State
        Specifies whether to enable or disable the account
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .EXAMPLE
        Set-AdminUserState -Name "john.doe" -State Disable
        
        Disables the user account
    
    .EXAMPLE
        Set-AdminUserState -Name "jane.smith" -State Enable
        
        Enables the user account
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Changes user state and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [ValidateSet("Enable","Disable")]
        [string]$State = "Enable",

        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Set-AdminUserState'
        throw "User '$Name' not found"
    }

    if ($State -eq "Enable" -and $user.Enabled) {
        Write-Host "User already enabled"
        return
    } elseif ($State -eq "Disable" -and -not $User.Enabled) {
        Write-Host "User already disabled"
        return
    }

    if ($State -eq "Enable") {
        Enable-LocalUser -Name $Name
    } else {
        Disable-LocalUser -Name $Name
    }

    Write-AdminLog -Message "User $Name has been $State" -Level INFO -FunctionName 'Set-UserState'
    Write-Host "User $Name now $State"
    
}


function Remove-AdminUser {
    <#
    .SYNOPSIS
        Removes a local user account
    
    .DESCRIPTION
        Removes the specified local user account. Includes protection against system account deletion
        and confirmation prompt (unless -Force is specified).
    
    .PARAMETER Name
        Specifies the username to remove. This parameter is mandatory.
    
    .PARAMETER Force
        Skips confirmation prompt
    
    .EXAMPLE
        Remove-AdminUser -Name "temp.user"
        
        Removes the user with confirmation
    
    .EXAMPLE
        Remove-AdminUser -Name "old.account" -Force
        
        Forcefully removes the user without confirmation
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Removes user account and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [switch]$Force
    )

    $ProtectedUsers = @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount")

    if ($Name -in $ProtectedUsers) {
        Write-AdminLog -Message "Attempt to remove protected user '$Name'." -Level WARNING -FunctionName 'Remove-AdminUser'
        throw "User $Name is a system account and cannot be removed."
    }

    $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    Write-AdminLog -Message "Attempt to remove user '$Name'." -Level INFO -FunctionName 'Remove-AdminUser'
    if (-not $User) {
        Write-AdminLog -Message "User $Name not found." -Level WARNING -FunctionName 'Remove-AdminUser'
        throw "User $Name not found."
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to remove user $Name? (Y/N)"
        if ($confirm -notin @("Y","y")) {
            Write-AdminLog "Removin User '$Name' operation cancelled." -Level INFO -FunctionName 'Remove-AdminUser'
            Write-Host "Operation cancelled."
            return
        }
    }
    Remove-LocalUser -Name $Name
    Write-AdminLog -Message "User '$Name' has been removed." -Level INFO -FunctionName 'Remove-AdminUser'
    Write-Host "User '$Name' has been removed."
}

function Set-AdminUserInfo {
    <#
    .SYNOPSIS
        Sets user account information
    
    .DESCRIPTION
        Updates user account properties such as full name and description.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .PARAMETER FullName
        Specifies the full name for the user
    
    .PARAMETER Description
        Specifies the description for the user
    
    .EXAMPLE
        Set-AdminUserInfo -Name "john.doe" -FullName "John Doe" -Description "Sales Department"
        
        Updates user information
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        PSCustomObject. Returns updated user information.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [string]$FullName,
        [string]$Description

    )
    begin {
        $SetParams = @{}
        $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

        if (-not $User) {
            Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Set-AdminUserInfo'
            throw "User '$Name' not found"
        }

        if (-not ($PSBoundParameters.ContainsKey("FullName") -or $PSBoundParameters.ContainsKey("Description"))) {
            Write-Host "Nothing to change"
            return
        }
    }
    process {
        if ($PSBoundParameters.ContainsKey("FullName")) {$SetParams["FullName"] = $FullName}
        if ($PSBoundParameters.ContainsKey("Description")) {$SetParams["Description"] = $Description}

        Set-LocalUser -Name $Name @SetParams

        $UpdatedUser = Get-LocalUser -Name $Name
        $UpdatedUser | Select-Object Name, FullName, Description | Format-List
    }
}

function Reset-AdminUserPassword {
    <#
    .SYNOPSIS
        Resets a user's password
    
    .DESCRIPTION
        Resets the password for the specified user account. Includes secure password prompt.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .EXAMPLE
        Reset-AdminUserPassword -Name "john.doe"
        
        Resets password for the user
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Resets password and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    begin {
        $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

        if (-not $User) {
            Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Reset-AdminUserPassword'
            throw "User '$Name' not found"
        }
    }
    process {
        $Password = Read-Host -AsSecureString "Enter new Password for $Name :"

        Set-LocalUser -Name $Name -Password $Password
        Write-AdminLog -Message "Password for '$Name' has been reset" -Level INFO -FunctionName 'Reset-AdminUserPassword'
        Write-Host "Password for '$Name' has been reset"
    }
}

#=====================================================
#Module Security & Logs
function Get-AdminEvent {
    <#
    .SYNOPSIS
        Gets Windows event log entries with filtering options
    
    .DESCRIPTION
        Retrieves events from Windows security log with advanced filtering capabilities.
        Supports filtering by user, event ID, time range, and failed logon events.
    
    .PARAMETER UserName
        Filters events by username
    
    .PARAMETER LastDays
        Number of days to look back. Default is 1 day.
    
    .PARAMETER EventID
        Filters by specific event IDs
    
    .PARAMETER MaxLenMessage
        Maximum length of message to return. Default is 250 characters.
    
    .PARAMETER FailedLogon
        Filters for failed logon events (Event ID 4625)
    
    .EXAMPLE
        Get-AdminEvent -LastDays 7
        
        Returns events from last 7 days
    
    .EXAMPLE
        Get-AdminEvent -UserName "john.doe" -EventID 4625 -FailedLogon
        
        Returns failed logon events for specific user
    
    .OUTPUTS
        PSCustomObject. Returns event log entries.
    
    .NOTES
        Author: Gwill1337
        Requires: Read access to security log
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [string]$UserName,
        [int]$LastDays = 1,
        [int[]]$EventID,
        [int]$MaxLenMessage = 250,

        [switch]$FailedLogon
    )
    
    $StartTime = (Get-Date).AddDays(-$LastDays)

    $FilterHash = @{
        LogName = 'Security'
        StartTime = $StartTime
    }

    if ($EventID) {
        $FilterHash.ID = $EventID
    }
    if ($FailedLogon) {
        $FilterHash.ID = 4625
    }

    $events = Get-WinEvent -FilterHashtable $FilterHash

    Write-Verbose "Found $($events.Count) events in the last $LastDays days"


    if ($UserName) {
        $events = $events | Where-Object {
            $uname = if ($_.Properties.Count -ge 6 -and $_.Properties[5].Value){
                        $_.Properties[5].Value
                    } else { "" }
            $uname -eq $UserName -or $_.Message -match $UserName
        }
    }

    $events | ForEach-Object {
        $UserNameSafe =  if ($_.Properties.Count -ge 6 -and $_.Properties[5].Value) {
                            $_.Properties[5].Value
                        } else {
                            "System / N/A"
                        }
        Write-Verbose "Processing EventID $($_.Id) User: $UserNameSafe"
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID     = $_.Id
            UserName    = $UserNameSafe
            EventType   = $_.LevelDisplayName
            Message     = $_.Message.Substring(0,[math]::Min($MaxLenMessage, $_.Message.Length))
        }

    }
    Write-AdminLog -Message "Function 'Get-AdminEvent' was used." -Level INFO -FunctionName 'Get-AdminEvent'
}


function Get-AdminInstalledUpdates {
    <#
    .SYNOPSIS
        Gets information about installed Windows updates
    
    .DESCRIPTION
        Retrieves information about installed hotfixes and updates.
        Supports filtering by date, update type, and computer name.
    
    .PARAMETER SinceDate
        Filters updates installed since specified date
    
    .PARAMETER Type
        Filters by update type (e.g., "Security Update", "Update")
    
    .PARAMETER ComputerName
        Gets updates from remote computers
    
    .PARAMETER SortByDate
        Sorts results by installation date
    
    .EXAMPLE
        Get-AdminInstalledUpdates -SinceDate (Get-Date).AddDays(-30)
        
        Returns updates installed in last 30 days
    
    .EXAMPLE
        Get-AdminInstalledUpdates -Type "Security Update" -SortByDate
        
        Returns security updates sorted by date
    
    .OUTPUTS
        PSCustomObject. Returns update information.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    param (
        [datetime]$SinceDate,
        [string]$Type,
        [string[]]$ComputerName,
        [switch]$SortByDate
    )
    
    $updates = Get-HotFix

    if ($ComputerName) {
        $updates = Get-HotFix -ComputerName $ComputerName
    }

    if ($SinceDate) {
        $updates = $updates | Where-Object {$_.InstalledOn -ge $SinceDate}
    }
    if ($Type) {
        $updates = $updates | Where-Object {$_.Description -eq $Type}
    }
    if ($SortByDate) {
        $updates = $updates | Sort-Object -Property InstalledOn
    }

    $updates | ForEach-Object {
        [PSCustomObject]@{
            Computer      = $_.PSComputerName
            Description   = $_.Description
            ID            = $_.HotFixID
            InstalledBy   = $_.InstalledBy
            InstalledTime = $_.InstalledOn
        }
    }
    Write-AdminLog -Message "Function 'Get-AdminInstalledUpdates' was used." -Level INFO -FunctionName 'Get-AdminInstalledUpdates'
}

#=====================================================
#Module NetWork-Tools
function Test-AdminHost {
    <#
    .SYNOPSIS
        Tests network connectivity to a host
    
    .DESCRIPTION
        Performs ping tests to check network connectivity to specified host.
        Returns detailed information about response times and status.
    
    .PARAMETER HostName
        Specifies the hostname or IP address to test. This parameter is mandatory.
    
    .PARAMETER Count
        Number of ping attempts. Default is 4.
    
    .PARAMETER Timeout
        Timeout in milliseconds. Default is 2000ms.
    
    .EXAMPLE
        Test-AdminHost -HostName "google.com"
        
        Tests connectivity to google.com
    
    .EXAMPLE
        Test-AdminHost -HostName "server01" -Count 8 -Timeout 3000
        
        Tests with 8 attempts and 3 second timeout
    
    .OUTPUTS
        PSCustomObject. Returns connectivity test results.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [int]$Count = 4,

        [int]$Timeout = 2000

    )
        begin {
        if (-not $HostName) {
            Write-AdminLog -Message "Host name is required." -Level WARNING -FunctionName 'Test-AdminHost'
            throw "Host name is required."
        }
        if ($Count -le 0 -or $Timeout -le 0) {
            Write-AdminLog -Message "Count and Timeout must be greater than zero." -Level WARNING -FunctionName 'Test-AdminHost'
            throw "Count and Timeout must be greater than zero."
        }    
    }
    process {
        
        try {
            $PingResult = Test-Connection -ComputerName $HostName -Count $Count -TimeoutSeconds  ($Timeout / 1000) -ErrorAction Stop
            $Reachable = $true
        }
        catch {
            $Reachable = $false
        }

        if ($Reachable) {
            Write-Host "Host $HostName is reachable." -ForegroundColor Green
            
            $avgTime = ($PingResult | Measure-object -Property ResponseTime -Average).Average
            Write-Verbose "Average Response Time: $([math]::Round($avgTime,2)) ms."
            
        } else {
            Write-Host "Host $HostName is not reachable." -ForegroundColor Red
        }
    }
    end {
        Write-AdminLog -Message "Function 'Test-AdminHost' was used." -Level INFO -FunctionName 'Test-AdminHost'
        return [PSCustomObject]@{
            HostName = $HostName
            Status = if ($Reachable) {"Reachable"} else {"Not reachable"}
            AvgResponseTime = if ($Reachable) {($PingResult | Measure-object -Property ResponseTime -Average).Average} else {$null}
        }
    }
}


function Test-AdminPort {
    <#
    .SYNOPSIS
        Tests TCP port connectivity
    
    .DESCRIPTION
        Tests whether a specific TCP port is open on a remote computer.
        Provides detailed network connection information.
    
    .PARAMETER ComputerName
        Specifies the computer name or IP address. This parameter is mandatory.
    
    .PARAMETER Port
        Specifies the TCP port to test. This parameter is mandatory.
    
    .EXAMPLE
        Test-AdminPort -ComputerName "google.com" -Port 443
        
        Tests if port 443 is open on google.com
    
    .EXAMPLE
        Test-AdminPort -ComputerName "myserver" -Port 3389
        
        Tests if RDP port is open on server
    
    .OUTPUTS
        PSCustomObject. Returns port test results.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    begin {
        if (-not $ComputerName) {
            Write-AdminLog -Message "Host name is required." -Level WARNING -FunctionName 'Test-AdminPort'
            throw "Host name is required."
        }

        if ($Port -lt 1 -or $Port -gt 65535) {
            Write-AdminLog -Message "Port $Port must be between 1 and 65535" -Level WARNING -FunctionName 'Test-AdminPort'
            throw "Port $Port must be between 1 and 65535"
        }
    }
    process {
        try {
            $Result = Test-NetConnection -ComputerName $ComputerName -Port $Port -InformationLevel Detailed
            $Open = $Result.TcpTestSucceeded
        }
        catch {
            $Open = $false
        }
        

        if ($open) {
            Write-AdminLog -Message "Port $Port on $ComputerName is open." -Level INFO -FunctionName 'Test-AdminPort'
            Write-Host "Port $Port on $ComputerName is open." -ForegroundColor Green
        } else {
            Write-AdminLog -Message "Port $Port on $ComputerName is closed." -Level INFO -FunctionName 'Test-AdminPort'
            Write-Host "Port $Port on $ComputerName is closed." -ForegroundColor Red
        }

        Write-Verbose "Remote Address: $($Result.RemoteAddress)"
        Write-Verbose "Ping Succeeded: $($Result.PingSucceeded)"
        Write-Verbose "TcpTestSucceeded: $($Result.TcpTestSucceeded)"
        Write-Verbose "RoundTripTime: $($Result.RoundTripTime) ms"
    }
    end {
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Port = $Port
            Status = if ($Open) {"Open"} else {"Closed"}
            RemoteAddress = $Result.RemoteAddress
            TcpTestSucceeded = $Result.TcpTestSucceeded
        }
    }
}

function Get-AdminNetworkAdapters {
    <#
    .SYNOPSIS
        Gets network adapter information
    
    .DESCRIPTION
        Retrieves information about network adapters on the system.
        Can filter to show only adapters that are up.
    
    .PARAMETER Uponly
        Shows only network adapters that are in 'Up' state
    
    .EXAMPLE
        Get-AdminNetworkAdapters
        
        Returns all network adapters
    
    .EXAMPLE
        Get-AdminNetworkAdapters -Uponly
        
        Returns only active network adapters
    
    .OUTPUTS
        None. Displays adapter information to console.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [switch]$Uponly
    )

    $adapters = Get-NetAdapter
    if ($Uponly) {
        $adapters = $adapters | Where-Object {$_.Status -eq "Up"}
    }
    
    foreach ($adapter in $adapters) {
        Write-Verbose "Name: $($adapter.Name), Status: $($adapter.Status), Mac: $($adapter.MacAddress), Speed: $($adapter.LinkSpeed)"
        Write-Host "Name: $($adapter.Name), Status: $($adapter.Status)"
    }
    Write-AdminLog -Message "Function 'Get-AdminNetworkAdapters' was used." -Level INFO -FunctionName 'Get-AdminNetworkAdapters'
}

function Get-AdminNetworkIP {
    <#
    .SYNOPSIS
        Gets IP address information
    
    .DESCRIPTION
        Retrieves IP address configuration for network interfaces.
        Supports filtering by interface, IP version, and address family.
    
    .PARAMETER InterfaceAlias
        Filters by specific network interface
    
    .PARAMETER IPv4Only
        Shows only IPv4 addresses
    
    .PARAMETER IPv6Only
        Shows only IPv6 addresses
    
    .EXAMPLE
        Get-AdminNetworkIP
        
        Returns all IP addresses
    
    .EXAMPLE
        Get-AdminNetworkIP -IPv4Only -InterfaceAlias "Ethernet"
        
        Returns IPv4 addresses for Ethernet interface
    
    .OUTPUTS
        PSCustomObject. Returns IP address information.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [string]$InterfaceAlias,
        [switch]$IPv4Only,
        [switch]$IPv6Only
    )


    if ($PSBoundParameters.ContainsKey("InterfaceAlias")) {
        $addresses = Get-NetIPAddress -InterfaceAlias $InterfaceAlias
    } else {
        $addresses = Get-NetIPAddress
    }
    
    if ($IPv4Only) {
        $addresses = $addresses | Where-Object {$_.AddressFamily -eq "IPv4"}
    } elseif ($IPv6Only) {
        $addresses = $addresses | Where-Object {$_.AddressFamily -eq "IPv6"}
    }

    foreach ($address in $addresses) {
        Write-Verbose "IPAddress: $($address.IPAddress) on Interface: $($address.InterfaceAlias), AddressFamily: $($address.AddressFamily), PrefixLength: $($address.PrefixLength)"
        Write-Verbose "---------------------------------------------------------------------------------------"

        [PSCustomObject]@{
            IPAddress = $address.IPAddress
            InterfaceAlias = $address.InterfaceAlias
            AddressFamily = $address.AddressFamily
            PrefixLength = $address.PrefixLength
        }
    }
    Write-AdminLog -Message "Function 'Get-AdminNetworkIP' was used." -Level INFO -FunctionName 'Get-AdminNetworkIP'
}

#=====================================================
#Module Automation
function Register-AdminTask {
    <#
    .SYNOPSIS
        Registers a scheduled task
    
    .DESCRIPTION
        Creates a new scheduled task with various trigger options.
        Supports daily, hourly, and logon triggers with custom credentials.
    
    .PARAMETER TaskName
        Specifies the task name. This parameter is mandatory.
    
    .PARAMETER ScriptPath
        Specifies the script path to execute. This parameter is mandatory.
    
    .PARAMETER TriggerType
        Specifies the trigger type: Daily, Hourly, or AtLogon
    
    .PARAMETER TriggerTime
        Specifies the time for daily triggers
    
    .PARAMETER User
        Specifies the user account to run the task
    
    .PARAMETER Password
        Specifies the password for the user account
    
    .PARAMETER RepeatInterval
        Specifies repetition interval for hourly triggers
    
    .PARAMETER Executable
        Specifies the executable to use
    
    .EXAMPLE
        Register-AdminTask -TaskName "DailyBackup" -ScriptPath "C:\Scripts\backup.ps1" -TriggerType Daily -TriggerTime "23:00"
        
        Creates daily backup task at 11 PM
    
    .INPUTS
        None. You cannot pipe input to this function.
    
    .OUTPUTS
        None. Creates scheduled task and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TaskName,

        [Parameter(Mandatory=$true)]
        [string]$ScriptPath,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Daily","Hourly","AtLogon")]
        [string]$TriggerType,

        [datetime]$TriggerTime,

        [string]$User = "SYSTEM",

        [string]$Password,

        [timespan]$RepeatInterval,

        [string]$Executable = "pwsh.exe"
    )
    
    begin {
        if ($Password) {
            $SecurePass = ConvertTo-SecureString $Password -AsPlainText -Force
        }
        if ($User -ne "SYSTEM" -and -not $Password) {
            Write-AdminLog -Message "For user not SYSTEM required password." -Level WARNING -FunctionName 'Register-AdminTask'
            throw "For user not SYSTEM required password."
        }
        if (-not (Test-Path $ScriptPath)) {
            Write-AdminLog -Message "File $ScriptPath not found." -Level WARNING -FunctionName 'Register-AdminTask'
            throw "File $ScriptPath not found."
        }
        if (-not (Get-Command $Executable -ErrorAction SilentlyContinue)) {
            Write-AdminLog -Message "Executable '$Executable' not found." -Level WARNING -FunctionName 'Register-AdminTask'
            throw "Executable '$Executable' not found."
        }
        if ($TriggerType -eq "Daily" -and -not $TriggerTime) {
            Write-AdminLog -Message "For trigger Daily need to specify a parameter -TriggerTime." -Level WARNING -FunctionName 'Register-AdminTask'
            throw "For trigger Daily need to specify a parameter -TriggerTime."
        }
        if ($TriggerType -eq "Hourly" -and -not $RepeatInterval) {
            $RepeatInterval = New-TimeSpan -Hours 1
        }

        $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Warning "Task with name '$TaskName' already exist and will be overwritten."
        }
    }

    process {
        $action = New-ScheduledTaskAction -Execute $Executable -Argument "-File $ScriptPath"

        if ($TriggerType -eq "Daily") {
            $trigger = New-ScheduledTaskTrigger -Daily -At $TriggerTime
        }
        if ($TriggerType -eq "Hourly") {
            $trigger = New-ScheduledTaskTrigger -RepetitionInterval $RepeatInterval
        }
        if ($TriggerType -eq "AtLogon") {
            $trigger = New-ScheduledTaskTrigger -AtLogon
        }
        
        if ($User -eq "SYSTEM") {
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
        } else {
            $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Password -Password $SecurePass
        }
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force

    }
    
    end {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-AdminLog -Message "Task '$TaskName' created successfully." -Level DEBUG -FunctionName 'Register-AdminTask'
            Write-Output "Task '$TaskName' created successfully."
        } else {
            Write-AdminLog -Message "Task '$TaskName' not created." -Level ERROR -FunctionName 'Register-AdminTask'
            Write-Warning "Task '$TaskName' not created."
        }
    }
}

function Remove-AdminTask {
    <#
    .SYNOPSIS
        Removes a scheduled task
    
    .DESCRIPTION
        Removes the specified scheduled task from Task Scheduler.
    
    .PARAMETER TaskName
        Specifies the task name to remove. This parameter is mandatory.
    
    .EXAMPLE
        Remove-AdminTask -TaskName "OldTask"
        
        Removes the specified task
    
    .INPUTS
        String. You can pipe task names to this function.
    
    .OUTPUTS
        None. Removes task and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$TaskName
    )
    
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-AdminLog -Message "Task '$TaskName' removed successfully" -Level INFO -FunctionName 'Remove-AdminTask'
        Write-Output "Task '$TaskName' removed successfully."
    } else {
        Write-AdminLog -Message "Task '$TaskName' not found." -Level WARNING -FunctionName 'Remove-AdminTask'
        Write-Warning "Task '$TaskName' not found."
    }
}

function Send-AdminReport {
    <#
    .SYNOPSIS
        Sends administrative reports via email
    
    .DESCRIPTION
        Generates and sends reports in various formats (CSV, JSON, HTML) via email.
        Supports including user, service, and update information.
    
    .PARAMETER ReportName
        Specifies the report name. This parameter is mandatory.
    
    .PARAMETER Format
        Specifies the report format: CSV, JSON, or HTML
    
    .PARAMETER Recipient
        Specifies the email recipient
    
    .PARAMETER fSender
        Specifies the sender email address
    
    .PARAMETER SmtpServer
        Specifies the SMTP server
    
    .PARAMETER IncludeUsers
        Includes user information in the report
    
    .PARAMETER IncludeServices
        Includes service information in the report
    
    .PARAMETER InclideUpdates
        Includes update information in the report
    
    .EXAMPLE
        Send-AdminReport -ReportName "WeeklyReport" -Format HTML -Recipient "admin@company.com" -IncludeUsers -IncludeServices
        
        Sends HTML report with user and service information
    
    .INPUTS
        None. You cannot pipe input to this function.
    
    .OUTPUTS
        None. Generates and sends report.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ReportName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("CSV","JSON","HTML")]
        [string]$Format,

        [string]$Recipient,
        
        [string]$fSender = "$($env:USERNAME)@localhost",
        [string]$SmtpServer,

        [switch]$IncludeUsers,
        [switch]$IncludeServices,
        [switch]$InclideUpdates
    )
    
    begin {
        $files = @()
        $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $fileName = "$ReportName-$timestamp.$Format"
        $filePath = Join-Path -Path "C:\Temp" -ChildPath $fileName

        if (-not (Test-Path "C:\Temp")) {
            Write-AdminLog -Message "Directory was created at path C:\Temp" -Level DEBUG -FunctionName 'Send-AdminReport'
            New-Item -Path "C:\Temp" -ItemType Directory -Force
        }
        
    }
    
    process {
        if ($PSBoundParameters.ContainsKey("CSV")) {
            if ($IncludeUsers) {
                $users = Get-LocalUser | Select-Object Name,Enabled
                $users | Export-Csv $filePath -NoTypeInformation -Force
                $files += $filePath
            }
            if ($IncludeServices) {
                $services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
                $services | Export-Csv $filePath -NoTypeInformation -Force
                $files += $filePath
            }
            if ($InclideUpdates) {
                $updates = Get-HotFix | Select-Object HotFixID,Description,InstalledOn
                $updates | Export-Csv $filePath -NoTypeInformation -Force
                $files += $filePath
            }
            Write-AdminLog -Message "CSV Report was created at path '$filePath'" -Level DEBUG -FunctionName 'Send-AdminReport'
        } elseif ($PSBoundParameters.ContainsKey("HTML")) {
            $files = "<h1>$ReportName Report</h1>"
            if ($IncludeUsers) {
                $users = Get-LocalUser | Select-Object Name,Enabled
                $files += "<h2>Users</h2>" + ($users | ConvertTo-Html -Fragment)
            }
            if ($IncludeServices) {
                $services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
                $files += "<h2>Services</h2>" + ($services | ConvertTo-Html -Fragment)
            }
            if ($InclideUpdates) {
                $updates = Get-HotFix | Select-Object HotFixID,Description,InstalledOn
                $files += "<h2>Updates</h2>" + ($updates | ConvertTo-Html -Fragment)
            }
            Write-AdminLog -Message "HTML Report was created at path '$filePath'" -Level DEBUG -FunctionName 'Send-AdminReport'
            $files | Out-File $filePath
        } else {
            $files = @{}
             if ($IncludeUsers) {
                $users = Get-LocalUser | Select-Object Name,Enabled
                $files.Users += $users
            }
            if ($IncludeServices) {
                $services = Get-Service -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
                $files.Service += $services
            }
            if ($InclideUpdates) {
                $updates = Get-HotFix | Select-Object HotFixID,Description,InstalledOn
                $files.Updates += $updates
            }
            Write-AdminLog -Message "JSON Report was created at path '$filePath'" -Level DEBUG -FunctionName 'Send-AdminReport'
            $files| ConvertTo-Json | Out-File $filePath -Force
        }
    }
    
    end {
        Write-Output "Report Generated in $filePath"
        if ($Recipient) {
            Send-MailMessage -To $Recipient -From $fSender -Subject "Admin Report: $ReportName" `
                         -Body "Report generated at $(Get-Date)" -SmtpServer $SmtpServer `
                         -Attachments $files
        Write-AdminLog -Message "Report sent to '$Recipient': '$filePath'" -Level INFO -FunctionName 'Send-AdminReport'
        Write-Output "Report sent to '$Recipient': '$filePath'"
        }
    }
}

#=====================================================
#Module Remote-Admin
function Invoke-AdminRemoteCommand {
    <#
    .SYNOPSIS
        Executes commands on remote computers
    
    .DESCRIPTION
        Executes PowerShell scriptblocks on one or more remote computers.
        Supports credentials, throttling, and error handling.
    
    .PARAMETER ComputerName
        Specifies the remote computers. This parameter is mandatory.
    
    .PARAMETER Scriptblock
        Specifies the scriptblock to execute. This parameter is mandatory.
    
    .PARAMETER Credential
        Specifies credentials for remote access
    
    .PARAMETER ThrottleLimit
        Specifies the maximum number of concurrent connections
    
    .PARAMETER fErrorAction
        Specifies error action preference
    
    .EXAMPLE
        Invoke-AdminRemoteCommand -ComputerName "Server01", "Server02" -Scriptblock { Get-Service }
        
        Gets services from multiple servers
    
    .EXAMPLE
        $cred = Get-Credential
        Invoke-AdminRemoteCommand -ComputerName "Server01" -Scriptblock { Get-Process } -Credential $cred
        
        Gets processes from server with credentials
    
    .OUTPUTS
        PSCustomObject. Returns remote execution results.
    
    .NOTES
        Author: Gwill1337
        Requires: PowerShell Remoting enabled on target computers
        Version: 1.0.0
    #>
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
    <#
    .SYNOPSIS
        Gets system information from remote computers
    
    .DESCRIPTION
        Retrieves comprehensive system information from one or more remote computers.
        Supports the same detail levels as Get-AdminHostInfo.
    
    .PARAMETER DetailLevel
        Specifies the level of detail: Basic, Detailed, or Full
    
    .PARAMETER Show
        Displays formatted output instead of returning objects
    
    .PARAMETER ComputerName
        Specifies the remote computers. This parameter is mandatory.
    
    .PARAMETER Credential
        Specifies credentials for remote access
    
    .PARAMETER fErrorAction
        Specifies error action preference
    
    .PARAMETER ThrottleLimit
        Specifies the maximum number of concurrent connections
    
    .EXAMPLE
        Get-AdminRemoteInfo -ComputerName "Server01" -DetailLevel Full
        
        Gets full system information from server
    
    .EXAMPLE
        Get-AdminRemoteInfo -ComputerName @("Server01", "Server02") -DetailLevel Basic -Show
        
        Displays basic information from multiple servers
    
    .OUTPUTS
        PSCustomObject. Returns remote system information.
    
    .NOTES
        Author: Gwill1337
        Requires: PowerShell Remoting enabled on target computers
        Version: 1.0.0
    #>
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
                    $network = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPAddress -ne $null}

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

#=====================================================
#Module Logger
function Write-AdminLog {
    <#
    .SYNOPSIS
        Writes log entries to text and JSON log files
    
    .DESCRIPTION
        Writes structured log entries to both text-based and JSON log files.
        Supports multiple log levels and automatic directory creation.
    
    .PARAMETER Message
        Specifies the log message. This parameter is mandatory.
    
    .PARAMETER Level
        Specifies the log level: DEBUG, INFO, WARNING, ERROR
    
    .PARAMETER LogFile
        Specifies the text log file path
    
    .PARAMETER JsonFile
        Specifies the JSON log file path
    
    .PARAMETER FunctionName
        Specifies the function name for logging context
    
    .EXAMPLE
        Write-AdminLog -Message "Application started" -Level INFO -FunctionName "MainScript"
        
        Writes info level log entry
    
    .EXAMPLE
        Write-AdminLog -Message "Error occurred" -Level ERROR -FunctionName "ProcessData"
        
        Writes error level log entry
    
    .INPUTS
        String. You can pipe log messages to this function.
    
    .OUTPUTS
        None. Writes to log files.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet("DEBUG","INFO","WARNING","ERROR")]
        [string]$Level = "INFO",

        [string]$LogFile = "C:\Logs\AdminTools.log",

        [string]$JsonFile = "C:\Logs\AdminTools.json",

        [string]$FunctionName
    )
    
    begin {
        foreach ($file in @($LogFile, $JsonFile)) {
            $logDir = Split-Path $file -Parent
        if (-not(Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
        if (-not(Test-Path $file)) {
            New-Item -Path $file -ItemType File -Force | Out-Null
            }
        }
    }
    
    process {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $entry = "[$timestamp] [User: $env:USERNAME] [$Level] [ComputerName: $env:COMPUTERNAME] [Message: $Message] [Function: $FunctionName]" 
        Add-Content -Path $LogFile -Value $entry

        $LogEntry = [PSCustomObject]@{
            Timestamp = $timestamp
            User = $env:USERNAME
            Level = $Level
            Function = $FunctionName
            Message = $Message
            ComputerName = $env:COMPUTERNAME
        }

        $jsonData = @()

        if (Test-Path $JsonFile) {
            try {
                $content = Get-Content $JsonFile -Raw -ErrorAction Stop
                if ($content.Trim() -ne "") {
                    $jsonData = $content | ConvertFrom-Json -ErrorAction Stop

                    if ($jsonData -isnot [array]) {
                        $jsonData = @($jsonData)
                    }
                }
            }
            catch {
                Write-Warning "Json log not found. creating new: "#$_
                $jsonData = @()
            }
        }
        $jsonData += $LogEntry
        $jsonData | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonFile -Force
    }
}

function Get-AdminLog {
    <#
    .SYNOPSIS
        Retrieves and filters log entries
    
    .DESCRIPTION
        Retrieves log entries from text or JSON log files with filtering capabilities.
        Supports filtering by log level, time range, and log type.
    
    .PARAMETER Type
        Specifies the log type: JSON or LOG
    
    .PARAMETER Level
        Filters by log level
    
    .PARAMETER After
        Filters entries after specified datetime
    
    .PARAMETER Before
        Filters entries before specified datetime
    
    .PARAMETER LogFile
        Specifies the text log file path
    
    .PARAMETER JsonFile
        Specifies the JSON log file path
    
    .EXAMPLE
        Get-AdminLog -Type JSON -Level ERROR -After (Get-Date).AddDays(-1)
        
        Gets error entries from JSON log for last day
    
    .EXAMPLE
        Get-AdminLog -Type LOG -Before (Get-Date).AddHours(-1)
        
        Gets entries from text log before last hour
    
    .OUTPUTS
        PSCustomObject. Returns log entries.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("JSON","LOG")]
        [string]$Type,

        [ValidateSet("DEBUG","INFO","WARNING","ERROR")]
        [string]$Level,
        
        [datetime]$After,
        [datetime]$Before,

        [string]$LogFile = "C:\Logs\AdminTools.log",
        [string]$JsonFile = "C:\Logs\AdminTools.json"
    )
    process {
        switch ($Type.ToUpper()) {
            "LOG" {
                if (Test-Path $LogFile) {
                    $lines = Get-Content $LogFile

                    if ($Level) {
                        $lines = $lines | Where-Object {$_ -match "\[$Level\]"}
                    }

                    if ($After -or $Before) {
                        $lines = $lines | Where-Object {
                            if ($_ -match "\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]") {
                                $ts = [datetime]::Parse($matches[1])
                                (!($After) -or $ts -ge $After) -and (!($Before) -or $ts -le $Before)
                            }
                        }
                    }
                    Write-AdminLog -Message "Showed Log file '$LogFile'." -Level INFO -FunctionName 'Get-AdminLog'
                    $lines
                } else {
                    Write-AdminLog -Message "Log file '$LogFile' not found." -Level WARNING -FunctionName 'Get-AdminLog'
                    Write-Warning "Log file '$LogFile' not found."
                }
            }
            "JSON" {
                if (Test-Path $JsonFile) {
                    $raw = Get-Content $JsonFile -Raw
                    if ($raw -and $raw.Trim() -ne "") {
                        $json = $raw | ConvertFrom-Json

                        if ($Level) {
                            $json = $json | Where-Object {$_.Level -eq $Level}
                        }
                        if ($After) {
                            $json = $json | Where-Object {[datetime]$_.Timestamp -ge $After}
                        }
                        if ($Before) {
                            $json = $json | Where-Object {[datetime]$_.Timestamp -le $Before}
                        }

                        $json | Format-Table Timestamp, User, Level, Function, Message, ComputerName -AutoSize
                    } else {
                        Write-Warning "Json file '$JsonFile' empty."
                    }
                } else {
                    Write-Warning "Json file '$JsonFile' not found."
                }
            }
        }
    }
}


function Start-AdminLoggerObject {
    <#
    .SYNOPSIS
        Monitors file system changes and logs them
    
    .DESCRIPTION
        Sets up file system watcher to monitor directory changes and log them.
        Tracks file creations, modifications, deletions, and renames.
    
    .PARAMETER Path
        Specifies the directory path to monitor. This parameter is mandatory.
    
    .PARAMETER LogDir
        Specifies the directory for log files
    
    .EXAMPLE
        Start-AdminLoggerObject -Path "C:\ImportantFiles"
        
        Starts monitoring important files directory
    
    .EXAMPLE
        Start-AdminLoggerObject -Path "D:\Projects" -LogDir "C:\Logs\FileMonitoring"
        
        Starts monitoring with custom log directory
    
    .INPUTS
        String. You can pipe directory paths to this function.
    
    .OUTPUTS
        None. Starts monitoring in background.
    
    .NOTES
        Author: Gwill1337
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param (
        [string]$Path,
        [string]$LogDir = "C:\Logs"
    )
    
    begin {
        if (-not (Test-Path $Path)) {
            throw "Path $Path not found"
        }
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir | Out-Null
        }

        $LogFileTxt = Join-Path $LogDir "logObject.log"
        $LogFileJson = Join-Path $LogDir "logObject.json"

        if (! (Test-Path $LogFileJson)) {
            @() | ConvertTo-Json | Set-Content $LogFileJson -Encoding utf8
        }
        $Global:AdminLoggerTxtPath = $LogFileTxt
        $Global:AdminLoggerJsonPath = $LogFileJson
    }
    
    process {
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = (Get-Item $Path).FullName
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true
        $watcher.NotifyFilter = [IO.NotifyFilters]'FileName, DirectoryName, LastWrite, Size'

        $action = {
            param($source, $feventArgs)

            $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            $user = $env:USERNAME
            $computer = $env:COMPUTERNAME
            $fevent = $feventArgs.changeType
            $file = $feventArgs.FullPath

            $msg = "$timestamp [$fevent] $file by $user@$computer"

            Add-Content -Path $Global:AdminLoggerTxtPath -Value $msg

            try {
                $jsonData = Get-Content $Global:AdminLoggerJsonPath -Raw | ConvertFrom-Json
            }
            catch {
                $jsonData = @()
            }

            if ($null -eq $jsonData) {
                $jsonData = @()
            }
            if ($jsonData -isnot [System.Collections.IEnumerable] -or $jsonData -is [string]) {
                $jsonData = @($jsonData)
            }

            $entry = [PSCustomObject]@{
            Timestamp    = $timestamp
            User         = $env:USERNAME
            ComputerName = $computer
            Event        = $fevent
            Path         = $file
        }

        $jsonData += $entry
        $jsonData | ConvertTo-Json -Depth 10 | Set-Content $Global:AdminLoggerJsonPath -Encoding utf8
        }

        $handlers = @()
        $handlers += Register-ObjectEvent -InputObject $watcher -EventName Created -Action $action
        $handlers += Register-ObjectEvent -InputObject $watcher -EventName Changed -Action $action
        $handlers += Register-ObjectEvent -InputObject $watcher -EventName Deleted -Action $action
        $handlers += Register-ObjectEvent -InputObject $watcher -EventName Renamed -Action $action

        Write-Host "Start monitoring: $Path"
        Write-AdminLog -Message "Start monitoring: $Path" -Level INFO -FunctionName 'Start-AdminLoggerObject'
        Write-Host "Log txt: $LogFileTxt"
        Write-Host "Log json: $LogFileJson"


        try {
            while ($true) {
                Start-Sleep -Seconds 1
            }
        }
        finally {
            Write-Host "`nStopping monitor..." -ForegroundColor Yellow
            
            foreach ($h in $handlers) {
                if ($h) {
                    Unregister-Event -SourceIdentifier $h.Name -ErrorAction SilentlyContinue
                }
                $watcher.EnableRaisingEvents = $false
                $watcher.Dispose()
                Write-Host "Monitoring stopped."
            }
        }
    }
}


Export-ModuleMember -Function * -Alias * -Variable *

$Script:ModuleName = 'AdminTools'
$Script:ModuleVersion = '1.0.0'
