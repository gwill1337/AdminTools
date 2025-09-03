#Module System-Info
function Get-AdminHostInfo {
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