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
        #Write-Host "Watch-Service monitoring was successfully started for $Name"
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
