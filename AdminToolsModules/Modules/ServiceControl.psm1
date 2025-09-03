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