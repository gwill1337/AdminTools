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
