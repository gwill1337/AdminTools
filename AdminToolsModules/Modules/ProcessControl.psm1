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