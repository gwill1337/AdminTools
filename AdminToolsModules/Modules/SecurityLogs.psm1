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