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
