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