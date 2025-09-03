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
