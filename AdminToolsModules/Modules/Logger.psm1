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
        
        #$LogEntry | ConvertTo-Json | Add-Content -Path $JsonFile
        #Write-Output $entry
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
