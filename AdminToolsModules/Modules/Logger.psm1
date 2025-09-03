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
        
        #$LogEntry | ConvertTo-Json | Add-Content -Path $JsonFile
        #Write-Output $entry
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