# PSAdminTools
![PowerShell](https://img.shields.io/badge/PowerShell-7.5+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B%20%7C%20Server%202016%2B-0078D4.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.1-orange.svg)

## About
This AdminTools module for windows system administration, has 9 submodules and 25+ functions. Module was created for convenience and security. Module logs actually all of its actions and handles errors.

## Requirements
The module works on version 7.5.2 but actually can work on 5.1+ but some things may not work correctly.

## Usage
Clone repository or download via Powershell Gallery:
   ```powershell
   Install-Module -Name AdminTools
   ```

## Commands/Functions
Some functions has flag "-verbose" for more information about his actions and functions.  
P.s. ***In version 1.0.1 includes help information and examples for all functions*** just write:
```powershell
Get-help Function -Full  #For Full info or -Detailed for detailed info
```
and
```powershell
Get-help Function -Examples  #For Examples
```
Below a few lines about each function and her parameters:
### System-Info:
```powershell
Get-AdminHostInfo  #Gets detailed information about the local system
Parameter: -DetailLevel Basic, Detailed, Full;
Parameter: -Show  #Displays formatted output to console instead of returning objects
```
### Service-Control:
```powershell
Start-AdminService  #Starts a Windows service with additional administrative features
Parameters: -Name; -Force
```
```powershell
Stop-AdminService  #Stops a Windows service with administrative features
Parameters: -Name; -Force
```
```powershell
Restart-AdminService  #Restarts a Windows service with administrative features
Parameters: -Name; -Force
```
```powershell
Watch-AdminService  #Monitors a Windows service and automatically restarts it if it stops
Parameters: -Name; -Force
Parameter: -StopWatch  #Stops the monitoring for the specified service
```
### Process-Control:
```powershell
Get-AdminAllProcesses  #Gets information about running processes with administrative features
Parameter: -Top  #Specifies the number of top processes to return. Default is 10.
Parameter: -SortByCPU  #Sorts processes by CPU usage instead of memory usage
```
```powershell
Stop-AdminProcess  #Stops a running process with administrative features
Parameters: -Name; -Force
```
```powershell
Start-AdminProcessByName  #Starts a process by specifying the executable path
Parameters: -Path; -Arguments
Parameter: -Wait  #Waits for the process to complete before continuing
```
### User-Management:
```powershell
Get-AdminAllUsers  #Gets information about local users
Parameter: -state  #Filters users by their enabled state: All, Enabled, or Disabled
```
```powershell
New-AdminUser
Parameters: -Name; -Groups
```
```powershell
Set-AdminUserState  #Changes the enabled state of a local user account. Includes validation and logging
Parameters: Parameter: -state; -Name
```
```powershell
Remove-AdminUser  #Removes a local user account
Parameters: Parameter: -Force; -Name
```
```powershell
Set-AdminUserInfo  #Sets user account information
Parameters: -Name; -FullName; -Description
```
```powershell
Reset-AdminUserPassword  #Resets a user's password
Parameter: -Name
```
### Security & Logs:

```powershell
Get-AdminEvent  #Gets Windows event log entries with filtering options
Parameters: -UserName; -EventID
Parameter: -LastDays  #Number of days to look back. Default is 1 day.
Parameter: -MaxLenMessage  #Maximum length of message to return. Default is 250 characters.
Parameter:  -FailedLogon  #Filters for failed logon events (Event ID 4625)
```
```powershell
Get-AdminInstalledUpdates  #Gets information about installed Windows updates
Parameter: -ComputerName  #It can Gets updates from remote computers
Parameter: -SinceDate  #Filters updates installed since specified date
Parameter: -Type  # Filters by update type (e.g., "Security Update", "Update")
Parameter: -SortByDate  #Sorts results by installation date
```
### NetWork-Tools:
```powershell
Test-AdminHost  #Tests network connectivity to a host
Parameter: -HostName  #Specifies the hostname or IP address to test. This parameter is mandatory.
Parameter: -Count  #Number of ping attempts. Default is 4.
Parameter: -TimeOut  #Timeout in milliseconds. Default is 2000ms.
Parameter:
```
```powershell
Test-AdminPort  #Tests TCP port connectivity
Parameter: -ComputerName  #Specifies the computer name or IP address. This parameter is mandatory.
Parameter: -Port  #Specifies the TCP port to test. This parameter is mandatory.
```
```powershell
Get-AdminNetworkAdapters  #Gets network adapter information
Parameter: -Uponly  # Shows only network adapters that are in 'Up' state
```
```powershell
Get-AdminNetworkIP  #Gets IP address information
Parameter:  -InterfaceAlias  #Filters by specific network interface
Parameters: -IPv4Only; -IPv6Only  #Shows only IPv4/IPv6 addresses
```
### Automation
```powershell
Register-AdminTask  #Registers a scheduled task
Parameter: -TaskName  #Specifies the task name. This parameter is mandatory.
Parameter: -ScriptPath  #Specifies the script path to execute. This parameter is mandatory. P.S This repo includes 'Send-AdminRemote.ps' which create and/or send reports with info about PC like 'Updates','Users','Services' in CSV/JSON/HTML "About this below". This '.ps' file for this function therefore you can configure schedule for send/creating reports.
Parameter: -TriggerType  #Specifies the trigger type: Daily, Hourly, or AtLogon
Parameter: -TriggerTime  #Specifies the time for daily triggers
Parameter: -User  #Specifies the user account to run the task
Parameter: -Password  #Specifies the password for the user account
Parameter: -RepeatInterval  #Specifies repetition interval for hourly triggers
Parameter: -Executable  #Specifies the executable to use, default 'pwsh.exe'
```
```powershell
Remove-AdminTask  #Removes a scheduled task
Parameter: -TaskName  #Specifies the task name to remove. This parameter is mandatory.
```
```powershell
Send-AdminReport  #Sends administrative reports via email
Parameter: -ReportName  #Specifies the report name. This parameter is mandatory.
Parameter: -Format  #Specifies the report format: CSV, JSON, or HTML
Parameter: -Recipient  #Specifies the email recipient
Parameter: -fSender  #Specifies the sender email address
Parameter: -SmtpServer  #Specifies the SMTP server
Parameter: -IncludeUsers  #Includes user information in the report
Parameter: -IncludeServices  #Includes service information in the report
Parameter: -InclideUpdates  #Includes update information in the report
```
###  Remote-Admin:

```powershell
Invoke-AdminRemoteCommand  #Executes commands on remote computers
Parameter: -ComputerName  #Specifies the remote computers. This parameter is mandatory.
Parameter: -ScriptBlock  #Specifies the scriptblock to execute. This parameter is mandatory.
Parameter: -Credential  #Specifies credentials for remote access
Parameter: -ThrottleLimit  #Specifies the maximum number of concurrent connections
Parameter: -fErrorAction  #Specifies error action preference ("Continue", "Stop", "SilentlyContinue")
```
```powershell
Get-AdminRemoteInfo  #Gets system information from remote computers
Parameter: -DetailLevel  #Specifies the level of detail: Basic, Detailed, or Full
Parameter: -Show  #Displays formatted output instead of returning objects
Parameter: -ComputerName  #Specifies the remote computers. This parameter is mandatory.
Parameter: -Credential  #Specifies credentials for remote access
Parameter: -ThrottleLimit  #Specifies error action preference
Parameter: -fErrorAction  #Specifies the maximum number of concurrent connections
```
### Logger:
```powershell
Write-AdminLog  #Writes log entries to text and JSON log files
Parameter: -Message  #Specifies the log message. This parameter is mandatory.
Parameter: -Level  #Specifies the log level: DEBUG, INFO, WARNING, ERROR, default INFO
Parameter: -LogFile  #Specifies the text log file path, default "C:\Logs\AdminTools.log"
Parameter: -JsonFile  #Specifies the JSON log file path, default "C:\Logs\AdminTools.json"
Parameter: -FunctionName  #Specifies the function name for logging context
```
```powershell
Get-AdminLog  #
Parameter: -Type  #Specifies the log type: JSON or LOG
Parameter: -Level  #Filters by log level
Parameter: -After  #Filters entries after specified datetime
Parameter: -Before  #Filters entries before specified datetime
Parameter: -LogFile  #Specifies the text log file path, default "C:\Logs\AdminTools.log"
Parameter: -JsonFile  #Specifies the JSON log file path, default "C:\Logs\AdminTools.json"
```
```powershell
Start-AdminLoggerObject  #Monitors file system changes and logs them
Parameter: -Path  #Specifies the directory path to monitor. This parameter is mandatory.
Parameter: -LogDir  #Specifies the directory for log files, default "C:\Logs"
```
