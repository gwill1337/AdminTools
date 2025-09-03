function Get-AdminAllUsers {
    <#
    .SYNOPSIS
        Gets information about local users
    
    .DESCRIPTION
        Retrieves information about all local users or filters by enabled/disabled state.
    
    .PARAMETER state
        Filters users by their enabled state: All, Enabled, or Disabled
    
    .EXAMPLE
        Get-AdminAllUsers
        
        Returns all local users
    
    .EXAMPLE
        Get-AdminAllUsers -State Enabled
        
        Returns only enabled users
    
    .OUTPUTS
        PSCustomObject. Returns user information objects
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [ValidateSet("All","Enabled","Disabled")]
        [string]$state = "All"
    )
    $users = Get-LocalUser

    if ($state -eq "Enabled") {
        $users = $users | Where-Object {$_.Enabled -eq $true}
    } elseif ($state -eq "Disabled") {
        $users = $users | Where-Object {$_.Enabled -eq $false}
    }
    Write-AdminLog -Message "Function 'Get-AdminAllUsers' was used." -Level INFO -FunctionName 'Get-AdminAllUsers'
    return $users | Select-Object Name, Enabled, Description
}

function New-AdminUser {
    <#
    .SYNOPSIS
        Creates a new local user account
    
    .DESCRIPTION
        Creates a new local user account with specified name and optional group memberships.
        Includes password prompt and automatic logging.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .PARAMETER Groups
        Specifies groups to add the user to
    
    .EXAMPLE
        New-AdminUser -Name "john.doe" -Groups @("Users", "RemoteDesktopUsers")
        
        Creates new user and adds to specified groups
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Creates user account and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name,

        
        [string[]]$Groups = @()
    )
    
    if (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue) {
        Write-Warning "User $Name already exists"
        return
    }

    $Password = Read-Host "Enter Password for $Name" -AsSecureString

    New-LocalUser -Name $Name -Password $Password -FullName $Name -Description "created by AdminTools"

    foreach ($group in $Groups) {
        Add-LocalGroupMember -Group $group -Member $Name
    }
    Write-AdminLog -Message "User created: $Name" -Level INFO -FunctionName 'New-AdminUser'
    Write-Host "User $Name created successfully"
}

function Set-AdminUserState {
    <#
    .SYNOPSIS
        Enables or disables a local user account
    
    .DESCRIPTION
        Changes the enabled state of a local user account. Includes validation and logging.
    
    .PARAMETER State
        Specifies whether to enable or disable the account
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .EXAMPLE
        Set-AdminUserState -Name "john.doe" -State Disable
        
        Disables the user account
    
    .EXAMPLE
        Set-AdminUserState -Name "jane.smith" -State Enable
        
        Enables the user account
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Changes user state and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        [ValidateSet("Enable","Disable")]
        [string]$State = "Enable",

        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Set-AdminUserState'
        throw "User '$Name' not found"
    }

    if ($State -eq "Enable" -and $user.Enabled) {
        Write-Host "User already enabled"
        return
    } elseif ($State -eq "Disable" -and -not $User.Enabled) {
        Write-Host "User already disabled"
        return
    }

    if ($State -eq "Enable") {
        Enable-LocalUser -Name $Name
    } else {
        Disable-LocalUser -Name $Name
    }

    Write-AdminLog -Message "User $Name has been $State" -Level INFO -FunctionName 'Set-UserState'
    Write-Host "User $Name now $State"
    
}


function Remove-AdminUser {
    <#
    .SYNOPSIS
        Removes a local user account
    
    .DESCRIPTION
        Removes the specified local user account. Includes protection against system account deletion
        and confirmation prompt (unless -Force is specified).
    
    .PARAMETER Name
        Specifies the username to remove. This parameter is mandatory.
    
    .PARAMETER Force
        Skips confirmation prompt
    
    .EXAMPLE
        Remove-AdminUser -Name "temp.user"
        
        Removes the user with confirmation
    
    .EXAMPLE
        Remove-AdminUser -Name "old.account" -Force
        
        Forcefully removes the user without confirmation
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Removes user account and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [switch]$Force
    )

    $ProtectedUsers = @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount")

    if ($Name -in $ProtectedUsers) {
        Write-AdminLog -Message "Attempt to remove protected user '$Name'." -Level WARNING -FunctionName 'Remove-AdminUser'
        throw "User $Name is a system account and cannot be removed."
    }

    $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    Write-AdminLog -Message "Attempt to remove user '$Name'." -Level INFO -FunctionName 'Remove-AdminUser'
    if (-not $User) {
        Write-AdminLog -Message "User $Name not found." -Level WARNING -FunctionName 'Remove-AdminUser'
        throw "User $Name not found."
    }
    
    if (-not $Force) {
        $confirm = Read-Host "Are you sure you want to remove user $Name? (Y/N)"
        if ($confirm -notin @("Y","y")) {
            Write-AdminLog "Removin User '$Name' operation cancelled." -Level INFO -FunctionName 'Remove-AdminUser'
            Write-Host "Operation cancelled."
            return
        }
    }
    Remove-LocalUser -Name $Name
    Write-AdminLog -Message "User '$Name' has been removed." -Level INFO -FunctionName 'Remove-AdminUser'
    Write-Host "User '$Name' has been removed."
}

function Set-AdminUserInfo {
    <#
    .SYNOPSIS
        Sets user account information
    
    .DESCRIPTION
        Updates user account properties such as full name and description.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .PARAMETER FullName
        Specifies the full name for the user
    
    .PARAMETER Description
        Specifies the description for the user
    
    .EXAMPLE
        Set-AdminUserInfo -Name "john.doe" -FullName "John Doe" -Description "Sales Department"
        
        Updates user information
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        PSCustomObject. Returns updated user information.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [string]$FullName,
        [string]$Description

    )
    begin {
        $SetParams = @{}
        $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

        if (-not $User) {
            Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Set-AdminUserInfo'
            throw "User '$Name' not found"
        }

        if (-not ($PSBoundParameters.ContainsKey("FullName") -or $PSBoundParameters.ContainsKey("Description"))) {
            Write-Host "Nothing to change"
            return
        }
    }
    process {
        if ($PSBoundParameters.ContainsKey("FullName")) {$SetParams["FullName"] = $FullName}
        if ($PSBoundParameters.ContainsKey("Description")) {$SetParams["Description"] = $Description}

        Set-LocalUser -Name $Name @SetParams

        $UpdatedUser = Get-LocalUser -Name $Name
        $UpdatedUser | Select-Object Name, FullName, Description | Format-List
    }
}

function Reset-AdminUserPassword {
    <#
    .SYNOPSIS
        Resets a user's password
    
    .DESCRIPTION
        Resets the password for the specified user account. Includes secure password prompt.
    
    .PARAMETER Name
        Specifies the username. This parameter is mandatory.
    
    .EXAMPLE
        Reset-AdminUserPassword -Name "john.doe"
        
        Resets password for the user
    
    .INPUTS
        String. You can pipe usernames to this function.
    
    .OUTPUTS
        None. Resets password and writes to log.
    
    .NOTES
        Author: Gwill1337
        Requires: Administrator privileges
        Version: 1.0.0
    #>
    param (
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    begin {
        $User = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

        if (-not $User) {
            Write-AdminLog -Message "User '$Name' not found" -Level WARNING -FunctionName 'Reset-AdminUserPassword'
            throw "User '$Name' not found"
        }
    }
    process {
        $Password = Read-Host -AsSecureString "Enter new Password for $Name :"

        Set-LocalUser -Name $Name -Password $Password
        Write-AdminLog -Message "Password for '$Name' has been reset" -Level INFO -FunctionName 'Reset-AdminUserPassword'
        Write-Host "Password for '$Name' has been reset"
    }
}
