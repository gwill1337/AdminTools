function Get-AdminAllUsers {
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