function Test-AdminHost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [int]$Count = 4,

        [int]$Timeout = 2000

    )
        begin {
        if (-not $HostName) {
            Write-AdminLog -Message "Host name is required." -Level WARNING -FunctionName 'Test-AdminHost'
            throw "Host name is required."
        }
        if ($Count -le 0 -or $Timeout -le 0) {
            Write-AdminLog -Message "Count and Timeout must be greater than zero." -Level WARNING -FunctionName 'Test-AdminHost'
            throw "Count and Timeout must be greater than zero."
        }    
    }
    process {
        
        try {
            $PingResult = Test-Connection -ComputerName $HostName -Count $Count -TimeoutSeconds  ($Timeout / 1000) -ErrorAction Stop
            $Reachable = $true
        }
        catch {
            $Reachable = $false
        }

        if ($Reachable) {
            Write-Host "Host $HostName is reachable." -ForegroundColor Green
            
            $avgTime = ($PingResult | Measure-object -Property ResponseTime -Average).Average
            Write-Verbose "Average Response Time: $([math]::Round($avgTime,2)) ms."
            
        } else {
            Write-Host "Host $HostName is not reachable." -ForegroundColor Red
        }
    }
    end {
        Write-AdminLog -Message "Function 'Test-AdminHost' was used." -Level INFO -FunctionName 'Test-AdminHost'
        return [PSCustomObject]@{
            HostName = $HostName
            Status = if ($Reachable) {"Reachable"} else {"Not reachable"}
            AvgResponseTime = if ($Reachable) {($PingResult | Measure-object -Property ResponseTime -Average).Average} else {$null}
        }
    }
}


function Test-AdminPort {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    begin {
        if (-not $ComputerName) {
            Write-AdminLog -Message "Host name is required." -Level WARNING -FunctionName 'Test-AdminPort'
            throw "Host name is required."
        }

        if ($Port -lt 1 -or $Port -gt 65535) {
            Write-AdminLog -Message "Port $Port must be between 1 and 65535" -Level WARNING -FunctionName 'Test-AdminPort'
            throw "Port $Port must be between 1 and 65535"
        }
    }
    process {
        try {
            $Result = Test-NetConnection -ComputerName $ComputerName -Port $Port -InformationLevel Detailed
            $Open = $Result.TcpTestSucceeded
        }
        catch {
            $Open = $false
        }
        

        if ($open) {
            Write-AdminLog -Message "Port $Port on $ComputerName is open." -Level INFO -FunctionName 'Test-AdminPort'
            Write-Host "Port $Port on $ComputerName is open." -ForegroundColor Green
        } else {
            Write-AdminLog -Message "Port $Port on $ComputerName is closed." -Level INFO -FunctionName 'Test-AdminPort'
            Write-Host "Port $Port on $ComputerName is closed." -ForegroundColor Red
        }

        Write-Verbose "Remote Address: $($Result.RemoteAddress)"
        Write-Verbose "Ping Succeeded: $($Result.PingSucceeded)"
        Write-Verbose "TcpTestSucceeded: $($Result.TcpTestSucceeded)"
        Write-Verbose "RoundTripTime: $($Result.RoundTripTime) ms"
    }
    end {
        return [PSCustomObject]@{
            ComputerName = $ComputerName
            Port = $Port
            Status = if ($Open) {"Open"} else {"Closed"}
            RemoteAddress = $Result.RemoteAddress
            TcpTestSucceeded = $Result.TcpTestSucceeded
        }
    }
}

function Get-AdminNetworkAdapters {
    [CmdletBinding()]
    param (
        [switch]$Uponly
    )

    $adapters = Get-NetAdapter
    if ($Uponly) {
        $adapters = $adapters | Where-Object {$_.Status -eq "Up"}
    }
    
    foreach ($adapter in $adapters) {
        Write-Verbose "Name: $($adapter.Name), Status: $($adapter.Status), Mac: $($adapter.MacAddress), Speed: $($adapter.LinkSpeed)"
        Write-Host "Name: $($adapter.Name), Status: $($adapter.Status)"
    }
    Write-AdminLog -Message "Function 'Get-AdminNetworkAdapters' was used." -Level INFO -FunctionName 'Get-AdminNetworkAdapters'
}

function Get-AdminNetworkIP {
    [CmdletBinding()]
    param (
        [string]$InterfaceAlias,
        [switch]$IPv4Only,
        [switch]$IPv6Only
    )


    if ($PSBoundParameters.ContainsKey("InterfaceAlias")) {
        $addresses = Get-NetIPAddress -InterfaceAlias $InterfaceAlias
    } else {
        $addresses = Get-NetIPAddress
    }
    
    if ($IPv4Only) {
        $addresses = $addresses | Where-Object {$_.AddressFamily -eq "IPv4"}
    } elseif ($IPv6Only) {
        $addresses = $addresses | Where-Object {$_.AddressFamily -eq "IPv6"}
    }

    foreach ($address in $addresses) {
        Write-Verbose "IPAddress: $($address.IPAddress) on Interface: $($address.InterfaceAlias), AddressFamily: $($address.AddressFamily), PrefixLength: $($address.PrefixLength)"
        Write-Verbose "---------------------------------------------------------------------------------------"

        [PSCustomObject]@{
            IPAddress = $address.IPAddress
            InterfaceAlias = $address.InterfaceAlias
            AddressFamily = $address.AddressFamily
            PrefixLength = $address.PrefixLength
        }
    }
    Write-AdminLog -Message "Function 'Get-AdminNetworkIP' was used." -Level INFO -FunctionName 'Get-AdminNetworkIP'
}