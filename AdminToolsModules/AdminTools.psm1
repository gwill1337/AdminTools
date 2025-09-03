$ModulesPath = Join-Path $PSScriptRoot "Modules"
Get-ChildItem -Path $ModulesPath -Filter "*.psm1" | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function *

$Script:ModuleName = 'AdminTools'
$Script:ModuleVersion = '1.0.1'
