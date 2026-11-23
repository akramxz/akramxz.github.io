<#
  02-crear-bosque.ps1 - Paso 2: crear el bosque akramlab.local
  Autor:    Akram El Mazzoudi Zarrouk
  Proyecto: Active Directory + PowerShell - Laboratorio AKRAM-LAB
#>
$ErrorActionPreference = 'Stop'
Install-WindowsFeature AD-Domain-Services, DNS, GPMC, RSAT-AD-PowerShell -IncludeManagementTools | Out-Null

$dsrm = ConvertTo-SecureString $env:AKRAM_DSRM -AsPlainText -Force
Install-ADDSForest `
  -DomainName 'akramlab.local' -DomainNetbiosName 'AKRAMLAB' `
  -ForestMode 'WinThreshold' -DomainMode 'WinThreshold' `
  -InstallDns -SafeModeAdministratorPassword $dsrm `
  -DatabasePath 'C:\Windows\NTDS' -LogPath 'C:\Windows\NTDS' -SysvolPath 'C:\Windows\SYSVOL' `
  -NoRebootOnCompletion:$false -Force
