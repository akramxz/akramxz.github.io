<#
  h.ps1 - Prueba del informe: cuenta de servicio mal configurada A PROPOSITO
  Autor: Akram El Mazzoudi Zarrouk · Proyecto AD + PowerShell · AKRAM-LAB
  Crea 'svc-backup-prueba' con los errores tipicos de una cuenta de servicio
  (SPN en un usuario, clave que no caduca, sin preautenticacion Kerberos y la
  clave en la descripcion) para comprobar que akram-ad-informe.ps1 los detecta.
  Con -Limpiar la borra y el dominio vuelve a quedar limpio.
#>
param([switch]$Limpiar)
Import-Module ActiveDirectory
$n = 'svc-backup-prueba'
if ($Limpiar) { Remove-ADUser $n -Confirm:$false; Write-Host "Cuenta de prueba $n eliminada" -ForegroundColor Green; return }
$ou = "OU=Servicios,OU=AkramSolutions,$((Get-ADDomain).DistinguishedName)"
New-ADUser -Name $n -SamAccountName $n -Path $ou -Enabled $true -PasswordNeverExpires $true `
  -AccountPassword (ConvertTo-SecureString 'Backup-Lab-2026!x' -AsPlainText -Force) `
  -Description 'PRUEBA AKRAM-LAB - copias nocturnas, clave: Backup-Lab-2026!x' `
  -ServicePrincipalName 'MSSQLSvc/srv-backup.akramlab.local:1433'
Set-ADAccountControl $n -DoesNotRequirePreAuth $true
Write-Host "Cuenta de prueba $n creada con 4 errores de configuracion" -ForegroundColor Yellow
