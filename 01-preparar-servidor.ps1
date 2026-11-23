<#
  01-preparar-servidor.ps1 - Paso 1: dejar el servidor listo para ser controlador de dominio
  Autor:    Akram El Mazzoudi Zarrouk
  Proyecto: Active Directory + PowerShell - Laboratorio AKRAM-LAB

  - IP fija en la red del laboratorio (akramlab 10.66.0.0/24)
  - El propio servidor como DNS (lo sera en cuanto sea DC)
  - Zona horaria de Madrid y nombre DC01-AKRAM
#>
$ErrorActionPreference = 'Stop'

# La tarjeta de la red interna es la que no recibe DHCP del NAT de VirtualBox
$nic = Get-NetAdapter | Where-Object Status -eq 'Up' |
       Where-Object { -not (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                            Where-Object IPAddress -like '10.0.2.*') } | Select-Object -First 1
Rename-NetAdapter -Name $nic.Name -NewName 'LAN-AKRAMLAB'
Get-NetIPAddress -InterfaceAlias 'LAN-AKRAMLAB' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias 'LAN-AKRAMLAB' -IPAddress 10.66.0.20 -PrefixLength 24 | Out-Null
Set-DnsClientServerAddress -InterfaceAlias 'LAN-AKRAMLAB' -ServerAddresses 127.0.0.1

$nat = Get-NetAdapter | Where-Object Name -ne 'LAN-AKRAMLAB' | Select-Object -First 1
Rename-NetAdapter -Name $nat.Name -NewName 'NAT-ADMIN'

Set-TimeZone -Id 'Romance Standard Time'
# Permitir ping desde la red del laboratorio (util para diagnosticar)
Enable-NetFirewallRule -Name 'FPS-ICMP4-ERQ-In' -ErrorAction SilentlyContinue

Rename-Computer -NewName 'DC01-AKRAM' -Force
Write-Output 'Servidor preparado: 10.66.0.20 / DC01-AKRAM. Reiniciando...'
Restart-Computer -Force
