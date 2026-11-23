<#
  03-estructura-dominio.ps1 - Paso 3: montar la empresa ficticia "Akram Solutions" en el dominio
  Autor:    Akram El Mazzoudi Zarrouk
  Proyecto: Active Directory + PowerShell - Laboratorio AKRAM-LAB

  Todo es idempotente: se puede volver a ejecutar sin duplicar nada.
    1. Unidades organizativas (modelo por niveles: Tier 0 separado)
    2. Usuarios desde CSV, con responsable, puesto y contrasena temporal
    3. Grupos con el modelo AGDLP (globales por departamento -> locales de dominio -> permisos)
    4. Carpeta compartida con permisos NTFS dados SOLO a grupos locales de dominio
    5. Politica de contrasenas y bloqueo del dominio + PSO estricta para administradores
    6. GPOs de seguridad enlazadas a sus OUs
    7. Auditoria avanzada en el DC (la que necesita el SIEM)
    8. Delegacion: RRHH puede restablecer contrasenas solo en su ambito
    9. Papelera de reciclaje de AD y registros DNS del laboratorio
#>
param([string]$Csv = 'C:\AkramLab\usuarios.csv')
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory, GroupPolicy
$dom   = Get-ADDomain
$dn    = $dom.DistinguishedName          # DC=akramlab,DC=local
$raiz  = "OU=AkramSolutions,$dn"
$log   = 'C:\AkramLab\03-estructura.log'
$daSid  = "$($dom.DomainSID)-512"                                   # Admins. del dominio (en cualquier idioma)
$daNom  = (Get-ADGroup $daSid).Name
function Nombre($sid) { (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value }
function Paso($t) { $l = "[{0:HH:mm:ss}] {1}" -f (Get-Date), $t; Write-Output $l; Add-Content $log $l }
function OU($nombre, $padre, $desc) {
  if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$nombre'" -SearchBase $padre -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $nombre -Path $padre -Description $desc -ProtectedFromAccidentalDeletion $true
  }
  "OU=$nombre,$padre"
}
function Grupo($nombre, $ambito, $ou, $desc) {
  if (-not (Get-ADGroup -Filter "Name -eq '$nombre'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $nombre -GroupScope $ambito -GroupCategory Security -Path $ou -Description $desc
  }
}
function Clave { # contrasena temporal aleatoria que cumple la complejidad
  $c = 'ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!$%*+?'
  -join (($c | ForEach-Object { $_[(Get-Random -Max $_.Length)] }) + (1..10 | ForEach-Object { ($c -join '')[(Get-Random -Max 62)] }) | Sort-Object { Get-Random })
}

# ---------------------------------------------------------------- 1. OUs ---
Paso '1. Unidades organizativas'
$null    = OU 'AkramSolutions' $dn 'Empresa ficticia del laboratorio de Akram El Mazzoudi'
$ouUsu   = OU 'Usuarios'   $raiz 'Cuentas de empleados por departamento'
$ouEq    = OU 'Equipos'    $raiz 'Equipos del dominio'
$ouGr    = OU 'Grupos'     $raiz 'Grupos de seguridad (AGDLP)'
$ouSvc   = OU 'Servicios'  $raiz 'Cuentas de servicio'
$ouT0    = OU 'Tier0-Admin' $raiz 'Cuentas de administracion del dominio (Tier 0)'
$null    = OU 'Servidores' $ouEq 'Servidores miembro'
$null    = OU 'Puestos'    $ouEq 'Equipos de usuario'
$ouGG    = OU 'Globales'   $ouGr 'Grupos globales: personas'
$ouGL    = OU 'Recursos'   $ouGr 'Grupos locales de dominio: permisos'
$deps    = 'Direccion', 'Sistemas', 'Desarrollo', 'Ventas', 'RRHH', 'Contabilidad'
$ouDep   = @{}
foreach ($d in $deps) { $ouDep[$d] = OU $d $ouUsu "Departamento de $d" }
redircmp $ouEq.Replace('OU=Equipos', 'OU=Puestos,OU=Equipos') | Out-Null   # equipos nuevos -> Puestos

# ------------------------------------------------------------- 2. Usuarios ---
Paso '2. Usuarios desde CSV'
$usuarios = Import-Csv $Csv
$creados = @()
foreach ($u in $usuarios) {
  if (Get-ADUser -Filter "SamAccountName -eq '$($u.Usuario)'" -ErrorAction SilentlyContinue) { continue }
  $clave = Clave
  New-ADUser -Name "$($u.Nombre) $($u.Apellido)" -GivenName $u.Nombre -Surname $u.Apellido `
    -SamAccountName $u.Usuario -UserPrincipalName "$($u.Usuario)@akramlab.local" `
    -DisplayName "$($u.Nombre) $($u.Apellido)" -Department $u.Departamento -Title $u.Puesto `
    -Company 'Akram Solutions' -Office 'Barcelona' -EmailAddress "$($u.Usuario)@akramsolutions.lab" `
    -Path $ouDep[$u.Departamento] -AccountPassword (ConvertTo-SecureString $clave -AsPlainText -Force) `
    -ChangePasswordAtLogon $true -Enabled $true
  $creados += [pscustomobject]@{ Usuario = $u.Usuario; ClaveTemporal = $clave }
}
foreach ($u in $usuarios | Where-Object Responsable) {      # jerarquia (campo Manager)
  Set-ADUser $u.Usuario -Manager $u.Responsable
}
if ($creados) { $creados | Export-Csv 'C:\AkramLab\claves-temporales.csv' -NoTypeInformation -Encoding UTF8 }

# Cuenta de administracion separada para Akram (nunca se usa la del dia a dia para administrar)
if (-not (Get-ADUser -Filter "SamAccountName -eq 'akram.admin'" -ErrorAction SilentlyContinue)) {
  New-ADUser -Name 'Akram El Mazzoudi (admin)' -GivenName 'Akram' -Surname 'El Mazzoudi' -SamAccountName 'akram.admin' `
    -UserPrincipalName 'akram.admin@akramlab.local' -Title 'Administrador del dominio' -Department 'Sistemas' `
    -Path $ouT0 -AccountPassword (ConvertTo-SecureString $env:AKRAM_ADMIN -AsPlainText -Force) -Enabled $true
}
# Tier 0: Admins. del dominio y Administradores de empresa (los necesita la papelera de AD)
foreach ($g in $daSid, "$($dom.DomainSID)-519") { Add-ADGroupMember $g 'akram.admin' -ErrorAction SilentlyContinue }
# Cuenta de servicio de ejemplo para el agente del SIEM (sin inicio de sesion interactivo)
if (-not (Get-ADUser -Filter "SamAccountName -eq 'svc-siem'" -ErrorAction SilentlyContinue)) {
  New-ADUser -Name 'svc-siem' -SamAccountName 'svc-siem' -Path $ouSvc -Description 'Lectura de eventos para AKRAM-SIEM' `
    -AccountPassword (ConvertTo-SecureString (Clave) -AsPlainText -Force) -Enabled $true -CannotChangePassword $true
  Add-ADGroupMember (Get-ADGroup -Filter "SID -eq 'S-1-5-32-573'") 'svc-siem'   # Lectores del registro de eventos
}

# ---------------------------------------------------------- 3. AGDLP ------
Paso '3. Grupos AGDLP'
foreach ($d in $deps) {
  Grupo "GG_$d" Global $ouGG "Personas del departamento de $d"
  $miembros = Get-ADUser -SearchBase $ouDep[$d] -Filter *
  if ($miembros) { Add-ADGroupMember "GG_$d" -Members $miembros }
}
Grupo 'GG_Responsables' Global $ouGG 'Responsables de departamento'
Add-ADGroupMember 'GG_Responsables' -Members ($usuarios | Where-Object Puesto -match '^(Jef|Respons|Direct)' | ForEach-Object Usuario)

$recursos = [ordered]@{
  'DL_Proyectos_RW'  = @('GG_Desarrollo', 'GG_Sistemas')
  'DL_Proyectos_R'   = @('GG_Direccion', 'GG_Ventas')
  'DL_Nominas_RW'    = @('GG_RRHH', 'GG_Contabilidad')
  'DL_Comun_RW'      = $deps | ForEach-Object { "GG_$_" }
  'DL_HelpdeskRRHH'  = @('GG_RRHH')
}
foreach ($g in $recursos.Keys) {
  Grupo $g DomainLocal $ouGL "Permiso sobre recurso: $g"
  Add-ADGroupMember $g -Members $recursos[$g]
}

# ------------------------------------------------- 4. Carpetas compartidas ---
Paso '4. Carpetas compartidas con permisos AGDLP'
$base = 'C:\Datos'
$compartidas = @{
  'Proyectos' = @{ RW = 'DL_Proyectos_RW'; R = 'DL_Proyectos_R' }
  'Nominas'   = @{ RW = 'DL_Nominas_RW' }
  'Comun'     = @{ RW = 'DL_Comun_RW' }
}
foreach ($c in $compartidas.Keys) {
  $ruta = Join-Path $base $c
  New-Item $ruta -ItemType Directory -Force | Out-Null
  $acl = Get-Acl $ruta
  $acl.SetAccessRuleProtection($true, $false)                     # sin herencia
  foreach ($sid in 'S-1-5-32-544', 'S-1-5-18') {                 # Administradores y SYSTEM
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier $sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("AKRAMLAB\$($compartidas[$c].RW)", 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  if ($compartidas[$c].R) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("AKRAMLAB\$($compartidas[$c].R)", 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  Set-Acl $ruta $acl
  if (-not (Get-SmbShare -Name $c -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $c -Path $ruta -FullAccess (Nombre $daSid) -ChangeAccess (Nombre 'S-1-5-11') -FolderEnumerationMode AccessBased | Out-Null
  }
}

# ------------------------------------------ 5. Contrasenas y bloqueo -------
Paso '5. Politica de contrasenas, bloqueo y PSO de administradores'
Set-ADDefaultDomainPasswordPolicy -Identity $dom.DNSRoot -MinPasswordLength 10 -ComplexityEnabled $true `
  -PasswordHistoryCount 12 -MaxPasswordAge '90.00:00:00' -MinPasswordAge '1.00:00:00' `
  -LockoutThreshold 5 -LockoutDuration '00:15:00' -LockoutObservationWindow '00:15:00'
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq 'PSO-Admins-Tier0'" -ErrorAction SilentlyContinue)) {
  New-ADFineGrainedPasswordPolicy -Name 'PSO-Admins-Tier0' -Precedence 10 -MinPasswordLength 16 -ComplexityEnabled $true `
    -PasswordHistoryCount 24 -MaxPasswordAge '60.00:00:00' -MinPasswordAge '1.00:00:00' `
    -LockoutThreshold 3 -LockoutDuration '00:30:00' -LockoutObservationWindow '00:30:00' -ReversibleEncryptionEnabled $false
  Add-ADFineGrainedPasswordPolicySubject 'PSO-Admins-Tier0' -Subjects $daSid
}

# ------------------------------------------------------------ 6. GPOs -----
Paso '6. GPOs de seguridad'
function GPO($nombre, $ou, $comentario, [scriptblock]$valores) {
  $g = Get-GPO -Name $nombre -ErrorAction SilentlyContinue
  if (-not $g) { $g = New-GPO -Name $nombre -Comment $comentario }
  & $valores $nombre
  if (-not (Get-GPInheritance -Target $ou).GpoLinks.DisplayName -contains $nombre) { New-GPLink -Name $nombre -Target $ou | Out-Null }
}
GPO 'AKRAM-Seguridad-Base' $raiz 'Endurecimiento comun para toda la empresa' {
  param($n)
  # Sin LLMNR ni NetBIOS-NS: evita el envenenamiento tipo Responder
  Set-GPRegistryValue -Name $n -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName EnableMulticast -Type DWord -Value 0 | Out-Null
  # SMB firmado obligatorio (cliente y servidor)
  Set-GPRegistryValue -Name $n -Key 'HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ValueName RequireSecuritySignature -Type DWord -Value 1 | Out-Null
  Set-GPRegistryValue -Name $n -Key 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters' -ValueName RequireSecuritySignature -Type DWord -Value 1 | Out-Null
  # Solo NTLMv2, rechazar LM y NTLMv1
  Set-GPRegistryValue -Name $n -Key 'HKLM\System\CurrentControlSet\Control\Lsa' -ValueName LmCompatibilityLevel -Type DWord -Value 5 | Out-Null
  # Registro de PowerShell (bloques de script) para el SIEM
  Set-GPRegistryValue -Name $n -Key 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName EnableScriptBlockLogging -Type DWord -Value 1 | Out-Null
}
GPO 'AKRAM-Usuarios-Puesto' $ouUsu 'Ajustes de puesto para empleados' {
  param($n)
  # Bloqueo de pantalla a los 10 minutos con contrasena
  Set-GPRegistryValue -Name $n -Key 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueName ScreenSaveActive -Type String -Value '1' | Out-Null
  Set-GPRegistryValue -Name $n -Key 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueName ScreenSaverIsSecure -Type String -Value '1' | Out-Null
  Set-GPRegistryValue -Name $n -Key 'HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop' -ValueName ScreenSaveTimeOut -Type String -Value '600' | Out-Null
  # Sin acceso al registro ni a la consola para usuarios normales
  Set-GPRegistryValue -Name $n -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System' -ValueName DisableRegistryTools -Type DWord -Value 1 | Out-Null
  Set-GPRegistryValue -Name $n -Key 'HKCU\Software\Policies\Microsoft\Windows\System' -ValueName DisableCMD -Type DWord -Value 2 | Out-Null
}
GPO 'AKRAM-Ventas-USB' $ouDep['Ventas'] 'Ventas no puede usar memorias USB (datos de clientes)' {
  param($n)
  Set-GPRegistryValue -Name $n -Key 'HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices' -ValueName Deny_All -Type DWord -Value 1 | Out-Null
}

# ---------------------------------------------------- 7. Auditoria --------
Paso '7. Auditoria avanzada en el DC'
# Por GUID y no por nombre: en un Windows en espanol los nombres de subcategoria cambian
$subcat = [ordered]@{ 'Inicio de sesion' = '0CCE9215'; 'Bloqueo de cuenta' = '0CCE9217'; 'Gestion de cuentas de usuario' = '0CCE9235'
  'Gestion de grupos de seguridad' = '0CCE9237'; 'Validacion de credenciales' = '0CCE923F'; 'Autenticacion Kerberos' = '0CCE9242'
  'Cambios en el servicio de directorio' = '0CCE923C'; 'Cambio de directiva de auditoria' = '0CCE922F' }
foreach ($s in $subcat.GetEnumerator()) {
  auditpol /set /subcategory:"{$($s.Value)-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol no pudo activar $($s.Key)" }
}
wevtutil sl Security /ms:268435456   # registro de seguridad de 256 MB

# --------------------------------------------------- 8. Delegacion --------
Paso '8. Delegacion: RRHH restablece contrasenas de empleados'
$sid = (Get-ADGroup 'DL_HelpdeskRRHH').SID
$acl = Get-Acl "AD:$ouUsu"
$guidUser = [guid]'bf967aba-0de6-11d0-a285-00aa003049e2'     # clase user
$guidReset = [guid]'00299570-246d-11d0-a768-00aa006e0529'    # derecho extendido Reset Password
$guidPwdLast = [guid]'bf967a0a-0de6-11d0-a285-00aa003049e2'  # atributo pwdLastSet
$acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ExtendedRight', 'Allow', $guidReset, 'Descendents', $guidUser)))
$acl.AddAccessRule((New-Object DirectoryServices.ActiveDirectoryAccessRule($sid, 'ReadProperty,WriteProperty', 'Allow', $guidPwdLast, 'Descendents', $guidUser)))
Set-Acl "AD:$ouUsu" $acl

# ---------------------------------------- 9. Papelera y DNS ----------------
Paso '9. Papelera de reciclaje de AD y DNS del laboratorio'
if (-not (Get-ADOptionalFeature 'Recycle Bin Feature').EnabledScopes) {
  # Es un cambio de bosque: solo puede hacerlo un Administrador de empresa (akram.admin)
  try { Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $dom.DNSRoot -Confirm:$false }
  catch { Write-Warning 'Papelera de AD pendiente: hay que activarla con akram.admin (Administradores de empresa)' }
}
foreach ($r in @(@('srv01', '10.66.0.10'), @('siem', '10.66.0.10'), @('kali', '10.66.0.50'))) {
  if (-not (Get-DnsServerResourceRecord -ZoneName $dom.DNSRoot -Name $r[0] -ErrorAction SilentlyContinue)) {
    Add-DnsServerResourceRecordA -ZoneName $dom.DNSRoot -Name $r[0] -IPv4Address $r[1]
  }
}
if (-not (Get-DnsServerZone -Name '0.66.10.in-addr.arpa' -ErrorAction SilentlyContinue)) {
  Add-DnsServerPrimaryZone -NetworkId '10.66.0.0/24' -ReplicationScope Forest
}
Set-DnsServerForwarder -IPAddress 10.0.2.3 -ErrorAction SilentlyContinue

Paso 'Estructura completada'
