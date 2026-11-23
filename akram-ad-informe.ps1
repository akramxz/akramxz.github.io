<#
  akram-ad-informe.ps1 - Informe de estado y seguridad del dominio
  Autor:    Akram El Mazzoudi Zarrouk
  Proyecto: Active Directory + PowerShell - Laboratorio AKRAM-LAB

  Resume como esta el dominio y revisa los fallos de higiene mas comunes:
  cuentas privilegiadas, contrasenas que no caducan, cuentas inactivas o
  sin estrenar, kerberoasting (SPN en usuarios), delegacion sin restringir,
  usuarios sin preautenticacion Kerberos y contrasenas en la descripcion.
  Uso:  .\akram-ad-informe.ps1  [-Json C:\AkramLab\informe-ad.json]
#>
param([string]$Json)
Import-Module ActiveDirectory, GroupPolicy
# Ojo: no llamar "H" a la funcion de hallazgos; "h" es el alias de Get-History y los alias ganan a las funciones
$dom = Get-ADDomain; $bos = Get-ADForest
$todos = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordNeverExpires, PasswordLastSet, Description, `
         ServicePrincipalName, DoesNotRequirePreAuth, TrustedForDelegation, Department, whenCreated, AdminCount
$personas = $todos | Where-Object { $_.SamAccountName -notin 'krbtgt', 'Guest', 'Invitado' }
$hall = New-Object System.Collections.Generic.List[object]
function Hallazgo($sev, $control, $quien, $porque) { $hall.Add([pscustomobject]@{ Gravedad = $sev; Control = $control; Objetos = $quien; Motivo = $porque }) }

Write-Host ("AKRAM-AD · [Akram El Mazzoudi] · {0} · {1:dd/MM/yyyy HH:mm}" -f $dom.DNSRoot, (Get-Date)) -ForegroundColor Cyan
Write-Host ("  Bosque {0} · nivel {1} · DC {2} · {3} OUs · {4} usuarios · {5} grupos · {6} GPOs" -f $bos.Name, $dom.DomainMode,
  (Get-ADDomainController).HostName, @(Get-ADOrganizationalUnit -Filter *).Count, @($personas).Count,
  @(Get-ADGroup -Filter *).Count, @(Get-GPO -All).Count) -ForegroundColor DarkGray

# --- Inventario por departamento ---------------------------------------------
Write-Host "`n  Usuarios por departamento" -ForegroundColor Cyan
$personas | Where-Object Department | Group-Object Department | Sort-Object Count -Descending |
  ForEach-Object { Write-Host ("    {0,-14} {1,3}  {2}" -f $_.Name, $_.Count, ('#' * $_.Count)) }

# --- Grupos privilegiados ------------------------------------------------------
$daSid = "$($dom.DomainSID)-512"; $eaSid = "$($bos.RootDomain | ForEach-Object { (Get-ADDomain $_).DomainSID })-519"
$priv = foreach ($sid in $daSid, $eaSid, 'S-1-5-32-544') {
  $g = Get-ADGroup -Filter "SID -eq '$sid'"
  if ($g) { Get-ADGroupMember $g -Recursive | Where-Object objectClass -eq 'user' | Select-Object @{n = 'Grupo'; e = { $g.Name } }, SamAccountName }
}
Write-Host "`n  Miembros de grupos privilegiados" -ForegroundColor Cyan
$priv | Sort-Object SamAccountName -Unique | ForEach-Object { Write-Host ("    {0,-22} en {1}" -f $_.SamAccountName, $_.Grupo) }
$extra = $priv | Where-Object SamAccountName -notin 'Administrador', 'Administrator', 'akram.admin', 'windowserver' | Sort-Object SamAccountName -Unique
if ($extra) { Hallazgo 'ALTA' 'Cuentas no previstas con privilegios de dominio' ($extra.SamAccountName -join ', ') 'Solo las cuentas Tier 0 deberian administrar el dominio' }

# --- Revisiones de higiene ----------------------------------------------------
$x = $personas | Where-Object { $_.Enabled -and $_.PasswordNeverExpires }
if ($x) { Hallazgo 'MEDIA' 'Contrasena que nunca caduca' ($x.SamAccountName -join ', ') 'Si se filtra, sirve para siempre' }
$x = $personas | Where-Object { $_.Enabled -and $_.ServicePrincipalName }
if ($x) { Hallazgo 'ALTA' 'Usuarios con SPN (kerberoastables)' ($x.SamAccountName -join ', ') 'Cualquiera del dominio puede pedir su ticket y crackearlo offline' }
$x = $personas | Where-Object DoesNotRequirePreAuth
if ($x) { Hallazgo 'ALTA' 'Sin preautenticacion Kerberos (AS-REP roasting)' ($x.SamAccountName -join ', ') 'Se puede obtener un hash sin conocer la contrasena' }
$x = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and PrimaryGroupID -ne 516 }
if ($x) { Hallazgo 'ALTA' 'Equipos con delegacion sin restringir' ($x.Name -join ', ') 'Guardan tickets TGT de quien se conecte' }
$x = $personas | Where-Object { $_.Description -match 'pass|contra|clave|pwd' }
if ($x) { Hallazgo 'ALTA' 'Contrasena en el campo descripcion' ($x.SamAccountName -join ', ') 'La descripcion la puede leer cualquier usuario del dominio' }
$x = $personas | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-90) }
if ($x) { Hallazgo 'MEDIA' 'Cuentas inactivas mas de 90 dias' ($x.SamAccountName -join ', ') 'Cuentas olvidadas = puerta trasera' }
$x = $personas | Where-Object { $_.Enabled -and -not $_.LastLogonDate -and $_.whenCreated -lt (Get-Date).AddDays(-30) }
if ($x) { Hallazgo 'BAJA' 'Cuentas creadas hace mas de 30 dias sin estrenar' ($x.SamAccountName -join ', ') 'Revisar si siguen haciendo falta' }
$pol = Get-ADDefaultDomainPasswordPolicy
if ($pol.MinPasswordLength -lt 10) { Hallazgo 'MEDIA' 'Longitud minima de contrasena baja' $pol.MinPasswordLength 'Recomendado 10 o mas' }
if ($pol.LockoutThreshold -eq 0) { Hallazgo 'ALTA' 'Sin bloqueo de cuentas' '-' 'Permite fuerza bruta ilimitada' }
if (-not (Get-ADOptionalFeature 'Recycle Bin Feature').EnabledScopes) { Hallazgo 'BAJA' 'Papelera de reciclaje de AD desactivada' '-' 'Un borrado accidental no se puede deshacer facilmente' }

Write-Host "`n  Politica del dominio: minimo $($pol.MinPasswordLength) caracteres · bloqueo a los $($pol.LockoutThreshold) intentos durante $($pol.LockoutDuration.TotalMinutes) min" -ForegroundColor DarkGray
$pso = Get-ADFineGrainedPasswordPolicy -Filter *
foreach ($p in $pso) { Write-Host "  PSO $($p.Name): minimo $($p.MinPasswordLength) caracteres · bloqueo a los $($p.LockoutThreshold) intentos" -ForegroundColor DarkGray }

Write-Host "`n  Hallazgos de seguridad" -ForegroundColor Cyan
if (-not $hall.Count) { Write-Host '    Ninguno. El dominio pasa todas las revisiones.' -ForegroundColor Green }
$col = @{ ALTA = 'Red'; MEDIA = 'Yellow'; BAJA = 'Cyan' }
foreach ($h in $hall | Sort-Object { @{ALTA = 0; MEDIA = 1; BAJA = 2 }[$_.Gravedad] }) {
  Write-Host ("    {0,-6}" -f $h.Gravedad) -ForegroundColor $col[$h.Gravedad] -NoNewline
  Write-Host (" {0}: {1}" -f $h.Control, $h.Objetos)
  Write-Host ("           {0}" -f $h.Motivo) -ForegroundColor DarkGray
}
if ($Json) {
  [pscustomobject]@{ autor = 'Akram El Mazzoudi Zarrouk'; dominio = $dom.DNSRoot; fecha = (Get-Date).ToString('s')
    usuarios = @($personas).Count; hallazgos = $hall } | ConvertTo-Json -Depth 4 | Set-Content $Json -Encoding UTF8
}
