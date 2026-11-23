<#
  akram-siem-agente.ps1 - Agente de AKRAM-SIEM para Windows / Active Directory
  Autor:    Akram El Mazzoudi Zarrouk
  Proyecto: SIEM final - Laboratorio AKRAM-LAB

  Lee del registro de Seguridad los eventos que interesan a un SOC y los envia
  en JSON al SIEM. Se ejecuta cada minuto como tarea programada (SYSTEM) y
  recuerda hasta donde leyo, asi no reenvia eventos ni pierde ninguno.

    4624 / 4625  inicio de sesion correcto / fallido (red y escritorio remoto)
    4720 / 4726  usuario creado / eliminado
    4728 4732 4756  alta en grupo de seguridad (global, local, universal)
    4740         cuenta bloqueada
    1102         alguien ha borrado el registro de seguridad
#>
param(
  [string]$Siem  = 'http://10.66.0.10:8443/api/ingest',
  [string]$Token = (Get-Content 'C:\ProgramData\AkramSIEM\token.txt' -ErrorAction Stop)
)

$dir = 'C:\ProgramData\AkramSIEM'
New-Item $dir -ItemType Directory -Force | Out-Null
$marca = Join-Path $dir 'ultimo.txt'
$desde = if (Test-Path $marca) { [datetime](Get-Content $marca) } else { (Get-Date).AddMinutes(-15) }
$hasta = Get-Date

$ids = 4624, 4625, 4720, 4726, 4728, 4732, 4756, 4740, 1102
$eventos = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $desde; EndTime = $hasta } -ErrorAction SilentlyContinue

$lote = foreach ($e in $eventos) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  $obj = [ordered]@{ Id = $e.Id; Hora = $e.TimeCreated.ToString('s'); Equipo = $env:COMPUTERNAME }
  $saltar = $false

  switch ($e.Id) {
    { $_ -in 4624, 4625 } {
      # Solo inicios de sesion de personas por red (3) o escritorio remoto (10)
      # Ojo: dentro de un switch, 'continue' solo salta el switch, no el foreach
      if ($d.TargetUserName -like '*$' -or $d.TargetUserName -eq 'ANONYMOUS LOGON') { $saltar = $true; break }
      if ($e.Id -eq 4624 -and $d.LogonType -notin '3', '10') { $saltar = $true; break }
      $obj.Usuario = $d.TargetUserName; $obj.Ip = $d.IpAddress; $obj.TipoLogon = $d.LogonType
    }
    { $_ -in 4720, 4726, 4740 } { $obj.Usuario = $d.TargetUserName; $obj.Autor = $d.SubjectUserName }
    { $_ -in 4728, 4732, 4756 } {
      $obj.Grupo = $d.TargetUserName; $obj.Autor = $d.SubjectUserName
      $obj.Miembro = ($d.MemberName -replace '^CN=([^,]+),.*$', '$1')
      $obj.Usuario = $obj.Miembro
    }
    1102 { $obj.Usuario = $x.Event.UserData.LogFileCleared.SubjectUserName }
  }
  if ($saltar) { continue }
  [pscustomobject]$obj
}

if ($lote) {
  $json = ConvertTo-Json @($lote) -Depth 3 -Compress
  try {
    Invoke-RestMethod -Uri $Siem -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($json)) `
      -ContentType 'application/json' -Headers @{ 'X-Akram-Token' = $Token } -TimeoutSec 10 | Out-Null
    $hasta.ToString('o') | Set-Content $marca
    "$(Get-Date -f s) enviados $(@($lote).Count) eventos" | Add-Content (Join-Path $dir 'agente.log')
  } catch {
    "$(Get-Date -f s) ERROR $($_.Exception.Message)" | Add-Content (Join-Path $dir 'agente.log')
  }
} else {
  $hasta.ToString('o') | Set-Content $marca
}
