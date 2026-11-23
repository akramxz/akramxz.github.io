# v.ps1 - Vista rapida del dominio akramlab.local
# Autor: Akram El Mazzoudi Zarrouk
Import-Module ActiveDirectory, GroupPolicy
$d = Get-ADDomain
Write-Host "AKRAM-AD · [Akram El Mazzoudi] · $($d.DNSRoot) · $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
Write-Host "`n  Unidades organizativas" -ForegroundColor Cyan
Get-ADOrganizationalUnit -Filter * -SearchBase "OU=AkramSolutions,$($d.DistinguishedName)" | Sort-Object { ($_.DistinguishedName -split ',' | Select-Object -Skip 1 | ForEach-Object { $_ }) -join ',' }, Name |
  ForEach-Object { $n = ($_.DistinguishedName -split ',OU=').Count - 1; $u = @(Get-ADUser -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel).Count
    Write-Host ("    {0}{1,-22} {2}" -f ('  ' * $n), $_.Name, $(if ($u) { "$u usuarios" } else { '' })) }
Write-Host "`n  Grupos AGDLP" -ForegroundColor Cyan
Get-ADGroup -Filter "Name -like 'GG_*' -or Name -like 'DL_*'" -Properties Members | Sort-Object Name |
  ForEach-Object { Write-Host ("    {0,-24} {1,-12} {2} miembros" -f $_.Name, $_.GroupScope, @($_.Members).Count) }
Write-Host "`n  GPOs" -ForegroundColor Cyan
Get-GPO -All | Where-Object DisplayName -like 'AKRAM*' | ForEach-Object { Write-Host ("    {0,-26} {1}" -f $_.DisplayName, $_.Description) }
Write-Host "`n  Recursos compartidos" -ForegroundColor Cyan
Get-SmbShare | Where-Object { $_.Path -like 'C:\Datos*' } | ForEach-Object { Write-Host ("    \\DC01-AKRAM\{0,-14} {1}" -f $_.Name, $_.Path) }
