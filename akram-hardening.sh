#!/usr/bin/env bash
# =============================================================================
#  akram-hardening.sh
#  Bastionado (hardening) de Ubuntu Server 22.04 según el CIS Benchmark
#
#  Autor:    Akram El Mazzoudi Zarrouk
#  Proyecto: Linux CIS Hardening Auditor · Laboratorio AKRAM-LAB
#  Máquina:  akram-lab-srv01 (VirtualBox)
#
#  Uso:      sudo GRUB_PASS='contraseña' ./akram-hardening.sh
#            (GRUB_PASS es opcional; sin ella no se protege GRUB)
#
#  Antes de modificar un fichero se guarda una copia en
#  /root/akram-hardening-backup/<fecha>/ para poder revertir.
# =============================================================================
set -euo pipefail

USUARIO_SSH="akram"
FECHA="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/akram-hardening-backup/${FECHA}"
LOG="/var/log/akram-hardening.log"

AZUL='\033[1;34m'; VERDE='\033[1;32m'; AMARILLO='\033[1;33m'; NC='\033[0m'

seccion() { echo -e "\n${AZUL}==> [$1] $2${NC}" | tee -a "$LOG"; }
ok()      { echo -e "    ${VERDE}✔${NC} $*" | tee -a "$LOG"; }
aviso()   { echo -e "    ${AMARILLO}!${NC} $*" | tee -a "$LOG"; }

ejecutar() { eval "$@"; }

respaldar() {
    local f="$1"
    [[ -e "$f" ]] || return 0
    mkdir -p "${BACKUP_DIR}$(dirname "$f")"
    cp -a "$f" "${BACKUP_DIR}${f}"
}

if [[ $EUID -ne 0 ]]; then
    echo "Este script debe ejecutarse como root (sudo)." >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
echo "=== akram-hardening.sh · ${FECHA} · $(hostname) ===" >> "$LOG"

# -----------------------------------------------------------------------------
seccion "1.1" "Deshabilitar sistemas de ficheros que no se usan"
# squashfs NO se bloquea: snapd lo necesita (excepción justificada y documentada).
# vfat sí se bloquea porque esta máquina arranca por BIOS y no por UEFI.
for fs in cramfs freevxfs jffs2 hfs hfsplus udf vfat; do
    ejecutar "echo 'install ${fs} /bin/false' > /etc/modprobe.d/cis-${fs}.conf"
    ejecutar "echo 'blacklist ${fs}' >> /etc/modprobe.d/cis-${fs}.conf"
    ejecutar "modprobe -r ${fs} 2>/dev/null || true"
done
ok "cramfs, freevxfs, jffs2, hfs, hfsplus, udf y vfat bloqueados"

# -----------------------------------------------------------------------------
seccion "1.2" "/tmp como sistema de ficheros independiente (tmpfs)"
respaldar /etc/fstab
# Lección aprendida: con /tmp en noexec, debconf no puede ejecutar los scripts de
# configuración de los paquetes ("Can't exec /tmp/...config"). Se le indica que use /var/tmp.
echo 'APT::ExtractTemplates::TempDir "/var/tmp";' > /etc/apt/apt.conf.d/50-akram-tmp-noexec
if ! grep -qE '\s/tmp\s' /etc/fstab; then
    ejecutar "echo 'tmpfs  /tmp  tmpfs  defaults,rw,nosuid,nodev,noexec,relatime,size=512M  0 0' >> /etc/fstab"
    ejecutar "systemctl daemon-reload"
    ejecutar "mount /tmp"
fi
ok "/tmp montado como tmpfs con nosuid, nodev y noexec"

# -----------------------------------------------------------------------------
seccion "1.4" "Protección del gestor de arranque (GRUB)"
# La contraseña de GRUB se pasa por variable de entorno, nunca escrita en el script:
#   sudo GRUB_PASS='...' ./akram-hardening.sh
if [[ -n "${GRUB_PASS:-}" ]]; then
    HASH=$(printf '%s\n%s\n' "$GRUB_PASS" "$GRUB_PASS" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/{print $NF}')
    respaldar /etc/grub.d/40_custom
    respaldar /etc/grub.d/10_linux
    if ! grep -q 'password_pbkdf2' /etc/grub.d/40_custom; then
        cat >> /etc/grub.d/40_custom <<EOF
# Akram El Mazzoudi · CIS 1.4.1
set superusers="akram"
password_pbkdf2 akram ${HASH}
EOF
    fi
    # --unrestricted: el sistema arranca solo, pero editar entradas pide contraseña
    grep -q -- '--unrestricted' /etc/grub.d/10_linux || \
        ejecutar "sed -i 's/^CLASS=\"--class gnu-linux --class gnu --class os\"/CLASS=\"--class gnu-linux --class gnu --class os --unrestricted\"/' /etc/grub.d/10_linux"
    ejecutar "update-grub > /dev/null 2>&1"
    ok "Contraseña PBKDF2 en GRUB (arranque normal sin pedirla, edición protegida)"
else
    aviso "GRUB_PASS no definida: se omite la contraseña de GRUB"
fi
ejecutar "chown root:root /boot/grub/grub.cfg"
ejecutar "chmod 0400 /boot/grub/grub.cfg"
ok "/boot/grub/grub.cfg solo legible por root (0400)"

# -----------------------------------------------------------------------------
seccion "2.2" "Eliminar servicios innecesarios"
if dpkg -s rsync > /dev/null 2>&1; then
    ejecutar "DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq rsync > /dev/null"
fi
ok "rsync desinstalado (no se usa en este servidor)"

# -----------------------------------------------------------------------------
seccion "1.5" "ASLR y volcados de memoria (core dumps)"
respaldar /etc/security/limits.conf
cat > /etc/sysctl.d/60-akram-kernel.conf <<'EOF'
# Akram El Mazzoudi · CIS 1.5
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
grep -q '^\*\s\+hard\s\+core\s\+0' /etc/security/limits.conf || \
    ejecutar "echo '*    hard    core    0' >> /etc/security/limits.conf"
# Lección aprendida: apport (gestor de fallos de Ubuntu) vuelve a poner
# fs.suid_dumpable = 2 en cada arranque, así que hay que desactivarlo.
ejecutar "systemctl disable --now apport > /dev/null 2>&1 || true"
ejecutar "sed -i 's/^enabled=1/enabled=0/' /etc/default/apport 2>/dev/null || true"
ejecutar "sysctl -w fs.suid_dumpable=0 > /dev/null"
ok "ASLR completo, core dumps restringidos y apport desactivado"

# -----------------------------------------------------------------------------
seccion "3.1-3.2" "Parámetros de red del kernel (sysctl)"
cat > /etc/sysctl.d/60-akram-red.conf <<'EOF'
# Akram El Mazzoudi · CIS 3.1 y 3.2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
ejecutar "sysctl --system > /dev/null"
ok "Redirecciones, source routing y forwarding desactivados; SYN cookies y rp_filter activos"

# -----------------------------------------------------------------------------
seccion "3.4" "Protocolos de red poco comunes"
for proto in dccp sctp rds tipc; do
    ejecutar "echo 'install ${proto} /bin/false' > /etc/modprobe.d/cis-${proto}.conf"
    ejecutar "echo 'blacklist ${proto}' >> /etc/modprobe.d/cis-${proto}.conf"
done
ok "DCCP, SCTP, RDS y TIPC bloqueados"

# -----------------------------------------------------------------------------
seccion "3.3" "Cortafuegos iptables con política DROP por defecto"
ejecutar "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables iptables-persistent > /dev/null"
# Se desactiva ufw para que no compita con las reglas propias.
ejecutar "ufw disable > /dev/null 2>&1 || true"
mkdir -p /etc/iptables
respaldar /etc/iptables/rules.v4
cat > /etc/iptables/rules.v4 <<'EOF'
# Akram El Mazzoudi · CIS 3.3 · política de mínimo privilegio
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
# Loopback
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
# Resolver DNS local (systemd-resolved)
-A INPUT -i lo -p tcp --dport 53 -j ACCEPT
-A INPUT -i lo -p udp --dport 53 -j ACCEPT
# Conexiones ya establecidas
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# SSH entrante (administración). La protección contra fuerza bruta llega en el proyecto SSH Brute Force Detector
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# ICMP limitado
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
# Salida: DNS, HTTP/HTTPS (actualizaciones) y NTP
-A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -p icmp -j ACCEPT
# Registro de lo que se descarta
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "AKRAM-FW-DROP-IN: " --log-level 4
-A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "AKRAM-FW-DROP-OUT: " --log-level 4
COMMIT
EOF
ejecutar "iptables-restore < /etc/iptables/rules.v4"
ejecutar "systemctl enable netfilter-persistent > /dev/null 2>&1"
ok "INPUT, FORWARD y OUTPUT en DROP; solo SSH entrante y DNS/HTTP(S)/NTP saliente"

# -----------------------------------------------------------------------------
seccion "4.1" "Auditoría del sistema con auditd"
ejecutar "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd audispd-plugins > /dev/null"
cat > /etc/audit/rules.d/60-akram-cis.rules <<'EOF'
## Akram El Mazzoudi · CIS 4.1 · reglas de auditoría
-b 8192
# 4.1.5 Fecha y hora
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# 4.1.6 Usuarios y grupos
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
# 4.1.7 Entorno de red
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
# 4.1.8 Política MAC (AppArmor)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
# 4.1.9 Inicios y cierres de sesión
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
# 4.1.10 Sesiones
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
# 4.1.11 Cambios de permisos
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
# 4.1.12 Accesos denegados a ficheros
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
# 4.1.13 Montajes
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# 4.1.14 Borrado de ficheros
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
# Cambios en sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF
respaldar /etc/default/grub
if ! grep -q 'audit=1' /etc/default/grub; then
    ejecutar "sed -i 's/^GRUB_CMDLINE_LINUX=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX=\"\\1 audit=1 audit_backlog_limit=8192\"/' /etc/default/grub"
    ejecutar "update-grub > /dev/null 2>&1"
    ejecutar "chmod 0400 /boot/grub/grub.cfg"
fi
ejecutar "systemctl enable --now auditd > /dev/null 2>&1"
ejecutar "augenrules --load > /dev/null 2>&1 || true"
ok "auditd activo con reglas CIS; audit=1 en el arranque"

# -----------------------------------------------------------------------------
seccion "4.2" "Registro con rsyslog"
respaldar /etc/rsyslog.conf
grep -q '^\$FileCreateMode 0640' /etc/rsyslog.conf || \
    ejecutar "sed -i '1i \$FileCreateMode 0640' /etc/rsyslog.conf"
ejecutar "systemctl restart rsyslog"
ok "Los ficheros de log nuevos se crean con permisos 0640"

# -----------------------------------------------------------------------------
seccion "5.1" "Permisos de cron"
ejecutar "chown root:root /etc/crontab && chmod 0600 /etc/crontab"
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    ejecutar "chown root:root $d && chmod 0700 $d"
done
ok "crontab y directorios de cron solo accesibles por root"

# -----------------------------------------------------------------------------
seccion "5.2" "Bastionado de SSH"
respaldar /etc/ssh/sshd_config
# Cada directiva se elimina primero (comentada o no) y luego se añade una sola vez,
# para que no haya valores duplicados: sshd usa siempre el primero que encuentra.
declare -A SSH_CIS=(
    [LogLevel]="VERBOSE"            [X11Forwarding]="no"
    [MaxAuthTries]="4"              [IgnoreRhosts]="yes"
    [PermitRootLogin]="no"          [PermitEmptyPasswords]="no"
    [PermitUserEnvironment]="no"    [LoginGraceTime]="60"
    [ClientAliveInterval]="300"     [ClientAliveCountMax]="3"
    [AllowUsers]="${USUARIO_SSH}"   [Banner]="/etc/issue.net"
    [Ciphers]="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    [MACs]="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    [KexAlgorithms]="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256"
)
sed -i '/^# --- Akram El Mazzoudi · CIS 5.2 ---$/d' /etc/ssh/sshd_config
for k in "${!SSH_CIS[@]}"; do
    sed -i -E "/^\s*#?\s*${k}\s/Id" /etc/ssh/sshd_config
done
echo "# --- Akram El Mazzoudi · CIS 5.2 ---" >> /etc/ssh/sshd_config
for k in $(printf '%s\n' "${!SSH_CIS[@]}" | sort); do
    echo "${k} ${SSH_CIS[$k]}" >> /etc/ssh/sshd_config
done
cat > /etc/issue.net <<'EOF'
*****************************************************************
*  AKRAM-LAB · Servidor de laboratorio de Akram El Mazzoudi      *
*  Acceso restringido a usuarios autorizados.                    *
*  Toda la actividad queda registrada y auditada.                *
*****************************************************************
EOF
cp /etc/issue.net /etc/issue
ejecutar "chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config"
ejecutar "chmod 0600 /etc/ssh/ssh_host_*_key"
if sshd -t; then
    ejecutar "systemctl reload ssh"
    ok "SSH bastionado y configuración validada con sshd -t"
else
    aviso "sshd -t ha fallado: se restaura la copia de seguridad"
    cp -a "${BACKUP_DIR}/etc/ssh/sshd_config" /etc/ssh/sshd_config
fi

# -----------------------------------------------------------------------------
seccion "5.3-5.5" "Política de contraseñas y bloqueo de cuentas"
ejecutar "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-pwquality > /dev/null"
respaldar /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf <<'EOF'
# Akram El Mazzoudi · CIS 5.3
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF
respaldar /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/; s/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
ejecutar "chage --maxdays 365 --mindays 1 --warndays 7 ${USUARIO_SSH}"

# Bloqueo tras 5 intentos fallidos durante 15 minutos (pam_faillock)
respaldar /etc/pam.d/common-auth
respaldar /etc/pam.d/common-account
cat > /etc/security/faillock.conf <<'EOF'
# Akram El Mazzoudi · CIS 5.5
deny = 5
unlock_time = 900
fail_interval = 900
audit
EOF
if ! grep -q pam_faillock /etc/pam.d/common-auth; then
cat > /etc/pam.d/common-auth <<'EOF'
# Akram El Mazzoudi · CIS 5.5 · bloqueo de cuentas con pam_faillock
auth    required                        pam_faillock.so preauth
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail
auth    sufficient                      pam_faillock.so authsucc
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
auth    optional                        pam_cap.so
EOF
fi
grep -q pam_faillock /etc/pam.d/common-account || \
    ejecutar "echo 'account required                        pam_faillock.so' >> /etc/pam.d/common-account"
ok "Contraseñas de 14+ caracteres, caducidad 365 días y bloqueo tras 5 fallos"

# -----------------------------------------------------------------------------
seccion "6.1" "Permisos de ficheros críticos"
ejecutar "chmod 0644 /etc/passwd /etc/group"
ejecutar "chown root:root /etc/passwd- /etc/group- && chmod 0600 /etc/passwd- /etc/group-"
ejecutar "chown root:shadow /etc/shadow /etc/gshadow && chmod 0640 /etc/shadow /etc/gshadow"
ejecutar "chmod 0600 /etc/shadow- /etc/gshadow- 2>/dev/null || true"
ok "passwd, group, shadow y gshadow con los permisos que pide CIS"

# -----------------------------------------------------------------------------
echo -e "\n${VERDE}Hardening completado.${NC} Copias de seguridad en ${BACKUP_DIR}"
echo "Registro: ${LOG}"
echo "Algunos cambios (audit=1 en el kernel) se aplican tras reiniciar."
