# Plantilla de servidor endurecida — Rocky Linux 9 (CIS Benchmark Nivel 1)

Obligatorio de **Seguridad en Redes y Datos** — Analista en Infraestructura Informática, Universidad ORT Uruguay.
Escenario: **Corporación de Generación S.A. (cdg.uy)**.

Este repositorio implementa el punto **1. "Plantilla de servidor endurecida"** del alcance: un proceso
estandarizado, automatizado (Ansible) y replicable en cada despliegue para endurecer el sistema operativo
GNU/Linux base de la infraestructura, tomando como referencia **CIS Benchmark Nivel 1**.

## Índice

1. [Alcance y referencia](#1-alcance-y-referencia)
2. [Requisitos mínimos del obligatorio](#2-requisitos-mínimos-del-obligatorio)
3. [Requisitos previos](#3-requisitos-previos)
4. [Instalación y ejecución paso a paso](#4-instalación-y-ejecución-paso-a-paso)
5. [Variables principales](#5-variables-principales)
6. [Estructura del repositorio](#6-estructura-del-repositorio)
7. [Controles CIS implementados](#7-controles-cis-implementados)
8. [Decisiones y desviaciones justificadas](#8-decisiones-y-desviaciones-justificadas)
9. [Verificación](#9-verificación)
10. [Resolución de problemas](#10-resolución-de-problemas)
11. [Pruebas realizadas y limitaciones](#11-pruebas-realizadas-y-limitaciones)
12. [Uso de IA generativa](#12-uso-de-ia-generativa)
13. [Referencias](#13-referencias)

---

## 1. Alcance y referencia

| Ítem | Valor |
|---|---|
| Sistema operativo | Rocky Linux 9.x (x86_64 o aarch64) |
| Referencia | CIS Rocky Linux 9 Benchmark v2.0.0 — perfil **Level 1 – Server** |
| Numeración de controles | Igual a CIS Red Hat Enterprise Linux 9 v2.0.0. Los IDs y niveles se verificaron contra el mapeo oficial de ComplianceAsCode (`products/rhel9/controls/cis_rhel9.yml`). Conviene contrastarlos con el PDF oficial de CIS (descarga gratuita con registro). |
| Herramienta | Ansible (`ansible-core` del repositorio AppStream de Rocky 9) + colección `ansible.posix` |
| Entregable | Scripts y roles (no una imagen), idempotentes: se pueden ejecutar en cada despliegue y volver a ejecutar sin efectos secundarios. |

Cada tarea de Ansible lleva en su nombre el ID del control CIS que implementa (por ejemplo
`CIS 5.1.20 | ...`). Lo que no es Nivel 1 se marca como **[L2]** (Nivel 2) o **[extra]**.

## 2. Requisitos mínimos del obligatorio

| Requisito del alcance | Implementación | Archivos |
|---|---|---|
| **1. Firewall local** | firewalld (backend nftables) activo, un único gestor de firewall, zona por defecto sólo con los servicios necesarios, tráfico de loopback restringido, registro de paquetes rechazados para el SIEM. | `tasks/firewall.yml` |
| **2. Auditoría del sistema** | auditd con el conjunto completo de reglas CIS 6.3 (inmutables con `-e 2`), auditoría desde el arranque (`audit=1`), log de sudo y verificación de integridad con AIDE (incluye las herramientas de auditoría). | `tasks/auditd.yml`, `tasks/aide.yml`, `templates/audit-*.rules.j2` |
| **3. Acceso administrativo seguro** | SSH endurecido (sin login de root, sólo el grupo `wheel`, sólo claves públicas, algoritmos fuertes vía *crypto policy*, banner, límites de intentos), SSH aceptado sólo desde la red de administración o el bastión, sudo con pty y log propio, `su` bloqueado, bloqueo por intentos fallidos (faillock), políticas de contraseña y timeout de sesión. | `tasks/ssh.yml`, `tasks/sudo.yml`, `tasks/pam.yml`, `tasks/accounts.yml`, `tasks/firewall.yml` |
| **4. Integración con el SIEM** | Agente **Wazuh** enrolado contra el manager (logs del sistema, auditd y sudo), o, como alternativa, reenvío de todos los logs con rsyslog (cola en disco) más eventos de auditd. | `tasks/siem*.yml` |

## 3. Requisitos previos

La VM la prepara otro integrante del equipo. Antes de ejecutar la plantilla, el servidor debe tener:

1. **Rocky Linux 9.x** instalado (la instalación *Minimal* alcanza).
2. Acceso a Internet: repositorios de Rocky, `github.com`, `galaxy.ansible.com` y `packages.wazuh.com`.
3. **Un usuario administrador que no sea root, en el grupo `wheel`**, con su clave pública en
   `~/.ssh/authorized_keys`. La plantilla deshabilita el login SSH de root y las contraseñas por SSH;
   si no encuentra ese usuario y esa clave, **se detiene antes de cambiar nada** (protección anti-bloqueo).
4. La **IP o FQDN del manager de Wazuh** (o del colector syslog).
5. Recomendado (CIS Nivel 2, se define al instalar): particiones separadas para `/home`, `/var`, `/var/tmp`,
   `/var/log` y `/var/log/audit`. Si existen, la plantilla les aplica `nodev`, `nosuid` y `noexec`. Si `/tmp` no
   es una partición separada, se agrega como `tmpfs`.

## 4. Instalación y ejecución paso a paso

### Opción A — En el propio servidor (recomendada)

Conectarse al servidor con el usuario administrador y ejecutar:

1. Instalar git:

   ```bash
   sudo dnf -y install git
   ```

2. Descargar el repositorio:

   ```bash
   git clone https://github.com/Fabricio-Ramirez/SRDObligatorio.git
   ```

3. Entrar a la carpeta:

   ```bash
   cd SRDObligatorio
   ```

4. (Opcional) Ver qué cambiaría sin aplicar nada (modo simulación):

   ```bash
   sudo ./bootstrap.sh --siem-host 10.0.10.12 --check
   ```

5. Aplicar el endurecimiento (reemplazar la IP por la del manager de Wazuh):

   ```bash
   sudo ./bootstrap.sh --siem-host 10.0.10.12
   ```

6. Reiniciar si el resumen final dice `REBOOT REQUIRED` (la primera ejecución normalmente lo pide):

   ```bash
   sudo systemctl reboot
   ```

7. Verificar y guardar la evidencia:

   ```bash
   sudo ./scripts/verify.sh
   ```

`bootstrap.sh` instala `ansible-core` desde los repositorios de Rocky, instala la colección `ansible.posix`
(desde Ansible Galaxy, o desde EPEL si Galaxy no está accesible) y ejecuta `site.yml` sobre el propio
servidor. El log queda en `/var/log/srd-hardening/` y el resumen en `/var/log/hardening-report.txt`.

### Opción B — Una sola línea (sin clonar a mano)

Clona el repositorio en `/opt/srd-hardening` y lo ejecuta:

```bash
curl -fsSL https://raw.githubusercontent.com/Fabricio-Ramirez/SRDObligatorio/HEAD/bootstrap.sh | sudo bash -s -- --siem-host 10.0.10.12
```

Opciones de `bootstrap.sh` (ver `./bootstrap.sh --help`):

| Opción | Descripción |
|---|---|
| `--siem-host HOST` | IP/FQDN del manager Wazuh o colector syslog. |
| `--siem-type TYPE` | `wazuh` (por defecto), `syslog` o `none`. |
| `--branch NAME` | Rama del repositorio a usar (por defecto la rama principal). |
| `--check` | Simulación: muestra los cambios sin aplicarlos. |
| `--tags LISTA` | Ejecuta sólo algunas secciones, p. ej. `--tags ssh,firewall`. |
| `-- ...` | Argumentos extra para `ansible-playbook`, p. ej. `-- -e hardening_ssh_password_authentication=true`. |

### Opción C — Desde un nodo de control, para varios servidores

1. Copiar el inventario de ejemplo y completar las IPs:

   ```bash
   cp inventory/hosts.ini.example inventory/hosts.ini
   ```

2. Instalar la colección requerida:

   ```bash
   ansible-galaxy collection install -r requirements.yml -p collections
   ```

3. Ejecutar contra todos los servidores:

   ```bash
   ansible-playbook -i inventory/hosts.ini site.yml -e hardening_siem_host=10.0.10.12 --ask-become-pass
   ```

## 5. Variables principales

Todas las variables, con su referencia CIS, están documentadas en `roles/hardening/defaults/main.yml`.
Los valores del sitio van en `group_vars/all.yml` y las diferencias por servidor en `host_vars/<servidor>.yml`
(ver el ejemplo `host_vars/srv-bastion.yml.example`).

| Variable | Defecto | Uso |
|---|---|---|
| `hardening_siem_type` | `wazuh` | `wazuh`, `syslog` o `none`. |
| `hardening_siem_host` | `""` | Manager Wazuh / colector syslog (obligatorio salvo `none`). |
| `hardening_wazuh_agent_version` | `""` (última) | Fijar la versión del agente; **no puede ser más nueva que el manager**. |
| `hardening_ssh_allow_groups` | `[wheel]` | Grupos con acceso SSH (CIS 5.1.7). |
| `hardening_ssh_allowed_networks` | `[]` | Si se completa, SSH sólo se acepta desde esas redes (bastión / VPN de administración). |
| `hardening_ssh_password_authentication` | `false` | `true` para permitir contraseñas por SSH (por ejemplo, mientras no hay claves cargadas). |
| `hardening_ssh_disable_forwarding` | `true` | Poner `false` **sólo en el bastión / jump server** (necesita `ssh -J`). |
| `hardening_firewall_allowed_services` / `_ports` | `[ssh]` / `[]` | Servicios/puertos según el rol del servidor (p. ej. `["443/tcp"]`, Wazuh manager `["1514/tcp","1515/tcp","55000/tcp"]`). |
| `hardening_packages_absent` | lista CIS 2.1/2.2 | Paquetes que se desinstalan. **Un servidor web debe quitar `httpd`/`nginx` de la lista.** |
| `hardening_ip_forwarding` | `false` | `true` sólo en routers, gateways VPN o hosts de contenedores. |
| `hardening_grub_password_pbkdf2` | `""` | Hash de `grub2-mkpasswd-pbkdf2` (CIS 1.4.1); guardarlo con `ansible-vault`. |
| `hardening_audit_immutable` | `true` | Reglas de auditoría inmutables (CIS 6.3.3.20): cambiarlas requiere reiniciar. |
| `hardening_<sección>_enabled` | `true` | Habilita o deshabilita cada sección completa. |

## 6. Estructura del repositorio

```text
.
├── bootstrap.sh                 # Instala git + Ansible, descarga el repo y ejecuta el playbook
├── site.yml                     # Playbook principal
├── ansible.cfg
├── requirements.yml             # Colección ansible.posix (versión compatible con Rocky 9)
├── inventory/
│   ├── localhost.ini            # Ejecución local (bootstrap.sh)
│   └── hosts.ini.example        # Ejecución remota desde un nodo de control
├── group_vars/all.yml           # Parámetros del sitio (SIEM, redes de administración, NTP)
├── host_vars/srv-bastion.yml.example
├── scripts/verify.sh            # Evidencia post-endurecimiento (+ escaneo OpenSCAP opcional)
└── roles/hardening/
    ├── defaults/main.yml        # Todas las variables, comentadas con su ID CIS
    ├── handlers/main.yml
    ├── templates/               # sshd, reglas de auditoría, modprobe, rsyslog
    └── tasks/
        ├── preflight.yml        # Validaciones y protección anti-bloqueo
        ├── packages.yml         # CIS 1.2, 2.1, 2.2
        ├── filesystem.yml       # CIS 1.1
        ├── bootloader.yml       # CIS 1.3.1.2, 1.4, 6.3.1.2-3
        ├── selinux.yml          # CIS 1.3
        ├── process.yml          # CIS 1.5
        ├── crypto_policy.yml    # CIS 1.6
        ├── banners.yml          # CIS 1.7
        ├── services.yml         # CIS 2.1.21, 2.3, 2.4
        ├── sysctl.yml           # CIS 1.5, 3.3
        ├── firewall.yml         # CIS 4
        ├── ssh.yml              # CIS 5.1
        ├── sudo.yml             # CIS 5.2
        ├── pam.yml              # CIS 5.3, 5.4.1
        ├── accounts.yml         # CIS 5.4
        ├── logging.yml          # CIS 6.2
        ├── auditd.yml           # CIS 6.3 (L2)
        ├── siem.yml, siem_wazuh.yml, siem_syslog.yml
        ├── file_permissions.yml # CIS 7.1
        ├── aide.yml             # CIS 6.1 (se ejecuta al final)
        └── summary.yml          # Reporte: reinicio pendiente y puntos a revisar
```

## 7. Controles CIS implementados

| Sección CIS | Controles | Notas |
|---|---|---|
| 1.1.1 Módulos del kernel | 1.1.1.1-1.1.1.5, 1.1.1.8 | `install <mod> /bin/false` + `blacklist`; se descargan si están cargados. |
| 1.1.2 Particiones | 1.1.2.1.x-1.1.2.7.x | `nodev/nosuid/noexec` en las particiones existentes; `/dev/shm` y `/tmp` (tmpfs). |
| 1.2 Gestión de paquetes | 1.2.1.2, 1.2.2.1 | `gpgcheck=1` global y por repositorio; actualizaciones + `dnf-automatic` [extra]. |
| 1.3 SELinux | 1.3.1.1-1.3.1.5, 1.3.1.7, 1.3.1.8 | Modo `enforcing` (1.3.1.5 es L2); quita `selinux=0` del arranque. |
| 1.4 Gestor de arranque | 1.4.1 (opcional), 1.4.2 | Permisos 0600; contraseña GRUB si se define el hash. |
| 1.5 Procesos | 1.5.1-1.5.4 | ASLR, `ptrace_scope`, core dumps deshabilitados. |
| 1.6 Crypto policy | 1.6.1-1.6.7 | `DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NO-SSHCHACHA20:NO-SSHETM:NO-SSHWEAKMACS`. |
| 1.7 Banners | 1.7.1-1.7.6 | Aviso legal sin información del sistema operativo. |
| 2.1 / 2.2 Servicios y clientes | 2.1.1-2.1.19, 2.1.21, 2.2.1, 2.2.3-2.2.5 | Desinstalación y MTA sólo en loopback. |
| 2.3 Sincronización de hora | 2.3.1-2.3.3 | chrony activo, sin `-u root`, servidores NTP opcionales. |
| 2.4 Planificadores | 2.4.1.1-2.4.1.8, 2.4.2.1 | Permisos de cron y `cron.allow` / `at.allow`. |
| 3.1 / 3.3 Red | 3.1.3, 3.3.1-3.3.11 | Parámetros de kernel en `/etc/sysctl.d/60-cis-hardening.conf`. |
| 4 Firewall | 4.1.1, 4.1.2, 4.2.1, 4.2.2 | firewalld; loopback en zona `trusted` con reglas anti-spoofing. |
| 5.1 SSH | 5.1.1-5.1.22 | Drop-in `00-cis-hardening.conf` validado con `sshd -t` antes de reiniciar. |
| 5.2 Escalada de privilegios | 5.2.1-5.2.3, 5.2.5 (reporte), 5.2.6, 5.2.7 | `use_pty`, `logfile`, `timestamp_timeout`, `su` restringido a un grupo vacío. |
| 5.3 PAM | 5.3.1.x, 5.3.2.x, 5.3.3.x | authselect: `with-faillock`, `with-pwhistory`, `without-nullok`; pwquality y pwhistory. |
| 5.4 Cuentas | 5.4.1.1-5.4.1.6, 5.4.2.1-5.4.2.8, 5.4.3.2, 5.4.3.3 | Vencimiento de contraseñas, cuentas de sistema sin shell, `TMOUT`, `umask 027`. |
| 6.1 Integridad | 6.1.1-6.1.3 | AIDE con base inicial y chequeo diario (salida a syslog/SIEM). |
| 6.2 Logging | 6.2.1.x, 6.2.2.3-4, 6.2.3.1-6.2.3.7, 6.2.4.1 | journald persistente, rsyslog `0640`, sin recepción remota. |
| 6.3 Auditoría **[L2]** | 6.3.1.x-6.3.4.x | Reglas generadas según la tabla de syscalls de la arquitectura (`ausyscall`). |
| 7.1 Permisos | 7.1.1-7.1.11 (7.1.12 reporte) | passwd/shadow/group, sticky bit en directorios de escritura global. |

## 8. Decisiones y desviaciones justificadas

| Tema | Decisión | Justificación |
|---|---|---|
| Auditoría (CIS 6.3) | Se aplica completa aunque es **Nivel 2**. | La auditoría del sistema es un requisito mínimo del obligatorio y alimenta los casos de uso del SIEM. |
| SELinux `enforcing` (1.3.1.5) | Se aplica (L2). | Control MAC efectivo; Rocky lo trae por defecto. |
| `max_log_file_action` (6.3.2.2) | `rotate` en lugar de `keep_logs`. | Los eventos se centralizan en el SIEM; evita que el disco se llene en VMs de laboratorio. Para cumplir CIS al pie de la letra, usar `keep_logs` en `hardening_auditd_conf`. |
| `DisableForwarding` / `GSSAPIAuthentication` (5.1.10/5.1.11, L2 en servidores) | Activados por defecto; el bastión deshabilita el forwarding. | Reduce superficie de túneles SSH; el jump server lo necesita para `ProxyJump`. |
| Contraseñas por SSH | Deshabilitadas [extra]. | Autenticación por clave; el preflight impide el bloqueo si no hay claves cargadas. |
| Inactividad de root (5.4.1.5) | Se aplica vencimiento a root, pero no `--inactive`. | Root queda como cuenta de emergencia por consola. |
| `space_left_action = email` | Requiere un MTA para enviar el correo. | Si no hay MTA, auditd sólo registra un error (verificado en el código fuente de auditd); el evento igual llega al SIEM. |
| Permisos de logs (6.2.4.1) | Sólo se quitan los permisos de "otros". | La remediación CIS completa tiene excepciones por archivo. |
| Controles manuales | 1.2.1.1, 1.2.1.4, 2.1.22, 3.1.1, 4.2.1 (puertos por rol), 7.1.12/7.1.13 | Requieren decisión humana: la plantilla los reporta en `/var/log/hardening-report.txt`. |
| Particiones separadas (L2) | No se crean. | Se definen al instalar la VM (otro integrante). |
| No aplican al diseño | 1.8.x (GNOME/GDM), 3.1.2 (wifi), 4.3.x (nftables directo), 6.2.2.1.x y 6.2.2.2 (sólo journald). | Servidores sin interfaz gráfica ni wifi; se eligió firewalld y rsyslog como única opción de cada control. |
| No automatizados | 5.4.2.5 (PATH de root), 7.1.13 (revisión de SUID/SGID), 7.2.1 y 7.2.3-7.2.9 (consistencia de cuentas y homes). | Son controles de auditoría que requieren revisión manual; quedan como trabajo futuro. |
| Extras | `dnf-automatic`, `LogDenied` en firewalld, `NO-SSHWEAKMACS`, auditoría de `renameat2`. | Mejoran la gestión de vulnerabilidades y la detección en el SIEM. |

## 9. Verificación

- `sudo ./scripts/verify.sh`: chequeos rápidos PASS/FAIL de cada requisito (firewall, SSH, PAM, auditd, AIDE, SIEM),
  útil como evidencia para la documentación y la defensa.
- `sudo ./scripts/verify.sh --oscap`: además instala OpenSCAP y `scap-security-guide` y genera un reporte HTML con el
  perfil `xccdf_org.ssgproject.content_profile_cis_server_l1`. Si la mayoría de las reglas aparecen como
  `notapplicable`, el contenido SCAP instalado no reconoce el sistema como RHEL 9.
- `/var/log/hardening-report.txt`: resultado de la última ejecución (reinicio pendiente y puntos a revisar).
- Re-ejecutar el playbook debe terminar con `changed=0` o muy cerca (idempotencia).

## 10. Resolución de problemas

| Síntoma | Causa / solución |
|---|---|
| El playbook se detiene en *Preflight* | Es la protección anti-bloqueo: crear un usuario en `wheel` con clave SSH, o ejecutar con `-- -e hardening_ssh_password_authentication=true`. |
| No puedo entrar por SSH | Usar la consola de la VM con root. Revisar `sshd -T`, `hardening_ssh_allowed_networks` y `firewall-cmd --list-all`. |
| Cambié reglas de auditoría y no se aplican | Con `-e 2` el kernel las bloquea hasta reiniciar (el resumen lo indica). |
| Falla la instalación del agente Wazuh | Verificar acceso a `packages.wazuh.com` y que `hardening_wazuh_agent_version` no sea mayor que la del manager. |
| Docker/VPN dejan de enrutar | `hardening_ip_forwarding: true` en ese host. |
| Un servicio web desapareció | Quitar `httpd`/`nginx` de `hardening_packages_absent` para ese servidor. |

## 11. Pruebas realizadas y limitaciones

**Pruebas realizadas:**

- `ansible-lint` (perfil `production`) sin observaciones, `ansible-playbook --syntax-check` y `shellcheck`.
- Ejecución con **ansible-core 2.14.18** (la versión que publica CentOS Stream 9 / AppStream) y `ansible.posix 1.5.4`
  dentro de un contenedor **Rocky Linux 9.8**, con archivos de configuración reales y simulando sólo lo que un
  contenedor no tiene (systemd, firewalld, kernel, auditd, grubby):
  - ejecución completa sin errores y segunda ejecución sin cambios atribuibles al rol (idempotencia);
  - variantes `wazuh` y `syslog`, SSH restringido a redes IPv4/IPv6 y modo `--check`;
  - protecciones de preflight: sin administrador, sin claves SSH y sin dirección de SIEM.
- Módulos de crypto policy aplicados con `update-crypto-policies` real en Rocky 9.8.
- Directivas de `sshd` verificadas contra el código fuente de OpenSSH 8.7, y parámetros de rsyslog contra rsyslog 8.2310.

**Limitaciones (pendiente de validar por el equipo en la VM real antes de la defensa):** no se ejecutó sobre una VM
Rocky completa (servicios systemd, firewalld, SELinux, carga de reglas auditd en el kernel, enrolamiento real de
Wazuh). Ejecutar primero `--check`, luego la ejecución real, reiniciar y correr `scripts/verify.sh`.

## 12. Uso de IA generativa

Según las pautas del obligatorio:

- **Herramienta:** Claude Code (Anthropic).
- **Contexto de uso:** generación del código Ansible y de los scripts, redacción de esta documentación y
  contraste de los controles contra fuentes públicas (CIS vía ComplianceAsCode, código fuente de OpenSSH, audit,
  authselect, rsyslog y dnf).
- **Verificación:** el equipo debe revisar el contenido y validarlo en la maqueta (ver sección 11).

## 13. Referencias

- Center for Internet Security — CIS Benchmarks (Rocky Linux 9 / Red Hat Enterprise Linux 9, v2.0.0): <https://www.cisecurity.org/cis-benchmarks>
- ComplianceAsCode — mapeo de controles CIS RHEL 9 y perfiles SCAP: <https://github.com/ComplianceAsCode/content>
- Red Hat — *Security hardening*, Red Hat Enterprise Linux 9: <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/index>
- Wazuh — documentación oficial (instalación y enrolamiento de agentes): <https://documentation.wazuh.com/current/>
- Ansible — colección `ansible.posix`: <https://github.com/ansible-collections/ansible.posix>
