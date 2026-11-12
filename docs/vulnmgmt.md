# Gestión de vulnerabilidades — plataforma sobre el servidor Wazuh

Punto **5. "Gestión de Vulnerabilidades"** del obligatorio de **Seguridad en Redes y Datos**
(Corporación de Generación S.A., cdg.uy).

> La plataforma debe gestionar las vulnerabilidades y actualizaciones de los servidores, emitir
> informes periódicos y traducirlos en acciones priorizadas y viables para los equipos de
> infraestructura. Suma valor el uso de IA y de flujos *no-code*.

Se instala igual que el endurecimiento (*install and play* con `bootstrap.sh` + Ansible), pero **sólo en
el servidor Wazuh**, y queda alojada en ese mismo servidor. Todo es software libre y gratuito, y la IA
corre **localmente**, sin APIs pagas ni envío de datos a terceros.

## Índice

1. [Qué resuelve](#1-qué-resuelve)
2. [Arquitectura](#2-arquitectura)
3. [Requisitos previos](#3-requisitos-previos)
4. [Instalación](#4-instalación)
5. [Uso diario](#5-uso-diario)
6. [Remediación de las vulnerabilidades](#6-remediación-de-las-vulnerabilidades)
7. [Metodología de priorización](#7-metodología-de-priorización)
8. [IA local optimizada para una VM chica](#8-ia-local-optimizada-para-una-vm-chica)
9. [Flujo no-code (n8n)](#9-flujo-no-code-n8n)
10. [Alertas en el SIEM](#10-alertas-en-el-siem)
11. [Seguridad de la propia plataforma](#11-seguridad-de-la-propia-plataforma)
12. [Variables principales](#12-variables-principales)
13. [Archivos](#13-archivos)
14. [Resolución de problemas](#14-resolución-de-problemas)
15. [Pruebas realizadas y limitaciones](#15-pruebas-realizadas-y-limitaciones)

---

## 1. Qué resuelve

| Requisito del punto 5 | Implementación |
|---|---|
| Gestionar vulnerabilidades **y actualizaciones** | Usa el inventario de paquetes y el detector de vulnerabilidades de Wazuh (≥ 4.8) de **todos los agentes**. Agrupa los hallazgos por paquete y genera la **acción concreta**: actualizar a la versión corregida (comando `dnf`/`apt` exacto), mitigar si no hay parche o revisar. Indica si la actualización **requiere reinicio** (kernel, glibc, systemd, openssl-libs…). |
| **Informes periódicos** | Temporizador systemd (todos los días 03:30). Cada ejecución publica el informe en el panel web, un CSV, el histórico (tendencia de 90 ejecuciones) y un resumen en Wazuh. |
| Acciones **priorizadas** | Riesgo 0-100 que combina **CVSS** (severidad), **EPSS** (probabilidad de explotación, FIRST), **CISA KEV** (explotadas activamente) y la **criticidad** del servidor. Prioridad P1-P4 con **plazo (SLA)** y seguimiento de acciones **vencidas**, **nuevas**, **escaladas** y **resueltas**. |
| Acciones **viables** | Una acción por paquete (no una por CVE): servidores afectados, versión objetivo, comandos de remediación y de verificación, aviso de reinicio y ventana de mantenimiento sugerida. |
| **Remediar** (resolver las vulnerabilidades) | Por cada servidor genera **comandos listos para copiar** y un **playbook de Ansible** (`remediation.yml`) con simulación previa (`--check`), filtro por prioridad y aviso de reinicio. La plataforma **no ejecuta nada** en los servidores: lo aplica el equipo desde el bastión (sección 6). |
| **IA** (valor agregado) | Modelo de lenguaje **local** (Ollama + Qwen2.5 0.5B/1.5B, licencia Apache 2.0) que redacta el resumen ejecutivo, los riesgos clave y una nota por acción. Afinado para pocos recursos (sección 8). |
| **No-code** (valor agregado) | **n8n Community Edition** (gratuito, *self-hosted*) con un flujo importado: cada lunes lee el informe, filtra P1/P2 y arma el aviso para infraestructura (correo, Teams, Slack, Telegram… se cambian desde el editor visual). |
| Integración con el SIEM | Eventos JSON leídos por el propio manager con reglas propias (100800-100808): acciones P1/P2 nuevas o escaladas, KEV y vencidas generan alertas de nivel 10-14. |

## 2. Arquitectura

```text
 Servidores (agente Wazuh)                              Servidor Wazuh (all-in-one)
 ┌────────────┐  inventario de paquetes   ┌──────────────────────────────────────────────────────────────┐
 │ srv-idp    │──────────────────────────▶│ wazuh-manager ── detector de vulnerabilidades                │
 │ srv-web    │                           │      │                                                       │
 │ srv-bastion│                           │      ▼                                                       │
 │ ...        │                           │ wazuh-indexer  índice wazuh-states-vulnerabilities-*         │
 └────────────┘                           │      │ (usuario de sólo lectura vulnmgmt-reader)             │
                                          │      ▼                                                       │
   Internet (opcional, con caché)         │ vulnmgmt.timer 03:30 ─▶ motor Python (sólo librería estándar)│
   CISA KEV ───────────────────────────────────▶ │  1. recolecta hallazgos y agentes                     │
   FIRST EPSS ─────────────────────────────────▶ │  2. enriquece con KEV + EPSS                          │
                                          │      │  3. agrupa, prioriza (P1-P4), SLA y seguimiento       │
                                          │      │  4. IA local (Ollama 127.0.0.1:11434) ─ resumen/notas │
                                          │      │  5. publica                                           │
                                          │      ├──▶ /var/www/vulnmgmt/data (JSON, CSV, histórico)      │
                                          │      │        └──▶ nginx :8443 (HTTPS + usuario) ─▶ Panel web│
                                          │      └──▶ /var/log/vulnmgmt/events.json ─▶ reglas Wazuh      │
                                          │                                            (alertas 10-14)   │
                                          │ n8n 127.0.0.1:5678 (lunes 08:00) ─▶ lee el informe ─▶ aviso  │
                                          └──────────────────────────────────────────────────────────────┘
```

Componentes y consumo aproximado:

| Componente | Cómo corre | Recursos |
|---|---|---|
| Motor `vulnmgmt` | Servicio *oneshot* disparado por el temporizador; sólo librería estándar de Python 3.9+ | Máx. 50 % de 1 CPU y 512 MB (`CPUQuota`/`MemoryMax`), prioridad baja |
| Ollama + modelo | Servicio en 127.0.0.1; el modelo se carga **sólo** durante la ejecución diaria y se descarga al terminar | Máx. 2 CPU y 3 GB; en reposo ≈ 0 de RAM para el modelo |
| nginx | Sirve archivos estáticos | Mínimo |
| n8n | Contenedor Podman (Quadlet) en 127.0.0.1 | Máx. 1 GB |

## 3. Requisitos previos

1. **Servidor Wazuh 4.8 o superior *all-in-one*** (manager + indexer + dashboard) sobre **Rocky Linux 9 o 10** o
   **Amazon Linux 2023** (el sistema de la imagen oficial de Wazuh, según el equipo), instalado con el asistente oficial
   (`wazuh-install.sh -a`) o con esa imagen. **Amazon Linux 2 no se admite** (trae Python 3.7 y el motor necesita 3.9 o
   superior). La detección de vulnerabilidades viene habilitada por defecto (`<vulnerability-detection>` en
   `/var/ossec/etc/ossec.conf`, con `index-status` en `yes`). Para saber qué sistema tiene el servidor:

   ```bash
   grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release; python3 --version
   ```
2. Agentes Wazuh enrolados en los servidores (lo hace la plantilla de endurecimiento).
3. La contraseña del usuario **`admin` del indexer**. El asistente la deja en `wazuh-install-files.tar`:

   ```bash
   sudo tar -O -xf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
   ```

   Se usa **una sola vez** para crear el usuario de sólo lectura `vulnmgmt-reader`; no se guarda.
4. Opcional: un usuario de la **API de Wazuh** con rol de sólo lectura, para mostrar la cobertura (agentes sin
   hallazgos y agentes desconectados).
5. **RAM:** Wazuh *all-in-one* necesita unos 8 GB; la IA suma 1-2 GB **sólo mientras corre** el informe. Si no hay
   memoria libre suficiente el motor usa el modelo más chico o, si tampoco alcanza, el resumen por reglas.
6. Salida a Internet durante la instalación: `github.com` (Ollama), `registry.ollama.ai` (modelos), `docker.io`
   (n8n) y los repositorios de la distribución (Rocky o Amazon Linux). En cada informe, opcionalmente, `cisa.gov` o `raw.githubusercontent.com` (KEV)
   y `api.first.org` (EPSS). Sin Internet la plataforma sigue funcionando con la última caché.

### Relación con el endurecimiento (punto 1)

> **Decisión del equipo: el servidor Wazuh no se endurece con la plantilla del punto 1.** En ese servidor sólo se
> instala la plataforma de vulnerabilidades (`sudo ./bootstrap.sh --component vulnmgmt`). El endurecimiento
> (`--component hardening`) se aplica al resto de los servidores.

Consecuencias de esa decisión:

- **Parches del propio servidor Wazuh:** sin el endurecimiento no hay `dnf-automatic`, así que sus actualizaciones las aplica
  el equipo a mano. El panel igual lo muestra como el agente 000, con su comando local (sección 6). Los componentes
  `wazuh-*` siempre se actualizan siguiendo la guía oficial de Wazuh.
- **No se usa `host_vars/srv-siem.yml.example`**: esa excepción (conservar `nginx`) sólo hace falta si algún día se
  endureciera un servidor Wazuh.
- **Sistema operativo:** el endurecimiento sólo aplica a Rocky Linux 9/10 (sigue los benchmarks CIS de Rocky y RHEL).
  `bootstrap.sh` lo rechaza en otros sistemas, como Amazon Linux, con un mensaje claro. Cada componente valida su propio
  sistema operativo, así que uno nunca bloquea al otro.

Si en el futuro se decidiera endurecer un servidor Wazuh **con Rocky Linux**, hay que declarar dos diferencias **antes** de
ejecutar la plantilla sobre él (si no, CIS 2.1.18 desinstala nginx y el panel deja de funcionar):

```bash
cp host_vars/srv-siem.yml.example host_vars/srv-siem.yml      # ejecución desde un nodo de control
cp host_vars/srv-siem.yml.example host_vars/localhost.yml     # ejecución local con bootstrap.sh
```

Ese archivo conserva `nginx` (`hardening_packages_keep: [nginx]`), abre los puertos de Wazuh y no instala el
agente en el propio manager (`hardening_siem_type: none`). El puerto del panel (8443) lo abre este rol.

## 4. Instalación

### Opción A — En el propio servidor Wazuh (recomendada)

```bash
sudo dnf -y install git
```

```bash
git clone https://github.com/Fabricio-Ramirez/SRDObligatorio.git
```

```bash
cd SRDObligatorio
```

```bash
sudo ./bootstrap.sh --component vulnmgmt
```

`bootstrap.sh` instala Ansible y la colección necesaria, pide (sin mostrarla) la contraseña de `admin` del indexer
y, opcionalmente, el usuario y la contraseña de la API, y ejecuta `vulnmgmt.yml`. Las contraseñas viajan en un
archivo temporal con permisos 0600 que se borra al terminar; nunca aparecen en la línea de comandos.
Al volver a ejecutarlo ya no pide la contraseña del indexer (usa el usuario de lectura creado).

**En Amazon Linux 2023** el mismo comando funciona. Si la distribución no empaqueta `ansible-core`, `bootstrap.sh` lo
instala en un entorno virtual de Python aparte (`/opt/srd-ansible`, `ansible-core` 2.14 o 2.15, que corren con Python 3.9)
y lo usa desde ahí; no toca el Python del sistema. Si ya tenías el repositorio clonado, actualizarlo **antes** de
ejecutar (el script no se actualiza a sí mismo al correr desde un clon):

```bash
git pull --ff-only
```

Si no hay `firewalld` activo (es lo habitual en Amazon Linux), el rol **no abre el puerto 8443** y lo avisa: hay que
abrirlo con el firewall que se use (iptables, nftables o el grupo de seguridad de la nube).

### Volver a ejecutar la instalación

El comando es idempotente: sirve para actualizar el motor, el panel o la configuración. Primero actualizar el repositorio
(el script no se actualiza a sí mismo cuando se ejecuta desde un clon) y volver a lanzar:

```bash
cd <carpeta-del-repositorio> && git pull --ff-only
```

```bash
sudo ./bootstrap.sh --component vulnmgmt
```

- **No vuelve a pedir** la contraseña de `admin` del indexer (usa el usuario de lectura que ya existe) y **conserva** la
  contraseña del panel, el certificado, el usuario de lectura y el flujo ya importado en n8n.
- **Recuerda el usuario de la API de Wazuh** (lo guarda en `/etc/vulnmgmt/api.user`, 0640) y vuelve a pedir **sólo su
  contraseña**, que nunca se escribe en disco ni se muestra. Si se da Enter en la contraseña, la configuración se regenera
  **sin la API** y el panel pierde la cobertura de agentes (los desconectados o sin hallazgos). No conviene pasar la
  contraseña en la línea de comandos, porque queda en el historial del shell.
- Cada ejecución genera además un informe nuevo, igual que `sudo systemctl start vulnmgmt.service`.

### Instalación desatendida

Las tres preguntas interactivas se pueden responder por variables de entorno, de modo que la instalación no espere a
nadie. El script las usa en lugar de preguntar:

| Variable | Equivale a |
|---|---|
| `VULNMGMT_INDEXER_ADMIN_PASSWORD` | Contraseña de `admin` del indexer (`wazuh-passwords.txt`) |
| `VULNMGMT_API_USER` | Usuario de la API de Wazuh para el inventario de agentes |
| `VULNMGMT_API_PASSWORD` | Contraseña de ese usuario |

Para que no queden en el historial del shell, conviene dejarlas en un archivo legible sólo por root y cargarlo en el
momento de ejecutar:

```bash
sudo install -m 0600 /dev/null /etc/vulnmgmt/install.env
sudo vi /etc/vulnmgmt/install.env
```

(contenido: las tres variables, una por línea, en formato `VARIABLE=valor`)

```bash
sudo bash -c 'set -a; . /etc/vulnmgmt/install.env; set +a; ./bootstrap.sh --component vulnmgmt'
```

### Entornos sin Podman

El flujo no-code de n8n corre como unidad Quadlet de Podman. En plataformas donde Podman no existe ni se puede
instalar —el caso de la OVA de Wazuh sobre Amazon Linux 2023—, el preflight lo detecta, **omite n8n** y deja instalado
todo el resto, avisándolo en la salida. Para desactivarlo de forma explícita:

```bash
sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_n8n_enabled=false
```

Prueba sin cambios (`--check`) y modo demostración (publica datos sintéticos si todavía no hay agentes con
hallazgos):

```bash
sudo ./bootstrap.sh --component vulnmgmt --check
```

```bash
sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_first_run=demo
```

### Opción B — Desde un nodo de control

Agregar el servidor al grupo `[wazuh_server]` de `inventory/hosts.ini` (ver `inventory/hosts.ini.example`) y
guardar las contraseñas cifradas con `ansible-vault`:

```bash
ansible-vault create secrets-vulnmgmt.yml
```

(contenido: `vulnmgmt_indexer_admin_password: "..."`, y opcionalmente `vulnmgmt_api_user` / `vulnmgmt_api_password`)

```bash
ansible-playbook -i inventory/hosts.ini vulnmgmt.yml -e @secrets-vulnmgmt.yml --ask-vault-pass
```

### Qué hace el rol `roles/vulnmgmt`

| Paso | Archivo |
|---|---|
| Valida el sistema operativo (Rocky 9/10 o Amazon Linux 2023), Python 3.9 o superior, que sea el servidor Wazuh, que haya credenciales y que Podman esté disponible si se pidió n8n | `tasks/preflight.yml` |
| Paquetes (python3, nginx, podman…), usuario de servicio `vulnmgmt`, motor y panel, certificado TLS, secretos generados | `tasks/base.yml` |
| Rol y usuario de **sólo lectura** en el indexer (sólo el índice de vulnerabilidades) y prueba de acceso | `tasks/indexer.yml` |
| Configuración del motor (`/etc/vulnmgmt/config.json`, 0640) y logrotate | `tasks/config.yml` |
| Ollama (versión fija, verificada con SHA-256), servicio limitado y descarga de los modelos | `tasks/ollama.yml` |
| nginx (HTTPS, usuario y contraseña, cabeceras de seguridad) y firewalld | `tasks/web.yml` |
| Reglas de Wazuh y lectura de los eventos (`wazuh-analysisd -t` antes de reiniciar) | `tasks/wazuh.yml` |
| n8n con Podman Quadlet e importación del flujo | `tasks/n8n.yml` |
| Servicio y temporizador, primer informe y resumen de acceso | `tasks/schedule.yml` |

Es idempotente: se puede volver a ejecutar para actualizar el motor, el panel o la configuración.

## 5. Uso diario

| Qué | Cómo |
|---|---|
| Panel web | `https://<IP-del-servidor-Wazuh>:8443/` — usuario `infra`, contraseña: `sudo cat /etc/vulnmgmt/web.secret`. El certificado es autofirmado (el navegador pide aceptarlo). |
| Generar un informe ahora | `sudo systemctl start vulnmgmt.service` (ver [Generar el informe en caliente](#generar-el-informe-en-caliente)) |
| Ver la ejecución | `journalctl -u vulnmgmt.service` |
| Próxima ejecución | `systemctl list-timers vulnmgmt.timer` |
| Plan de remediación | `/var/www/vulnmgmt/data/remediation.yml` (botón *Descargar playbook* del panel) |
| Datos | `/var/www/vulnmgmt/data/latest.json`, `actionables.csv` (botón *Descargar CSV*), `history.json`, `reports/AAAA-MM-DD.json` |
| Estado (SLA y seguimiento) | `/var/lib/vulnmgmt/state.json` |

El panel muestra:

- **Indicadores:** CVE únicas, servidores afectados / total, explotadas activamente (KEV), acciones P1/P2,
  **vencidas**, sin parche y resueltas en los últimos 30 días.
- **Resumen de la IA:** resumen ejecutivo, riesgos clave y ventana de mantenimiento sugerida (o el resumen por
  reglas si la IA no estuvo disponible; el panel indica la fuente).
- **Plan de acción:** tabla filtrable por prioridad, tipo de acción, texto (paquete, servidor o CVE) y "sólo vencidas". Cada fila se despliega con los CVE (enlace a
  NVD), los servidores, los comandos de remediación y de verificación con botón de copiar, el motivo de la
  prioridad y la nota de la IA.
- **Plan de remediación:** comandos por servidor (sólo P1, hasta P2 o todas) con botón de copiar, los comandos de Ansible
  y la lista de acciones que requieren intervención manual.
- **Servidores:** hallazgos, riesgo máximo y criticidad de cada uno (incluye los agentes sin hallazgos si la API
  está configurada).
- **Tendencia** y **metodología** usadas.

### Generar el informe en caliente

El informe no hace falta esperarlo: se puede generar en cualquier momento, desde el servidor Wazuh, sin esperar al horario programado.

```bash
sudo systemctl start vulnmgmt.service
```

Ese comando espera a que el informe termine y devuelve error si falló. Para que la terminal vuelva enseguida y seguir
el avance aparte:

```bash
sudo systemctl start --no-block vulnmgmt.service
```

```bash
journalctl -u vulnmgmt.service -f
```

Al terminar, el panel muestra el informe nuevo al recargar la página. La primera vez, el informe también se genera
solo al final de la instalación (`vulnmgmt_first_run: run`).

| Qué | Detalle |
|---|---|
| **Informe programado** | Todos los días a las 03:30 (`vulnmgmt_schedule`), con hasta 15 minutos de retraso aleatorio. Si el servidor estaba apagado a esa hora, se ejecuta al volver a encenderse (`Persistent=true`). El generado en caliente no cambia ese horario. |
| **Desde el panel o n8n** | **No está previsto**: el panel es de sólo lectura a propósito, porque lanzar un comando desde la web ampliaría la superficie de ataque del servidor Wazuh. Se genera desde la terminal. |
| **Cuánto tarda** | Con la IA activa puede tardar varios minutos en una VM chica (el límite es `vulnmgmt_ai_timeout`, 900 segundos); sin IA, o con el resumen por reglas, mucho menos. No se midieron tiempos reales en una VM. |
| **Qué tan actual es** | El informe refleja lo que Wazuh **ya tiene indexado**. El inventario de paquetes de cada agente se refresca cada hora (`syscollector`) y el feed de vulnerabilidades cada 60 minutos (`feed-update-interval`), así que un servidor recién parcheado puede seguir apareciendo hasta el siguiente ciclo de Wazuh. |
| **KEV y EPSS** | Se guardan en caché (KEV 24 horas, EPSS por día), por lo que varios informes el mismo día reutilizan esos datos. |
| **Si falla** | `journalctl -u vulnmgmt.service` indica la causa. El panel sigue mostrando el último informe válido: una ejecución fallida no publica un resultado vacío. |

## 6. Remediación de las vulnerabilidades

La plataforma **prepara** la remediación y el equipo de infraestructura la **ejecuta**. El motor nunca corre comandos
en los servidores, por dos razones de seguridad:

- Para parchear por SSH desde el servidor Wazuh haría falta una clave con permisos de administrador en **todos** los
  servidores guardada en el equipo más sensible (el SIEM): quien lo comprometiera controlaría toda la infraestructura.
- El endurecimiento sólo acepta SSH desde el bastión o la red de administración (`hardening_ssh_allowed_networks`),
  que no tiene por qué incluir al servidor Wazuh. Además, parchear sin revisión puede romper servicios.

Hay tres niveles, de menor a mayor control:

| Nivel | Qué hace | Cuándo usarlo |
|---|---|---|
| **1. Parches de seguridad automáticos** | El hardening instala las actualizaciones pendientes y activa `dnf-automatic` (`upgrade_type = security`, `apply_updates = yes`). | Siempre: reduce las vulnerabilidades abiertas sin intervención. |
| **2. Un comando por servidor** | En el panel, sección *Plan de remediación*, cada servidor muestra su comando para copiar, por ejemplo `sudo dnf upgrade -y --disablerepo='wazuh*' glibc kernel`. Hay tres alcances: sólo P1, P1 + P2 y todas. Junto a cada uno aparecen sus comandos de Ansible (simular y aplicar) con el nombre real del servidor. | Pocos servidores o una urgencia (P1 / KEV). Se ejecuta en el propio servidor. |
| **3. Playbook de Ansible** | `remediation.yml`: una *play* por servidor, con una tarea por prioridad (etiquetas `P1`…`P4`), simulación real con `--check --diff` y aviso de reinicio. | Varios servidores, o cuando se quiere dejar registro y poder repetirlo. |

### Con el playbook (nivel 3), desde el bastión o el nodo de control

1. **Obtener el playbook** (se regenera en cada informe): botón *Descargar playbook* del panel, o por SSH:

   ```bash
   scp <admin>@<servidor-wazuh>:/var/www/vulnmgmt/data/remediation.yml .
   ```

2. **Simular**, sin cambiar nada (`-K` pide la contraseña de sudo: el hardening no concede `NOPASSWD`):

   ```bash
   ansible-playbook -i inventory/hosts.ini remediation.yml --limit srv-web --tags P1 -K --check --diff
   ```

3. **Aplicar**, con el mismo comando sin `--check --diff`:

   ```bash
   ansible-playbook -i inventory/hosts.ini remediation.yml --limit srv-web --tags P1 -K
   ```

4. **Reiniciar si hace falta.** Al final de cada servidor el playbook informa `REINICIO NECESARIO` (kernel, glibc, systemd…)
   o `No hace falta reiniciar`. **Ningún paso reinicia el servidor**: se programa en la ventana de mantenimiento.
5. **Verificar.** Cada acción del panel trae su comando de verificación (por ejemplo `rpm -q <paquete>`). El inventario
   de paquetes de Wazuh se actualiza cada hora (`syscollector`, `interval 1h`), así que la acción pasa a *resuelta* en
   el informe siguiente a ese refresco; para adelantarlo, `sudo systemctl start vulnmgmt.service` una vez actualizado.

- `--tags P1` aplica sólo la prioridad P1; usar `P2`, `P3` o `P4`, o quitarlo para aplicar todas. El panel ya trae el
  comando de cada servidor con su nombre real (y la variante local para el servidor Wazuh), listo para copiar.
- **El servidor Wazuh** (agente 000) se parchea en local con el nombre que muestra el panel:
  `ansible-playbook -i '<nombre-del-agente>,' -c local remediation.yml -K`
- **Nombres:** las *plays* usan el **nombre del agente de Wazuh**, que el endurecimiento fija igual al *hostname*
  (`hardening_wazuh_agent_name`). Debe coincidir con el nombre del servidor en `inventory/hosts.ini`; si no, usar ese
  nombre como alias en el inventario (`srv-web ansible_host=10.0.10.20`). Si no coincide, Ansible avisa
  `skipping: no hosts matched` y no hace nada.

### Qué se automatiza y qué queda manual

| Caso | Tratamiento |
|---|---|
| Acción **Actualizar** de paquetes `rpm` (dnf) o `deb` (apt) | Se incluye en el playbook y en los comandos por servidor. Sólo actualiza paquetes **ya instalados** (`update_only` / `only_upgrade`), a la última versión disponible (≥ la corregida). |
| Acción **Mitigar** (sin parche) o **Revisar** | Manual: se lista con el motivo y las mitigaciones sugeridas. |
| Otros gestores de paquetes (pip, npm, Windows…) | Manual. |
| Componentes de Wazuh (`wazuh-*`) | **Siempre manual.** El agente no puede ser más nuevo que el manager; actualizarlos sin orden rompe la regla que aplica el endurecimiento (repositorio de Wazuh deshabilitado). Se excluyen también con `--disablerepo='wazuh*'`. |
| Nombres de paquete o de servidor con caracteres no estándar | Manual: no se genera ningún comando, ni en el playbook ni en el botón *Copiar* ni en el CSV (evita inyección de comandos desde datos externos). Una versión corregida o un CVE con formato dudoso se descartan del comando en lugar de pegarse en él. |

**Recomendaciones:** probar primero en un servidor de menor criticidad, tomar un *snapshot* de la VM antes de actualizar
un kernel o glibc (P1) y aplicar en la ventana de mantenimiento sugerida. El playbook no hace *rollback*.

## 7. Metodología de priorización

Para cada CVE en cada servidor:

```text
riesgo (0-100) = min(100, (CVSS × 6 + EPSS × 25 + KEV × 15) × criticidad)
```

| Elemento | Fuente | Peso |
|---|---|---|
| CVSS (0-10) | Wazuh (`vulnerability.score.base`); si falta, se estima por la severidad (Critical 9, High 7, Medium 4, Low 0,1) | hasta 60 |
| EPSS (0-1) | FIRST — probabilidad de explotación en los próximos 30 días | hasta 25 |
| KEV | CISA *Known Exploited Vulnerabilities* — explotación activa confirmada | 15 |
| Criticidad del servidor | `vulnmgmt_scoring.criticality` por nombre de agente o grupo de Wazuh | ×1,2 alta / ×1,0 media / ×0,8 baja |

| Prioridad | Condición | Plazo (SLA) desde que se detectó |
|---|---|---|
| **P1** | CVE en KEV **o** riesgo ≥ 75 | 7 días (o la fecha límite de CISA si es anterior) |
| **P2** | riesgo ≥ 55 | 30 días |
| **P3** | riesgo ≥ 35 | 90 días |
| **P4** | resto | 180 días |

- Los hallazgos se **agrupan por paquete**: una acción = un paquete en uno o más servidores, con el riesgo y la
  prioridad del peor de sus CVE.
- **Tipo de acción:** `actualizar` (existe versión corregida: se indica la versión mínima y el comando),
  `mitigar` (sin parche: aislar, deshabilitar o monitorear) o `revisar` (condición que no permite deducir la
  versión).
- **Seguimiento:** la fecha de primera detección se conserva entre ejecuciones; una acción que supera su plazo
  queda **vencida**; si sube de prioridad queda **escalada**; si deja de aparecer pasa a **resueltas**.
- Pesos, umbrales, plazos y criticidades son variables (sección 12). Ejemplo para marcar servidores críticos:

  ```yaml
  vulnmgmt_scoring:
    weights: {cvss: 6, epss: 25, kev: 15}
    thresholds: {P1: 75, P2: 55, P3: 35}
    sla_days: {P1: 7, P2: 30, P3: 90, P4: 180}
    criticality:
      default: media
      factors: {alta: 1.2, media: 1.0, baja: 0.8}
      hosts: {srv-idp: alta, wazuh-server: alta}
      groups: {}
  ```

La priorización la hace el **código** (reproducible y auditable); la IA no cambia prioridades ni plazos.

## 8. IA local optimizada para una VM chica

| Decisión | Por qué |
|---|---|
| **Ollama** local en 127.0.0.1, versión fija verificada con SHA-256 | Gratis, sin enviar datos de vulnerabilidades a terceros, funciona sin Internet una vez instalado. |
| **Qwen2.5 1.5B** y, si no alcanza la memoria, **Qwen2.5 0.5B** (cuantizados, ≈ 1 GB y ≈ 0,4 GB) | Modelos chicos con buen español y salida JSON, licencia Apache 2.0. El motor elige el primero que entra en la RAM libre (`/proc/meminfo`) en ese momento. |
| El modelo se carga sólo durante el informe (`keep_alive 0`) | No ocupa memoria el resto del día. |
| Un modelo y una petición a la vez, contexto de 4096 tokens, caché KV cuantizada (`q8_0`), *flash attention* | Menos RAM por petición. |
| `CPUQuota=200%`, `MemoryMax=3G`, `Nice=10`, E/S *idle*, hilos = CPU − 1 (máx. 4) | El indexer y el manager de Wazuh siempre tienen prioridad. |
| Se envían **sólo las 8 acciones principales** con datos estructurados (sin texto libre de los agentes) | Prompt corto (más rápido) y sin riesgo de inyección de instrucciones desde los datos. |
| Salida obligada por **esquema JSON**, temperatura 0,2 y semilla fija | Respuestas estables y siempre parseables. |
| **Validación** de la respuesta: largos acotados, sólo notas de acciones existentes, sin cambiar prioridades | La IA no puede inventar acciones ni alterar la priorización. |
| **Respaldo por reglas** | Si Ollama no responde, no hay memoria o la respuesta no es válida, el informe se publica igual con un resumen determinístico y el panel lo indica. |

## 9. Flujo no-code (n8n)

n8n Community Edition corre en un contenedor Podman, **sólo en 127.0.0.1:5678** y sin telemetría. Para usarlo:

```bash
ssh -L 5678:127.0.0.1:5678 <admin>@<servidor-wazuh>
```

Abrir `http://localhost:5678`, crear la cuenta de propietario (la primera vez) y abrir el flujo
**"Gestión de vulnerabilidades - aviso semanal de acciones P1/P2"**, ya importado:

```text
Cada lunes 08:00 / Ejecución manual ─▶ Leer informe (https://127.0.0.1:8443/data/latest.json)
  ─▶ Separar acciones ─▶ Sólo P1 y P2 ─▶ Agrupar ─▶ Armar mensaje ─▶ Enviar correo (deshabilitado)
```

Para activarlo: cargar la credencial SMTP de la empresa en el nodo *Enviar correo*, habilitar el nodo y publicar
o activar el flujo. El nodo de correo se puede reemplazar desde el editor visual, sin código, por Teams, Slack,
Telegram, un *ticket* en la mesa de ayuda, etc. El flujo lee el informe desde el propio servidor (127.0.0.1), por
eso no necesita la contraseña del panel.

## 10. Alertas en el SIEM

El motor escribe eventos JSON en `/var/log/vulnmgmt/events.json`, que el manager lee como `localfile` (formato
`json`). Para no repetir alertas todos los días se emite un resumen por informe y, por cada acción P1/P2, sólo
cuando es **nueva**, **escalada** o está **vencida**.

| Regla | Nivel | Cuándo |
|---|---|---|
| 100801 | 3 | Informe generado (CVE, P1, P2, vencidas) |
| 100802 | 5 | Acción (base) |
| 100803 | 10 | Acción P2 nueva o escalada |
| 100804 | 12 | Acción P1 nueva o escalada |
| 100805 | 13 | Acción P1 con CVE explotada activamente (KEV) |
| 100806 | 12 | Acción P2 vencida |
| 100807 | 13 | Acción P1 vencida |
| 100808 | 14 | Acción P1 vencida con CVE en KEV |

En el dashboard de Wazuh se buscan con `rule.groups: vulnmgmt`.

## 11. Seguridad de la propia plataforma

- **Mínimo privilegio:** el motor lee el indexer con `vulnmgmt-reader` (sólo lectura del índice de
  vulnerabilidades); la contraseña de `admin` no se guarda. Corre como usuario de sistema `vulnmgmt` con
  *sandbox* de systemd (`ProtectSystem=strict`, sin capacidades, sólo escribe en sus tres directorios).
- **Secretos** generados al instalar y guardados con permisos 0600 (`/etc/vulnmgmt/*.secret`), nunca en el
  repositorio. Las tareas que los usan llevan `no_log`.
- **Panel:** HTTPS (sólo TLS 1.2 y 1.3; cifrados de la *crypto policy* del sistema), usuario y contraseña (hash SHA-512 crypt),
  sólo lectura (GET/HEAD; el resto devuelve 405), archivos ocultos bloqueados, CSP estricta sin JavaScript en línea,
  HSTS, `X-Frame-Options`, `nosniff`, `no-referrer` y datos sin caché. El acceso se puede limitar a la red de
  administración o al bastión con `vulnmgmt_allowed_networks`.
- **Servicios internos sólo en loopback:** Ollama (11434) y n8n (5678).
- **Integridad del software:** Ollama con checksum SHA-256 oficial e imagen de n8n con versión fija.
- **CSV:** se neutralizan las celdas que empiezan con `=`, `+`, `-`, `@`, tabulador o retorno de carro, para evitar inyección de fórmulas en Excel.
- **SELinux** en modo *enforcing*: certificado en `/etc/pki/tls`, puerto 8443 ya etiquetado `http_port_t`,
  volúmenes de n8n con `:Z`.

## 12. Variables principales

Todas están en `roles/vulnmgmt/defaults/main.yml`.

| Variable | Defecto | Uso |
|---|---|---|
| `vulnmgmt_indexer_admin_password` | `""` | Contraseña de `admin` del indexer (una sola vez, para crear el usuario de lectura). |
| `vulnmgmt_api_user` / `vulnmgmt_api_password` | `""` | API de Wazuh (opcional, cobertura de agentes). |
| `vulnmgmt_scoring` | ver sección 7 | Pesos, umbrales, SLA y criticidad por servidor o grupo. |
| `vulnmgmt_ai_enabled` | `true` | `false` para no instalar Ollama (queda el resumen por reglas). |
| `vulnmgmt_ai_models` | 1.5B y 0.5B | Modelos y RAM libre mínima de cada uno. |
| `vulnmgmt_ollama_memory_max` / `_cpu_quota` | `3G` / `200%` | Límites de la IA. |
| `vulnmgmt_web_port` / `vulnmgmt_web_user` | `8443` / `infra` | Panel. |
| `vulnmgmt_web_password` | `""` (generada) | Contraseña del panel; si queda vacía se genera y se guarda en `/etc/vulnmgmt/web.secret`. |
| `vulnmgmt_allowed_networks` | `[]` (cualquiera) | Redes que pueden abrir el panel, p. ej. `["10.0.99.0/24"]`. |
| `vulnmgmt_schedule` | `*-*-* 03:30:00` | Frecuencia del informe (formato `OnCalendar` de systemd). |
| `vulnmgmt_wazuh_event_priorities` | `[P1, P2]` | Prioridades que generan alertas en Wazuh. |
| `vulnmgmt_n8n_enabled` | `true` | `false` para no instalar n8n (n8n necesita Podman 4.4 o superior). |
| `vulnmgmt_allow_untested_platform` | `false` | `true` para probar otra distribución con `dnf` (sin soporte); nunca saltea la verificación de Python. |
| `vulnmgmt_first_run` | `run` | `demo` publica datos sintéticos de demostración. |

## 13. Archivos

```text
vulnmgmt.yml                       # Playbook (grupo wazuh_server)
roles/vulnmgmt/                    # Rol de instalación (tareas, plantillas, variables)
host_vars/srv-siem.yml.example     # Excepciones del endurecimiento para el servidor Wazuh
vulnmgmt/
├── engine/vulnmgmt/               # Motor (Python 3.9+, sólo librería estándar)
│   ├── wazuh.py                   #   indexer (scroll) y API de Wazuh
│   ├── intel.py                   #   CISA KEV y FIRST EPSS con caché y modo sin conexión
│   ├── prioritize.py              #   agrupación, riesgo, prioridad, SLA y seguimiento
│   ├── ai.py                      #   IA local (Ollama) y respaldo por reglas
│   ├── remediation.py             #   comandos por servidor y playbook de remediación
│   ├── publish.py                 #   JSON, CSV, histórico y eventos para Wazuh
│   └── demo.py                    #   datos de demostración
├── engine/tests/test_engine.py    # Pruebas unitarias y de integración con servidores simulados
├── web/                           # Panel (HTML + JS + CSS, sin dependencias externas)
├── wazuh/vulnmgmt_rules.xml       # Reglas 100800-100808
└── n8n/vulnmgmt-workflow.json     # Flujo no-code
```

## 14. Resolución de problemas

| Síntoma | Causa / solución |
|---|---|
| *Preflight*: "must run on the Wazuh server" | Se ejecutó en otro servidor: usar `--component vulnmgmt` sólo en el servidor Wazuh. |
| *Preflight*: faltan credenciales del indexer | Pasar la contraseña de `admin` (sección 3). |
| El panel dice "Todavía no hay informes" o muestra 0 hallazgos | El motor aún no corrió o los agentes todavía no enviaron el inventario: `systemctl start vulnmgmt.service` más tarde, o usar el modo `demo`. |
| `journalctl -u vulnmgmt.service` muestra error 401/403 del indexer | Recrear el usuario de lectura: `sudo rm /etc/vulnmgmt/indexer.secret` y volver a ejecutar `sudo ./bootstrap.sh --component vulnmgmt` (pide la contraseña de `admin` y genera una nueva). |
| El panel dice "Resumen por reglas (IA no disponible)" | Falta memoria libre o Ollama está detenido: `systemctl status ollama`, `journalctl -u ollama`. El informe se publica igual. |
| Faltan KEV/EPSS (aviso en el panel) | Sin salida a Internet: se usa la última caché; los avisos lo indican. |
| `The vulnerability platform targets Rocky Linux 9/10 or Amazon Linux 2023` | El sistema no está soportado (por ejemplo Amazon Linux 2 o Rocky 8). Ver `grep PRETTY_NAME /etc/os-release`. |
| `No package nginx available` (o `podman`, `zstd`, `logrotate`) en Amazon Linux | Dos causas posibles: el paquete **no existe** en esa distribución, o el servidor **no llega a sus repositorios**. Distinguirlo con `dnf repolist` y `dnf list --available nginx podman zstd logrotate`. Si falta sólo `podman`, instalar sin n8n (ver la fila siguiente). |
| `n8n needs Podman 4.4 or newer`, o `podman` no disponible | Actualizar Podman, o instalar sin n8n: `sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_n8n_enabled=false`. **Sin n8n se pierde el flujo no-code semanal**; el resto de la plataforma (panel, IA, alertas y remediación) funciona igual. |
| `firewalld is not running ... NOT opened` | No hay `firewalld`: abrir el puerto 8443/tcp con el firewall que se use. |
| `skipping: no hosts matched` al ejecutar el playbook | El nombre del agente de Wazuh no existe en el inventario: usarlo como alias en `inventory/hosts.ini` (sección 6). |
| El panel no abre desde la red | `firewall-cmd --list-all` y `vulnmgmt_allowed_networks`; `systemctl status nginx`. |
| nginx desapareció tras endurecer el servidor Wazuh | Falta `host_vars` con `hardening_packages_keep: [nginx]` (sección 3); volver a ejecutar el rol `vulnmgmt`. |

## 15. Pruebas realizadas y limitaciones

**Pruebas realizadas (en contenedores, con versiones reales de cada componente):**

- Motor: 22 pruebas automáticas (Python 3.13 y Python 3.9 de Rocky 9) que incluyen servidores simulados del
  indexer (*scroll*), la API de Wazuh, EPSS y Ollama, el respaldo por reglas y el seguimiento de SLA.
- **OpenSearch 2.19** con el plugin de seguridad: creación idempotente del rol y del usuario de sólo lectura,
  y lectura con verificación TLS contra la CA.
- **Wazuh manager 4.12.0:** `wazuh-analysisd -t` y `wazuh-logtest` con eventos generados por el propio motor
  para los 8 casos (resumen, P1/P2 nuevas, escaladas, vencidas, KEV y KEV vencida); lectura real del archivo de
  eventos por `localfile`.
- **n8n 2.46.4:** importación por CLI y ejecución del flujo (lectura del informe, filtro P1/P2 y armado del mensaje).
- **nginx 1.26** con la configuración generada: 401 sin usuario o con contraseña incorrecta, 200 con usuario,
  405 para métodos distintos de GET/HEAD, 404 para archivos ocultos (también con usuario válido), acceso local sin
  contraseña para n8n, cabeceras de seguridad y TLS 1.1 rechazado.
- Panel en Chromium con la CSP estricta (tema claro, oscuro y móvil).
- **Remediación:** 22 pruebas automáticas del motor (8 son de la remediación: filtros, exclusión de `wazuh-*`, nombres, versiones y CVE
  hostiles que no llegan a ningún comando, comandos por alcance y gestor de paquetes, comandos de Ansible que bash
  tokeniza como se espera, orden por prioridad y que el playbook sea YAML válido y no reinicie). Se comprobó con
  mutaciones que las pruebas de seguridad fallan si se quita la validación.
  El playbook generado pasa `ansible-lint` (perfil `production`) y `ansible-playbook --syntax-check`, y se ejecutó con
  ansible-core 2.14 en Rocky 9: la comprobación de reinicio con los cuatro comportamientos posibles de `dnf
  needs-restarting` (reinicio necesario, no necesario, comando inexistente y `dnf` ausente) y el paso `dnf` en modo
  `--check` (parámetros aceptados, incluido `disablerepo` con comodín). La sección del panel se probó en Chromium
  (CSP, descarga, copiar al portapapeles, tema oscuro y móvil).
- `ansible-lint` (perfil `production`), `--syntax-check` y `shellcheck`.

**Limitaciones (validar en la maqueta antes de la defensa):**

- No se ejecutó el rol completo sobre una VM (Rocky 9/10 o Amazon Linux 2023) con Wazuh real (systemd, SELinux *enforcing*,
  firewalld y Podman reales).
- **Amazon Linux 2023:** se probó `bootstrap.sh --component vulnmgmt` completo dentro de la imagen oficial de Amazon Linux 2023
  (`ID=amzn`, Python 3.9.25): detecta el sistema, instala `ansible-core` 2.15.13 en el entorno virtual, y el rol pasa los
  chequeos de sistema operativo, de Python, de servidor Wazuh y de credenciales con los hechos reales de Ansible
  (`Amazon` / `2023`). También se probó la matriz de plataformas (Rocky 9/10 y Amazon 2023 pasan; Amazon 2, Rocky 8 y
  Ubuntu se rechazan con un mensaje claro), que el endurecimiento sigue rechazando a Amazon Linux y que Rocky 9 y 10
  eligen los mismos playbooks que antes.
- **Sin validar en Amazon Linux 2023** (el entorno de pruebas no llega a `cdn.amazonlinux.com`): que sus repositorios
  tengan `nginx`, `openssl`, `tar`, `zstd`, `logrotate` y `podman` (y que `podman` sea 4.4 o superior), el usuario y las
  rutas de `nginx`, `systemd`, SELinux y el firewall reales, y las rutas de Wazuh de esa imagen
  (`/var/ossec`, `/etc/wazuh-indexer/certs/root-ca.pem`). Si falta algún paquete, el error aparece en la tarea
  *Install the required packages*.
- **No se probó una actualización real con `dnf`/`apt`**: el entorno de pruebas no llega a los repositorios de Rocky, así
  que el paso `dnf` se verificó sólo en modo `--check` (sin repositorios) y la variante `deb` sólo con sintaxis y lint.
  Validar `--check` y luego la aplicación en un servidor de prueba antes de usarlo en producción.
- El texto que imprime `dnf needs-restarting` se verificó contra el código fuente de `dnf-plugins-core`, no contra un
  servidor con reinicio pendiente real.
- No se descargaron ni ejecutaron los modelos de Ollama en este entorno (el registro de modelos no era
  accesible): falta medir en la VM el tiempo de respuesta y el uso de memoria reales.
- EPSS y `cisa.gov` no eran accesibles desde el entorno de pruebas; KEV se probó con el espejo oficial de GitHub
  y EPSS con un servidor simulado.
- Los datos de vulnerabilidades dependen de la cobertura del detector de Wazuh para cada sistema operativo.
