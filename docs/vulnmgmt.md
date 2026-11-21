# Gestión de vulnerabilidades — plataforma sobre el servidor Wazuh

Punto **5. "Gestión de Vulnerabilidades"** del obligatorio de **Seguridad en Redes y Datos**
(Corporación de Generación S.A., cdg.uy).

> La plataforma debe gestionar las vulnerabilidades y actualizaciones de los servidores, emitir
> informes periódicos y traducirlos en acciones priorizadas y viables para los equipos de
> infraestructura. Suma valor el uso de IA y de flujos *no-code*.

Se instala igual que el endurecimiento (*install and play* con `bootstrap.sh` + Ansible), **en el propio servidor
Wazuh** (imagen oficial, Amazon Linux 2023), y todo queda alojado ahí: el motor en Python que arma el informe y el orden de
las vulnerabilidades, el panel web y **n8n en un contenedor Docker local**. No hace falta ningún otro servidor. Todo es
software libre y gratuito y corre **dentro de la infraestructura**, sin APIs pagas ni envío de datos a terceros.

## Índice

1. [Qué resuelve](#1-qué-resuelve)
2. [Arquitectura](#2-arquitectura)
3. [Requisitos previos](#3-requisitos-previos)
4. [Instalación](#4-instalación)
5. [Uso diario](#5-uso-diario)
6. [Remediación de las vulnerabilidades](#6-remediación-de-las-vulnerabilidades)
7. [Metodología de priorización](#7-metodología-de-priorización)
8. [Priorización determinística](#8-priorización-determinística)
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
| **No-code** (valor agregado) | **n8n Community Edition** (gratuito, *self-hosted*) en un **contenedor Docker en el servidor Wazuh**, con un flujo importado: cada lunes lee el informe y un **script determinístico** ordena las acciones por urgencia, propone la solución y la verificación de cada una, las agrupa en ventanas de mantenimiento y arma el aviso para infraestructura (correo, Teams, Slack, Telegram… se cambian desde el editor visual). Ver sección 9. |
| Explicabilidad | Toda la priorización y todo el texto del informe salen de **código determinístico y auditable**: las mismas entradas dan siempre el mismo resultado, sin modelos de lenguaje (sección 8). |
| Integración con el SIEM | Eventos JSON que el propio manager lee, con reglas propias (100800-100808): las acciones P1/P2 nuevas o escaladas, KEV y vencidas generan alertas de nivel 10-14. |

## 2. Arquitectura

```text
 Servidores (agente Wazuh)                              Servidor Wazuh (imagen oficial, Amazon Linux 2023)
 ┌────────────┐  inventario de paquetes   ┌──────────────────────────────────────────────────────────────┐
 │ srv-idp    │──────────────────────────▶│ wazuh-manager ── detector de vulnerabilidades                │
 │ srv-web    │                           │      │                                                       │
 │ srv-bastion│                           │      ▼                                                       │
 │ ...        │                           │ wazuh-indexer 127.0.0.1:9200                                 │
 └────────────┘                           │   índice wazuh-states-vulnerabilities-*                      │
                                          │      │ (HTTPS verificado con root-ca.pem,                    │
                                          │      │  usuario de sólo lectura vulnmgmt-reader)             │
   Internet (opcional, con caché)         │      ▼                                                       │
   CISA KEV ───────────────────────────────────▶ vulnmgmt.timer 03:30 ─▶ motor Python                    │
   FIRST EPSS ─────────────────────────────────▶  1. recolecta hallazgos y agentes                       │
                                          │       2. enriquece con KEV + EPSS                            │
                                          │       3. agrupa, prioriza (P1-P4), SLA y seguimiento         │
                                          │       4. resumen determinístico (analysis.py)                │
                                          │       5. publica                                             │
                                          │      ├──▶ /var/www/vulnmgmt/data (JSON, CSV, histórico)      │
                                          │      │        └──▶ nginx :8443 (HTTPS + usuario) ─▶ Panel web│
                                          │      └──▶ /var/log/vulnmgmt/events.json ─▶ reglas Wazuh      │
                                          │                                            (alertas 10-14)   │
                                          │ Docker ─ contenedor n8n 127.0.0.1:5678 (lunes 08:00)         │
                                          │   └─▶ lee latest.json ─▶ script "Priorizar y proponer        │
                                          │        soluciones" ─▶ plan ordenado + ventanas ─▶ aviso      │
                                          └──────────────────────────────────────────────────────────────┘
```

Todas las conexiones internas de la plataforma (motor → indexer, n8n → panel) usan `127.0.0.1`: **no salen del
servidor**. Hacia afuera sólo se abre el panel (8443/tcp), y opcionalmente se consultan KEV y EPSS en Internet.

Componentes y consumo aproximado:

| Componente | Cómo corre | Recursos |
|---|---|---|
| Motor `vulnmgmt` | Servicio *oneshot* disparado por el temporizador; sólo librería estándar de Python 3.9+ | Máx. 50 % de 1 CPU y 512 MB (`CPUQuota`/`MemoryMax`), prioridad baja |
| nginx | Sirve archivos estáticos | Mínimo |
| n8n | Contenedor **Docker local** (unidad systemd `n8n.service`) en 127.0.0.1; ejecuta el script de priorización una vez por semana | Máx. 1 GB (`--memory`) |

## 3. Requisitos previos

1. **Servidor Wazuh 4.8 o superior *all-in-one*** (manager + indexer + dashboard), instalado con la imagen oficial
   (**Amazon Linux 2023**) o con el asistente oficial (`wazuh-install.sh -a`) sobre **Rocky Linux 9 o 10**. **Amazon Linux 2
   no se admite** (trae Python 3.7 y el motor necesita 3.9 o superior). La detección de vulnerabilidades viene habilitada por
   defecto (`<vulnerability-detection>` en `/var/ossec/etc/ossec.conf`, con `index-status` en `yes`). Para saber qué
   sistema tiene el servidor:

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
5. **RAM:** Wazuh *all-in-one* necesita unos 8 GB. La plataforma agrega poco: el motor está limitado a 512 MB y n8n a
   1 GB. Sin n8n (`-e vulnmgmt_n8n_enabled=false`) el agregado es sólo el del motor.
6. Salida a Internet durante la instalación: los repositorios de Amazon Linux (`nginx`, `docker`…) y `docker.io` (imagen
   de n8n, sólo la primera vez). En cada informe, opcionalmente, `cisa.gov` o `raw.githubusercontent.com` (KEV) y
   `api.first.org` (EPSS). Sin Internet la plataforma sigue funcionando con la última caché.

### Relación con el endurecimiento (punto 1)

> **Decisión del equipo: el servidor Wazuh no se endurece con la plantilla del punto 1.** En ese servidor sólo se
> instala la plataforma de vulnerabilidades (`sudo ./bootstrap.sh --component vulnmgmt`). El endurecimiento
> (`--component hardening`) se aplica al resto de los servidores.

Consecuencias de esa decisión:

- **No aplica ningún control CIS en el servidor Wazuh.** Por ejemplo, Docker activa el reenvío de IP al arrancar
  (`net.ipv4.ip_forward=1`), que es su comportamiento normal; como el servidor no está endurecido, no hay control que lo
  contradiga, y el rol no toca la configuración de Docker (`/etc/docker/daemon.json`). n8n usa la red del host, así que
  tampoco depende de ese reenvío.
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

### En el servidor Wazuh

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

El rol instala **Docker** desde los repositorios de Amazon Linux 2023 (paquete `docker`), lo deja habilitado y levanta
n8n como servicio `n8n.service`, que arranca el contenedor. La primera vez descarga la imagen de n8n desde `docker.io`.

**En Amazon Linux 2023**, si la distribución no empaqueta `ansible-core`, `bootstrap.sh` lo instala en un entorno virtual
de Python aparte (`/opt/srd-ansible`, `ansible-core` 2.14 o 2.15, que corren con Python 3.9) y lo usa desde ahí; no toca
el Python del sistema.

Si no hay `firewalld` activo (es lo habitual en Amazon Linux), el rol **no abre el puerto 8443** y lo avisa: hay que
abrirlo en el grupo de seguridad de AWS (o con el firewall que se use), idealmente sólo desde la red de administración.

**Comprobar que quedó funcionando:**

```bash
systemctl status vulnmgmt.timer docker n8n --no-pager
```

```bash
curl -s http://127.0.0.1:5678/healthz        # n8n: debe responder {"status":"ok"}
```

### Volver a ejecutar la instalación

El comando es idempotente: sirve para actualizar el motor, el panel, n8n o la configuración. Primero actualizar el
repositorio (el script no se actualiza a sí mismo cuando se ejecuta desde un clon) y volver a lanzar:

```bash
cd <carpeta-del-repositorio> && git pull --ff-only
```

```bash
sudo ./bootstrap.sh --component vulnmgmt
```

- **No vuelve a pedir** la contraseña de `admin` del indexer (usa el usuario de lectura que ya existe) y **conserva** la
  contraseña del panel, el certificado, el usuario de lectura, los datos de n8n (`/var/lib/n8n`) y el flujo ya importado.
- **Sí vuelve a preguntar por el usuario de la API de Wazuh.** Si se da Enter, la configuración se regenera **sin la API** y el
  panel pierde la cobertura de agentes (los desconectados o sin hallazgos). Para conservarla, **escribir de nuevo el usuario y
  la contraseña** cuando los pregunte (la contraseña no se muestra ni queda en el historial del shell). No conviene pasarla
  en la línea de comandos por esa misma razón.
- Cada ejecución genera además un informe nuevo, igual que `sudo systemctl start vulnmgmt.service`.

Prueba sin cambios (`--check`) y modo demostración (publica datos sintéticos si todavía no hay agentes con
hallazgos):

```bash
sudo ./bootstrap.sh --component vulnmgmt --check
```

```bash
sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_first_run=demo
```

### Desde un nodo de control

Agregar el servidor Wazuh al grupo `[wazuh_server]` de `inventory/hosts.ini` (ver `inventory/hosts.ini.example`) y
guardar las contraseñas cifradas con `ansible-vault`:

```bash
ansible-vault create secrets-vulnmgmt.yml
```

(contenido: `vulnmgmt_indexer_admin_password: "..."`, y opcionalmente `vulnmgmt_api_user` / `vulnmgmt_api_password`)

```bash
ansible-playbook -i inventory/hosts.ini vulnmgmt.yml -l wazuh_server -e @secrets-vulnmgmt.yml --ask-vault-pass
```

### Qué hace el rol `roles/vulnmgmt`

| Paso | Archivo |
|---|---|
| Valida el sistema operativo (Amazon Linux 2023 o Rocky 9/10), Python 3.9 o superior, que sea el manager de Wazuh y que haya credenciales | `tasks/preflight.yml` |
| Paquetes (python3, nginx, openssl…), usuario de servicio `vulnmgmt`, motor y panel, certificado TLS, secretos generados | `tasks/base.yml` |
| Prueba TLS contra el indexer, rol y usuario de **sólo lectura** (sólo el índice de vulnerabilidades) y prueba de acceso | `tasks/indexer.yml` |
| Configuración del motor (`/etc/vulnmgmt/config.json`, 0640) y logrotate | `tasks/config.yml` |
| nginx (HTTPS, usuario y contraseña, cabeceras de seguridad) y firewalld si está activo | `tasks/web.yml` |
| Reglas de Wazuh en el manager y lectura de los eventos (`wazuh-analysisd -t` antes de reiniciar) | `tasks/wazuh.yml` |
| **Docker** (paquete `docker` de Amazon Linux 2023) y n8n como unidad systemd que lanza el contenedor; arma el flujo con el script de priorización y lo importa cuando cambió | `tasks/n8n.yml`, `templates/n8n.service.j2` |
| Servicio y temporizador, primer informe y resumen de acceso | `tasks/schedule.yml` |

Es idempotente: se puede volver a ejecutar para actualizar el motor, el panel o la configuración.

### Alternativa no utilizada: la plataforma en otro servidor

> **El equipo no usa esta opción**: la plataforma y n8n corren en el servidor Wazuh. Se deja documentada porque el rol la
> soporta, pero **no se validó en la maqueta**.

El rol también puede instalarse en un servidor aparte (Rocky Linux 9/10) que lee el indexer de Wazuh por la red:
`sudo ./bootstrap.sh --component vulnmgmt --wazuh-host <IP-wazuh> --wazuh-ca /root/wazuh-root-ca.pem` (más
`--indexer-name <nombre>` si el certificado del indexer no incluye la IP). Requiere abrir 9200/tcp del servidor Wazuh sólo
para ese servidor, que el indexer escuche en la red (`network.host`), copiar `root-ca.pem`, instalar a mano las reglas
`vulnmgmt/wazuh/vulnmgmt_rules.xml` en el manager y endurecer el servidor con `--profile vulnmgmt-server`
(`profiles/vulnmgmt-server.yml`). Las variables están en `roles/vulnmgmt/defaults/main.yml` (`vulnmgmt_wazuh_host`,
`vulnmgmt_indexer_ca_source`, `vulnmgmt_indexer_tls_name`).

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
- **Análisis y recomendaciones:** resumen, riesgos clave y ventana de mantenimiento sugerida, calculados a partir
  de los datos del informe (determinístico: las mismas entradas dan el mismo texto).
- **Plan de acción:** tabla filtrable por prioridad, tipo de acción, texto (paquete, servidor o CVE) y "sólo vencidas". Cada fila se despliega con los CVE (enlace a
  NVD), los servidores, los comandos de remediación y de verificación con botón de copiar y el motivo de la
  prioridad.
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
| **Cuánto tarda** | El informe es sobre todo recolección: lo que tarde el indexer y, la primera vez del día, la descarga de KEV y EPSS. No se midieron tiempos reales en una VM. |
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

### En base a qué se prioriza

Los cuatro insumos se combinan, en lugar de usar uno solo, porque cada uno responde una pregunta distinta:

- **CVSS** mide **severidad**: cuánto daño haría si la explotaran. No dice nada sobre la probabilidad de que
  eso ocurra, y la mayoría de las CVE con CVSS alto nunca se explotan. Por eso pesa mucho (hasta 60 puntos)
  pero no decide solo.
- **EPSS** agrega la **probabilidad**: el modelo de FIRST estima, a partir de explotación observada en
  Internet, qué chance hay de que esa CVE se explote en los próximos 30 días.
- **CISA KEV** no es una estimación, es un **hecho**: la CVE está en el catálogo porque se observó
  explotación real. Por eso, además de sumar 15 puntos, **fuerza P1 sin importar el puntaje**.
- **La criticidad del servidor** aporta el **contexto**: la misma CVE no pesa lo mismo en el IdP que en un
  servidor de pruebas.

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

### Por qué no alcanza con ordenar por CVSS

Dos acciones de un informe real, las dos sobre servidores de criticidad media (factor ×1,0):

| Paquete | CVE | CVSS | EPSS | KEV | Cuenta | Riesgo | Prioridad |
|---|---|---|---|---|---|---|---|
| `curl` | CVE-2023-38545 | **9,8** | 4 % | no | 9,8×6 + 0,04×25 + 0 | 59,8 | **P2** |
| `sudo` | CVE-2021-3156 | 7,8 | 92 % | **sí** | 7,8×6 + 0,92×25 + 15 | 84,8 | **P1** |

`curl` tiene el CVSS más alto y queda por debajo: su probabilidad de explotación es baja y nadie observó que
se esté explotando. `sudo` es menos grave en el papel, pero se explota activamente y figura en KEV. Ordenar
por CVSS habría puesto primera justamente la que menos urge.

- Los hallazgos se **agrupan por paquete**: una acción = un paquete en uno o más servidores, con el riesgo y la
  prioridad del peor de sus CVE.
- **Tipo de acción:** `actualizar` (existe versión corregida: se indica la versión mínima y el comando),
  `mitigar` (sin parche: aislar, deshabilitar o monitorear) o `revisar` (condición que no permite deducir la
  versión).
- **Seguimiento:** la fecha de primera detección se conserva entre ejecuciones; una acción que supera su plazo
  queda **vencida**; si sube de prioridad queda **escalada**; si deja de aparecer pasa a **resueltas**.
- **Explicabilidad:** cada acción publica el campo `reasons` con los motivos concretos por los que quedó en esa
  prioridad (CVSS, el porcentaje de EPSS, cuántas de sus CVE están en KEV, si se usa en campañas de ransomware,
  qué servidores de criticidad alta afecta). El panel lo muestra en *"Por qué tiene esta prioridad"*, el CSV lo
  exporta y el aviso de n8n lo repite: cualquier P1 se puede justificar sin volver a calcular nada.
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

La priorización la hace el **código** (reproducible y auditable). Ningún otro componente cambia las
prioridades ni los plazos: el script de n8n (sección 9) sólo ordena **dentro** de cada prioridad, y lo hace
con una clave de desempate **estricta**, no con otra suma de pesos.

## 8. Priorización determinística

Toda la priorización y todo el texto que produce la plataforma salen de **código determinístico**: no hay ningún
modelo de lenguaje en el camino. El trabajo está repartido así:

| Qué | Quién lo hace | Dónde |
|---|---|---|
| Prioridad P1-P4, riesgo 0-100, plazo (SLA) | Motor Python, con CVSS + EPSS + KEV + criticidad | `prioritize.py` (sección 7) |
| Comandos de remediación y de verificación | Motor Python, validando el nombre del paquete y la versión | `prioritize.py`, `remediation.py` |
| Resumen, riesgos clave y ventana sugerida del panel | Motor Python, determinístico | `analysis.py` |
| **Orden de trabajo, solución propuesta por acción y ventanas de mantenimiento** | **Script de n8n** | `vulnmgmt/n8n/priorizar-soluciones.js` (sección 9) |

### Por qué es determinística

| Motivo | Detalle |
|---|---|
| **Explicabilidad** | Un script determinístico se puede leer, versionar y defender línea por línea. Las mismas entradas dan siempre el mismo resultado. |
| **Nada que inventar** | El texto no puede traer un CVE, una versión o un servidor que no esté en los datos: todo sale del informe. |
| **Recursos** | No hay inferencia: el motor está limitado a 512 MB de RAM y cada informe es sobre todo la lectura del indexer. |
| **Menos superficie** | No hay servicios extra escuchando ni modelos que descargar, actualizar o proteger. |
| **Mantenimiento** | Cambiar el criterio de triaje o el texto del aviso es editar un archivo JavaScript o Python, sin *prompts* ni esquemas. |

## 9. Flujo no-code (n8n)

Acá es donde la plataforma **prioriza las vulnerabilidades y propone las soluciones**: n8n lee el informe
del motor y un script determinístico arma el plan de trabajo para el equipo de infraestructura.

n8n Community Edition corre en un contenedor **Docker**, **sólo en 127.0.0.1:5678** y sin telemetría. Para usarlo:

```bash
ssh -L 5678:127.0.0.1:5678 <admin>@<servidor-wazuh>
```

Abrir `http://localhost:5678`, crear la cuenta de propietario (la primera vez) y abrir el flujo
**"Gestión de vulnerabilidades - plan priorizado de remediación"**, ya importado:

```text
Cada lunes 08:00 / Ejecución manual
  ─▶ Leer informe (https://127.0.0.1:8443/data/latest.json)
  ─▶ Priorizar y proponer soluciones   ← nodo "Code": el script
  ─▶ Enviar correo (deshabilitado)
```

### Qué hace el script

El script es `vulnmgmt/n8n/priorizar-soluciones.js` (nodo *Code*, JavaScript, modo
*Run Once for All Items*). Recibe el informe completo y devuelve un único item con `asunto`, `cuerpo`
(el texto del aviso) y el plan estructurado (`plan`, `ventanas`, `servidores`, `resumen`), para que
cualquier otro nodo lo use sin recalcular nada.

1. **Triaje.** Respeta la prioridad P1-P4 del motor y ordena **dentro** de cada una: primero las
   **vencidas**, después las usadas en **ransomware**, después las que están en **CISA KEV**, después las
   que pegan en servidores de **criticidad alta**, las que **escalaron** de prioridad, y recién entonces el
   riesgo y la cantidad de servidores afectados. Los niveles son **estrictos**: se comparan como una clave
   lexicográfica, así que el primero que difiere decide y los de abajo no lo pueden compensar. Con una suma de
   pesos, una acción sin KEV pero de riesgo alto y presente en muchos servidores podía adelantarse a otra que
   CISA marca como explotada; hay pruebas que lo verifican (`vulnmgmt/n8n/tests/edge-cases.js`).
2. **Solución propuesta por acción.** Para cada una: *qué* hay que hacer (paquete, versión objetivo y
   servidores), *cómo* (el comando del motor), *cómo verificar* (el comando del motor), el *impacto*
   operativo (si requiere reinicio, o cómo detectar los servicios a reiniciar con `needs-restarting -s`),
   el *plazo* con los días que faltan y *por qué* tiene esa prioridad.
3. **Ventanas de mantenimiento.** Agrupa en ventana de **emergencia** (P1), **semanal** (P2) y
   **planificada** (P3/P4), y dentro de cada una separa lo que se actualiza en caliente, lo que **requiere
   reinicio** (para juntar los reinicios en uno por servidor) y lo que **no tiene parche**.
4. **Vista por servidor.** Reusa los comandos agrupados que ya publicó el motor (`remediation.hosts`),
   incluido el comando de Ansible para simular con `--check --diff`.

Dos reglas de diseño, para que el panel, el CSV, las alertas del SIEM y este aviso **nunca se contradigan**:

- **No recalcula prioridades.** El puntaje de triaje sólo reordena dentro de la prioridad que fijó el motor.
- **No construye comandos.** Los nombres de paquete vienen del indexer; interpolarlos en un comando dentro
  del script saltearía las validaciones del motor (`SAFE_PACKAGE`, `SAFE_VERSION` y la protección de los
  componentes `wazuh-*`). El script reusa los comandos ya generados, tal cual.

### Ajustes sin tocar el repositorio

Abriendo el nodo *Priorizar y proponer soluciones* en el editor visual, arriba del script:

| Constante | Por omisión | Para qué |
|---|---|---|
| `PRIORIDADES_AVISO` | `['P1', 'P2']` | Qué prioridades entran en el aviso. |
| `MAX_ACCIONES` | `25` | Tope de acciones detalladas (el resto se cuenta y remite al panel). |
| `URL_PANEL` | el FQDN del servidor | Enlace al panel que se incluye en el aviso. |
| `VENTANAS` | emergencia / semanal / planificada | Cómo se agrupan las prioridades en ventanas. |

### Activar el envío

Cargar la credencial SMTP de la empresa en el nodo *Enviar correo*, completar remitente y destinatario
(por omisión `vulnmgmt_n8n_mail_from` y `vulnmgmt_n8n_mail_to`), habilitar el nodo y activar el flujo.

> **Ojo:** la reimportación sobrescribe el flujo, así que el nodo de correo vuelve a quedar **deshabilitado
> y sin credencial, y el flujo inactivo**. Después de una ejecución del rol que haya reimportado el flujo
> (porque cambió el script), hay que volver a habilitar el nodo y activar el flujo.

El
nodo de correo se puede reemplazar desde el editor visual, **sin código**, por Teams, Slack, Telegram, un
*ticket* en la mesa de ayuda, etc.: el aviso ya viene armado en `asunto` y `cuerpo`. El flujo lee el informe
desde el propio servidor (127.0.0.1), por eso no necesita la contraseña del panel.

### Cómo se mantiene el flujo

El script vive en el repositorio, no pegado dentro del JSON del flujo: el rol arma el flujo con la plantilla
`roles/vulnmgmt/templates/vulnmgmt-workflow.json.j2`, que incrusta el archivo `.js` y lo escapa. Cuando el
script cambia, el archivo renderizado cambia y el rol **vuelve a importar** el flujo; como el flujo tiene un
`id` fijo (`vulnmgmtWeekly01`), la importación **actualiza** el existente en lugar de duplicarlo.

> Por eso el repositorio es la fuente de verdad: los cambios hechos a mano en el editor de n8n sobre ese
> flujo se pierden en la siguiente ejecución del rol. Para experimentar, duplicar el flujo en el editor.

## 9. Flujo no-code (n8n)

n8n Community Edition corre en un contenedor **Docker**, **sólo en 127.0.0.1:5678** y sin telemetría. Para usarlo:

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

El motor escribe eventos JSON en `/var/log/vulnmgmt/events.json`, que el propio manager lee como `localfile`
(formato `json`); las reglas las instala el rol en `/var/ossec/etc/rules/vulnmgmt_rules.xml`. Para no repetir alertas todos los días se emite un resumen por informe y, por cada acción P1/P2, sólo
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
- **Servicios internos sólo en loopback:** n8n (5678). El motor no escucha en ningún puerto.
- **Conexión con el indexer:** el motor sólo **lee**, por `127.0.0.1:9200` (el tráfico no sale del servidor), con TLS
  verificado contra la CA del indexer (`/etc/vulnmgmt/indexer-ca.pem`), nunca con la verificación desactivada. El porqué
  está en la subsección
  [*Por qué se verifica el certificado del indexer*](#por-qué-se-verifica-el-certificado-del-indexer-protección-contra-spoofing).
- **n8n en Docker:** el contenedor usa la red del host pero escucha **sólo en 127.0.0.1:5678**, corre sin capacidades
  (`--cap-drop ALL`), con `no-new-privileges` y con un límite de memoria. Al editor se entra con un túnel SSH.
- **Integridad del software:** imagen de n8n con versión fija (`docker.io/n8nio/n8n:2.46.4`).
- **Script de n8n:** no construye comandos con datos del indexer ni ejecuta nada en los servidores; sólo
  lee el informe y arma texto (sección 9).
- **CSV:** se neutralizan las celdas que empiezan con `=`, `+`, `-`, `@`, tabulador o retorno de carro, para evitar inyección de fórmulas en Excel.
- **SELinux** en modo *enforcing*: certificado en `/etc/pki/tls`, puerto 8443 ya etiquetado `http_port_t`,
  volúmenes de n8n con `:Z`.

### Por qué se verifica el certificado del indexer (protección contra *spoofing*)

Esta decisión de diseño responde a un criterio de **seguridad**. El motor le envía credenciales al indexer (la
contraseña de `admin` en la instalación y la de `vulnmgmt-reader` todos los días) y confía en los hallazgos que recibe.
Por eso no alcanza con cifrar la conexión: tiene que comprobar **con quién** habla.

**Cómo es hoy:** la plataforma corre en el servidor Wazuh y se conecta a `127.0.0.1:9200`, así que el tráfico **no sale
del servidor** y nadie en la red puede interceptarlo. Aun así, la verificación TLS se mantiene como **defensa en
profundidad**: si el indexer se detuviera y otro proceso ocupara el puerto 9200, no podría presentar un certificado
válido y el motor no le entregaría la contraseña ni tomaría sus datos.

**El riesgo que evita: suplantación del indexer (*spoofing* / *man-in-the-middle*).** Si el motor aceptara cualquier
certificado (y sobre todo si alguna vez la conexión pasara por la red, como en la alternativa de la sección 4), un equipo
podría hacerse pasar por el indexer de Wazuh, con un *ARP spoofing*, una entrada DNS falsa o tomando su IP. Así podría:

| Ataque | Consecuencia |
|---|---|
| **Robo de credenciales** | En la instalación viaja la contraseña de `admin` del indexer (control total de Wazuh); todos los días, la de `vulnmgmt-reader`. |
| **Datos falsos** | El atacante entrega hallazgos inventados u omite los reales: una vulnerabilidad crítica (P1, KEV) desaparece del informe, del orden de prioridades, del plan de n8n y de las alertas. El equipo de infraestructura trabaja sobre un informe manipulado sin saberlo. |
| **Ocultar un ataque en curso** | Si el atacante ya explota una vulnerabilidad, puede borrarla del informe para que nadie la parchee. |

**La defensa: TLS con verificación completa.** El motor y Ansible sólo aceptan la conexión si se cumplen las dos
condiciones de TLS:

1. **El certificado está firmado por la CA de Wazuh** (`/etc/wazuh-indexer/certs/root-ca.pem`, que el rol copia a
   `/etc/vulnmgmt/indexer-ca.pem`). Es la autoridad con la que el asistente de Wazuh firmó el certificado del indexer. Un
   impostor no tiene la clave privada de esa CA, así que no puede presentar un certificado válido. `root-ca.pem` es un
   certificado **público**: copiarlo no expone ningún secreto.
2. **El certificado corresponde a la dirección a la que se conecta** (campo *subjectAltName*): en la instalación de Wazuh
   incluye `127.0.0.1`, que es justamente la dirección que usa el motor.

**Lo que no se hace, a propósito:** desactivar la verificación (`verify_tls: false` o `curl -k`). Funcionaría igual, pero
dejaría la conexión cifrada **con cualquiera**, también con un impostor: equivale a no tener protección frente a un
*spoofing*.

**Defensa en profundidad.** La verificación TLS se complementa con:

- el usuario `vulnmgmt-reader`, que sólo puede **leer** el índice de vulnerabilidades: aunque se filtrara su contraseña,
  no permite modificar Wazuh;
- la contraseña de `admin`, que se usa una sola vez y no se guarda;
- el puerto 9200, que no hace falta abrir hacia afuera: la plataforma lo usa por `127.0.0.1`.

**Límite conocido: la API de Wazuh (55000, opcional).** La API viene con un certificado autofirmado que no está firmado
por ninguna CA, así que no se puede verificar de la misma forma; como la plataforma la consulta por `127.0.0.1`, el
tráfico tampoco sale del servidor. Se recomienda un usuario de rol `readonly`. Si no se usa, el informe de
vulnerabilidades y su priorización funcionan igual: la API sólo aporta la cobertura de agentes.

## 12. Variables principales

Todas están en `roles/vulnmgmt/defaults/main.yml`.

| Variable | Defecto | Uso |
|---|---|---|
| `vulnmgmt_wazuh_host` | `""` | Vacío = la plataforma está en el servidor Wazuh (lo que usa el equipo). Sólo para la alternativa no utilizada (sección 4). |
| `vulnmgmt_indexer_admin_password` | `""` | Contraseña de `admin` del indexer (una sola vez, para crear el usuario de lectura). |
| `vulnmgmt_api_user` / `vulnmgmt_api_password` | `""` | API de Wazuh (opcional, cobertura de agentes). |
| `vulnmgmt_scoring` | ver sección 7 | Pesos, umbrales, SLA y criticidad por servidor o grupo. |
| `vulnmgmt_web_port` / `vulnmgmt_web_user` | `8443` / `infra` | Panel. |
| `vulnmgmt_web_password` | `""` (generada) | Contraseña del panel; si queda vacía se genera y se guarda en `/etc/vulnmgmt/web.secret`. |
| `vulnmgmt_allowed_networks` | `[]` (cualquiera) | Redes que pueden abrir el panel, p. ej. `["10.10.99.0/24"]`. |
| `vulnmgmt_schedule` | `*-*-* 03:30:00` | Frecuencia del informe (formato `OnCalendar` de systemd). |
| `vulnmgmt_wazuh_event_priorities` | `[P1, P2]` | Prioridades que generan alertas en Wazuh. |
| `vulnmgmt_n8n_enabled` | `true` | `false` para no instalar n8n ni Docker. **Sin n8n no hay plan priorizado ni aviso semanal.** |
| `vulnmgmt_n8n_mail_from` / `_mail_to` | `vulnmgmt@cdg.uy` / `infraestructura@cdg.uy` | Remitente y destinatario del aviso (el nodo de correo igual viene deshabilitado). |
| `vulnmgmt_panel_url` | `https://<fqdn>:8443/` | Enlace al panel que se incluye en el aviso. |
| `vulnmgmt_allow_untested_platform` | `false` | `true` para probar otra distribución con `dnf` (sin soporte); nunca saltea la verificación de Python. |
| `vulnmgmt_first_run` | `run` | `demo` publica datos sintéticos de demostración. |

## 13. Archivos

```text
vulnmgmt.yml                       # Playbook (se ejecuta en el servidor Wazuh)
roles/vulnmgmt/                    # Rol de instalación (tareas, plantillas, variables)
roles/vulnmgmt/templates/n8n.service.j2  # Unidad systemd que lanza n8n con Docker
host_vars/srv-siem.yml.example     # Excepciones del endurecimiento si algún día se endureciera el servidor Wazuh
profiles/vulnmgmt-server.yml       # Sólo para la alternativa no utilizada (sección 4)
vulnmgmt/
├── engine/vulnmgmt/               # Motor (Python 3.9+, sólo librería estándar)
│   ├── wazuh.py                   #   indexer (scroll) y API de Wazuh
│   ├── intel.py                   #   CISA KEV y FIRST EPSS con caché y modo sin conexión
│   ├── prioritize.py              #   agrupación, riesgo, prioridad, SLA y seguimiento
│   ├── analysis.py                #   resumen determinístico del panel
│   ├── remediation.py             #   comandos por servidor y playbook de remediación
│   ├── publish.py                 #   JSON, CSV, histórico y eventos para Wazuh
│   └── demo.py                    #   datos de demostración
├── engine/tests/test_engine.py    # Pruebas unitarias y de integración con servidores simulados
├── web/                           # Panel (HTML + JS + CSS, sin dependencias externas)
├── wazuh/vulnmgmt_rules.xml       # Reglas 100800-100808
├── n8n/priorizar-soluciones.js    # Script del nodo "Code": triaje y soluciones propuestas (sección 9)
└── n8n/tests/                     # Pruebas del script con Node (ver su README)
```

El JSON del flujo de n8n no está en el repositorio: lo arma el rol con
`roles/vulnmgmt/templates/vulnmgmt-workflow.json.j2`, que incrusta el script anterior.

## 14. Resolución de problemas

| Síntoma | Causa / solución |
|---|---|
| `Abort if the TLS connection to the indexer fails` | El certificado del indexer no es válido para `127.0.0.1` o no lo firmó `/etc/wazuh-indexer/certs/root-ca.pem` (por ejemplo, si se regeneraron los certificados de Wazuh): volver a ejecutar el rol, que copia la CA actual. En la **primera** instalación, borrar `sudo rm /etc/vulnmgmt/indexer.secret` antes de reintentar. |
| `Abort if the engine cannot read the vulnerability index` con 401 | El usuario de lectura no existe (por ejemplo, la primera instalación falló a mitad): `sudo rm /etc/vulnmgmt/indexer.secret` y volver a ejecutar; `bootstrap.sh` pide de nuevo la contraseña de `admin`. |
| No aparecen las alertas `rule.groups: vulnmgmt` | Ver que exista `/var/ossec/etc/rules/vulnmgmt_rules.xml` y el bloque `vulnmgmt` en `/var/ossec/etc/ossec.conf`; volver a ejecutar el rol (valida con `wazuh-analysisd -t` y reinicia el manager). |
| *Preflight*: faltan credenciales del indexer | Pasar la contraseña de `admin` (sección 3). |
| El panel dice "Todavía no hay informes" o muestra 0 hallazgos | El motor aún no corrió o los agentes todavía no enviaron el inventario: `systemctl start vulnmgmt.service` más tarde, o usar el modo `demo`. |
| `journalctl -u vulnmgmt.service` muestra error 401/403 del indexer | Recrear el usuario de lectura: `sudo rm /etc/vulnmgmt/indexer.secret` y volver a ejecutar `sudo ./bootstrap.sh --component vulnmgmt` (pide la contraseña de `admin` y genera una nueva). |
| El aviso de n8n no llega | El nodo *Enviar correo* viene deshabilitado a propósito: cargar la credencial SMTP, habilitarlo y activar el flujo (sección 9). Para probar sin correo, usar *Ejecución manual* y mirar la salida del nodo *Priorizar y proponer soluciones*. |
| El nodo *Leer informe* falla con error de certificado | n8n confía en el certificado del panel por `NODE_EXTRA_CA_CERTS`; si se regeneró el certificado, volver a ejecutar el rol (copia el nuevo y reinicia n8n). |
| El flujo de n8n quedó viejo tras actualizar el repositorio | El rol lo reimporta sólo cuando el archivo renderizado cambia. Forzarlo con `sudo rm /var/lib/n8n/import/vulnmgmt-workflow.json` y volver a ejecutar el rol. |
| Aparecieron dos flujos iguales en n8n | Se duplicó a mano en el editor: el importado por el rol es el que tiene el `id` `vulnmgmtWeekly01`; borrar el otro. |
| Faltan KEV/EPSS (aviso en el panel) | Sin salida a Internet: se usa la última caché; los avisos lo indican. |
| `The vulnerability platform targets Rocky Linux 9/10 or Amazon Linux 2023` | El sistema no está soportado (por ejemplo Amazon Linux 2 o Rocky 8). Ver `grep PRETTY_NAME /etc/os-release`. |
| `No package nginx available` (o `docker`, `logrotate`) en Amazon Linux | El servidor **no llega a los repositorios** de Amazon Linux (los tres paquetes están en los repositorios por defecto de Amazon Linux 2023). Comprobarlo con `dnf repolist` y `dnf list --available nginx docker logrotate`. |
| n8n no arranca (`systemctl status n8n`, `journalctl -u n8n`) | La primera vez descarga la imagen de `docker.io`: sin salida a Internet falla el `docker pull`. Ver `docker images` y `systemctl status docker`. Para instalar el resto sin n8n: `sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_n8n_enabled=false` (**sin n8n se pierden el plan priorizado y el aviso semanal**, sección 9; el panel, las alertas y la remediación funcionan igual). |
| `firewalld is not running ... NOT opened` | No hay `firewalld`: abrir el puerto 8443/tcp con el firewall que se use. |
| `skipping: no hosts matched` al ejecutar el playbook | El nombre del agente de Wazuh no existe en el inventario: usarlo como alias en `inventory/hosts.ini` (sección 6). |
| El panel no abre desde la red | `firewall-cmd --list-all` y `vulnmgmt_allowed_networks`; `systemctl status nginx`. |
| nginx desapareció tras endurecer el servidor Wazuh | Falta `host_vars` con `hardening_packages_keep: [nginx]` (sección 3); volver a ejecutar el rol `vulnmgmt`. |

## 15. Pruebas realizadas y limitaciones

**Pruebas realizadas (en contenedores, con versiones reales de cada componente):**

- Motor: **24 pruebas automáticas, 23 pasan**. Incluyen servidores simulados del indexer (*scroll*), la API de
  Wazuh y EPSS, el resumen determinístico y el seguimiento de SLA. La que falla
  (`test_ansible_commands_are_real_and_tokenise_as_intended_in_bash`) es un **fallo del entorno, no del
  código**: lanza `bash` desde Python y en Windows eso resuelve a WSL. El mismo comando corrido a mano en
  bash da el resultado esperado.
  - Las corridas anteriores del proyecto fueron en Python 3.13 y en el Python 3.9 de Rocky 9; **los cambios
    de esta versión sólo se ejecutaron en Python 3.14 sobre Windows**. Conviene repetir la suite en el
    Python 3.9 de la VM.
- **Script de priorización de n8n** (`priorizar-soluciones.js`), ejecutado con **Node 24** tal como lo ejecuta
  el nodo *Code* (envuelto en una función, modo *Run Once for All Items*, con `$input` simulado) contra un
  informe real generado por el motor: orden de triaje, soluciones propuestas, ventanas y texto del aviso.
  Además **24 comprobaciones de casos borde** (`vulnmgmt/n8n/tests/edge-cases.js`): informe vacío, informe sin
  acciones, acción vencida y escalada, paquete protegido `wazuh-*` (conserva la guía del motor en lugar de un
  comando), acción con campos faltantes, prioridad desconocida, tope `MAX_ACCIONES` con el conteo de omitidas
  y, sobre todo, que el **triaje sea estricto**: la prioridad del motor manda sobre todo lo demás, ransomware
  gana a KEV, KEV gana al riesgo más alto y una vencida gana a todo lo que está por debajo.
- **Plantilla del flujo** (`vulnmgmt-workflow.json.j2`): se verificó, **simulando el render con Python** (en
  este entorno no hay Ansible), que produce JSON válido, que el script incrustado queda idéntico al archivo
  `.js` **salvo la sustitución de `URL_PANEL`**, que todas las conexiones apuntan a nodos existentes y que el
  nodo de correo sigue deshabilitado. El procedimiento para repetirlo con Ansible está en
  `vulnmgmt/n8n/tests/README.md`.
- Coherencia del repositorio: los 72 archivos YAML parsean, los `import_tasks`, `notify` y plantillas
  referenciados existen, los módulos que importa el motor existen, los anclajes del índice y los enlaces del
  README a este documento resuelven, y los `id` que lee `app.js` están en `index.html`.
- **OpenSearch 2.19** con el plugin de seguridad: creación idempotente del rol y del usuario de sólo lectura,
  y lectura con verificación TLS contra la CA.
- **Wazuh manager 4.12.0:** `wazuh-analysisd -t` y `wazuh-logtest` con eventos generados por el propio motor
  para los 8 casos (resumen, P1/P2 nuevas, escaladas, vencidas, KEV y KEV vencida); lectura real del archivo de
  eventos por `localfile`.
- **n8n 2.46.4:** importación por CLI y ejecución del flujo anterior (lectura del informe, filtro P1/P2 y armado
  del mensaje). **El flujo nuevo, con el nodo *Code*, no se importó ni se ejecutó dentro de n8n en este
  entorno** (ver limitaciones).
- **nginx 1.26** con la configuración generada: 401 sin usuario o con contraseña incorrecta, 200 con usuario,
  405 para métodos distintos de GET/HEAD, 404 para archivos ocultos (también con usuario válido), acceso local sin
  contraseña para n8n, cabeceras de seguridad y TLS 1.1 rechazado.
- Panel en Chromium con la CSP estricta (tema claro, oscuro y móvil).
- **Remediación:** 24 pruebas automáticas del motor (8 son de la remediación: filtros, exclusión de `wazuh-*`, nombres, versiones y CVE
  hostiles que no llegan a ningún comando, comandos por alcance y gestor de paquetes, comandos de Ansible que bash
  tokeniza como se espera, orden por prioridad y que el playbook sea YAML válido y no reinicie). Se comprobó con
  mutaciones que las pruebas de seguridad fallan si se quita la validación.
  El playbook generado pasa `ansible-lint` (perfil `production`) y `ansible-playbook --syntax-check`, y se ejecutó con
  ansible-core 2.14 en Rocky 9: la comprobación de reinicio con los cuatro comportamientos posibles de `dnf
  needs-restarting` (reinicio necesario, no necesario, comando inexistente y `dnf` ausente) y el paso `dnf` en modo
  `--check` (parámetros aceptados, incluido `disablerepo` con comodín). La sección del panel se probó en Chromium
  (CSP, descarga, copiar al portapapeles, tema oscuro y móvil).
- `ansible-lint` (perfil `production`), `--syntax-check` y `shellcheck`. **No se volvieron a correr para los
  cambios de esta versión** (no hay Ansible en el entorno donde se hicieron): correrlos antes de la defensa.

**Limitaciones (validar en la maqueta antes de la defensa):**

- **n8n con Docker: no se ejecutó con un Docker real** (no hay Docker en el entorno de pruebas). Se verificó que la
  unidad `n8n.service` se genera bien para Amazon Linux (sin etiquetas SELinux) y para Rocky (con `:Z`), que
  `systemd-analyze verify` no marca errores y que el paquete elegido es `docker` en Amazon y `docker-ce` en Rocky.
  Falta confirmar en el servidor Wazuh: `dnf install docker`, la descarga de la imagen de n8n, que n8n responda en
  `127.0.0.1:5678` y la importación del flujo con `docker exec`.

- No se ejecutó el rol completo sobre una VM (Rocky 9/10 o Amazon Linux 2023) con Wazuh real (systemd, SELinux *enforcing*,
  firewalld y Docker reales).
- **Amazon Linux 2023:** se probó `bootstrap.sh --component vulnmgmt` completo dentro de la imagen oficial de Amazon Linux 2023
  (`ID=amzn`, Python 3.9.25): detecta el sistema, instala `ansible-core` 2.15.13 en el entorno virtual, y el rol pasa los
  chequeos de sistema operativo, de Python, de servidor Wazuh y de credenciales con los hechos reales de Ansible
  (`Amazon` / `2023`). También se probó la matriz de plataformas (Rocky 9/10 y Amazon 2023 pasan; Amazon 2, Rocky 8 y
  Ubuntu se rechazan con un mensaje claro), que el endurecimiento sigue rechazando a Amazon Linux y que Rocky 9 y 10
  eligen los mismos playbooks que antes.
- **Sin validar en Amazon Linux 2023** (el entorno de pruebas no llega a `cdn.amazonlinux.com`): que sus repositorios
  tengan `nginx`, `openssl`, `tar`, `logrotate` y `docker`, el usuario y las
  rutas de `nginx`, `systemd`, SELinux y el firewall reales, y las rutas de Wazuh de esa imagen
  (`/var/ossec`, `/etc/wazuh-indexer/certs/root-ca.pem`). Si falta algún paquete, el error aparece en la tarea
  *Install the required packages*.
- **No se probó una actualización real con `dnf`/`apt`**: el entorno de pruebas no llega a los repositorios de Rocky, así
  que el paso `dnf` se verificó sólo en modo `--check` (sin repositorios) y la variante `deb` sólo con sintaxis y lint.
  Validar `--check` y luego la aplicación en un servidor de prueba antes de usarlo en producción.
- El texto que imprime `dnf needs-restarting` se verificó contra el código fuente de `dnf-plugins-core`, no contra un
  servidor con reinicio pendiente real.
- **El flujo nuevo no se importó dentro de n8n**: en este entorno no había Docker ni la imagen de n8n. El
  script se ejecutó con Node 24 reproduciendo cómo lo invoca el nodo *Code*, y la plantilla se verificó
  renderizada, pero falta confirmar en la maqueta: que `n8n import:workflow` acepte el flujo, que
  **actualice** el existente en lugar de duplicarlo (el `id` es fijo) y que el nodo *Code* de la versión
  2.46.4 acepte `mode: runOnceForAllItems` y `language: javaScript` tal como los escribe la plantilla.
- EPSS y `cisa.gov` no eran accesibles desde el entorno de pruebas; KEV se probó con el espejo oficial de GitHub
  y EPSS con un servidor simulado.
- Los datos de vulnerabilidades dependen de la cobertura del detector de Wazuh para cada sistema operativo.
