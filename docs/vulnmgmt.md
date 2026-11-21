# Gestión de vulnerabilidades — servidor dedicado que lee Wazuh

Punto **5. "Gestión de Vulnerabilidades"** del obligatorio de **Seguridad en Redes y Datos**
(Corporación de Generación S.A., cdg.uy).

> La plataforma debe gestionar las vulnerabilidades y actualizaciones de los servidores, emitir
> informes periódicos y traducirlos en acciones priorizadas y viables para los equipos de
> infraestructura. Suma valor el uso de IA y de flujos *no-code*.

Se instala igual que el endurecimiento (*install and play* con `bootstrap.sh` + Ansible) en un **servidor
dedicado con Rocky Linux 10** (`srv-vulnmgmt`). Ese servidor se endurece con la plantilla del punto 1 y **lee por
la red los hallazgos que genera Wazuh** (indexer, puerto 9200, con un usuario de sólo lectura). El motor en
Python arma el informe y el orden de las vulnerabilidades. Sobre el servidor Wazuh (imagen oficial, Amazon Linux 2023) no
se instala nada salvo el archivo de reglas de alertas. Todo es software libre y gratuito y corre **dentro de la
infraestructura**, sin APIs pagas ni envío de datos a terceros.

> **Cambio de arquitectura:** antes la plataforma se instalaba en el propio servidor Wazuh. Ese modo sigue
> disponible (sin `--wazuh-host`, sección 4, opción B), pero el recomendado es el servidor dedicado: no
> carga al servidor Wazuh, no depende de los paquetes de Amazon Linux (Podman/n8n) y queda endurecido.

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
| **No-code** (valor agregado) | **n8n Community Edition** (gratuito, *self-hosted*) con un flujo importado: cada lunes lee el informe y un **script determinístico** ordena las acciones por urgencia, propone la solución y la verificación de cada una, las agrupa en ventanas de mantenimiento y arma el aviso para infraestructura (correo, Teams, Slack, Telegram… se cambian desde el editor visual). Ver sección 9. |
| Explicabilidad | Toda la priorización y todo el texto del informe salen de **código determinístico y auditable**: las mismas entradas dan siempre el mismo resultado, sin modelos de lenguaje (sección 8). |
| Integración con el SIEM | Eventos JSON que el **agente Wazuh del servidor dedicado** envía al manager, donde las reglas propias (100800-100808) generan alertas de nivel 10-14 para las acciones P1/P2 nuevas o escaladas, KEV y vencidas. |

## 2. Arquitectura

```text
 Servidores (agente Wazuh)          Servidor Wazuh (imagen oficial,           srv-vulnmgmt (Rocky Linux 10,
 ┌────────────┐ inventario de       Amazon Linux 2023)                        endurecido con el punto 1)
 │ srv-idp    │ paquetes   ┌──────────────────────────────────┐     ┌─────────────────────────────────────────────┐
 │ srv-web    │───────────▶│ wazuh-manager ─ detector de      │     │ vulnmgmt.timer 03:30 ─▶ motor Python         │
 │ srv-bastion│            │                 vulnerabilidades │     │  1. lee hallazgos (HTTPS 9200, verificado     │
 │ ...        │            │      │                           │     │     con root-ca.pem) y agentes (API 55000)   │
 └────────────┘            │      ▼                           │     │  2. enriquece con KEV + EPSS                 │
                           │ wazuh-indexer :9200 ◀───────────────────│  3. agrupa, prioriza (P1-P4), SLA            │
                           │  wazuh-states-vulnerabilities-*  │ lee │  4. resumen determinístico                   │
                           │  (usuario vulnmgmt-reader)       │     │  5. publica                                  │
                           │                                  │     │   ├─▶ /var/www/vulnmgmt/data (JSON, CSV)     │
                           │ reglas 100800-100808 ◀───────────────┐ │   │     └─▶ nginx :8443 (HTTPS + usuario)    │
                           │ (alertas 10-14 en el dashboard)  │  │ │   └─▶ /var/log/vulnmgmt/events.json          │
                           └──────────────────────────────────┘  │ │           │                                │
                                                                 └─│── agente Wazuh (1514) ◀┘                   │
   Internet (opcional, con caché)                                  │                                             │
   CISA KEV, FIRST EPSS ──────────────────────────────────────────▶│ n8n 127.0.0.1:5678 (lunes 08:00)            │
                                                                   │   └─▶ lee latest.json ─▶ script de          │
                                                                   │       priorización ─▶ plan + aviso          │
                                                                   └─────────────────────────────────────────────┘
```

Qué viaja por la red entre los dos servidores:

| Origen → destino | Puerto | Para qué | Seguridad |
|---|---|---|---|
| srv-vulnmgmt → Wazuh | 9200/tcp | Leer los hallazgos de vulnerabilidades del indexer | TLS **verificado** contra la CA del indexer (`root-ca.pem`), usuario `vulnmgmt-reader` de sólo lectura |
| srv-vulnmgmt → Wazuh | 55000/tcp (opcional) | Inventario de agentes (cobertura) | TLS sin verificar (certificado autofirmado de la API): usuario con rol `readonly` y puerto abierto sólo para srv-vulnmgmt |
| srv-vulnmgmt → Wazuh | 1514/tcp y 1515/tcp | Agente Wazuh: logs del servidor y alertas de la plataforma | El cifrado propio del agente |

Componentes y consumo aproximado:

| Componente | Cómo corre | Recursos |
|---|---|---|
| Motor `vulnmgmt` | Servicio *oneshot* disparado por el temporizador; sólo librería estándar de Python 3.9+ | Máx. 50 % de 1 CPU y 512 MB (`CPUQuota`/`MemoryMax`), prioridad baja |
| nginx | Sirve archivos estáticos | Mínimo |
| n8n | Contenedor Podman (Quadlet) en 127.0.0.1; ejecuta el script de priorización una vez por semana | Máx. 1 GB |

## 3. Requisitos previos

**Servidor dedicado (recomendado):** una VM nueva con **Rocky Linux 10** (2 vCPU, 2-4 GB de RAM, 20 GB de disco),
con un usuario administrador del grupo `wheel` con clave SSH (lo exige la plantilla de endurecimiento), en la misma red
que el servidor Wazuh. En el servidor Wazuh hay que preparar cuatro cosas (sólo una vez):

| # | En el servidor Wazuh (Amazon Linux 2023) | Cómo |
|---|---|---|
| a | **Grupo de seguridad de AWS**: permitir desde la IP de srv-vulnmgmt **9200/tcp**, **1514/tcp**, **1515/tcp** y, si se usa la API, **55000/tcp**. Desde ninguna otra IP. | Consola de EC2 → *Security groups* → *Inbound rules*. Si además corre `firewalld` en el servidor: `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<IP-srv-vulnmgmt>" port port="9200" protocol="tcp" accept'` (y lo mismo para 55000) y `sudo firewall-cmd --reload`. |
| b | **Que el indexer escuche en la red**, no sólo en `127.0.0.1`. | `sudo ss -ltnp \| grep 9200`. Si muestra `127.0.0.1:9200`, poner `network.host: "0.0.0.0"` en `/etc/wazuh-indexer/opensearch.yml` y `sudo systemctl restart wazuh-indexer`. |
| c | **Ver qué nombres tiene el certificado del indexer** (para que TLS se verifique sin errores). | `sudo ls /etc/wazuh-indexer/certs/` y, con el certificado del nodo (el `.pem` que no es `admin`, `root-ca` ni `*-key`): `sudo openssl x509 -in /etc/wazuh-indexer/certs/<nodo>.pem -noout -ext subjectAltName`. Si **no** aparece la IP del servidor Wazuh, anotar uno de los nombres `DNS:` que sí aparezcan: se pasa con `--indexer-name` (el rol lo agrega a `/etc/hosts` de srv-vulnmgmt). Si el certificado no tiene **ningún** nombre `DNS:` (sólo `IP:127.0.0.1`), hay que regenerar el certificado del nodo incluyendo la IP del servidor, con la herramienta de certificados de Wazuh (`wazuh-certs-tool.sh`). **No** se desactiva la verificación TLS. |
| d | **Copiar la CA del indexer** a srv-vulnmgmt. | Desde srv-vulnmgmt: `sudo scp <admin>@<IP-wazuh>:/etc/wazuh-indexer/certs/root-ca.pem /root/wazuh-root-ca.pem` (o copiar el contenido a mano). Es un certificado público, no una clave. Si se copió desde Windows, quitarle los finales de línea CRLF (`sudo sed -i 's/
$//' /root/wazuh-root-ca.pem`): con CRLF, Ansible no lo lee ("Empty certificate data"). |

Además: la contraseña de `admin` del indexer (punto 3 de la lista siguiente), la versión del manager para fijar la del
agente (`sudo /var/ossec/bin/wazuh-control info` → `WAZUH_VERSION`) y, después de instalar, las **reglas** en el manager
(sección 4, paso 4).

**Requisitos comunes a los dos modos:**

1. **Servidor Wazuh 4.8 o superior *all-in-one*** (manager + indexer + dashboard), instalado con el asistente oficial
   (`wazuh-install.sh -a`) o con la imagen oficial (Amazon Linux 2023). En el modo local (plataforma instalada en el
   propio servidor Wazuh) ese servidor tiene que ser **Rocky Linux 9 o 10** o **Amazon Linux 2023**; **Amazon Linux 2 no
   se admite** (trae Python 3.7 y el motor necesita 3.9 o superior). La detección de vulnerabilidades viene habilitada por
   defecto (`<vulnerability-detection>` en `/var/ossec/etc/ossec.conf`, con `index-status` en `yes`). Para saber qué
   sistema tiene un servidor:

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
5. **RAM:** en el servidor dedicado, el motor está limitado a 512 MB y n8n a 1 GB (2 GB alcanzan, 4 GB es holgado).
   En el modo local, Wazuh *all-in-one* necesita unos 8 GB y la plataforma suma esos mismos límites; sin n8n
   (`-e vulnmgmt_n8n_enabled=false`) se suma sólo el motor.
6. Salida a Internet durante la instalación: `docker.io` (imagen de n8n), `packages.wazuh.com` (agente) y los
   repositorios de la distribución. En cada informe, opcionalmente, `cisa.gov` o `raw.githubusercontent.com` (KEV)
   y `api.first.org` (EPSS). Sin Internet la plataforma sigue funcionando con la última caché.

### Relación con el endurecimiento (punto 1)

> **El servidor dedicado srv-vulnmgmt sí se endurece** con la plantilla del punto 1 (Rocky Linux 10, CIS RHEL 10 L1)
> usando el perfil `profiles/vulnmgmt-server.yml`, que declara tres excepciones documentadas:
>
> - **conserva `nginx`**: CIS 2.1.18 lo desinstala, y es lo que publica el panel;
> - **permite el reenvío de puertos SSH** (CIS 5.1.10, que es de nivel 2), porque `ssh -L` es la única entrada al editor de n8n;
> - **instala el agente Wazuh**, que envía al manager los logs del servidor y las alertas de la plataforma.
>
> El puerto del panel (8443) lo abre el rol `vulnmgmt`, limitado a `vulnmgmt_allowed_networks`.

> **Decisión del equipo: el servidor Wazuh no se endurece con la plantilla del punto 1.** Con el servidor dedicado,
> sobre el servidor Wazuh sólo se instalan las reglas de alertas. El endurecimiento (`--component hardening`) se aplica
> al resto de los servidores, incluido srv-vulnmgmt.

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

### Opción A — Servidor dedicado Rocky Linux 10 (recomendada)

Antes, preparar el servidor Wazuh (sección 3, puntos a-d). Todo lo que sigue se ejecuta **en srv-vulnmgmt**;
en los ejemplos el servidor Wazuh es `10.0.10.12`.

**1. Clonar el repositorio:**

```bash
sudo dnf -y install git
```

```bash
git clone https://github.com/Fabricio-Ramirez/SRDObligatorio.git && cd SRDObligatorio
```

**2. Endurecer el servidor e instalar el agente Wazuh** (fijar la versión del agente a la del manager):

```bash
sudo ./bootstrap.sh --component hardening --profile vulnmgmt-server --siem-host 10.0.10.12 -- -e hardening_wazuh_agent_version=<versión-del-manager>-1
```

Reiniciar si el resumen dice `REBOOT REQUIRED`, y verificar con `sudo ./scripts/verify.sh`. **Cada vez que se vuelva a
endurecer este servidor hay que pasar `--profile vulnmgmt-server`**: sin el perfil, la plantilla desinstala nginx (el
panel deja de funcionar) y vuelve a bloquear el túnel SSH hacia n8n. En el dashboard de Wazuh
el agente `srv-vulnmgmt` tiene que aparecer como activo.

**3. Instalar la plataforma** leyendo el Wazuh remoto:

```bash
sudo ./bootstrap.sh --component vulnmgmt --wazuh-host 10.0.10.12 --wazuh-ca /root/wazuh-root-ca.pem
```

Si el certificado del indexer no tiene la IP del servidor Wazuh (sección 3, punto c), agregar el nombre que sí tiene,
por ejemplo `--indexer-name wazuh-indexer`. `bootstrap.sh` pide, sin mostrarla, la contraseña de `admin` del indexer.
Con ella el rol crea por la red el usuario de sólo lectura `vulnmgmt-reader` y después ya no la usa ni la guarda.
También pregunta por el usuario de la API, que es opcional. Antes de instalar nada, el rol comprueba que llega a
`10.0.10.12:9200` y que existe la CA. Si algo falla, el mensaje indica qué revisar (grupo de seguridad, `network.host`,
nombre del certificado). Al terminar muestra la URL del panel (`https://<IP-srv-vulnmgmt>:8443/`).

**4. Instalar las reglas de alertas en el manager** (una sola vez, **en el servidor Wazuh**). Copiar
`vulnmgmt/wazuh/vulnmgmt_rules.xml` del repositorio al servidor Wazuh (con `scp` o pegando el contenido) y:

```bash
sudo install -o wazuh -g wazuh -m 0660 vulnmgmt_rules.xml /var/ossec/etc/rules/vulnmgmt_rules.xml
```

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

`wazuh-analysisd -t` valida las reglas **antes** de reiniciar: si da error, el manager no se reinicia y sigue
funcionando con las reglas anteriores. Las reglas reconocen los eventos por su contenido JSON (`vulnmgmt.event`), así
que aplican igual aunque lleguen por el agente de srv-vulnmgmt.

**5. Si la plataforma estaba instalada en el servidor Wazuh** (versión anterior), desactivarla allí para no tener
informes ni alertas duplicados:

```bash
sudo systemctl disable --now vulnmgmt.timer n8n.service
```

**Comprobar que llegan los datos** (en srv-vulnmgmt): `sudo systemctl start vulnmgmt.service` y después
`journalctl -u vulnmgmt.service -n 30`. El log tiene que mostrar los hallazgos leídos del indexer remoto, y el panel
tiene que mostrar los agentes de toda la red.

### Opción B — En el propio servidor Wazuh (modo local)

Era la opción anterior y sigue soportada. Sólo se usa si no hay un servidor dedicado: es el mismo comando **sin**
`--wazuh-host`.

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

El comando es idempotente: sirve para actualizar el motor, el panel o la configuración. **En el servidor dedicado**
se repite con las mismas opciones de la instalación (`--wazuh-host`, `--wazuh-ca` y, si se usó, `--indexer-name`);
sin `--wazuh-host` el rol se detiene avisando que ese servidor no es el manager. Primero actualizar el repositorio
(el script no se actualiza a sí mismo cuando se ejecuta desde un clon) y volver a lanzar:

```bash
cd <carpeta-del-repositorio> && git pull --ff-only
```

```bash
sudo ./bootstrap.sh --component vulnmgmt
```

- **No vuelve a pedir** la contraseña de `admin` del indexer (usa el usuario de lectura que ya existe) y **conserva** la
  contraseña del panel, el certificado, el usuario de lectura y el flujo ya importado en n8n.
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

### Opción C — Desde un nodo de control

Agregar srv-vulnmgmt al grupo `[vulnmgmt_server]` de `inventory/hosts.ini` (ver `inventory/hosts.ini.example`),
copiar `host_vars/srv-vulnmgmt.yml.example` a `host_vars/srv-vulnmgmt.yml` y ajustar la IP del Wazuh. Endurecerlo con
`ansible-playbook -i inventory/hosts.ini site-rocky10.yml -l srv-vulnmgmt -e @profiles/vulnmgmt-server.yml`, y
guardar las contraseñas cifradas con `ansible-vault`:

```bash
ansible-vault create secrets-vulnmgmt.yml
```

(contenido: `vulnmgmt_indexer_admin_password: "..."`, y opcionalmente `vulnmgmt_api_user` / `vulnmgmt_api_password`)

```bash
ansible-playbook -i inventory/hosts.ini vulnmgmt.yml -l srv-vulnmgmt -e @secrets-vulnmgmt.yml --ask-vault-pass
```

(Para el modo local, poner el servidor Wazuh en `[wazuh_server]` y no definir `vulnmgmt_wazuh_host`.)

### Qué hace el rol `roles/vulnmgmt`

| Paso | Archivo |
|---|---|
| Valida el sistema operativo (Rocky 9/10 o Amazon Linux 2023), Python 3.9 o superior y las credenciales. En modo remoto: que exista la CA y que el indexer responda en 9200. En modo local: que sea el manager de Wazuh | `tasks/preflight.yml` |
| Paquetes (python3, nginx, podman…), usuario de servicio `vulnmgmt`, motor y panel, certificado TLS, secretos generados | `tasks/base.yml` |
| Nombre del certificado en `/etc/hosts` (si se pasó `--indexer-name`), rol y usuario de **sólo lectura** en el indexer (sólo el índice de vulnerabilidades) y prueba de acceso | `tasks/indexer.yml` |
| Configuración del motor (`/etc/vulnmgmt/config.json`, 0640) y logrotate | `tasks/config.yml` |
| nginx (HTTPS, usuario y contraseña, cabeceras de seguridad) y firewalld | `tasks/web.yml` |
| Modo remoto: el agente Wazuh lee `events.json` (bloque `localfile` en su `ossec.conf`). Modo local: reglas en el manager y lectura de los eventos (`wazuh-analysisd -t` antes de reiniciar) | `tasks/wazuh.yml` |
| n8n con Podman Quadlet; arma el flujo con el script de priorización y lo importa cuando cambió | `tasks/n8n.yml` |
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

El informe no hace falta esperarlo: se puede generar en cualquier momento, desde el servidor de la plataforma (srv-vulnmgmt, o el servidor Wazuh en el modo local), sin esperar al horario programado.

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

n8n Community Edition corre en un contenedor Podman, **sólo en 127.0.0.1:5678** y sin telemetría. Para usarlo:

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

El motor escribe eventos JSON en `/var/log/vulnmgmt/events.json`. En el servidor dedicado los lee el **agente Wazuh**
de srv-vulnmgmt (`localfile` en formato `json`) y los envía al manager, que tiene las reglas instaladas (sección 4,
paso 4). En el modo local los lee directamente el manager. Para no repetir alertas todos los días se emite un resumen por informe y, por cada acción P1/P2, sólo
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
- **Conexión con Wazuh (servidor dedicado):** el motor sólo **lee**. Al indexer se conecta con TLS verificado contra su
  CA (`/etc/vulnmgmt/indexer-ca.pem`), nunca con la verificación desactivada; si el certificado no nombra la IP, se usa
  uno de sus nombres (`vulnmgmt_indexer_tls_name`) en lugar de apagar la verificación. Los puertos 9200 y 55000 del
  servidor Wazuh se abren **sólo** para la IP de srv-vulnmgmt. La API (opcional) usa un certificado autofirmado que
  no se puede verificar: por eso se recomienda un usuario con rol `readonly`. El porqué está en la subsección
  [*Por qué se verifica el certificado del indexer*](#por-qué-se-verifica-el-certificado-del-indexer-protección-contra-spoofing).
- **Endurecimiento:** srv-vulnmgmt aplica CIS RHEL 10 L1 con tres excepciones documentadas (sección 3).
- **Integridad del software:** imagen de n8n con versión fija (`docker.io/n8nio/n8n:2.46.4`).
- **Script de n8n:** no construye comandos con datos del indexer ni ejecuta nada en los servidores; sólo
  lee el informe y arma texto (sección 9).
- **CSV:** se neutralizan las celdas que empiezan con `=`, `+`, `-`, `@`, tabulador o retorno de carro, para evitar inyección de fórmulas en Excel.
- **SELinux** en modo *enforcing*: certificado en `/etc/pki/tls`, puerto 8443 ya etiquetado `http_port_t`,
  volúmenes de n8n con `:Z`.

### Por qué se verifica el certificado del indexer (protección contra *spoofing*)

Esta decisión de diseño responde a un criterio de **seguridad**. Al pasar la plataforma a un servidor dedicado, los
datos dejan de quedarse dentro de una sola máquina (antes el motor leía `127.0.0.1`) y ahora **cruzan la red** entre
srv-vulnmgmt y el servidor Wazuh. Por eso el motor tiene que comprobar **con quién** habla, no sólo cifrar la conexión.

**El riesgo: suplantación del indexer (*spoofing* / *man-in-the-middle*).** Si srv-vulnmgmt aceptara cualquier
certificado, un equipo de la misma red podría hacerse pasar por el indexer de Wazuh. Le bastaría con un *ARP spoofing*,
una entrada DNS falsa o tomar la IP del servidor. Así podría:

| Ataque | Consecuencia |
|---|---|
| **Robo de credenciales** | En la instalación viaja la contraseña de `admin` del indexer (control total de Wazuh); todos los días, la de `vulnmgmt-reader`. |
| **Datos falsos** | El atacante entrega hallazgos inventados u omite los reales: una vulnerabilidad crítica (P1, KEV) desaparece del informe, del orden de prioridades, del plan de n8n y de las alertas. El equipo de infraestructura trabaja sobre un informe manipulado sin saberlo. |
| **Ocultar un ataque en curso** | Si el atacante ya explota una vulnerabilidad, puede borrarla del informe para que nadie la parchee. |

**La defensa: TLS con verificación completa.** El motor y Ansible sólo aceptan la conexión si se cumplen las dos
condiciones de TLS:

1. **El certificado está firmado por la CA de Wazuh.** Por eso se copia `root-ca.pem` del servidor Wazuh a srv-vulnmgmt
   (`--wazuh-ca`): es la autoridad con la que el asistente de Wazuh firmó el certificado del indexer. Un impostor no
   tiene la clave privada de esa CA, así que no puede presentar un certificado válido. `root-ca.pem` es un certificado
   **público**: copiarlo no expone ningún secreto.
2. **El certificado corresponde a la dirección a la que se conecta** (campo *subjectAltName*). Los certificados que genera
   Wazuh suelen incluir `127.0.0.1` o un nombre como `wazuh-indexer`, pero no siempre la IP de red del servidor. Si no la
   incluyen, la conexión se rechaza ("IP address mismatch"). Para esos casos existe `--indexer-name`: el rol agrega
   `<IP-wazuh> <nombre>` a `/etc/hosts` de srv-vulnmgmt y se conecta con el nombre que sí está en el certificado. Así la
   verificación sigue siendo **completa**.

**Lo que no se hace, a propósito:** desactivar la verificación (`verify_tls: false` o `curl -k`). Funcionaría al
instante, pero dejaría la conexión cifrada **con cualquiera**, también con el impostor: equivale a no tener protección
frente a un *spoofing*. Por eso, si el certificado no tiene ningún nombre utilizable, la solución documentada es
regenerarlo incluyendo la IP (sección 3, punto c), no apagar la verificación.

**Defensa en profundidad.** La verificación TLS se complementa con:

- el grupo de seguridad de AWS, que abre 9200 y 55000 **sólo** para la IP de srv-vulnmgmt;
- el usuario `vulnmgmt-reader`, que sólo puede **leer** el índice de vulnerabilidades: aunque se filtrara su contraseña,
  no permite modificar Wazuh;
- la contraseña de `admin`, que se usa una sola vez y no se guarda en srv-vulnmgmt.

**Límite conocido: la API de Wazuh (55000, opcional).** La API viene con un certificado autofirmado que no está firmado
por ninguna CA, así que no se puede verificar de la misma forma. Por eso es opcional y se recomienda usarla sólo con un
usuario de rol `readonly`, con el puerto abierto únicamente para srv-vulnmgmt. Si no se usa, el informe de
vulnerabilidades y su priorización funcionan igual: la API sólo aporta la cobertura de agentes.

## 12. Variables principales

Todas están en `roles/vulnmgmt/defaults/main.yml`.

| Variable | Defecto | Uso |
|---|---|---|
| `vulnmgmt_wazuh_host` | `""` (modo local) | IP o nombre del servidor Wazuh que se lee por la red (`--wazuh-host`). Vacío = la plataforma está en el propio servidor Wazuh. |
| `vulnmgmt_indexer_ca_source` | `/root/wazuh-root-ca.pem` (remoto) | Copia de la CA del indexer (`--wazuh-ca`). En modo local, `/etc/wazuh-indexer/certs/root-ca.pem`. |
| `vulnmgmt_indexer_tls_name` | `""` | Nombre del certificado del indexer, si no contiene la IP (`--indexer-name`); se agrega a `/etc/hosts`. |
| `vulnmgmt_indexer_admin_password` | `""` | Contraseña de `admin` del indexer (una sola vez, para crear el usuario de lectura). |
| `vulnmgmt_api_user` / `vulnmgmt_api_password` | `""` | API de Wazuh (opcional, cobertura de agentes). |
| `vulnmgmt_scoring` | ver sección 7 | Pesos, umbrales, SLA y criticidad por servidor o grupo. |
| `vulnmgmt_web_port` / `vulnmgmt_web_user` | `8443` / `infra` | Panel. |
| `vulnmgmt_web_password` | `""` (generada) | Contraseña del panel; si queda vacía se genera y se guarda en `/etc/vulnmgmt/web.secret`. |
| `vulnmgmt_allowed_networks` | `[]` (cualquiera) | Redes que pueden abrir el panel, p. ej. `["10.0.99.0/24"]`. |
| `vulnmgmt_schedule` | `*-*-* 03:30:00` | Frecuencia del informe (formato `OnCalendar` de systemd). |
| `vulnmgmt_wazuh_event_priorities` | `[P1, P2]` | Prioridades que generan alertas en Wazuh. |
| `vulnmgmt_n8n_enabled` | `true` | `false` para no instalar n8n (n8n necesita Podman 4.4 o superior). **Sin n8n no hay plan priorizado ni aviso semanal.** |
| `vulnmgmt_n8n_mail_from` / `_mail_to` | `vulnmgmt@cdg.uy` / `infraestructura@cdg.uy` | Remitente y destinatario del aviso (el nodo de correo igual viene deshabilitado). |
| `vulnmgmt_panel_url` | `https://<fqdn>:8443/` | Enlace al panel que se incluye en el aviso. |
| `vulnmgmt_allow_untested_platform` | `false` | `true` para probar otra distribución con `dnf` (sin soporte); nunca saltea la verificación de Python. |
| `vulnmgmt_first_run` | `run` | `demo` publica datos sintéticos de demostración. |

## 13. Archivos

```text
vulnmgmt.yml                       # Playbook (grupos vulnmgmt_server y wazuh_server)
roles/vulnmgmt/                    # Rol de instalación (tareas, plantillas, variables)
profiles/vulnmgmt-server.yml       # Excepciones del endurecimiento para srv-vulnmgmt (--profile)
host_vars/srv-vulnmgmt.yml.example # Variables de srv-vulnmgmt para un nodo de control
host_vars/srv-siem.yml.example     # Excepciones del endurecimiento si algún día se endureciera el servidor Wazuh
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
| *Preflight*: "Local mode installs the platform on the Wazuh server" | Se ejecutó en srv-vulnmgmt sin `--wazuh-host`: agregar `--wazuh-host <IP-wazuh>`. |
| *Preflight*: "... was not found. Copy the indexer root CA" | Falta la CA en srv-vulnmgmt: sección 3, punto d, o indicar la ruta con `--wazuh-ca`. |
| *Preflight*: "<IP>:9200 does not answer" | Grupo de seguridad de AWS o `firewalld` del servidor Wazuh sin la regla para srv-vulnmgmt, o el indexer escucha sólo en `127.0.0.1` (sección 3, puntos a y b). Probar desde srv-vulnmgmt: `curl -k https://<IP-wazuh>:9200` (debe responder 401; `-k` sólo sirve para probar que el puerto responde, sin enviar credenciales: la plataforma siempre verifica el certificado). Si el fallo fue en la **primera** instalación, borrar `sudo rm /etc/vulnmgmt/indexer.secret` antes de reintentar, para que `bootstrap.sh` vuelva a pedir la contraseña de `admin` y cree el usuario de lectura. |
| `Abort if the TLS connection to the indexer fails` con "IP address mismatch", "hostname mismatch" o `CERTIFICATE_VERIFY_FAILED` | El certificado del indexer no nombra la IP: pasar `--indexer-name <nombre-DNS-del-certificado>` (sección 3, punto c). Si dice que no confía en el emisor, la CA copiada no es la correcta. Con "Empty certificate data", la CA tiene finales de línea CRLF (sección 3, punto d). En la **primera** instalación, borrar `sudo rm /etc/vulnmgmt/indexer.secret` antes de reintentar. |
| `Abort if the engine cannot read the vulnerability index` con 401 | El usuario de lectura no existe (por ejemplo, la primera instalación falló a mitad): `sudo rm /etc/vulnmgmt/indexer.secret` y volver a ejecutar; `bootstrap.sh` pide de nuevo la contraseña de `admin`. |
| El agente `srv-vulnmgmt` no aparece en Wazuh | Puertos 1514/1515 en el grupo de seguridad; versión del agente más nueva que el manager (fijarla con `hardening_wazuh_agent_version`); `sudo tail /var/ossec/logs/ossec.log` en srv-vulnmgmt. |
| No aparecen las alertas `rule.groups: vulnmgmt` | Faltan las reglas en el manager (sección 4, paso 4) o el agente no está activo. |
| *Preflight*: "Remote mode must not run on the Wazuh server itself" | Se pasó `--wazuh-host` en el propio servidor Wazuh: ahí usar el modo local (sin `--wazuh-host`). |
| *Preflight*: faltan credenciales del indexer | Pasar la contraseña de `admin` (sección 3). |
| El panel dice "Todavía no hay informes" o muestra 0 hallazgos | El motor aún no corrió o los agentes todavía no enviaron el inventario: `systemctl start vulnmgmt.service` más tarde, o usar el modo `demo`. |
| `journalctl -u vulnmgmt.service` muestra error 401/403 del indexer | Recrear el usuario de lectura: `sudo rm /etc/vulnmgmt/indexer.secret` y volver a ejecutar `sudo ./bootstrap.sh --component vulnmgmt` (pide la contraseña de `admin` y genera una nueva). |
| El aviso de n8n no llega | El nodo *Enviar correo* viene deshabilitado a propósito: cargar la credencial SMTP, habilitarlo y activar el flujo (sección 9). Para probar sin correo, usar *Ejecución manual* y mirar la salida del nodo *Priorizar y proponer soluciones*. |
| El nodo *Leer informe* falla con error de certificado | n8n confía en el certificado del panel por `NODE_EXTRA_CA_CERTS`; si se regeneró el certificado, volver a ejecutar el rol (copia el nuevo y reinicia n8n). |
| El flujo de n8n quedó viejo tras actualizar el repositorio | El rol lo reimporta sólo cuando el archivo renderizado cambia. Forzarlo con `sudo rm /var/lib/n8n/import/vulnmgmt-workflow.json` y volver a ejecutar el rol. |
| Aparecieron dos flujos iguales en n8n | Se duplicó a mano en el editor: el importado por el rol es el que tiene el `id` `vulnmgmtWeekly01`; borrar el otro. |
| Faltan KEV/EPSS (aviso en el panel) | Sin salida a Internet: se usa la última caché; los avisos lo indican. |
| `The vulnerability platform targets Rocky Linux 9/10 or Amazon Linux 2023` | El sistema no está soportado (por ejemplo Amazon Linux 2 o Rocky 8). Ver `grep PRETTY_NAME /etc/os-release`. |
| `No package nginx available` (o `podman`, `logrotate`) en Amazon Linux | Dos causas posibles: el paquete **no existe** en esa distribución, o el servidor **no llega a sus repositorios**. Distinguirlo con `dnf repolist` y `dnf list --available nginx podman logrotate`. Si falta sólo `podman`, instalar sin n8n (ver la fila siguiente). |
| `n8n needs Podman 4.4 or newer`, o `podman` no disponible | Actualizar Podman, o instalar sin n8n: `sudo ./bootstrap.sh --component vulnmgmt -- -e vulnmgmt_n8n_enabled=false`. **Sin n8n se pierden el plan priorizado y el aviso semanal** (sección 9); el panel, las alertas y la remediación funcionan igual. |
| `firewalld is not running ... NOT opened` | No hay `firewalld`: abrir el puerto 8443/tcp con el firewall que se use. |
| `skipping: no hosts matched` al ejecutar el playbook | El nombre del agente de Wazuh no existe en el inventario: usarlo como alias en `inventory/hosts.ini` (sección 6). |
| El panel no abre desde la red | `firewall-cmd --list-all` y `vulnmgmt_allowed_networks`; `systemctl status nginx`. |
| nginx desapareció de srv-vulnmgmt, o `ssh -L 5678:...` dejó de funcionar | Se volvió a endurecer sin `--profile vulnmgmt-server`. Repetir el endurecimiento con el perfil y después `sudo ./bootstrap.sh --component vulnmgmt --wazuh-host ...` (reinstala nginx y su configuración). |
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

- **Servidor dedicado (modo remoto): no se ejecutó sobre VMs reales.** Lo probado, en Rocky Linux 10.2 (WSL) con
  ansible-core 2.16: `--syntax-check` de `vulnmgmt.yml` y `site-rocky10.yml` con el perfil, las URL derivadas en los tres
  casos (local, remoto y remoto con `--indexer-name`), el *preflight* real en cuatro situaciones (servidor que no es
  Wazuh sin `--wazuh-host`, CA faltante, puerto 9200 cerrado y puerto abierto), el texto de los mensajes de error, y las
  opciones nuevas de `bootstrap.sh` con `dnf`/`ansible` simulados. **TLS real** contra un servidor HTTPS con un certificado
  firmado por una CA propia cuyo SAN es sólo `DNS:localhost`: por IP, la sonda corta con la pista de `--indexer-name`; con
  el nombre, conecta y verifica (Ansible `uri` y el cliente HTTP del motor), y en `--check` no se interrumpe. Falta comprobar en la maqueta: la conexión al indexer
  de la imagen de Amazon Linux (puerto, `network.host` y nombres del certificado), la creación remota del usuario de
  lectura, el enrolamiento del agente en Rocky 10 y que las alertas lleguen al manager por el agente.

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
- **El flujo nuevo no se importó dentro de n8n**: en este entorno no había Podman ni la imagen de n8n. El
  script se ejecutó con Node 24 reproduciendo cómo lo invoca el nodo *Code*, y la plantilla se verificó
  renderizada, pero falta confirmar en la maqueta: que `n8n import:workflow` acepte el flujo, que
  **actualice** el existente en lugar de duplicarlo (el `id` es fijo) y que el nodo *Code* de la versión
  2.46.4 acepte `mode: runOnceForAllItems` y `language: javaScript` tal como los escribe la plantilla.
- EPSS y `cisa.gov` no eran accesibles desde el entorno de pruebas; KEV se probó con el espejo oficial de GitHub
  y EPSS con un servidor simulado.
- Los datos de vulnerabilidades dependen de la cobertura del detector de Wazuh para cada sistema operativo.
