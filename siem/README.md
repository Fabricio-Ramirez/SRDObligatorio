# SIEM: reglas propias y respuesta activa (puntos 2 y 3)

Configuración de Wazuh **tal como está desplegada en la maqueta** (21/11/2026). No la instala ningún playbook: se copia a
mano en el servidor Wazuh (srv-wazuh, 10.10.30.10) y en el agente de srv-ipa (10.10.30.20).

| Archivo | Destino | Dueño y permisos |
|---|---|---|
| `wazuh/local_decoder.xml` | srv-wazuh: `/var/ossec/etc/decoders/local_decoder.xml` | `wazuh:wazuh` 0660 |
| `wazuh/local_rules.xml` | srv-wazuh: `/var/ossec/etc/rules/local_rules.xml` | `wazuh:wazuh` 0660 |
| `wazuh/ossec-active-response.xml` | srv-wazuh: dentro de `<ossec_config>` en `/var/ossec/etc/ossec.conf` | (fragmento) |
| `active-response/ipa-disable-user.sh` | srv-ipa: `/var/ossec/active-response/bin/ipa-disable-user.sh` | `root:wazuh` 0750 |

pfSense envía sus registros (filterlog y OpenVPN) por syslog remoto en formato **RFC 5424** a srv-wazuh. Los decoders
esperan ese formato.

## Aplicar un cambio en las reglas

```bash
sudo cp -p /var/ossec/etc/rules/local_rules.xml /root/local_rules.xml.bak
# ... copiar o editar el archivo ...
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager && echo REGLAS-OK
```

`wazuh-analysisd -t` valida decoders y reglas antes de reiniciar: si hay un error, el manager no se reinicia.

## Reglas

| Regla | Nivel | Qué detecta |
|---|---|---|
| 100100 | 5 | Paquete bloqueado por pfSense |
| 100101 | 10 | 10 bloqueos desde el mismo origen en 1 minuto |
| 100102 / 100103 | 12 | Violación de política: la VPN de usuarios intenta llegar a administración / servidores |
| 100104 | 10 | Violación de política: un puesto de usuario intenta llegar a administración |
| 100110 | 0 | Agrupa los eventos de OpenVPN |
| 100111 / 100112 | 3 | Conexión / desconexión a la VPN |
| 100113 | 5 | Autenticación fallida en la VPN |
| 100115 | 8 | Conexión con el perfil de administradores (servidor `ovpns2`) |
| 100116 | 3 | Inicio de negociación de un cliente VPN |
| **100117** | **10** | **3 autenticaciones fallidas del mismo usuario en 3 minutos**: dispara la respuesta activa 1 |

La 100117 depende de la 100113 con `<same_srcuser />`: cuenta **fallos de un mismo usuario**, no conexiones. Una versión
anterior contaba negociaciones desde una IP y bloqueaba a usuarios legítimos que se reconectaban. Hubo además otra regla
(100114, «3 fallos en 5 minutos» de cualquier usuario) que se eliminó: Wazuh evalúa las reglas hijas en orden y se queda
con la primera que coincide, así que la 100114 se quedaba con el tercer fallo y la 100117 nunca disparaba.

### Probar sin tocar ninguna cuenta

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Pegar tres veces la línea siguiente. Las dos primeras dan 100113 y la tercera 100117 (el simulador no ejecuta respuestas
activas):

```
1 2026-11-21T19:52:58.345681-03:00 fw-pfsense.corp.cdg.uy openvpn 397 - - user 'jperez' could not authenticate.
```

## Respuesta activa 1: deshabilitar la cuenta en FreeIPA

Cuando dispara la 100117, el manager ordena al agente de srv-ipa (002) ejecutar `ipa-disable-user.sh`:

1. Lee la alerta (una línea JSON por la entrada estándar) y toma el usuario (`srcuser`).
2. **Cuentas protegidas:** nunca deshabilita `admin`, `root`, `localadm`, `amontero` ni `svc-*`; deja constancia. Sin esa
   lista, cualquiera podría dejar afuera al administrador fallando a propósito con su nombre.
3. **Intercambio con el agente (`check_keys`):** antes de actuar le informa el usuario y espera `continue` o `abort`.
   Wazuh 4.x lo exige en toda respuesta con plazo: sin él, el agente no agenda la reversión y la cuenta queda
   deshabilitada para siempre. Si ya hay una respuesta en curso para ese usuario, el agente responde `abort`, no se
   repite la acción y **el plazo se extiende**.
4. Se autentica con el keytab del principal `wazuh-ar/srv-ipa.corp.cdg.uy`, que sólo puede escribir el atributo
   `nsaccountlock` (permiso → privilegio → rol en FreeIPA), y ejecuta `ipa user-disable`.
5. A los **300 segundos** sin nuevos disparos, el agente vuelve a llamar al script con `delete` y la cuenta se rehabilita.

Registro en srv-ipa: `sudo tail -f /var/ossec/logs/active-responses.log`. Secuencia de la prueba del 21/11:

```
20:04:59 ipa-disable-user: cuenta 'jperez' DESHABILITADA en el directorio
20:06:23 ipa-disable-user: ya hay una respuesta en curso para 'jperez', no se repite
20:11:25 ipa-disable-user: cuenta 'jperez' rehabilitada al vencer el plazo
```

## Respuesta activa 2: bloquear la IP de origen

Ante la regla nativa 5712 (fuerza bruta por SSH), el equipo atacado ejecuta `firewall-drop` y descarta la IP de origen
durante 600 segundos.
