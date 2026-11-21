#!/bin/bash
# ------------------------------------------------------------------------------
# Respuesta activa: deshabilita en FreeIPA la cuenta senalada por una alerta.
# Obligatorio de Seguridad en Redes y Datos 2026.
# ------------------------------------------------------------------------------

LOG=/var/ossec/logs/active-responses.log
KEYTAB=/etc/wazuh/ar-ipa.keytab
PRINCIPAL=wazuh-ar/srv-ipa.corp.cdg.uy
CCACHE=/tmp/krb5cc_wazuh_ar

# Cuentas que esta respuesta NUNCA deshabilita. Sin esta lista, un atacante
# provoca una denegacion de servicio fallando a proposito la autenticacion de
# una cuenta administrativa hasta que el propio SIEM la bloquee.
PROTEGIDAS='admin|root|localadm|amontero|svc-'

registrar() {
  printf '%s ipa-disable-user: %s\n' "$(date '+%Y/%m/%d %H:%M:%S')" "$1" >> "$LOG"
}

read -r ENTRADA

COMANDO=$(printf '%s' "$ENTRADA" | python3 -c \
  'import sys,json; print(json.load(sys.stdin).get("command",""))' 2>/dev/null)

USUARIO=$(printf '%s' "$ENTRADA" | python3 -c '
import sys, json
d = json.load(sys.stdin)
a = d.get("parameters", {}).get("alert", {}).get("data", {})
print(a.get("srcuser") or a.get("dstuser") or "")
' 2>/dev/null)

if [ -z "$USUARIO" ]; then
  registrar "la alerta no trae usuario, no se ejecuta ninguna accion"
  exit 0
fi

if printf '%s' "$USUARIO" | grep -qE "^($PROTEGIDAS)"; then
  registrar "cuenta protegida '$USUARIO': no se deshabilita, queda la constancia"
  exit 0
fi

export KRB5CCNAME="$CCACHE"
if ! printf '%s' "$USUARIO" | grep -qE '^[a-z0-9._-]+$'; then
  registrar "usuario con formato invalido, no se ejecuta ninguna accion"; exit 0
fi
if [ "$COMANDO" = "add" ]; then
  printf '{"version":1,"origin":{"name":"ipa-disable-user","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' "$USUARIO"
  read -r RESPUESTA
  case "$RESPUESTA" in
    *'"continue"'*) ;;
    *) registrar "ya hay una respuesta en curso para '$USUARIO', no se repite"; exit 0 ;;
  esac
fi
if ! kinit -kt "$KEYTAB" "$PRINCIPAL" >/dev/null 2>&1; then
  registrar "no se pudo obtener ticket Kerberos con $KEYTAB"
  exit 1
fi

case "$COMANDO" in
  add)
    if ipa user-disable "$USUARIO" >/dev/null 2>&1; then
      registrar "cuenta '$USUARIO' DESHABILITADA en el directorio"
    else
      registrar "no se pudo deshabilitar '$USUARIO' (inexistente o ya deshabilitada)"
    fi
    ;;
  delete)
    if ipa user-enable "$USUARIO" >/dev/null 2>&1; then
      registrar "cuenta '$USUARIO' rehabilitada al vencer el plazo"
    else
      registrar "no se pudo rehabilitar '$USUARIO'"
    fi
    ;;
  *)
    registrar "comando no reconocido: '$COMANDO'"
    ;;
esac

kdestroy -q 2>/dev/null
exit 0
