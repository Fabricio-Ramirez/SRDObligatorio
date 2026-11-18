# Pruebas del script de priorización (nodo "Code" de n8n)

El script `../priorizar-soluciones.js` se ejecuta dentro de n8n, pero se puede probar sin levantar el
contenedor: estos dos archivos lo invocan igual que el nodo *Code* (envuelto en una función, modo
*Run Once for All Items*, con `$input` simulado).

Hace falta **Node.js 18 o superior** (se usó Node 24).

## 1. Generar un informe de prueba

Sin tocar un servidor Wazuh, con los datos sintéticos del motor:

```bash
mkdir -p /tmp/vm/data /tmp/vm/state
cat > /tmp/vm/config.json <<'EOF'
{
  "indexer": {"url": "https://127.0.0.1:9200", "username": "x", "password": "x",
              "verify_tls": false, "index": "i"},
  "api": {"enabled": false},
  "intel": {"enabled": false},
  "scoring": {},
  "output": {"web_data_dir": "/tmp/vm/data", "state_dir": "/tmp/vm/state",
             "history_runs": 90, "wazuh_events_log": ""}
}
EOF
cd ../../engine && python3 -m vulnmgmt demo --config /tmp/vm/config.json
```

En un servidor ya instalado se puede usar directamente `/var/www/vulnmgmt/data/latest.json`.

## 2. Ver la salida del script

```bash
node run-code-node.js ../priorizar-soluciones.js /tmp/vm/data/latest.json
```

Imprime el asunto, el cuerpo del aviso y las estructuras `resumen`, `ventanas`, `plan` y `servidores`,
que es exactamente lo que el nodo entrega al siguiente nodo del flujo.

## 3. Casos borde

```bash
node edge-cases.js ../priorizar-soluciones.js /tmp/vm/data/latest.json
```

24 comprobaciones; devuelve 0 si todas pasan. Cubren informe vacío, informe sin acciones, acción vencida
y escalada, paquete protegido `wazuh-*`, acción con campos faltantes, el tope `MAX_ACCIONES` y —sobre
todo— que el **triaje sea estricto**: que la prioridad del motor mande, y que ransomware gane a KEV, KEV
al riesgo más alto, y una vencida a todo lo que está por debajo. Ese último grupo es el que detecta la
regresión más fácil de introducir: cambiar la clave lexicográfica de `claveTriaje` por una suma de pesos.

## 4. Verificar el flujo que se importa

El JSON del flujo lo arma Ansible con `roles/vulnmgmt/templates/vulnmgmt-workflow.json.j2`, que incrusta
este script. Para ver el resultado sin instalar nada:

```bash
# desde la raíz del repositorio
ansible localhost -m template \
  -a "src=roles/vulnmgmt/templates/vulnmgmt-workflow.json.j2 dest=/tmp/flujo.json" \
  -e vulnmgmt_panel_url=https://wazuh.example:8443/ \
  -e vulnmgmt_n8n_mail_from=a@example \
  -e vulnmgmt_n8n_mail_to=b@example \
  -e playbook_dir="$PWD"
python3 -m json.tool /tmp/flujo.json > /dev/null && echo "JSON válido"
```
