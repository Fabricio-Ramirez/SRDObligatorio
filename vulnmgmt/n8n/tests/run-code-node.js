/*
 * Ejecuta el script del nodo "Code" igual que lo ejecuta n8n, para poder
 * probarlo sin levantar el contenedor.
 *
 * n8n envuelve el contenido de "jsCode" en una función y le pasa $input, por
 * eso el "return" final del script es válido. El modo es runOnceForAllItems:
 * el script corre una sola vez con todos los items de entrada.
 *
 * Uso:
 *   node vulnmgmt/n8n/tests/run-code-node.js \
 *        vulnmgmt/n8n/priorizar-soluciones.js /ruta/a/latest.json
 *
 * Para obtener un latest.json de prueba, sin tocar un servidor Wazuh:
 *   cd vulnmgmt/engine && python3 -m vulnmgmt demo --config <config.json>
 */
const fs = require('fs');

const scriptPath = process.argv[2];
const reportPath = process.argv[3];

if (!scriptPath || !reportPath) {
  console.error('uso: run-code-node.js <priorizar-soluciones.js> <latest.json>');
  process.exit(2);
}

const code = fs.readFileSync(scriptPath, 'utf8');
const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

const items = [{ json: report }];
const $input = {
  all: () => items,
  first: () => items[0],
  last: () => items[items.length - 1],
};

const fn = new Function('$input', '$json', '"use strict";\n' + code);
const out = fn($input, report);

if (!Array.isArray(out)) throw new Error('el script debe devolver un array de items');
out.forEach((item, i) => {
  if (!item || typeof item.json !== 'object') {
    throw new Error('el item ' + i + ' no tiene la propiedad json');
  }
});

const result = out[0].json;
console.log('=== items devueltos: ' + out.length + ' ===');
console.log('=== claves: ' + Object.keys(result).join(', ') + ' ===');
console.log('\n=== ASUNTO ===\n' + result.asunto);
console.log('\n=== CUERPO ===\n' + result.cuerpo);
console.log('\n=== resumen ===\n' + JSON.stringify(result.resumen, null, 1));
console.log('\n=== ventanas ===\n' + JSON.stringify(result.ventanas, null, 1));
console.log('\n=== plan[0] ===\n' + JSON.stringify(result.plan[0], null, 1));
console.log('\n=== servidores ===\n' + JSON.stringify(result.servidores, null, 1));
