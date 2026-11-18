/*
 * Casos borde del script de priorización (nodo "Code" de n8n).
 *
 * Comprueba sobre todo que el triaje sea ESTRICTO: la prioridad del motor manda,
 * y después cada criterio desempata al siguiente sin que los de abajo puedan
 * compensar a los de arriba (por eso claveTriaje usa una clave lexicográfica y
 * no una suma de pesos).
 *
 * Uso:
 *   node vulnmgmt/n8n/tests/edge-cases.js \
 *        vulnmgmt/n8n/priorizar-soluciones.js /ruta/a/latest.json
 *
 * Devuelve 0 si todo pasa, 1 si algo falla.
 */
const fs = require('fs');

const scriptPath = process.argv[2];
const reportPath = process.argv[3];

if (!scriptPath || !reportPath) {
  console.error('uso: edge-cases.js <priorizar-soluciones.js> <latest.json>');
  process.exit(2);
}

const code = fs.readFileSync(scriptPath, 'utf8');
const base = JSON.parse(fs.readFileSync(reportPath, 'utf8'));

function run(report) {
  const items = [{ json: report }];
  const $input = { all: () => items, first: () => items[0], last: () => items[0] };
  const fn = new Function('$input', '$json', '"use strict";\n' + code);
  const out = fn($input, report);
  if (!Array.isArray(out) || !out[0] || typeof out[0].json !== 'object') {
    throw new Error('el script devolvió algo que no son items de n8n');
  }
  return out[0].json;
}

let fallos = 0;
function check(name, cond, extra) {
  if (!cond) fallos += 1;
  console.log((cond ? 'OK   ' : 'FALLA ') + name + (extra ? '  -> ' + extra : ''));
}

const clone = (o) => JSON.parse(JSON.stringify(o));

/** Acción mínima, para armar casos sin arrastrar el informe entero. */
function accion(extra) {
  return Object.assign({
    id: 'X', priority: 'P1', risk: 50, action: 'actualizar', package: 'pkg',
    hosts: [{ name: 'h', criticality: 'media' }], cves: [], kev_count: 0,
    overdue: false, commands: { remediation: 'c', verification: 'v' },
    due_date: '2026-12-01', reasons: [], reboot_required: false,
  }, extra);
}

// --- 1. Informe vacío -------------------------------------------------------
let r = run({});
check('informe vacío: devuelve un asunto', typeof r.asunto === 'string' && r.asunto.length > 0, r.asunto);
check('informe vacío: avisa que no hay nada pendiente', r.cuerpo.includes('No hay acciones'));
check('informe vacío: plan vacío', r.plan.length === 0);
check('informe vacío: sin ventanas', r.ventanas.length === 0);

// --- 2. Informe con KPI pero sin acciones -----------------------------------
const vacio = clone(base);
vacio.actionables = [];
vacio.remediation = { hosts: [] };
vacio.kpis.actions = { P1: 0, P2: 0, P3: 0, P4: 0 };
r = run(vacio);
check('sin acciones: el asunto lo dice', r.asunto.includes('Sin acciones'), r.asunto);
check('sin acciones: sin ventanas', r.ventanas.length === 0);

// --- 3. Acción vencida y escalada -------------------------------------------
const vencido = clone(base);
const last = vencido.actionables[vencido.actionables.length - 1];
last.priority = 'P2';
last.overdue = true;
last.due_date = '2020-01-01';
last.previous_priority = 'P4';
r = run(vencido);
const p2 = r.plan.filter((p) => p.prioridad === 'P2');
check('la vencida va primera dentro de su prioridad', p2[0].paquete === last.package, p2[0].paquete);
check('se marca como vencida', p2[0].vencida === true);
check('se marca la escalada', p2[0].escalada === true);
check('el asunto avisa que hay vencidas', r.asunto.includes('fuera de plazo'), r.asunto);
check('el cuerpo la marca VENCIDA', r.cuerpo.includes('VENCIDA el 2020-01-01'));
check('días restantes negativos', p2[0].dias_restantes < 0, String(p2[0].dias_restantes));

// --- 4. Paquete protegido (wazuh-*) -----------------------------------------
const protegido = clone(base);
protegido.actionables[0].package = 'wazuh-agent';
protegido.actionables[0].commands = {
  remediation: 'Componente de Wazuh: no se actualiza automáticamente.',
  verification: 'rpm -q wazuh-agent',
};
r = run(protegido);
const pasoWazuh = r.plan.find((p) => p.paquete === 'wazuh-agent');
check('el paquete protegido conserva la guía del motor, no un comando',
  Boolean(pasoWazuh) && pasoWazuh.como.startsWith('Componente de Wazuh'),
  pasoWazuh ? pasoWazuh.como : 'no apareció en el plan');

// --- 5. Acción con campos faltantes -----------------------------------------
const roto = clone(base);
roto.actionables = [{ id: 'X', priority: 'P1', package: 'x', action: 'actualizar' }];
r = run(roto);
check('acción sin cves/hosts/commands no rompe', r.plan.length === 1);
check('comando ausente queda vacío', r.plan[0].como === '');
check('sin fecha de vencimiento, días = null', r.plan[0].dias_restantes === null);

// --- 6. Tope MAX_ACCIONES ---------------------------------------------------
const muchas = clone(base);
muchas.actionables = [];
for (let i = 0; i < 40; i += 1) {
  muchas.actionables.push(accion({ id: 'VM-' + i, priority: 'P2', risk: 60, package: 'pkg' + i }));
}
r = run(muchas);
check('el plan se corta en MAX_ACCIONES (25)', r.plan.length === 25, String(r.plan.length));
check('se informan las omitidas', r.resumen.acciones_omitidas === 15, String(r.resumen.acciones_omitidas));
check('el cuerpo menciona las omitidas', r.cuerpo.includes('15 acciones más'));

// --- 7. La prioridad del motor manda sobre todo lo demás --------------------
const orden = clone(base);
orden.actionables = [
  accion({ id: 'A', priority: 'P2', risk: 100, package: 'alto-riesgo', overdue: true,
           due_date: '2020-01-01', kev_count: 5, cves: [{ id: 'C1', kev_ransomware: true }],
           hosts: [{ name: 'h', criticality: 'alta' }] }),
  accion({ id: 'B', priority: 'P1', risk: 1, package: 'bajo-riesgo', hosts: [] }),
];
r = run(orden);
check('una P1 de riesgo bajo va antes que una P2 vencida y en KEV',
  r.plan[0].paquete === 'bajo-riesgo', r.plan[0].paquete);

// --- 8. KEV gana al riesgo más alto, dentro de la misma prioridad -----------
//     Con una suma de pesos esto se invertía: 200+40+2=242 perdía contra
//     100+50+95+20=265.
const kevVsRiesgo = clone(base);
kevVsRiesgo.actionables = [
  accion({ id: 'RISK', risk: 95, package: 'zz-riesgo-alto', previous_priority: 'P3',
           hosts: Array.from({ length: 10 }, (_, i) => ({ name: 'h' + i, criticality: 'alta' })) }),
  accion({ id: 'KEV', risk: 40, package: 'aa-kev', kev_count: 1,
           cves: [{ id: 'C', kev_ransomware: false }] }),
];
r = run(kevVsRiesgo);
check('KEV gana al riesgo más alto dentro de la misma prioridad',
  r.plan[0].paquete === 'aa-kev', r.plan[0].paquete + ' quedó primera');

// --- 9. Los niveles son estrictos: ransomware > KEV > criticidad alta -------
const niveles = clone(base);
niveles.actionables = [
  accion({ id: 'ALTA', risk: 99, package: 'c-alta', hosts: [{ name: 'h', criticality: 'alta' }] }),
  accion({ id: 'KEV', risk: 50, package: 'b-kev', kev_count: 1,
           cves: [{ id: 'C', kev_ransomware: false }] }),
  accion({ id: 'RANSOM', risk: 10, package: 'a-ransom', kev_count: 1,
           hosts: [{ name: 'h', criticality: 'baja' }], cves: [{ id: 'C', kev_ransomware: true }] }),
];
r = run(niveles);
check('niveles estrictos: ransomware > KEV > criticidad alta',
  r.plan.map((p) => p.paquete).join(',') === 'a-ransom,b-kev,c-alta',
  r.plan.map((p) => p.paquete).join(','));

// --- 10. Vencida gana a todo lo que está por debajo -------------------------
const vencidaGana = clone(base);
vencidaGana.actionables = [
  accion({ id: 'RANSOM', risk: 100, package: 'ransom', kev_count: 9,
           hosts: [{ name: 'h', criticality: 'alta' }], cves: [{ id: 'C', kev_ransomware: true }] }),
  accion({ id: 'OLD', risk: 1, package: 'vencida', overdue: true,
           due_date: '2020-01-01', hosts: [] }),
];
r = run(vencidaGana);
check('vencida gana a ransomware dentro de la misma prioridad',
  r.plan[0].paquete === 'vencida', r.plan[0].paquete);

// --- 11. Prioridad desconocida ----------------------------------------------
const raro = clone(base);
raro.actionables = [
  accion({ id: 'WEIRD', priority: 'PX', risk: 100, package: 'raro', hosts: [] }),
  accion({ id: 'OK', risk: 1, package: 'normal', hosts: [] }),
];
r = run(raro);
check('una prioridad desconocida va al final y no entra en el aviso',
  r.plan.length === 1 && r.plan[0].paquete === 'normal',
  r.plan.map((p) => p.paquete).join(','));

console.log('\n' + (fallos ? fallos + ' comprobación(es) FALLARON' : 'todas las comprobaciones pasaron'));
process.exit(fallos ? 1 : 0);
