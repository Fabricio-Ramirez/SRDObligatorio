/*
 * Priorización y propuesta de soluciones — script del nodo "Code" de n8n.
 *
 * Reemplaza a la IA local (Ollama): en lugar de pedirle el texto a un modelo de
 * lenguaje, este script arma de forma determinística el plan de trabajo que
 * recibe el equipo de infraestructura.
 *
 * Entrada : un único item con el informe del motor (data/latest.json), tal
 *           como lo entrega el nodo "Leer informe".
 * Salida  : un único item con "asunto", "cuerpo" (texto del aviso) y el plan
 *           estructurado ("plan", "ventanas", "servidores", "resumen") para
 *           que otros nodos lo puedan usar sin volver a calcular nada.
 *
 * Dos reglas de diseño, importantes para que el panel, el CSV, las alertas del
 * SIEM y este aviso nunca se contradigan:
 *
 *  1. Las prioridades P1-P4 las calcula el motor (prioritize.py) con
 *     CVSS + EPSS + KEV + criticidad del servidor. Este script NO las
 *     recalcula: sólo ordena dentro de cada prioridad (triaje) y explica.
 *     El orden es lexicográfico, no una suma de pesos: ver claveTriaje.
 *  2. Los comandos NO se construyen acá. Se reusan tal cual los publica el
 *     motor (a.commands.* y remediation.hosts[].commands.*), que ya validan
 *     el nombre del paquete y la versión y protegen los componentes wazuh-*.
 *     Armar un comando con un nombre de paquete venido del indexer saltearía
 *     esas validaciones.
 *
 * Modo del nodo: "Run Once for All Items" (runOnceForAllItems).
 */

// ---------------------------------------------------------------------------
// Parámetros ajustables desde el editor visual de n8n (no hace falta tocar
// nada más para cambiar el alcance del aviso).
// ---------------------------------------------------------------------------
const PRIORIDADES_AVISO = ['P1', 'P2']; // prioridades que entran en el aviso
const MAX_ACCIONES = 25; // tope de acciones detalladas en el correo
const URL_PANEL = 'https://<servidor-wazuh>:8443/'; // completar con el nombre real

// Ventanas de mantenimiento sugeridas. El plazo que se menciona es el SLA del
// motor para esa prioridad (ver "scoring.sla_days" en el informe).
const VENTANAS = [
  { clave: 'emergencia', titulo: 'Ventana de emergencia', prioridades: ['P1'] },
  { clave: 'semanal', titulo: 'Ventana semanal', prioridades: ['P2'] },
  { clave: 'planificada', titulo: 'Ventana planificada', prioridades: ['P3', 'P4'] },
];

const ORDEN_PRIORIDAD = { P1: 0, P2: 1, P3: 2, P4: 3 };

// ---------------------------------------------------------------------------
// Entrada
// ---------------------------------------------------------------------------
const informe = $input.first().json || {};
const acciones = Array.isArray(informe.actionables) ? informe.actionables : [];
const kpis = informe.kpis || {};
const sla = (informe.scoring || {}).sla_days || {};
const planRemediacion = informe.remediation || {};

/** Fecha del informe, usada para contar los días que faltan para cada plazo. */
function fechaInforme() {
  const fecha = new Date(informe.generated_at || Date.now());
  return isNaN(fecha.getTime()) ? new Date() : fecha;
}

/** "2026-11-18T19:57:18-0300" -> "2026-11-18 19:57". */
function fechaLegible(iso) {
  const texto = String(iso || '');
  if (texto.length < 16) return texto;
  return texto.slice(0, 10) + ' ' + texto.slice(11, 16);
}

/** Riesgo siempre con un decimal, como lo muestra el panel. */
function riesgo(valor) {
  return (Number(valor) || 0).toFixed(1);
}

/** Días hasta una fecha "YYYY-MM-DD" (negativo = ya venció). */
function diasHasta(fechaISO) {
  if (!fechaISO) return null;
  const vence = new Date(String(fechaISO) + 'T00:00:00Z');
  if (isNaN(vence.getTime())) return null;
  const hoy = fechaInforme();
  const hoyUTC = Date.UTC(hoy.getUTCFullYear(), hoy.getUTCMonth(), hoy.getUTCDate());
  return Math.round((vence.getTime() - hoyUTC) / 86400000);
}

// ---------------------------------------------------------------------------
// 1. Triaje: en qué orden conviene atacar las acciones.
//
// Criterios en orden estricto de desempate (el primero que difiere decide, los
// siguientes no lo pueden compensar):
//
//   1. prioridad del motor (P1 antes que P2, siempre)
//   2. vencidas (fuera de SLA, se arrastran de informes anteriores)
//   3. usadas en campañas de ransomware
//   4. explotación activa confirmada (CISA KEV)
//   5. afectan servidores de criticidad alta
//   6. escalaron de prioridad desde la corrida anterior
//   7. mayor riesgo
//   8. más servidores afectados
//   9. nombre del paquete (para que el orden sea estable)
//
// Se usa una clave lexicográfica, no una suma de pesos: con una suma, varios
// criterios bajos podrían superar a uno alto (por ejemplo una acción sin KEV
// pero de riesgo alto adelantándose a una que CISA marca como explotada).
// ---------------------------------------------------------------------------
function claveTriaje(a) {
  const cves = Array.isArray(a.cves) ? a.cves : [];
  const hosts = Array.isArray(a.hosts) ? a.hosts : [];
  const orden = ORDEN_PRIORIDAD[a.priority];
  const escalada =
    a.previous_priority && ORDEN_PRIORIDAD[a.previous_priority] > ORDEN_PRIORIDAD[a.priority];
  // En cada posición, menor va primero.
  return [
    orden === undefined ? 9 : orden,
    a.overdue ? 0 : 1,
    cves.some((c) => c.kev_ransomware) ? 0 : 1,
    (a.kev_count || 0) > 0 ? 0 : 1,
    hosts.some((h) => h.criticality === 'alta') ? 0 : 1,
    escalada ? 0 : 1,
    -(Number(a.risk) || 0),
    -hosts.length,
  ];
}

function ordenar(lista) {
  return lista.slice().sort((x, y) => {
    const kx = claveTriaje(x);
    const ky = claveTriaje(y);
    for (let i = 0; i < kx.length; i += 1) {
      if (kx[i] !== ky[i]) return kx[i] - ky[i];
    }
    return String(x.package).localeCompare(String(y.package));
  });
}

// ---------------------------------------------------------------------------
// 2. Solución propuesta para cada acción.
//
// "que": qué hay que hacer, en una línea.
// "como" / "verificar": los comandos del motor, sin modificar.
// "impacto": qué le pasa al servicio al aplicarlo.
// "por_que": las razones con las que el motor le puso esa prioridad.
// ---------------------------------------------------------------------------
function queHacer(a) {
  const servidores = (Array.isArray(a.hosts) ? a.hosts : []).map((h) => h.name).join(', ');
  const donde = servidores ? ` en ${servidores}` : '';
  if (a.action === 'actualizar') {
    const version = a.fixed_version ? ` a la versión ${a.fixed_version} o posterior` : '';
    return `Actualizar el paquete ${a.package}${version}${donde}.`;
  }
  if (a.action === 'mitigar') {
    return `Mitigar ${a.package}${donde}: todavía no hay versión corregida publicada.`;
  }
  return `Revisar ${a.package}${donde}: el estado del parche no es concluyente, confirmar con el aviso del proveedor.`;
}

function impacto(a) {
  if (a.reboot_required) {
    return 'Requiere reiniciar el servidor (paquete de base del sistema): agendar la ventana con el responsable del servicio.';
  }
  if (a.action === 'mitigar') {
    return 'Sin paquete que actualizar: el impacto depende de la mitigación que se elija (deshabilitar el módulo, restringir el acceso por firewall).';
  }
  return 'No requiere reiniciar el servidor; sí reiniciar los servicios que usen el paquete (ver "needs-restarting -s", del paquete dnf-utils).';
}

function solucion(a, paso) {
  const cves = Array.isArray(a.cves) ? a.cves : [];
  const dias = diasHasta(a.due_date);
  return {
    paso: paso,
    id: a.id,
    prioridad: a.priority,
    riesgo: a.risk,
    paquete: a.package,
    que: queHacer(a),
    // Comandos del motor, sin modificar: ya validó el nombre del paquete.
    como: (a.commands || {}).remediation || '',
    verificar: (a.commands || {}).verification || '',
    impacto: impacto(a),
    por_que: Array.isArray(a.reasons) ? a.reasons : [],
    servidores: (Array.isArray(a.hosts) ? a.hosts : []).map((h) => h.name),
    cves: cves.map((c) => c.id),
    kev: (a.kev_count || 0) > 0,
    ransomware: cves.some((c) => c.kev_ransomware),
    requiere_reinicio: Boolean(a.reboot_required),
    vence: a.due_date || '',
    dias_restantes: dias,
    vencida: Boolean(a.overdue),
    escalada: Boolean(
      a.previous_priority && ORDEN_PRIORIDAD[a.previous_priority] > ORDEN_PRIORIDAD[a.priority],
    ),
  };
}

// ---------------------------------------------------------------------------
// 3. Armado del plan
// ---------------------------------------------------------------------------
const seleccionadas = ordenar(acciones.filter((a) => PRIORIDADES_AVISO.indexOf(a.priority) !== -1));
const plan = seleccionadas.slice(0, MAX_ACCIONES).map((a, i) => solucion(a, i + 1));
const omitidas = Math.max(0, seleccionadas.length - plan.length);

// Ventanas de mantenimiento: dentro de cada una se separa lo que se puede
// aplicar en caliente de lo que obliga a reiniciar, para juntar los reinicios.
const ventanas = VENTANAS.map((v) => {
  const dentro = ordenar(acciones.filter((a) => v.prioridades.indexOf(a.priority) !== -1));
  const plazos = v.prioridades.map((p) => sla[p]).filter((d) => typeof d === 'number');
  return {
    clave: v.clave,
    titulo: v.titulo,
    prioridades: v.prioridades,
    plazo_dias: plazos.length ? Math.min.apply(null, plazos) : null,
    total: dentro.length,
    // Las tres categorías parten el total sin solaparse.
    con_reinicio: dentro.filter((a) => a.reboot_required).map((a) => a.package),
    sin_reinicio: dentro
      .filter((a) => !a.reboot_required && a.action === 'actualizar')
      .map((a) => a.package),
    sin_parche: dentro
      .filter((a) => !a.reboot_required && a.action !== 'actualizar')
      .map((a) => a.package),
  };
}).filter((v) => v.total > 0);

// Vista por servidor: se reusan los comandos agrupados que ya publicó el motor.
const servidores = (Array.isArray(planRemediacion.hosts) ? planRemediacion.hosts : [])
  .filter((h) => (h.total || 0) > 0)
  .map((h) => {
    const paquetes = h.packages || {};
    return {
      servidor: h.name,
      so: h.os || '',
      total: h.total || 0,
      P1: paquetes.P1 || [],
      P2: paquetes.P2 || [],
      comando: (h.commands || {}).P1 || (h.commands || {})['hasta-P2'] || '',
      comando_hasta_P2: (h.commands || {})['hasta-P2'] || '',
      ansible_simular: (h.ansible || {}).simular || '',
      ansible_aplicar: (h.ansible || {}).aplicar || '',
    };
  })
  .sort((x, y) => y.P1.length - x.P1.length || y.total - x.total);

const porPrioridad = kpis.actions || {};
const resumen = {
  generado: informe.generated_at || '',
  origen: informe.source || '',
  cve_unicas: kpis.unique_cves || 0,
  servidores_afectados: kpis.hosts_affected || 0,
  kev: kpis.kev || 0,
  vencidas: kpis.overdue || 0,
  sin_parche: kpis.no_fix || 0,
  por_prioridad: porPrioridad,
  acciones_en_aviso: plan.length,
  acciones_omitidas: omitidas,
};

// ---------------------------------------------------------------------------
// 4. Texto del aviso
// ---------------------------------------------------------------------------
function plural(n, singular, plural_) {
  return n === 1 ? singular : plural_;
}

function lineaPlazo(p) {
  if (p.vencida) return `VENCIDA el ${p.vence}`;
  if (p.dias_restantes === null) return 'sin plazo calculado';
  if (p.dias_restantes === 0) return `vence hoy (${p.vence})`;
  return `vence el ${p.vence} (${p.dias_restantes} ${plural(p.dias_restantes, 'día', 'días')})`;
}

const lineas = [];
lineas.push(`Plan de remediación priorizado — informe del ${fechaLegible(resumen.generado) || 's/d'}`);
lineas.push('');
lineas.push(
  `Se detectaron ${resumen.cve_unicas} ${plural(resumen.cve_unicas, 'vulnerabilidad única', 'vulnerabilidades únicas')} ` +
    `en ${resumen.servidores_afectados} ${plural(resumen.servidores_afectados, 'servidor', 'servidores')}. ` +
    `Acciones: P1=${porPrioridad.P1 || 0}, P2=${porPrioridad.P2 || 0}, P3=${porPrioridad.P3 || 0}, P4=${porPrioridad.P4 || 0}. ` +
    `${resumen.kev} ${plural(resumen.kev, 'CVE figura', 'CVE figuran')} en el catálogo KEV de CISA (explotación activa). ` +
    `${resumen.vencidas} ${plural(resumen.vencidas, 'acción está', 'acciones están')} fuera de plazo.`,
);

if (!plan.length) {
  lineas.push('');
  lineas.push(
    `No hay acciones ${PRIORIDADES_AVISO.join(' ni ')} pendientes. No se requiere intervención esta semana.`,
  );
} else {
  lineas.push('');
  lineas.push(`ORDEN DE TRABAJO SUGERIDO (${plan.length} ${plural(plan.length, 'acción', 'acciones')})`);
  lineas.push('Dentro de cada prioridad se ordena por: vencidas, explotación activa, servidores críticos y riesgo.');
  plan.forEach((p) => {
    const etiquetas = [];
    if (p.vencida) etiquetas.push('VENCIDA');
    if (p.ransomware) etiquetas.push('RANSOMWARE');
    else if (p.kev) etiquetas.push('KEV');
    if (p.escalada) etiquetas.push('ESCALÓ DE PRIORIDAD');
    if (p.requiere_reinicio) etiquetas.push('REINICIO');
    lineas.push('');
    lineas.push(
      `${p.paso}. [${p.prioridad}] ${p.paquete} — riesgo ${riesgo(p.riesgo)}${etiquetas.length ? ' — ' + etiquetas.join(' · ') : ''}`,
    );
    lineas.push(`   Qué: ${p.que}`);
    lineas.push(`   Cómo: ${p.como}`);
    lineas.push(`   Verificar: ${p.verificar}`);
    lineas.push(`   Impacto: ${p.impacto}`);
    lineas.push(`   Plazo: ${lineaPlazo(p)}`);
    if (p.por_que.length) lineas.push(`   Por qué esta prioridad: ${p.por_que.join('; ')}`);
    if (p.cves.length) lineas.push(`   CVE: ${p.cves.join(', ')}`);
  });
  if (omitidas > 0) {
    lineas.push('');
    lineas.push(`(+ ${omitidas} ${plural(omitidas, 'acción', 'acciones')} más del mismo alcance: ver el panel.)`);
  }
}

if (ventanas.length) {
  lineas.push('');
  lineas.push('VENTANAS DE MANTENIMIENTO SUGERIDAS');
  ventanas.forEach((v) => {
    const plazo = v.plazo_dias ? ` — plazo ${v.plazo_dias} días` : '';
    lineas.push('');
    lineas.push(`${v.titulo} (${v.prioridades.join('/')}${plazo}): ${v.total} ${plural(v.total, 'acción', 'acciones')}`);
    if (v.sin_reinicio.length) lineas.push(`   Se actualizan en caliente: ${v.sin_reinicio.join(', ')}`);
    if (v.con_reinicio.length) {
      lineas.push(`   Requieren reinicio (agrupar en un solo reinicio por servidor): ${v.con_reinicio.join(', ')}`);
    }
    if (v.sin_parche.length) {
      lineas.push(`   Sin versión corregida, requieren mitigación o revisión: ${v.sin_parche.join(', ')}`);
    }
  });
}

if (servidores.length) {
  lineas.push('');
  lineas.push('POR SERVIDOR (comandos generados por el motor)');
  servidores.forEach((s) => {
    lineas.push('');
    lineas.push(`${s.servidor}${s.so ? ' (' + s.so + ')' : ''} — ${s.total} ${plural(s.total, 'acción', 'acciones')}`);
    if (s.P1.length) lineas.push(`   P1: ${s.P1.join(', ')}`);
    if (s.P2.length) lineas.push(`   P2: ${s.P2.join(', ')}`);
    if (s.comando) lineas.push(`   Comando (P1): ${s.comando}`);
    if (s.ansible_simular) lineas.push(`   Simular con Ansible: ${s.ansible_simular}`);
  });
}

const analisis = informe.analysis || {};
if (analisis.summary) {
  lineas.push('');
  lineas.push('RESUMEN DEL MOTOR');
  lineas.push(analisis.summary);
}

const avisos = Array.isArray(informe.warnings) ? informe.warnings : [];
if (avisos.length) {
  lineas.push('');
  lineas.push('AVISOS DE LA CORRIDA');
  avisos.forEach((w) => lineas.push(`   - ${w}`));
}

lineas.push('');
lineas.push(`Detalle completo, CSV y playbook de Ansible en el panel: ${URL_PANEL}`);
lineas.push('La plataforma no ejecuta nada en los servidores: los cambios los aplica el equipo desde el bastión.');

const p1 = plan.filter((p) => p.prioridad === 'P1').length;
const p2 = plan.filter((p) => p.prioridad === 'P2').length;
const vencidas = plan.filter((p) => p.vencida).length;
const asunto = plan.length
  ? `[Vulnerabilidades] ${p1} ${plural(p1, 'acción', 'acciones')} P1 y ${p2} P2 pendientes` +
    (vencidas ? ` — ${vencidas} fuera de plazo` : '')
  : '[Vulnerabilidades] Sin acciones P1/P2 pendientes';

return [
  {
    json: {
      asunto: asunto,
      cuerpo: lineas.join('\n'),
      resumen: resumen,
      plan: plan,
      ventanas: ventanas,
      servidores: servidores,
    },
  },
];
