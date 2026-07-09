// Test the browser parser + analyzer under Node against the synthetic .evtx
// files from make_evtx.py. Usage: node tests/test_parser.js <dir-with-evtx>
// Uses the streaming (Blob/slice) code path - the same one the worker uses.
'use strict';
const fs = require('fs');
const path = require('path');

const repo = path.join(__dirname, '..');
const Evtx = require(path.join(repo, 'web/evtx.js'));
const Analyzer = require(path.join(repo, 'web/analyzer.js'));

const dir = process.argv[2] || '.';
const rules = JSON.parse(fs.readFileSync(path.join(repo, 'rules.json'), 'utf8'));

let failures = 0;
function check(cond, msg) {
  if (cond) console.log('  ok:', msg);
  else { failures++; console.error('  FAIL:', msg); }
}

async function parseInto(analyzer, fileName) {
  const blob = new Blob([fs.readFileSync(path.join(dir, fileName))]);
  return Evtx.parseEvtxFile(blob, (rec) => {
    rec.source = fileName;
    analyzer.onRecord(rec);
  }, {});
}

(async () => {
  const analyzer = Analyzer.makeAnalyzer(rules);
  const s1 = await parseInto(analyzer, 'system.evtx');
  const s2 = await parseInto(analyzer, 'application.evtx');
  const result = analyzer.finish(s1.totalEvents + s2.totalEvents);

  console.log(`total=${result.totalEvents} problems=${result.problemEvents} ` +
    `findings=${result.findings.length} parseErrors=${s1.parseErrors + s2.parseErrors}`);

  // --- parsing basics ---
  check(s1.parseErrors === 0 && s2.parseErrors === 0, 'no parse errors');
  check(result.totalEvents === 25, `total events = 25 (got ${result.totalEvents})`);
  check(result.problemEvents === 21, `problem events = 21, info excluded (got ${result.problemEvents})`);

  // --- classic grouping / rules ---
  const disk = result.findings.find((f) => f.provider === 'disk' && f.eventId === 7);
  check(!!disk && disk.recognised && disk.severity === 'critical' && disk.count === 3,
    'disk/7 grouped, critical rule, count 3');
  check(!!disk && disk.channels.join(',') === 'System', 'disk/7 tagged with System channel');

  const scm = result.findings.find((f) => f.provider === 'Service Control Manager');
  const bd = scm ? Object.fromEntries(scm.breakdown) : {};
  check(!!scm && bd['Print Spooler'] === 3 && bd['Windows Update'] === 1,
    'SCM/7031 breakdown by service');

  const unknown = result.findings.find((f) => f.provider === 'FooBarDriver');
  check(!!unknown && !unknown.recognised && unknown.count === 2, 'unknown provider still reported');

  // --- personalized advice ---
  check(scm && scm.solutions[0].includes('Start with Print Spooler') && scm.solutions[0].includes('3 of the 4'),
    `SCM advice names the top culprit: ${scm && scm.solutions[0]}`);
  check(disk && disk.impact && disk.impact.includes('Back up'),
    'disk/7 has an impact-if-ignored line');
  check(Analyzer.formatFinding(disk).includes('If ignored:'),
    'impact renders in the report');
  const appGeneric = result.findings.find((f) => f.provider === 'Application Error' && !f.title.includes('ntdll'));
  check(!!appGeneric && appGeneric.solutions.some((s) => s.includes('badapp.exe')),
    'app-crash advice names the faulting app via {top}');

  // --- unknown-event heuristics ---
  const baz = result.findings.find((f) => f.provider === 'BazVolumeMgr');
  check(!!baz && baz.title.includes('(looks storage-related)'),
    `provider-name heuristic categorises BazVolumeMgr: ${baz && baz.title}`);
  check(!!baz && baz.solutions.some((s) => s.includes('CrystalDiskInfo')),
    'heuristic adds storage-specific steps');
  check(!!unknown && !unknown.title.includes('(looks'),
    'no false category for FooBarDriver');

  // --- multi-file / channels ---
  check(result.channels.join(',') === 'Application,System',
    `channels merged (got ${result.channels.join(',')})`);

  // --- keyword (dataContains) rule splits Application Error 1000 ---
  const appErr = result.findings.filter((f) => f.provider === 'Application Error' && f.eventId === 1000);
  check(appErr.length === 2, `Application Error 1000 split into 2 findings (got ${appErr.length})`);
  const ntdll = appErr.find((f) => f.title.includes('ntdll.dll'));
  const generic = appErr.find((f) => !f.title.includes('ntdll.dll'));
  check(!!ntdll && ntdll.count === 1, 'ntdll.dll keyword rule matched 1 crash');
  check(!!generic && generic.count === 2, 'generic crash rule matched the other 2');

  // --- noise tier sorts last ---
  const dcom = result.findings.find((f) => f.eventId === 10016);
  check(!!dcom && dcom.severity === 'noise', 'DCOM 10016 classified as noise');
  check(result.findings[result.findings.length - 1].severity === 'noise', 'noise sorts last');
  check(Analyzer.severityRank('noise') > Analyzer.severityRank('info'), 'noise ranks below info');

  // --- boot sessions & crash detection ---
  check(result.sessions.boots === 2, `2 boot sessions (got ${result.sessions.boots})`);
  check(result.crashes.length === 1, `1 unexpected shutdown (got ${result.crashes.length})`);
  const crash = result.crashes[0];
  if (crash) {
    check(crash.causes.length === 2, `Kernel-Power 41 + BugCheck 1001 merged into one crash (got ${crash.causes.length})`);
    check(crash.bugcheck.startsWith('0x0000009f'), `bugcheck code captured (got ${JSON.stringify(crash.bugcheck)})`);
    const ctx = crash.events.map((e) => `${e.provider}:${e.eventId}`);
    check(ctx.includes('storahci:129') && ctx.includes('disk:153'),
      `pre-crash context has the storage errors (got ${ctx.join(' ')})`);
    check(!ctx.some((c) => c.includes('Kernel-Power')), 'context excludes the post-boot marker itself');
  }

  // --- timeline ---
  const tl = result.timeline;
  check(!!tl && tl.buckets.length >= 2, 'timeline built');
  if (tl) {
    const sum = tl.buckets.reduce((a, b) => a + b.critical + b.error + b.warning, 0);
    check(sum === result.problemEvents, `timeline buckets sum to problem count (${sum})`);
    check(tl.buckets.some((b) => b.critical > 0), 'timeline has a critical bucket (Kernel-Power 41)');
  }

  // --- report ---
  const report = Analyzer.formatFullReport('system.evtx, application.evtx', result);
  check(report.includes('UNEXPECTED SHUTDOWNS'), 'report has crash section');
  check(report.includes('Boot sessions: 2'), 'report has session summary');
  check(report.includes('ntdll.dll'), 'report includes keyword finding');

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL TESTS PASSED');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
