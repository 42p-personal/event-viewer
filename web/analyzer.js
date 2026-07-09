// Analysis engine shared by the page and the worker (and Node for tests).
// Groups error/warning events into findings via rules.json, and additionally:
//  - segments the log into boot sessions and detects unexpected shutdowns
//    (Kernel-Power 41, EventLog 6008, BugCheck 1001) with the tail of events
//    that preceded each crash
//  - collects timestamps for a severity timeline histogram
//  - merges multiple log files, tagging findings with their channel
(function (global) {
  'use strict';

  const MAX_SAMPLES = 3;
  const MAX_SAMPLE_ATTEMPTS = 10;
  const MAX_BREAKDOWN_KEYS = 200;
  const TIMELINE_CAP = 500000;          // timestamps kept for the histogram
  const CONTEXT_MAX_ENTRIES = 400;      // rolling pre-crash buffer per file
  const CONTEXT_MAX_AGE_MS = 600000;    // keep 10 min of history in the buffer
  const CONTEXT_WINDOW_MS = 180000;     // show up to 3 min before the crash
  const CONTEXT_SHOWN = 25;             // max events per crash card
  const CRASH_MERGE_MS = 300000;        // markers within 5 min = one crash

  // Markers are logged at the boot AFTER the crash, so the rolling buffer
  // holds the previous session's tail when we encounter one. Events closer
  // than this to the marker belong to the new boot, not the crash.
  const CRASH_GAP_MS = 20000;

  const CRASH_MARKERS = [
    { provider: 'microsoft-windows-kernel-power', id: 41, cause: 'Unexpected loss of power or hard reset (Kernel-Power 41)' },
    { provider: 'eventlog', id: 6008, cause: 'Unexpected shutdown (EventLog 6008)' },
    { provider: 'microsoft-windows-wer-systemerrorreporting', id: 1001, cause: 'Blue screen / bugcheck (Event 1001)' },
    { provider: 'bugcheck', id: 1001, cause: 'Blue screen / bugcheck (Event 1001)' },
  ];

  function severityRank(sev) {
    switch ((sev || '').toLowerCase()) {
      case 'critical': return 0;
      case 'high': return 1;
      case 'medium': return 2;
      case 'low': return 3;
      case 'info': return 4;
      case 'noise': return 5;
      default: return 2;
    }
  }

  // Rules are matched per event, first match in file order wins - put
  // specific rules (e.g. with dataContains) before generic ones.
  function ruleMatches(rule, provider, eventId, properties) {
    if (eventId !== rule.eventId) return false;
    const p = (provider || '').toLowerCase();
    const providerOk = p === (rule.provider || '').toLowerCase() ||
      (rule.altProviders || []).some((a) => p === a.toLowerCase());
    if (!providerOk) return false;
    if (rule.dataContains && rule.dataContains.length) {
      const hay = (properties || []).map((v) => String(v ?? '').toLowerCase());
      return rule.dataContains.some((kw) => {
        const k = kw.toLowerCase();
        return hay.some((h) => h.includes(k));
      });
    }
    return true;
  }

  // ---------------------------------------------------------------- helpers
  // Fill {top}/{topCount}/{count}/{provider}/{eventId} placeholders in rule
  // text with the finding's own data, so advice names the actual culprit.

  function fillPlaceholders(text, f, lenient) {
    const top = f.breakdown && f.breakdown.length ? f.breakdown[0][0] : null;
    const genericTop = 'the affected ' + (f.breakdownLabel ? f.breakdownLabel.toLowerCase() : 'item');
    const map = {
      '{top}': top !== null ? top : (lenient ? genericTop : null),
      '{topCount}': top !== null ? String(f.breakdown[0][1]) : null,
      '{count}': String(f.count),
      '{provider}': f.provider,
      '{eventId}': String(f.eventId),
      '{breakdownLabel}': f.breakdownLabel || null,
    };
    let unresolved = false;
    const out = text.replace(/\{top\}|\{topCount\}|\{count\}|\{provider\}|\{eventId\}|\{breakdownLabel\}/g, (m) => {
      if (map[m] === null || map[m] === undefined) { unresolved = true; return m; }
      return map[m];
    });
    return unresolved ? null : out; // strict mode: drop lines whose data we don't have
  }

  function personalize(f) {
    // cause/impact always render (generic fallback); solution lines with
    // unavailable data are dropped instead of showing raw placeholders.
    f.cause = fillPlaceholders(f.cause, f, true) || f.cause;
    if (f.impact) f.impact = fillPlaceholders(f.impact, f, true) || f.impact;
    f.solutions = f.solutions.map((s) => fillPlaceholders(s, f, false)).filter((s) => s !== null);
    // When we know the top culprit, make "start here" the literal first step.
    const top = f.breakdown && f.breakdown.length ? f.breakdown[0] : null;
    if (top && top[0] !== '?' && f.count > top[1]) {
      f.solutions.unshift(
        `Start with ${top[0]} - it accounts for ${nf.format(top[1])} of the ${nf.format(f.count)} occurrences (${f.breakdownLabel}).`);
    }
  }

  // Provider-name heuristics: even without a specific rule, the provider
  // usually reveals which subsystem an event belongs to.
  const PROVIDER_HINTS = [
    { match: /disk|stor|nvme|ahci|raid|volsnap|ntfs|volume|partmgr|volmgr|iastor/i, label: 'storage',
      cause: 'The provider name suggests this is a storage (disk/SSD/controller) event.',
      steps: [
        'Check the drive health with CrystalDiskInfo (SMART attributes: Reallocated Sectors, Pending Sectors).',
        'Back up important data before troubleshooting further - storage errors can escalate.',
        "Run 'chkdsk /r' on the affected volume from an elevated prompt." ] },
    { match: /display|nvlddmkm|amdkmdag|igfx|dxgkrnl|graphics|nvhda/i, label: 'graphics',
      cause: 'The provider name suggests this involves the graphics card or display driver.',
      steps: [
        'Update the GPU driver from NVIDIA/AMD/Intel directly (not Windows Update).',
        'If it started after a driver update, roll back via Device Manager > Display adapters.',
        'Check GPU temperatures under load (HWiNFO) - overheating causes driver resets.' ] },
    { match: /tcpip|dhcp|dns|netbt|wlan|netwtw|e1dexpress|rtl8|winhttp|network|lldp|smbclient|smbserver/i, label: 'network',
      cause: 'The provider name suggests this is a networking event.',
      steps: [
        'Update the network adapter driver from the PC or motherboard vendor.',
        "Try 'ipconfig /flushdns' and 'netsh winsock reset' from an elevated prompt, then reboot.",
        'If it correlates with drops/disconnects, test with a cable instead of Wi-Fi (or vice versa) to isolate.' ] },
    { match: /usb|hidclass|bthusb|bluetooth|kernel-pnp|pnp/i, label: 'USB/device',
      cause: 'The provider name suggests a USB or plug-and-play device issue.',
      steps: [
        'Note which device the event data names, then update or reinstall its driver.',
        'Try a different USB port (rear motherboard ports are more reliable than front-panel or hubs).',
        'If it repeats for the same device, test the device on another PC to rule out the device itself.' ] },
    { match: /print|spool/i, label: 'printing',
      cause: 'The provider name suggests this is a printing subsystem event.',
      steps: [
        'Clear the print queue: stop the Print Spooler service, delete C:\\Windows\\System32\\spool\\PRINTERS\\*, start it again.',
        'Reinstall the printer with the newest driver from the manufacturer.' ] },
    { match: /defender|antimalware|security/i, label: 'security',
      cause: 'The provider name suggests this comes from security or antivirus software.',
      steps: [
        'Open Windows Security > Protection history and review what happened.',
        'Run a Full scan if anything looks suspicious.' ] },
    { match: /update|wuau|servicing|installer|msi/i, label: 'updates/installer',
      cause: 'The provider name suggests this relates to Windows Update or a software installer.',
      steps: [
        'Run Settings > Windows Update > Retry, then the built-in Windows Update troubleshooter.',
        "If updates fail repeatedly: 'dism /online /cleanup-image /restorehealth' then 'sfc /scannow' from an elevated prompt." ] },
    { match: /power|acpi|battery|thermal/i, label: 'power/thermal',
      cause: 'The provider name suggests a power management or thermal event.',
      steps: [
        'Check Power Options - aggressive power saving causes many device dropouts.',
        'On desktops: verify the PSU is adequate; on laptops: check the battery report (powercfg /batteryreport).' ] },
    { match: /\.net|clr|runtime/i, label: 'application runtime',
      cause: 'The provider name suggests an application runtime error (a program, not Windows itself).',
      steps: [
        'The sample data usually names the application - update or reinstall it.',
        'Install the latest .NET runtime from Microsoft if several apps are affected.' ] },
  ];

  function unknownAdvice(provider, eventId, level) {
    const levelName = level === 1 ? 'critical' : level === 2 ? 'error' : 'warning';
    const hint = PROVIDER_HINTS.find((h) => h.match.test(provider));
    const cause = hint
      ? `This ${levelName} event isn't in the rules database, but it can still be narrowed down: ${hint.cause}`
      : `This ${levelName} event isn't in the rules database, so there's no specific explanation - but the details below still narrow it down.`;
    const steps = [
      'Read the sample event data below - it often states the problem directly (file paths, device names, error codes).',
      ...(hint ? hint.steps : []),
      `Search the web for: ${provider} event ${eventId}`,
      'If it lines up with a symptom you\'re seeing, note when it occurs (see First/Last seen and the timeline) and what changed on the machine around that time.',
    ];
    return { cause, steps, category: hint ? hint.label : null };
  }

  function sampleFromRecord(rec) {
    if (!rec.properties.length) return '';
    const parts = rec.properties.map((v, i) => {
      const name = rec.propNames[i];
      const val = v === null || v === undefined || v === '' ? '?' : String(v);
      return name ? name + ' = ' + val : val;
    });
    return 'Event data: ' + parts.join(' | ');
  }

  function shortSummary(rec) {
    const s = rec.properties.filter((v) => v !== null && v !== undefined && v !== '').join(' | ');
    return s.length > 140 ? s.slice(0, 137) + '...' : s;
  }

  function makeAnalyzer(rules) {
    const groups = new Map();
    let problems = 0;
    let boots = 0;
    const channels = new Set();
    const timeline = { ts: [], lvl: [], dropped: 0 };
    const buffers = new Map();   // source file -> rolling pre-crash buffer
    const crashes = [];

    // eventId -> rule indexes, so per-record matching stays cheap.
    const rulesById = new Map();
    rules.forEach((r, i) => {
      if (!rulesById.has(r.eventId)) rulesById.set(r.eventId, []);
      rulesById.get(r.eventId).push(i);
    });

    function bufferFor(source) {
      let b = buffers.get(source);
      if (!b) { b = []; buffers.set(source, b); }
      return b;
    }

    function recordCrash(marker, rec, t) {
      const existing = crashes.find((c) => Math.abs(c.time - t) < CRASH_MERGE_MS && c.source === (rec.source || ''));
      const bugcheck = marker.id === 1001 && rec.properties.length
        ? String(rec.properties[0] ?? '').trim() : '';
      if (existing) {
        if (!existing.causes.includes(marker.cause)) existing.causes.push(marker.cause);
        if (bugcheck && !existing.bugcheck) existing.bugcheck = bugcheck;
        return;
      }
      const buf = bufferFor(rec.source || '');
      const eligible = buf.filter((e) => e.t <= t - CRASH_GAP_MS);
      let events = [];
      if (eligible.length) {
        const tail = eligible[eligible.length - 1].t;
        events = eligible.filter((e) => e.t >= tail - CONTEXT_WINDOW_MS).slice(-CONTEXT_SHOWN);
      }
      crashes.push({
        time: t,
        causes: [marker.cause],
        bugcheck,
        source: rec.source || '',
        channel: rec.channel || '',
        events,
      });
    }

    function onRecord(rec) {
      const provider = rec.provider || '(unknown provider)';
      const pl = provider.toLowerCase();
      if (rec.channel) channels.add(rec.channel);

      // Boot session boundary: "The Event log service was started."
      if (pl === 'eventlog' && rec.eventId === 6005) boots++;

      const t = rec.time ? rec.time.getTime() : null;
      if (t !== null) {
        const marker = CRASH_MARKERS.find((m) => m.id === rec.eventId && m.provider === pl);
        if (marker) recordCrash(marker, rec, t);
      }

      // Level: 1=Critical, 2=Error, 3=Warning, 4=Info, 0=LogAlways
      const level = rec.level == null ? 4 : rec.level;
      if (level === 0 || level > 3) return; // info-level: markers only
      problems++;

      if (t !== null) {
        if (timeline.ts.length < TIMELINE_CAP) { timeline.ts.push(t); timeline.lvl.push(level); }
        else timeline.dropped++;

        const buf = bufferFor(rec.source || '');
        buf.push({ t, level, provider, eventId: rec.eventId, summary: shortSummary(rec) });
        if (buf.length > CONTEXT_MAX_ENTRIES) buf.splice(0, buf.length - CONTEXT_MAX_ENTRIES);
        while (buf.length && buf[0].t < t - CONTEXT_MAX_AGE_MS) buf.shift();
      }

      const candidates = rulesById.get(rec.eventId);
      let rIdx = -1;
      if (candidates) {
        for (const i of candidates) {
          if (ruleMatches(rules[i], provider, rec.eventId, rec.properties)) { rIdx = i; break; }
        }
      }

      const key = rIdx + '|' + provider + '|' + rec.eventId;
      let agg = groups.get(key);
      if (!agg) {
        agg = {
          provider, eventId: rec.eventId, count: 0, level,
          first: null, last: null,
          rule: rIdx >= 0 ? rules[rIdx] : null,
          samples: [], sampleAttempts: 0,
          breakdown: new Map(), breakdownOverflow: 0,
          channels: new Set(),
        };
        groups.set(key, agg);
      }
      agg.count++;
      if (level < agg.level) agg.level = level;
      if (rec.channel || rec.source) agg.channels.add(rec.channel || rec.source);

      if (rec.time) {
        if (!agg.first || rec.time < agg.first) agg.first = rec.time;
        if (!agg.last || rec.time > agg.last) agg.last = rec.time;
      }

      if (agg.samples.length < MAX_SAMPLES && agg.sampleAttempts < MAX_SAMPLE_ATTEMPTS) {
        agg.sampleAttempts++;
        const msg = sampleFromRecord(rec);
        if (msg && !agg.samples.includes(msg)) agg.samples.push(msg);
      }

      const props = agg.rule && agg.rule.breakdownProps;
      if (props && props.length) {
        const key2 = props
          .map((p) => (p.index < rec.properties.length ? String(rec.properties[p.index] ?? '?') : '?'))
          .join(' / ');
        if (agg.breakdown.has(key2)) agg.breakdown.set(key2, agg.breakdown.get(key2) + 1);
        else if (agg.breakdown.size < MAX_BREAKDOWN_KEYS) agg.breakdown.set(key2, 1);
        else agg.breakdownOverflow++;
      }
    }

    function buildTimeline() {
      const n = timeline.ts.length;
      if (n === 0) return null;
      let min = Infinity, max = -Infinity;
      for (let i = 0; i < n; i++) {
        if (timeline.ts[i] < min) min = timeline.ts[i];
        if (timeline.ts[i] > max) max = timeline.ts[i];
      }
      const range = Math.max(max - min, 1);
      const bucketMs = Math.max(60000, Math.ceil(range / 100));
      const nBuckets = Math.max(1, Math.ceil(range / bucketMs) + 1);
      const buckets = Array.from({ length: nBuckets }, () => ({ critical: 0, error: 0, warning: 0 }));
      for (let i = 0; i < n; i++) {
        const b = buckets[Math.min(Math.floor((timeline.ts[i] - min) / bucketMs), nBuckets - 1)];
        if (timeline.lvl[i] === 1) b.critical++;
        else if (timeline.lvl[i] === 2) b.error++;
        else b.warning++;
      }
      return { start: min, bucketMs, buckets, dropped: timeline.dropped };
    }

    function finish(totalEvents) {
      const findings = [];
      for (const agg of groups.values()) {
        const base = {
          provider: agg.provider,
          eventId: agg.eventId,
          count: agg.count,
          firstSeen: agg.first,
          lastSeen: agg.last,
          channels: [...agg.channels].sort(),
          samples: agg.samples,
        };
        if (agg.rule) {
          const f = Object.assign(base, {
            recognised: true,
            severity: agg.rule.severity || 'medium',
            title: agg.rule.title,
            cause: agg.rule.cause,
            impact: agg.rule.impact || '',
            solutions: agg.rule.solutions || [],
            breakdown: [...agg.breakdown.entries()].sort((a, b) => b[1] - a[1]),
            breakdownLabel: (agg.rule.breakdownProps || []).map((p) => p.name).join(' / '),
            breakdownOverflow: agg.breakdownOverflow,
          });
          personalize(f);
          findings.push(f);
        } else {
          const levelName = agg.level === 1 ? 'critical' : agg.level === 2 ? 'error' : 'warning';
          const severity = agg.level === 1 ? 'high' : agg.level === 2 ? 'medium' : 'low';
          const advice = unknownAdvice(agg.provider, agg.eventId, agg.level);
          findings.push(Object.assign(base, {
            recognised: false,
            severity,
            title: `Unrecognised ${levelName} event from ${agg.provider}` +
              (advice.category ? ` (looks ${advice.category}-related)` : ''),
            cause: advice.cause,
            impact: '',
            solutions: advice.steps,
            breakdown: [],
            breakdownLabel: '',
            breakdownOverflow: 0,
          }));
        }
      }

      findings.sort((a, b) => {
        const c = severityRank(a.severity) - severityRank(b.severity);
        return c !== 0 ? c : b.count - a.count;
      });

      crashes.sort((a, b) => b.time - a.time);

      return {
        totalEvents,
        problemEvents: problems,
        findings,
        crashes,
        sessions: { boots, unexpectedShutdowns: crashes.length },
        timeline: buildTimeline(),
        channels: [...channels].sort(),
      };
    }

    return { onRecord, finish };
  }

  // ------------------------------------------------------- report formatting

  const nf = new Intl.NumberFormat('en-GB');

  function fmtDate(d, withSeconds) {
    if (!d) return '';
    if (typeof d === 'number') d = new Date(d);
    const p = (n, w = 2) => String(n).padStart(w, '0');
    let s = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
    if (withSeconds) s += ':' + p(d.getSeconds());
    return s;
  }

  function formatFinding(f) {
    const lines = [];
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    let meta = `Provider: ${f.provider}    Event ID: ${f.eventId}    Occurrences: ${nf.format(f.count)}`;
    if (f.channels && f.channels.length) meta += `    Log: ${f.channels.join(', ')}`;
    lines.push(meta);
    if (f.firstSeen || f.lastSeen)
      lines.push(`First seen: ${fmtDate(f.firstSeen, true)}    Last seen: ${fmtDate(f.lastSeen, true)}`);
    lines.push('');
    lines.push('What it means:');
    lines.push('  ' + f.cause);
    if (f.impact) lines.push('  If ignored: ' + f.impact);

    if (f.breakdown.length > 0) {
      lines.push('');
      lines.push(`Breakdown by ${f.breakdownLabel}:`);
      for (const [value, count] of f.breakdown.slice(0, 10))
        lines.push(`  ${nf.format(count).padStart(6)} x  ${value}`);
      const more = f.breakdown.length - 10;
      if (more > 0) lines.push(`          ... and ${nf.format(more)} more distinct value(s)`);
      if (f.breakdownOverflow > 0) lines.push(`          ... plus ${nf.format(f.breakdownOverflow)} occurrence(s) not itemised`);
    }

    lines.push('');
    lines.push('What to do:');
    f.solutions.forEach((s, i) => lines.push(`  ${i + 1}. ${s}`));

    if (f.samples.length > 0) {
      lines.push('');
      lines.push(f.samples.length === 1 ? 'Sample event data:' : `Sample event data (${f.samples.length} distinct):`);
      f.samples.forEach((sample, i) => {
        if (f.samples.length > 1) lines.push(`  --- sample ${i + 1} ---`);
        for (const line of sample.trim().split('\n')) lines.push('  ' + line.trimEnd());
      });
    }
    return lines.join('\n') + '\n';
  }

  function formatCrash(c) {
    const lines = [];
    lines.push(`Unexpected shutdown around ${fmtDate(c.time, true)}${c.channel ? '  (' + c.channel + ' log)' : ''}`);
    for (const cause of c.causes) lines.push(`  Marker: ${cause}`);
    if (c.bugcheck) lines.push(`  Bugcheck: ${c.bugcheck}`);
    if (c.events.length) {
      lines.push('  Events in the minutes before the crash:');
      for (const e of c.events) {
        const lvl = e.level === 1 ? 'CRIT' : e.level === 2 ? 'ERR ' : 'WARN';
        lines.push(`    ${fmtDate(e.t, true)}  ${lvl}  ${e.provider} ${e.eventId}${e.summary ? '  - ' + e.summary : ''}`);
      }
    } else {
      lines.push('  No errors or warnings were logged in the minutes before the crash -');
      lines.push('  that usually points at power, hardware, or a hard hang rather than software.');
    }
    return lines.join('\n') + '\n';
  }

  function formatFullReport(fileName, result) {
    const lines = [];
    lines.push(`Event Log Analyzer report for: ${fileName}`);
    lines.push(
      `Total events: ${nf.format(result.totalEvents)}   Errors/warnings: ${nf.format(result.problemEvents)}   ` +
      `Distinct issues: ${result.findings.length}` +
      (result.sessions ? `   Boot sessions: ${nf.format(result.sessions.boots)}   Unexpected shutdowns: ${result.sessions.unexpectedShutdowns}` : ''));
    lines.push('='.repeat(78));
    if (result.crashes && result.crashes.length) {
      lines.push('UNEXPECTED SHUTDOWNS / CRASHES');
      lines.push('-'.repeat(78));
      for (const c of result.crashes) {
        lines.push(formatCrash(c));
        lines.push('-'.repeat(78));
      }
    }
    for (const f of result.findings) {
      lines.push(formatFinding(f));
      lines.push('-'.repeat(78));
    }
    return lines.join('\n');
  }

  const api = { makeAnalyzer, formatFinding, formatCrash, formatFullReport, fmtDate, severityRank };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.Analyzer = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
