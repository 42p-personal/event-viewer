// UI wiring for the web version of Event Log Analyzer.
// Parsing/analysis happens in a Web Worker (worker.js); this file renders.
(function () {
  'use strict';

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const statusEl = document.getElementById('status');
  const resultsEl = document.getElementById('results');
  const summaryEl = document.getElementById('summary');
  const crashesEl = document.getElementById('crashes');
  const crashCardsEl = document.getElementById('crashCards');
  const timelineSection = document.getElementById('timelineSection');
  const timelineChart = document.getElementById('timelineChart');
  const timelineLegend = document.getElementById('timelineLegend');
  const tlTooltip = document.getElementById('tlTooltip');
  const tbody = document.querySelector('#findingsTable tbody');
  const detailEl = document.getElementById('detail');
  const downloadBtn = document.getElementById('downloadBtn');
  const resetBtn = document.getElementById('resetBtn');

  const nf = new Intl.NumberFormat('en-GB');

  let rules = [];
  let rulesError = null;
  let lastResult = null;
  let lastFileNames = '';
  let busy = false;

  fetch('rules.json')
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status))))
    .then((json) => { rules = json; })
    .catch((e) => { rulesError = e; });

  function setStatus(msg, isError) {
    statusEl.hidden = !msg;
    statusEl.textContent = msg || '';
    statusEl.classList.toggle('error', !!isError);
  }

  // ------------------------------------------------------------ file intake

  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) analyzeFiles([...fileInput.files]);
  });

  ['dragenter', 'dragover'].forEach((ev) =>
    document.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    document.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  document.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files.length) analyzeFiles([...e.dataTransfer.files]);
  });

  resetBtn.addEventListener('click', () => {
    resultsEl.hidden = true;
    setStatus('');
    fileInput.value = '';
    fileInput.click();
  });

  downloadBtn.addEventListener('click', () => {
    if (!lastResult) return;
    const text = Analyzer.formatFullReport(lastFileNames, lastResult);
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'event-log-report.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // -------------------------------------------------------------- analysis

  async function analyzeFiles(files) {
    if (busy) return;
    files = files.filter((f) => f.size > 0);
    if (!files.length) return;
    busy = true;
    resultsEl.hidden = true;
    detailEl.textContent = '';
    tbody.textContent = '';
    lastFileNames = files.map((f) => f.name).join(', ');
    setStatus(`Analyzing ${lastFileNames}…`);

    const payload = { files: files.map((f) => ({ file: f, name: f.name })), rules };
    try {
      const { result, parseErrors } = await runInWorker(payload);
      lastResult = result;
      render(result, parseErrors);
    } catch (err) {
      setStatus('Could not analyze: ' + err.message, true);
    } finally {
      busy = false;
    }
  }

  function runInWorker(payload) {
    return new Promise((resolve, reject) => {
      let worker;
      try {
        worker = new Worker('worker.js');
      } catch (e) {
        resolve(runInline(payload)); // e.g. opened from file://
        return;
      }
      worker.onmessage = (e) => {
        const m = e.data;
        if (m.type === 'progress') {
          const which = m.fileCount > 1 ? ` (file ${m.fileIndex + 1}/${m.fileCount})` : '';
          setStatus(`Analyzing ${m.fileName}${which}… ${Math.round(m.fraction * 100)}%`);
        } else if (m.type === 'done') {
          worker.terminate();
          resolve({ result: m.result, parseErrors: m.parseErrors });
        } else if (m.type === 'error') {
          worker.terminate();
          reject(new Error(m.message));
        }
      };
      worker.onerror = (e) => {
        worker.terminate();
        // Fall back to parsing on the main thread.
        runInline(payload).then(resolve, reject);
      };
      worker.postMessage(payload);
    });
  }

  async function runInline(payload) {
    const analyzer = Analyzer.makeAnalyzer(payload.rules);
    let total = 0, parseErrors = 0;
    for (const { file, name } of payload.files) {
      const stats = await Evtx.parseEvtxFile(file, (rec) => {
        rec.source = name;
        analyzer.onRecord(rec);
      }, { onProgress: (f) => setStatus(`Analyzing ${name}… ${Math.round(f * 100)}%`) });
      total += stats.totalEvents;
      parseErrors += stats.parseErrors;
    }
    return { result: analyzer.finish(total), parseErrors };
  }

  // -------------------------------------------------------------- rendering

  function render(result, parseErrors) {
    setStatus('');

    const recognised = result.findings.filter((f) => f.recognised).length;
    if (result.findings.length === 0) {
      summaryEl.textContent = `${nf.format(result.totalEvents)} events scanned — no errors or warnings found. This log looks healthy.`;
    } else {
      let s = `${nf.format(result.totalEvents)} events scanned — ${nf.format(result.problemEvents)} errors/warnings in ` +
        `${result.findings.length} distinct issues (${recognised} with specific advice).`;
      if (result.sessions && result.sessions.boots > 0)
        s += ` ${nf.format(result.sessions.boots)} boot session(s), ${result.sessions.unexpectedShutdowns} unexpected shutdown(s).`;
      if (parseErrors) s += ` ${nf.format(parseErrors)} record(s) could not be decoded.`;
      if (rulesError) s += ' Warning: rules.json failed to load, so findings have generic advice only.';
      summaryEl.textContent = s;
    }

    renderCrashes(result.crashes || []);
    renderTimeline(result.timeline, result.crashes || []);
    renderGrid(result);

    resultsEl.hidden = false;
  }

  // ------------------------------------------------------------ crash cards

  function renderCrashes(crashes) {
    crashCardsEl.textContent = '';
    crashesEl.hidden = crashes.length === 0;
    for (const c of crashes) {
      const card = document.createElement('details');
      card.className = 'crash-card';
      if (crashes.length <= 3) card.open = true;

      const summary = document.createElement('summary');
      const when = document.createElement('strong');
      when.textContent = Analyzer.fmtDate(c.time, true);
      summary.appendChild(when);
      summary.appendChild(document.createTextNode(
        ' — ' + c.causes.join('; ') + (c.bugcheck ? ` — ${c.bugcheck}` : '')));
      card.appendChild(summary);

      const body = document.createElement('div');
      body.className = 'crash-body';
      if (c.events.length) {
        const intro = document.createElement('p');
        intro.textContent = 'Errors and warnings in the minutes before the crash' +
          (c.channel ? ` (${c.channel} log)` : '') + ':';
        body.appendChild(intro);
        const list = document.createElement('table');
        list.className = 'crash-events';
        for (const e of c.events) {
          const tr = document.createElement('tr');
          const cells = [
            Analyzer.fmtDate(e.t, true),
            e.level === 1 ? 'CRITICAL' : e.level === 2 ? 'ERROR' : 'WARNING',
            `${e.provider} ${e.eventId}`,
            e.summary || '',
          ];
          cells.forEach((text, i) => {
            const td = document.createElement('td');
            td.textContent = text;
            if (i === 0) td.className = 'nowrap';
            if (i === 1) td.className = 'crash-lvl-' + (e.level === 1 ? 'critical' : e.level === 2 ? 'error' : 'warning');
            tr.appendChild(td);
          });
          list.appendChild(tr);
        }
        body.appendChild(list);
      } else {
        const p = document.createElement('p');
        p.textContent = 'No errors or warnings were logged in the minutes before this crash — ' +
          'that usually points at power, hardware, or a hard hang rather than software.';
        body.appendChild(p);
      }
      card.appendChild(body);
      crashCardsEl.appendChild(card);
    }
  }

  // --------------------------------------------------------------- timeline

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const TL_W = 860, TL_H = 150, TL_PAD_L = 44, TL_PAD_R = 8, TL_PAD_T = 8, TL_PAD_B = 22;

  function svgEl(name, attrs) {
    const el = document.createElementNS(SVG_NS, name);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
    return el;
  }

  function niceMax(v) {
    if (v <= 5) return 5;
    const mag = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 5, 10]) if (v <= m * mag) return m * mag;
    return 10 * mag;
  }

  function renderTimeline(tl, crashes) {
    timelineChart.textContent = '';
    timelineLegend.textContent = '';
    timelineSection.hidden = !tl || tl.buckets.length < 2;
    if (timelineSection.hidden) return;

    const buckets = tl.buckets;
    const plotW = TL_W - TL_PAD_L - TL_PAD_R;
    const plotH = TL_H - TL_PAD_T - TL_PAD_B;
    const slot = plotW / buckets.length;
    const barW = Math.min(24, Math.max(2, slot - 2));
    const maxTotal = niceMax(Math.max(...buckets.map((b) => b.critical + b.error + b.warning), 1));
    const y = (v) => TL_PAD_T + plotH - (v / maxTotal) * plotH;

    const svg = svgEl('svg', {
      viewBox: `0 0 ${TL_W} ${TL_H}`, role: 'img',
      'aria-label': 'Histogram of errors and warnings over time, stacked by severity',
    });
    svg.classList.add('tl-svg');

    // hairline gridlines + y labels at 0 / half / max (integers only)
    const yTicks = maxTotal % 2 === 0 ? [0, maxTotal / 2, maxTotal] : [0, maxTotal];
    for (const v of yTicks) {
      svg.appendChild(svgEl('line', { x1: TL_PAD_L, x2: TL_W - TL_PAD_R, y1: y(v), y2: y(v), class: v === 0 ? 'tl-baseline' : 'tl-grid' }));
      const lbl = svgEl('text', { x: TL_PAD_L - 6, y: y(v) + 3, 'text-anchor': 'end', class: 'tl-tick' });
      lbl.textContent = nf.format(v);
      svg.appendChild(lbl);
    }

    // stacked bars: critical anchored to the baseline, then error, then warning;
    // 2px surface gaps between segments, rounded cap on the top segment only.
    buckets.forEach((b, i) => {
      const x = TL_PAD_L + i * slot + (slot - barW) / 2;
      const segs = [
        ['critical', b.critical],
        ['error', b.error],
        ['warning', b.warning],
      ].filter(([, v]) => v > 0);
      let acc = 0;
      segs.forEach(([sev, v], si) => {
        const y0 = y(acc + v);
        const h = y(acc) - y0;
        const isTop = si === segs.length - 1;
        const gap = si > 0 ? 1 : 0; // 2px total gap split between neighbours
        const hh = Math.max(h - gap, 0.75);
        if (isTop && hh >= 3) {
          const r = Math.min(2, barW / 2);
          const yTop = y(acc + v);
          const p = `M ${x} ${yTop + hh} L ${x} ${yTop + r} Q ${x} ${yTop} ${x + r} ${yTop} ` +
            `L ${x + barW - r} ${yTop} Q ${x + barW} ${yTop} ${x + barW} ${yTop + r} L ${x + barW} ${yTop + hh} Z`;
          svg.appendChild(svgEl('path', { d: p, class: 'tl-' + sev }));
        } else {
          svg.appendChild(svgEl('rect', { x, y: y0, width: barW, height: hh, class: 'tl-' + sev }));
        }
        acc += v;
      });

      // full-height invisible hit target for the tooltip
      const hit = svgEl('rect', { x: TL_PAD_L + i * slot, y: TL_PAD_T, width: slot, height: plotH, class: 'tl-hit' });
      hit.addEventListener('mouseenter', (ev) => showTlTooltip(ev, tl, i));
      hit.addEventListener('mousemove', (ev) => positionTlTooltip(ev));
      hit.addEventListener('mouseleave', hideTlTooltip);
      svg.appendChild(hit);
    });

    // x-axis time labels: first / middle / last bucket
    const label = (i) => Analyzer.fmtDate(tl.start + i * tl.bucketMs);
    [[0, 'start'], [Math.floor(buckets.length / 2), 'middle'], [buckets.length - 1, 'end']].forEach(([i, anchor]) => {
      const t = svgEl('text', {
        x: TL_PAD_L + i * slot + slot / 2, y: TL_H - 6,
        'text-anchor': anchor === 'start' ? 'start' : anchor === 'end' ? 'end' : 'middle',
        class: 'tl-tick',
      });
      t.textContent = label(i);
      svg.appendChild(t);
    });

    timelineChart.appendChild(svg);

    // legend (identity never color-alone)
    const totals = buckets.reduce((a, b) => ({
      critical: a.critical + b.critical, error: a.error + b.error, warning: a.warning + b.warning,
    }), { critical: 0, error: 0, warning: 0 });
    for (const sev of ['critical', 'error', 'warning']) {
      const item = document.createElement('span');
      item.className = 'tl-key';
      item.setAttribute('role', 'listitem');
      const swatch = document.createElement('span');
      swatch.className = 'tl-swatch tl-' + sev;
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(`${sev[0].toUpperCase() + sev.slice(1)} (${nf.format(totals[sev])})`));
      timelineLegend.appendChild(item);
    }
    if (tl.dropped > 0) {
      const note = document.createElement('span');
      note.className = 'tl-key';
      note.textContent = `${nf.format(tl.dropped)} events beyond the sampling cap are not charted`;
      timelineLegend.appendChild(note);
    }
  }

  function showTlTooltip(ev, tl, i) {
    const b = tl.buckets[i];
    const from = Analyzer.fmtDate(tl.start + i * tl.bucketMs);
    const to = Analyzer.fmtDate(tl.start + (i + 1) * tl.bucketMs);
    tlTooltip.textContent = `${from} – ${to}\nCritical: ${nf.format(b.critical)}   Errors: ${nf.format(b.error)}   Warnings: ${nf.format(b.warning)}`;
    tlTooltip.hidden = false;
    positionTlTooltip(ev);
  }
  function positionTlTooltip(ev) {
    if (tlTooltip.hidden) return;
    const rect = timelineSection.getBoundingClientRect();
    let lx = ev.clientX - rect.left + 14;
    const ly = ev.clientY - rect.top + 14;
    if (lx + tlTooltip.offsetWidth > rect.width - 8) lx = lx - tlTooltip.offsetWidth - 24;
    tlTooltip.style.left = lx + 'px';
    tlTooltip.style.top = ly + 'px';
  }
  function hideTlTooltip() { tlTooltip.hidden = true; }

  // ------------------------------------------------------------ findings grid

  function renderGrid(result) {
    result.findings.forEach((f, i) => {
      const tr = document.createElement('tr');
      tr.className = 'sev sev-' + f.severity.toLowerCase();
      const cells = [
        [f.severity.toUpperCase(), 'nowrap'],
        [nf.format(f.count), 'num'],
        [f.provider, ''],
        [String(f.eventId), 'num'],
        [f.title, ''],
        [(f.channels || []).join(', '), 'nowrap'],
        [Analyzer.fmtDate(f.firstSeen), 'nowrap'],
        [Analyzer.fmtDate(f.lastSeen), 'nowrap'],
      ];
      for (const [text, cls] of cells) {
        const td = document.createElement('td');
        td.textContent = text;
        if (cls) td.className = cls;
        tr.appendChild(td);
      }
      tr.addEventListener('click', () => select(tr, f));
      tbody.appendChild(tr);
      if (i === 0) select(tr, f);
    });
  }

  function select(tr, finding) {
    for (const row of tbody.children) row.classList.remove('selected');
    tr.classList.add('selected');
    detailEl.textContent = Analyzer.formatFinding(finding);
    detailEl.scrollTop = 0;
  }
})();
