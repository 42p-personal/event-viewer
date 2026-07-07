// UI wiring for the web version of Event Log Analyzer.
(function () {
  'use strict';

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const statusEl = document.getElementById('status');
  const resultsEl = document.getElementById('results');
  const summaryEl = document.getElementById('summary');
  const tbody = document.querySelector('#findingsTable tbody');
  const detailEl = document.getElementById('detail');
  const downloadBtn = document.getElementById('downloadBtn');
  const resetBtn = document.getElementById('resetBtn');

  let rules = [];
  let rulesError = null;
  let lastResult = null;
  let lastFileName = '';

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
    if (fileInput.files.length) analyzeFile(fileInput.files[0]);
  });

  ['dragenter', 'dragover'].forEach((ev) =>
    document.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('drag'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    document.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('drag'); }));
  document.addEventListener('drop', (e) => {
    if (e.dataTransfer && e.dataTransfer.files.length) analyzeFile(e.dataTransfer.files[0]);
  });

  resetBtn.addEventListener('click', () => {
    resultsEl.hidden = true;
    setStatus('');
    fileInput.value = '';
    fileInput.click();
  });

  downloadBtn.addEventListener('click', () => {
    if (!lastResult) return;
    const text = Analyzer.formatFullReport(lastFileName, lastResult);
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = lastFileName.replace(/\.evtx$/i, '') + '.report.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  });

  // -------------------------------------------------------------- analysis

  async function analyzeFile(file) {
    resultsEl.hidden = true;
    detailEl.textContent = '';
    tbody.textContent = '';
    setStatus(`Analyzing ${file.name}… (large logs can take a minute)`);

    try {
      const buffer = await file.arrayBuffer();
      const analyzer = Analyzer.makeAnalyzer(rules);
      const stats = await Evtx.parseEvtx(buffer, analyzer.onRecord, {
        onProgress: (f) => setStatus(`Analyzing ${file.name}… ${Math.round(f * 100)}%`),
      });
      const result = analyzer.finish(stats.totalEvents);
      lastResult = result;
      lastFileName = file.name;
      render(result, stats);
    } catch (err) {
      setStatus('Could not analyze this file: ' + err.message, true);
    }
  }

  const nf = new Intl.NumberFormat('en-GB');

  function render(result, stats) {
    setStatus('');
    const recognised = result.findings.filter((f) => f.recognised).length;
    if (result.findings.length === 0) {
      summaryEl.textContent = `${nf.format(result.totalEvents)} events scanned — no errors or warnings found. This log looks healthy.`;
    } else {
      summaryEl.textContent =
        `${nf.format(result.totalEvents)} events scanned — ${nf.format(result.problemEvents)} errors/warnings in ` +
        `${result.findings.length} distinct issues (${recognised} with specific advice). Select a row for details.` +
        (stats.parseErrors ? ` ${nf.format(stats.parseErrors)} record(s) could not be decoded.` : '') +
        (rulesError ? ' Warning: rules.json failed to load, so findings have generic advice only.' : '');
    }

    result.findings.forEach((f, i) => {
      const tr = document.createElement('tr');
      tr.className = 'sev sev-' + f.severity.toLowerCase();
      const cells = [
        [f.severity.toUpperCase(), 'nowrap'],
        [nf.format(f.count), 'num'],
        [f.provider, ''],
        [String(f.eventId), 'num'],
        [f.title, ''],
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

    resultsEl.hidden = false;
  }

  function select(tr, finding) {
    for (const row of tbody.children) row.classList.remove('selected');
    tr.classList.add('selected');
    detailEl.textContent = Analyzer.formatFinding(finding);
    detailEl.scrollTop = 0;
  }
})();
