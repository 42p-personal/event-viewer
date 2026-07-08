// Web Worker: parses .evtx files off the main thread and runs the analyzer.
// Receives {files: [{file, name}], rules}; posts progress then the result.
importScripts('evtx.js', 'analyzer.js');

self.onmessage = async (e) => {
  const { files, rules } = e.data;
  const analyzer = Analyzer.makeAnalyzer(rules);
  let total = 0;
  let parseErrors = 0;

  try {
    for (let i = 0; i < files.length; i++) {
      const { file, name } = files[i];
      const stats = await Evtx.parseEvtxFile(file, (rec) => {
        rec.source = name;
        analyzer.onRecord(rec);
      }, {
        onProgress: (fraction) => self.postMessage({
          type: 'progress', fileName: name, fileIndex: i, fileCount: files.length, fraction,
        }),
      });
      total += stats.totalEvents;
      parseErrors += stats.parseErrors;
    }
    self.postMessage({ type: 'done', result: analyzer.finish(total), parseErrors });
  } catch (err) {
    self.postMessage({ type: 'error', message: err && err.message ? err.message : String(err) });
  }
};
