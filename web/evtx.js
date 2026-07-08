// EVTX (Windows Event Log) parser - runs entirely in the browser.
// Implements the file/chunk layout and the Binary XML encoding, including
// templates, substitutions and nested BinXml values. Checksums are not
// verified (a corrupt chunk is skipped rather than rejected).
//
// Format references: libevtx format documentation, python-evtx, rust evtx.
(function (global) {
  'use strict';

  const CHUNK_SIZE = 0x10000;
  const FILE_HEADER_SIZE = 0x1000;

  // ---------------------------------------------------------------- helpers

  class Cursor {
    constructor(view, pos) {
      this.v = view;       // DataView over the whole chunk
      this.pos = pos | 0;  // offset relative to chunk start
    }
    u8() { const x = this.v.getUint8(this.pos); this.pos += 1; return x; }
    u16() { const x = this.v.getUint16(this.pos, true); this.pos += 2; return x; }
    u32() { const x = this.v.getUint32(this.pos, true); this.pos += 4; return x; }
    u64() { const x = this.v.getBigUint64(this.pos, true); this.pos += 8; return x; }
    peek() { return this.v.getUint8(this.pos); }
    skip(n) { this.pos += n; }
    bytes(n) {
      const out = new Uint8Array(this.v.buffer, this.v.byteOffset + this.pos, n);
      this.pos += n;
      return out;
    }
    utf16(nChars) {
      let s = '';
      for (let i = 0; i < nChars; i++) s += String.fromCharCode(this.v.getUint16(this.pos + i * 2, true));
      this.pos += nChars * 2;
      return s;
    }
  }

  function decodeUtf16(bytes) {
    let s = '';
    const n = bytes.length & ~1;
    for (let i = 0; i < n; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
    // strip trailing NULs
    return s.replace(/\0+$/, '');
  }

  function decodeAnsi(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 0) break;
      s += String.fromCharCode(bytes[i]);
    }
    return s;
  }

  function toHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s.toUpperCase();
  }

  const FILETIME_EPOCH_DIFF_MS = 11644473600000;
  function filetimeToDate(v) { // v: BigInt, 100ns intervals since 1601-01-01
    if (v === 0n) return null;
    const ms = Number(v / 10000n) - FILETIME_EPOCH_DIFF_MS;
    return new Date(ms);
  }

  function guidToString(b) {
    const hex = (i) => b[i].toString(16).padStart(2, '0');
    return (
      hex(3) + hex(2) + hex(1) + hex(0) + '-' +
      hex(5) + hex(4) + '-' +
      hex(7) + hex(6) + '-' +
      hex(8) + hex(9) + '-' +
      hex(10) + hex(11) + hex(12) + hex(13) + hex(14) + hex(15)
    ).toUpperCase();
  }

  function sidToString(b) {
    if (b.length < 8) return '(invalid sid)';
    const revision = b[0];
    const count = b[1];
    let authority = 0;
    for (let i = 2; i < 8; i++) authority = authority * 256 + b[i];
    let s = 'S-' + revision + '-' + authority;
    for (let i = 0; i < count && 8 + i * 4 + 3 < b.length; i++) {
      const off = 8 + i * 4;
      const sub = (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
      s += '-' + sub;
    }
    return s;
  }

  // ------------------------------------------------------------ BinXml tree
  //
  // Elements are {name, attrs: {..}, children: [elements], text: string}.
  // Substitution placeholders (only inside template definitions) are
  // {sub: id, optional: bool} stored in attrs values or children.

  const T = {
    EOF: 0x00, OPEN_START: 0x01, CLOSE_START: 0x02, CLOSE_EMPTY: 0x03,
    CLOSE_ELEMENT: 0x04, VALUE: 0x05, ATTRIBUTE: 0x06, CDATA: 0x07,
    CHAR_REF: 0x08, ENTITY_REF: 0x09, PI_TARGET: 0x0a, PI_DATA: 0x0b,
    TEMPLATE_INSTANCE: 0x0c, SUBST_NORMAL: 0x0d, SUBST_OPTIONAL: 0x0e,
    FRAGMENT_HEADER: 0x0f,
  };

  class BinXmlParser {
    constructor(chunkView, templateCache) {
      this.view = chunkView;
      this.templates = templateCache; // Map<offset, {def, endPos}>
    }

    // Parse a BinXml stream starting at cur.pos; returns list of root nodes.
    // Stops at EOF token or when maxPos is reached.
    parseFragment(cur, maxPos) {
      const roots = [];
      while (cur.pos < maxPos) {
        const tok = cur.peek();
        if (tok === T.EOF) { cur.skip(1); break; }
        if (tok === T.FRAGMENT_HEADER) { cur.skip(4); continue; } // token+major+minor+flags
        if (tok === T.TEMPLATE_INSTANCE) {
          roots.push(this.parseTemplateInstance(cur));
          continue;
        }
        if ((tok & 0x1f) === T.OPEN_START) {
          roots.push(this.parseElement(cur));
          continue;
        }
        if (tok === T.PI_TARGET) { cur.skip(1); cur.skip(4); continue; }
        if (tok === T.PI_DATA) { cur.skip(1); const n = cur.u16(); cur.skip(n * 2); continue; }
        // Unknown token: stop parsing this fragment rather than looping.
        break;
      }
      return roots;
    }

    readName(cur) {
      const nameOffset = cur.u32();
      if (nameOffset === cur.pos) {
        // Inline name structure; skip over it after reading.
        return this.readNameAt(cur, true);
      }
      const saved = cur.pos;
      const c = new Cursor(this.view, nameOffset);
      const name = this.readNameAt(c, false);
      cur.pos = saved;
      return name;
    }

    readNameAt(cur) {
      cur.skip(4); // next-string offset (hash bucket chain)
      cur.skip(2); // name hash
      const nChars = cur.u16();
      const name = cur.utf16(nChars);
      cur.skip(2); // NUL terminator
      return name;
    }

    parseElement(cur) {
      const tok = cur.u8();
      const hasAttrs = (tok & 0x40) !== 0;
      cur.skip(2); // dependency identifier
      cur.skip(4); // data size (token-driven parsing; not needed)
      const name = this.readName(cur);
      const el = { name, attrs: {}, children: [], text: '' };

      if (hasAttrs) {
        cur.skip(4); // attribute list size
        for (;;) {
          const atok = cur.peek();
          if ((atok & 0x1f) !== T.ATTRIBUTE) break;
          cur.skip(1);
          const aname = this.readName(cur);
          el.attrs[aname] = this.parseValueToken(cur);
          if ((atok & 0x40) === 0) break; // last attribute
        }
      }

      const closer = cur.u8();
      if (closer === T.CLOSE_EMPTY) return el;
      // closer === CLOSE_START: parse content until CloseElement
      for (;;) {
        const tok2 = cur.peek();
        if (tok2 === T.CLOSE_ELEMENT) { cur.skip(1); break; }
        if (tok2 === T.EOF) { cur.skip(1); break; }
        if ((tok2 & 0x1f) === T.OPEN_START) { el.children.push(this.parseElement(cur)); continue; }
        const v = this.parseValueToken(cur);
        if (v && typeof v === 'object' && 'sub' in v) el.children.push(v);
        else el.text += String(v);
      }
      return el;
    }

    // Parses value-ish tokens: value text, substitutions, char/entity refs, CDATA.
    parseValueToken(cur) {
      const tok = cur.u8();
      const base = tok & 0x1f;
      switch (base) {
        case T.VALUE: {
          const type = cur.u8();
          if (type === 0x01) { const n = cur.u16(); return cur.utf16(n); }
          if (type === 0x02) { const n = cur.u16(); return decodeAnsi(cur.bytes(n)); }
          // Other inline value types are rare; treat as empty.
          return '';
        }
        case T.SUBST_NORMAL: {
          const id = cur.u16(); cur.skip(1); // value type hint
          return { sub: id, optional: false };
        }
        case T.SUBST_OPTIONAL: {
          const id = cur.u16(); cur.skip(1);
          return { sub: id, optional: true };
        }
        case T.CHAR_REF: return String.fromCharCode(cur.u16());
        case T.ENTITY_REF: {
          const name = this.readName(cur);
          return ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[name] || ('&' + name + ';');
        }
        case T.CDATA: { const n = cur.u16(); return cur.utf16(n); }
        default:
          return '';
      }
    }

    parseTemplateInstance(cur) {
      cur.skip(1); // token 0x0c
      cur.skip(1); // unknown/version
      cur.skip(4); // template id (first dword of the definition GUID)
      const defOffset = cur.u32();

      let def;
      if (defOffset === cur.pos) {
        def = this.parseTemplateDefinition(cur, defOffset);
      } else {
        def = this.templates.get(defOffset);
        if (!def) {
          const c = new Cursor(this.view, defOffset);
          def = this.parseTemplateDefinition(c, defOffset);
        }
      }

      // Substitution values follow the instance header/definition.
      const nValues = cur.u32();
      const descs = [];
      for (let i = 0; i < nValues; i++) {
        const size = cur.u16();
        const type = cur.u8();
        cur.skip(1);
        descs.push({ size, type });
      }
      const values = [];
      for (const d of descs) values.push(this.readValue(cur, d.type, d.size));

      return this.instantiate(def.nodes, values);
    }

    parseTemplateDefinition(cur, offset) {
      cur.skip(4);  // next template offset (hash chain)
      cur.skip(16); // template GUID
      const dataSize = cur.u32();
      const end = cur.pos + dataSize;
      const nodes = this.parseFragment(cur, end);
      cur.pos = end;
      const def = { nodes };
      this.templates.set(offset, def);
      return def;
    }

    // ------------------------------------------------------------- values

    readValue(cur, type, size) {
      const end = cur.pos + size;
      let out;
      try {
        out = this.readValueInner(cur, type, size);
      } catch (e) {
        out = '?';
      }
      cur.pos = end;
      return out;
    }

    readValueInner(cur, type, size) {
      if (type & 0x80) return this.readArray(cur, type & 0x7f, size);
      switch (type) {
        case 0x00: return null; // NullType
        case 0x01: return decodeUtf16(cur.bytes(size));
        case 0x02: return decodeAnsi(cur.bytes(size));
        case 0x03: return this.v(cur).getInt8(cur.pos);
        case 0x04: return cur.u8();
        case 0x05: return this.v(cur).getInt16(cur.pos, true);
        case 0x06: return cur.u16();
        case 0x07: return this.v(cur).getInt32(cur.pos, true);
        case 0x08: return cur.u32();
        case 0x09: return this.v(cur).getBigInt64(cur.pos, true).toString();
        case 0x0a: return cur.u64().toString();
        case 0x0b: return this.v(cur).getFloat32(cur.pos, true);
        case 0x0c: return this.v(cur).getFloat64(cur.pos, true);
        case 0x0d: return cur.u32() !== 0;
        case 0x0e: return toHex(cur.bytes(size));
        case 0x0f: return guidToString(cur.bytes(16));
        case 0x10: return size === 8 ? cur.u64().toString() : cur.u32();
        case 0x11: { const d = filetimeToDate(cur.u64()); return d ? d : null; }
        case 0x12: { // SYSTEMTIME
          const y = cur.u16(), mo = cur.u16(); cur.u16(); const d = cur.u16();
          const h = cur.u16(), mi = cur.u16(), s = cur.u16(), ms = cur.u16();
          return new Date(Date.UTC(y, mo - 1, d, h, mi, s, ms));
        }
        case 0x13: return sidToString(cur.bytes(size));
        case 0x14: return '0x' + (cur.u32() >>> 0).toString(16);
        case 0x15: return '0x' + cur.u64().toString(16);
        case 0x21: { // nested BinXml
          const nodes = this.parseFragment(cur, cur.pos + size);
          return { binxml: nodes };
        }
        default:
          return size > 0 ? toHex(cur.bytes(Math.min(size, 64))) : '';
      }
    }

    v(cur) { return cur.v; }

    readArray(cur, elemType, size) {
      const end = cur.pos + size;
      const items = [];
      if (elemType === 0x01) { // UTF-16 strings, NUL-separated
        let s = '';
        while (cur.pos + 1 < end) {
          const ch = cur.u16();
          if (ch === 0) { items.push(s); s = ''; } else s += String.fromCharCode(ch);
        }
        if (s) items.push(s);
      } else {
        const sizes = { 0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0a: 8, 0x0b: 4, 0x0c: 8, 0x0f: 16, 0x11: 8 };
        const es = sizes[elemType] || 0;
        if (es === 0) return toHex(cur.bytes(size));
        while (cur.pos + es <= end) {
          const at = cur.pos;
          items.push(this.readValueInner(cur, elemType, es));
          cur.pos = at + es; // some branches read via DataView without advancing
        }
      }
      return items.join(', ');
    }

    // ------------------------------------------------- template instantiation

    instantiate(nodes, values) {
      const outs = [];
      for (const n of nodes) {
        const r = this.instantiateNode(n, values);
        if (r !== undefined) outs.push(r);
      }
      return outs.length === 1 ? outs[0] : { name: '', attrs: {}, children: outs, text: '' };
    }

    instantiateNode(node, values) {
      if (node && typeof node === 'object' && 'sub' in node) {
        const v = node.sub < values.length ? values[node.sub] : null;
        if (v === null) return node.optional ? undefined : '';
        return v;
      }
      if (!node || typeof node !== 'object' || !('name' in node)) return node; // literal text/values
      const el = { name: node.name, attrs: {}, children: [], text: node.text || '' };
      for (const [k, av] of Object.entries(node.attrs)) {
        const rv = this.instantiateNode(av, values);
        if (rv === undefined) continue;
        el.attrs[k] = this.stringifyValue(rv);
      }
      for (const c of node.children) {
        const rc = this.instantiateNode(c, values);
        if (rc === undefined) continue;
        if (rc && typeof rc === 'object' && 'binxml' in rc) {
          for (const sub of [].concat(rc.binxml)) {
            if (sub && typeof sub === 'object' && 'name' in sub) el.children.push(sub);
          }
        } else if (rc && typeof rc === 'object' && 'name' in rc) {
          el.children.push(rc);
        } else {
          el.text += this.stringifyValue(rc);
        }
      }
      return el;
    }

    stringifyValue(v) {
      if (v === null || v === undefined) return '';
      if (v instanceof Date) return v.toISOString();
      if (typeof v === 'object' && 'binxml' in v) return '';
      return String(v);
    }
  }

  // -------------------------------------------------------------- record IO

  function findText(el, name) {
    if (!el) return null;
    for (const c of el.children) if (c.name === name) return c;
    return null;
  }

  // Flatten a parsed record tree into the fields the analyzer needs.
  function extractRecord(root, writtenTime) {
    // root should be the <Event> element (possibly wrapped)
    let ev = root;
    if (ev && ev.name !== 'Event') {
      const q = [ev];
      ev = null;
      while (q.length) {
        const n = q.shift();
        if (n.name === 'Event') { ev = n; break; }
        for (const c of n.children || []) q.push(c);
      }
    }
    if (!ev) return null;

    const sys = findText(ev, 'System');
    const rec = {
      provider: null, eventId: 0, level: 4, time: writtenTime,
      channel: null, computer: null, properties: [], propNames: [],
    };
    if (sys) {
      const prov = findText(sys, 'Provider');
      if (prov) rec.provider = prov.attrs['Name'] || prov.attrs['EventSourceName'] || null;
      const eid = findText(sys, 'EventID');
      if (eid) rec.eventId = parseInt(eid.text, 10) || 0;
      const lvl = findText(sys, 'Level');
      if (lvl && lvl.text !== '') rec.level = parseInt(lvl.text, 10);
      const tc = findText(sys, 'TimeCreated');
      if (tc && tc.attrs['SystemTime']) {
        const d = new Date(tc.attrs['SystemTime']);
        if (!isNaN(d)) rec.time = d;
      }
      const ch = findText(sys, 'Channel');
      if (ch) rec.channel = ch.text;
      const comp = findText(sys, 'Computer');
      if (comp) rec.computer = comp.text;
    }

    const ed = findText(ev, 'EventData') || findText(ev, 'ProcessingErrorData');
    if (ed) {
      for (const d of ed.children) {
        if (d.name === 'Data') {
          rec.properties.push(d.text);
          rec.propNames.push(d.attrs['Name'] || '');
        } else if (d.name === 'Binary') {
          rec.properties.push(d.text);
          rec.propNames.push('Binary');
        }
      }
      // <Data>text</Data> with no children but direct text on EventData
      if (ed.children.length === 0 && ed.text) {
        rec.properties.push(ed.text);
        rec.propNames.push('');
      }
    } else {
      const ud = findText(ev, 'UserData');
      if (ud) {
        // UserData wraps one provider-specific element; flatten its children.
        const wrap = ud.children[0];
        const src = wrap && wrap.children.length ? wrap.children : ud.children;
        for (const d of src) {
          rec.properties.push(d.text);
          rec.propNames.push(d.name || '');
        }
      }
    }
    return rec;
  }

  // Parse one 64 KiB chunk. view/chunkBytes must be aligned to the chunk start.
  function parseChunk(view, chunkBytes, onRecord, stats) {
    const csig = decodeAnsi(chunkBytes.subarray(0, 7));
    if (csig !== 'ElfChnk') return;

    const freeSpaceOffset = view.getUint32(0x30, true);
    const limit = Math.min(freeSpaceOffset || CHUNK_SIZE, CHUNK_SIZE);
    const parser = new BinXmlParser(view, new Map());

    let pos = 0x200;
    while (pos + 24 <= limit) {
      // record signature 2a 2a 00 00
      if (!(chunkBytes[pos] === 0x2a && chunkBytes[pos + 1] === 0x2a && chunkBytes[pos + 2] === 0 && chunkBytes[pos + 3] === 0)) break;
      const size = view.getUint32(pos + 4, true);
      if (size < 28 || pos + size > CHUNK_SIZE) break;
      const written = filetimeToDate(view.getBigUint64(pos + 16, true));
      stats.totalEvents++;
      try {
        const cur = new Cursor(view, pos + 24);
        const nodes = parser.parseFragment(cur, pos + size - 4);
        const root = nodes.length === 1 ? nodes[0] : { name: '', attrs: {}, children: nodes, text: '' };
        const rec = extractRecord(root, written);
        if (rec) onRecord(rec);
        else stats.parseErrors++;
      } catch (e) {
        stats.parseErrors++;
      }
      pos += size;
    }
  }

  function checkFileHeader(bytes) {
    if (bytes.length < 8 || decodeAnsi(bytes.subarray(0, 7)) !== 'ElfFile')
      throw new Error('Not an .evtx file (missing ElfFile signature).');
  }

  // Parse a whole file held in memory. onRecord(rec) per decoded record;
  // returns {totalEvents, parseErrors}. options.onProgress(fraction).
  async function parseEvtx(arrayBuffer, onRecord, options = {}) {
    const fileBytes = new Uint8Array(arrayBuffer);
    if (fileBytes.length < FILE_HEADER_SIZE) throw new Error('File is too small to be an .evtx file.');
    checkFileHeader(fileBytes);

    const stats = { totalEvents: 0, parseErrors: 0 };
    const nChunks = Math.floor((fileBytes.length - FILE_HEADER_SIZE) / CHUNK_SIZE);
    for (let ci = 0; ci < nChunks; ci++) {
      const chunkStart = FILE_HEADER_SIZE + ci * CHUNK_SIZE;
      parseChunk(
        new DataView(arrayBuffer, chunkStart, CHUNK_SIZE),
        fileBytes.subarray(chunkStart, chunkStart + CHUNK_SIZE),
        onRecord, stats);
      if (options.onProgress && (ci & 15) === 0) {
        options.onProgress((ci + 1) / nChunks);
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    if (options.onProgress) options.onProgress(1);
    return stats;
  }

  // Parse a File/Blob incrementally via slice() so huge logs never need one
  // giant ArrayBuffer. Reads 4 MiB (64 chunks) at a time.
  const SLICE_CHUNKS = 64;
  async function parseEvtxFile(file, onRecord, options = {}) {
    if (file.size < FILE_HEADER_SIZE) throw new Error('File is too small to be an .evtx file.');
    checkFileHeader(new Uint8Array(await file.slice(0, FILE_HEADER_SIZE).arrayBuffer()));

    const stats = { totalEvents: 0, parseErrors: 0 };
    const groupSize = SLICE_CHUNKS * CHUNK_SIZE;
    for (let off = FILE_HEADER_SIZE; off + CHUNK_SIZE <= file.size; off += groupSize) {
      const end = Math.min(off + groupSize, file.size);
      const buf = await file.slice(off, end).arrayBuffer();
      const bytes = new Uint8Array(buf);
      const nChunks = Math.floor(bytes.length / CHUNK_SIZE);
      for (let ci = 0; ci < nChunks; ci++) {
        parseChunk(
          new DataView(buf, ci * CHUNK_SIZE, CHUNK_SIZE),
          bytes.subarray(ci * CHUNK_SIZE, (ci + 1) * CHUNK_SIZE),
          onRecord, stats);
      }
      if (options.onProgress) options.onProgress(Math.min(end / file.size, 1));
    }
    if (options.onProgress) options.onProgress(1);
    return stats;
  }

  const api = { parseEvtx, parseEvtxFile };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.Evtx = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
