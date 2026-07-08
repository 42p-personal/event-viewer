#!/usr/bin/env python3
"""Generate small well-formed .evtx files to test the JS parser and analyzer.

Writes two files into the output directory (default: cwd):
  system.evtx      - System channel: disk/service errors, two boot sessions,
                     and an unexpected-shutdown sequence (Kernel-Power 41 +
                     BugCheck 1001) preceded by storage errors.
  application.evtx - Application channel: app crashes (generic + ntdll.dll
                     keyword variant) and DCOM 10016 noise.

Each file is one chunk; records share a BinXml template (inline definition on
the first record, back-references after). Checksums are left zero - the JS
parser does not verify them.
"""
import struct
import sys
import uuid

CHUNK_DATA_START = 512
FILETIME_EPOCH = 11644473600  # seconds between 1601 and 1970

T0 = 1751800000  # ~2025-07-06, base timestamp for all synthetic events


def filetime(unix_seconds):
    return int((unix_seconds + FILETIME_EPOCH) * 10_000_000)


def utf16(s):
    return s.encode('utf-16-le')


class ChunkBuilder:
    def __init__(self):
        self.buf = bytearray()

    @property
    def pos(self):
        return len(self.buf)

    def raw(self, b): self.buf += b
    def u8(self, v): self.buf += struct.pack('<B', v)
    def u16(self, v): self.buf += struct.pack('<H', v)
    def u32(self, v): self.buf += struct.pack('<I', v)
    def u64(self, v): self.buf += struct.pack('<Q', v)

    # --- binxml pieces -----------------------------------------------------

    def name_inline(self, s):
        self.u32(self.pos + 4)          # offset == position right after this field
        self.u32(0)                     # next-string offset
        self.u16(0)                     # name hash (unchecked)
        self.u16(len(s))
        self.raw(utf16(s))
        self.u16(0)                     # NUL

    def value_string(self, s):
        self.u8(0x05); self.u8(0x01)
        self.u16(len(s)); self.raw(utf16(s))

    def subst(self, sub_id, vtype, optional=False):
        self.u8(0x0E if optional else 0x0D)
        self.u16(sub_id); self.u8(vtype)

    def open_element(self, name, has_attrs=False):
        self.u8(0x41 if has_attrs else 0x01)
        self.u16(0xFFFF)                # dependency identifier
        self.u32(0)                     # data size (length hint, unused by parser)
        self.name_inline(name)

    def attribute(self, name, more=False):
        self.u8(0x46 if more else 0x06)
        self.name_inline(name)

    def close_start(self): self.u8(0x02)
    def close_empty(self): self.u8(0x03)
    def close_element(self): self.u8(0x04)
    def eof(self): self.u8(0x00)
    def fragment_header(self): self.raw(bytes([0x0F, 0x01, 0x01, 0x00]))


def build_template_body(b: ChunkBuilder, channel: str):
    """Substitutions: 0=Provider (str), 1=EventID (u16), 2=Level (u8),
    3=TimeCreated (filetime), 4=param1 (str), 5=param2 (str, optional)."""
    b.fragment_header()
    b.open_element('Event', has_attrs=True)
    b.u32(0)
    b.attribute('xmlns')
    b.value_string('http://schemas.microsoft.com/win/2004/08/events/event')
    b.close_start()

    b.open_element('System')
    b.close_start()
    b.open_element('Provider', has_attrs=True)
    b.u32(0)
    b.attribute('Name')
    b.subst(0, 0x01)
    b.close_empty()
    b.open_element('EventID')
    b.close_start(); b.subst(1, 0x06); b.close_element()
    b.open_element('Level')
    b.close_start(); b.subst(2, 0x04); b.close_element()
    b.open_element('TimeCreated', has_attrs=True)
    b.u32(0)
    b.attribute('SystemTime')
    b.subst(3, 0x11)
    b.close_empty()
    b.open_element('Channel')
    b.close_start(); b.value_string(channel); b.close_element()
    b.open_element('Computer')
    b.close_start(); b.value_string('DESKTOP-TEST'); b.close_element()
    b.close_element()  # </System>

    b.open_element('EventData')
    b.close_start()
    b.open_element('Data', has_attrs=True)
    b.u32(0)
    b.attribute('Name')
    b.value_string('param1')
    b.close_start(); b.subst(4, 0x01); b.close_element()
    b.open_element('Data', has_attrs=True)
    b.u32(0)
    b.attribute('Name')
    b.value_string('param2')
    b.close_start(); b.subst(5, 0x01, optional=True); b.close_element()
    b.close_element()  # </EventData>

    b.close_element()  # </Event>
    b.eof()


def write_record(b: ChunkBuilder, record_id, template_offset_holder, guid, channel, values):
    provider, event_id, level, t, p1, p2 = values
    rec_start = b.pos
    b.raw(b'\x2a\x2a\x00\x00')
    size_pos = b.pos
    b.u32(0)
    b.u64(record_id)
    b.u64(filetime(t))

    b.fragment_header()
    b.u8(0x0C); b.u8(0x01)
    b.u32(struct.unpack('<I', guid[:4])[0])
    if template_offset_holder[0] is None:
        b.u32(b.pos + 4)
        template_offset_holder[0] = b.pos
        b.u32(0)
        b.raw(guid)
        dsize_pos = b.pos
        b.u32(0)
        body_start = b.pos
        build_template_body(b, channel)
        struct.pack_into('<I', b.buf, dsize_pos, b.pos - body_start)
    else:
        b.u32(template_offset_holder[0])

    vals = [
        (utf16(provider), 0x01),
        (struct.pack('<H', event_id), 0x06),
        (struct.pack('<B', level), 0x04),
        (struct.pack('<Q', filetime(t)), 0x11),
        (utf16(p1), 0x01),
        (utf16(p2) if p2 is not None else b'', 0x01 if p2 is not None else 0x00),
    ]
    b.u32(len(vals))
    for data, vtype in vals:
        b.u16(len(data)); b.u8(vtype); b.u8(0)
    for data, _ in vals:
        b.raw(data)

    b.u32(0)
    size = b.pos - rec_start
    struct.pack_into('<I', b.buf, size_pos, size)
    struct.pack_into('<I', b.buf, rec_start + size - 4, size)
    return rec_start


def write_evtx(path, channel, records):
    b = ChunkBuilder()
    b.raw(b'ElfChnk\x00')
    b.u64(1); b.u64(len(records))          # first/last event record number
    b.u64(1); b.u64(len(records))          # first/last event record id
    b.u32(128)                             # header size
    b.u32(0)                               # last event record data offset (patched)
    b.u32(0)                               # free space offset (patched)
    b.u32(0)                               # event records checksum
    b.raw(bytes(64))
    b.u32(0); b.u32(0)                     # flags, checksum
    b.raw(bytes(64 * 4))                   # common string offset table
    b.raw(bytes(32 * 4))                   # template offset table
    assert b.pos == CHUNK_DATA_START, b.pos

    guid = uuid.uuid4().bytes_le
    holder = [None]
    last_rec = 0
    for i, r in enumerate(records, start=1):
        last_rec = write_record(b, i, holder, guid, channel, r)

    struct.pack_into('<I', b.buf, 44, last_rec)
    struct.pack_into('<I', b.buf, 48, b.pos)

    chunk = bytes(b.buf) + bytes(0x10000 - b.pos)
    hdr = bytearray(4096)
    hdr[0:8] = b'ElfFile\x00'
    struct.pack_into('<QQQ', hdr, 8, 0, 0, len(records) + 1)
    struct.pack_into('<IHHHH', hdr, 32, 128, 1, 3, 4096, 1)

    with open(path, 'wb') as f:
        f.write(hdr)
        f.write(chunk)
    print(f'wrote {path}: {len(records)} records')


def system_records():
    T = T0 + 5000  # moment of the simulated crash
    return [
        # boot session 1 starts
        ('EventLog', 6005, 4, T0 - 1000, 'Event log service started', None),
        # everyday errors/warnings
        ('disk', 7, 2, T0 + 100, '\\Device\\Harddisk0\\DR0', None),
        ('disk', 7, 2, T0 + 200, '\\Device\\Harddisk0\\DR0', None),
        ('disk', 7, 2, T0 + 900, '\\Device\\Harddisk0\\DR0', None),
        ('Service Control Manager', 7031, 2, T0 + 300, 'Print Spooler', '1'),
        ('Service Control Manager', 7031, 2, T0 + 400, 'Print Spooler', '1'),
        ('Service Control Manager', 7031, 2, T0 + 500, 'Print Spooler', '2'),
        ('Service Control Manager', 7031, 2, T0 + 600, 'Windows Update', '1'),
        ('FooBarDriver', 999, 3, T0 + 700, 'widget stalled', None),
        ('FooBarDriver', 999, 3, T0 + 800, 'widget stalled again', None),
        ('EventLog', 6013, 4, T0 + 850, 'uptime 12345', None),
        # storage trouble right before the crash
        ('storahci', 129, 2, T - 90, 'ResetBus \\Device\\RaidPort0', None),
        ('storahci', 129, 2, T - 60, 'ResetBus \\Device\\RaidPort0', None),
        ('disk', 153, 3, T - 30, 'IO retried \\Device\\Harddisk0', None),
        # ...crash happens at T (nothing logged, machine died)...
        # boot session 2: markers logged shortly after the next startup
        ('EventLog', 6005, 4, T + 60, 'Event log service started', None),
        ('Microsoft-Windows-Kernel-Power', 41, 1, T + 70, '0', '0'),
        ('BugCheck', 1001, 2, T + 75,
         '0x0000009f (0x0000000000000003, 0xffff8000, 0xffff9000, 0xffffa000)', 'C:\\Windows\\MEMORY.DMP'),
    ]


def application_records():
    return [
        ('Application Error', 1000, 2, T0 + 1000, 'badapp.exe', 'KERNELBASE.dll'),
        ('Application Error', 1000, 2, T0 + 1100, 'badapp.exe', 'KERNELBASE.dll'),
        ('Application Error', 1000, 2, T0 + 1200, 'other.exe', 'ntdll.dll'),
        ('Microsoft-Windows-DistributedCOM', 10016, 3, T0 + 1300, 'CLSID {123}', 'APPID {456}'),
        ('Microsoft-Windows-DistributedCOM', 10016, 3, T0 + 1400, 'CLSID {123}', 'APPID {456}'),
        ('Microsoft-Windows-DistributedCOM', 10016, 3, T0 + 1500, 'CLSID {789}', 'APPID {456}'),
        ('MsiInstaller', 1035, 4, T0 + 1600, 'Some product reconfigured', None),
    ]


def main(out_dir='.'):
    write_evtx(f'{out_dir}/system.evtx', 'System', system_records())
    write_evtx(f'{out_dir}/application.evtx', 'Application', application_records())


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
