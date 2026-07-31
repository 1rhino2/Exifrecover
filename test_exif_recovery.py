# Tests for exif_recovery_tool. Builds tiny fixtures in a temp dir, no real photos needed.
import io
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

import exif_recovery_tool as tool


def _pad_even(blob: bytes) -> bytes:
    return blob if len(blob) % 2 == 0 else blob + b'\x00'


def build_tiff_ifd0(ascii_tags):
    # ascii_tags: list of (tag_id, string)
    # Layout: header(8) + IFD + string heap
    n = len(ascii_tags)
    str_start = 8 + 2 + n * 12 + 4
    blobs = b''
    offsets = []
    for tag, text in ascii_tags:
        raw = _pad_even(text.encode('ascii') + b'\x00')
        offsets.append((tag, len(raw), str_start + len(blobs)))
        blobs += raw
    ifd = struct.pack('<H', n)
    for tag, count, off in offsets:
        ifd += struct.pack('<HHI', tag, 2, count)
        ifd += struct.pack('<I', off)
    ifd += struct.pack('<I', 0)
    header = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)
    return header + ifd + blobs


def build_tiff_with_gps(lat_deg=40.0, lon_deg=-74.0):
    # IFD0 with GPSInfo pointer -> GPS IFD with lat/lon + refs
    # We lay it out by hand so offsets are honest.
    #
    # header @0 (8 bytes), IFD0 @8
    # IFD0: 1 entry (GPS pointer 0x8825) + next=0
    # GPS IFD follows, then rational heap

    gps_ifd_rel = 8 + 2 + 12 + 4  # 26

    # GPS IFD: 4 entries: lat ref, lat, lon ref, lon
    # entry size 12, so gps body = 2 + 4*12 + 4 = 54
    rationals_rel = gps_ifd_rel + 54

    def rational_triple(deg):
        # deg/1, 0/1, 0/1
        return struct.pack('<IIIIII', int(deg), 1, 0, 1, 0, 1)

    lat_blob = rational_triple(abs(lat_deg))
    lon_blob = rational_triple(abs(lon_deg))
    lat_ref = b'N\x00\x00\x00' if lat_deg >= 0 else b'S\x00\x00\x00'
    lon_ref = b'E\x00\x00\x00' if lon_deg >= 0 else b'W\x00\x00\x00'

    # refs fit inline (4 bytes). rationals need offsets.
    lat_off = rationals_rel
    lon_off = rationals_rel + 24

    gps_ifd = struct.pack('<H', 4)
    # 0x0001 GPSLatitudeRef ASCII count 2 inline
    gps_ifd += struct.pack('<HHI', 0x0001, 2, 2) + lat_ref
    # 0x0002 GPSLatitude RATIONAL count 3
    gps_ifd += struct.pack('<HHI', 0x0002, 5, 3) + struct.pack('<I', lat_off)
    # 0x0003 GPSLongitudeRef
    gps_ifd += struct.pack('<HHI', 0x0003, 2, 2) + lon_ref
    # 0x0004 GPSLongitude
    gps_ifd += struct.pack('<HHI', 0x0004, 5, 3) + struct.pack('<I', lon_off)
    gps_ifd += struct.pack('<I', 0)

    ifd0 = struct.pack('<H', 1)
    # GPSInfo pointer LONG count 1 inline
    ifd0 += struct.pack('<HHI', 0x8825, 4, 1) + struct.pack('<I', gps_ifd_rel)
    ifd0 += struct.pack('<I', 0)

    header = b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)
    return header + ifd0 + gps_ifd + lat_blob + lon_blob


def wrap_jpeg_app1(tiff: bytes, trailing: bytes = b'') -> bytes:
    exif = b'Exif\x00\x00' + tiff
    app1 = b'\xff\xe1' + struct.pack('>H', len(exif) + 2) + exif
    return b'\xff\xd8' + app1 + trailing + b'\xff\xd9'


def jpeg_with_orphan(tiff: bytes) -> bytes:
    # SOI + SOS (so segment walk stops) + orphan Exif blob + EOI
    # minimal SOS: FF DA, len=8, 6 bytes of dummy scan header-ish junk then 'data'
    sos = b'\xff\xda' + struct.pack('>H', 8) + b'\x00' * 6
    orphan = b'Exif\x00\x00' + tiff
    # pad some fake scan bytes before the orphan so it is clearly past SOS
    return b'\xff\xd8' + sos + b'\x11\x22\x33\x44' + orphan + b'\xff\xd9'


def jpeg_with_comment(text: str) -> bytes:
    raw = text.encode('utf-8')
    com = b'\xff\xfe' + struct.pack('>H', len(raw) + 2) + raw
    return b'\xff\xd8' + com + b'\xff\xd9'


def jpeg_with_xmp(create_date: str = '2024-06-01T12:00:00') -> bytes:
    # element form XMP; build attribute quotes with chr so source stays single-quoted
    q = chr(34)
    xml = (
        '<?xpacket begin=' + q + q + ' id=' + q + 'W5M0MpCehiHzreSzNTczkc9d' + q + '?>'
        '<x:xmpmeta xmlns:x=' + q + 'adobe:ns:meta/' + q + '>'
        '<rdf:RDF xmlns:rdf=' + q + 'http://www.w3.org/1999/02/22-rdf-syntax-ns#' + q + '>'
        f'<xmp:CreateDate>{create_date}</xmp:CreateDate>'
        '<xmp:CreatorTool>RhinoTest</xmp:CreatorTool>'
        '</rdf:RDF></x:xmpmeta><?xpacket end=' + q + 'w' + q + '?>'
    )
    payload = b'http://ns.adobe.com/xap/1.0/\x00' + xml.encode('utf-8')
    app1 = b'\xff\xe1' + struct.pack('>H', len(payload) + 2) + payload
    return b'\xff\xd8' + app1 + b'\xff\xd9'


def png_with_text(key: str, value: str) -> bytes:
    def chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + ctype + data + struct.pack('>I', crc)

    # 1x1 IHDR
    ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    # tiny IDAT: filter0 + RGB
    raw = b'\x00\xff\x00\x00'
    idat = zlib.compress(raw)
    text = key.encode('latin-1') + b'\x00' + value.encode('latin-1')
    return (
        b'\x89PNG\r\n\x1a\n'
        + chunk(b'IHDR', ihdr)
        + chunk(b'tEXt', text)
        + chunk(b'IDAT', idat)
        + chunk(b'IEND', b'')
    )


def stripped_jpeg_with_brand() -> bytes:
    # no APP1, but Canon bytes somewhere in the body after SOS
    sos = b'\xff\xda' + struct.pack('>H', 8) + b'\x00' * 6
    return b'\xff\xd8' + sos + b'xxCanonxx' + b'\xff\xd9'


class ExifRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, data: bytes) -> str:
        path = self.root / name
        path.write_bytes(data)
        return str(path)

    def test_live_exif_make_model_datetime(self):
        tiff = build_tiff_ifd0([
            (0x010F, 'RhinoCam'),
            (0x0110, 'RX-1'),
            (0x0132, '2024:01:15 12:34:56'),
        ])
        path = self._write('live.jpg', wrap_jpeg_app1(tiff))
        report = tool.analyze_image(path)
        exif = report['recovered']['primary_exif']
        self.assertEqual(exif['Make'], 'RhinoCam')
        self.assertEqual(exif['Model'], 'RX-1')
        self.assertEqual(exif['DateTime'], '2024:01:15 12:34:56')
        self.assertTrue(report['confidence']['live_exif'])
        self.assertIn('live EXIF', report['summary'])

    def test_orphaned_exif_past_sos(self):
        tiff = build_tiff_ifd0([(0x010F, 'GhostMake'), (0x0110, 'GhostModel')])
        path = self._write('orphan.jpg', jpeg_with_orphan(tiff))
        report = tool.analyze_image(path)
        self.assertTrue(report['confidence']['orphaned_exif'])
        exif = report['recovered']['primary_exif']
        self.assertEqual(exif['Make'], 'GhostMake')
        self.assertEqual(exif['Model'], 'GhostModel')
        sources = [b['source'] for b in report['recovered']['exif_blocks']]
        self.assertIn('orphaned_signature', sources)

    def test_gps_decimal(self):
        tiff = build_tiff_with_gps(40.0, -74.0)
        path = self._write('gps.jpg', wrap_jpeg_app1(tiff))
        report = tool.analyze_image(path, geocode=False)
        gps = report['recovered'].get('gps_decimal')
        self.assertIsNotNone(gps)
        self.assertAlmostEqual(gps['lat'], 40.0, places=4)
        self.assertAlmostEqual(gps['lon'], -74.0, places=4)
        self.assertIn('GPS', report['recovered']['primary_exif'])

    def test_jpeg_comment(self):
        path = self._write('com.jpg', jpeg_with_comment('hello rhino'))
        report = tool.analyze_image(path)
        self.assertEqual(report['recovered']['jpeg_comment'], 'hello rhino')

    def test_xmp_fields(self):
        path = self._write('xmp.jpg', jpeg_with_xmp('2024-06-01T12:00:00'))
        report = tool.analyze_image(path)
        self.assertTrue(report['confidence']['xmp'])
        fields = report['recovered']['xmp']['fields']
        self.assertEqual(fields['CreateDate'], '2024-06-01T12:00:00')
        self.assertEqual(fields['CreatorTool'], 'RhinoTest')

    def test_png_text_chunk(self):
        path = self._write('meta.png', png_with_text('Author', '1rhino2'))
        report = tool.analyze_image(path)
        self.assertTrue(report['confidence']['container_meta'])
        self.assertEqual(report['recovered']['png']['TextChunks']['Author'], '1rhino2')

    def test_filename_and_brand_heuristics(self):
        path = self._write('IMG_20240101_153045.jpg', stripped_jpeg_with_brand())
        report = tool.analyze_image(path)
        self.assertFalse(report['confidence']['live_exif'])
        self.assertTrue(report['confidence']['filename_only'])
        self.assertEqual(report['heuristics']['brand_bytes_in_file'], 'Canon')
        self.assertIn('DateFromFilename', report['heuristics']['filename'])
        self.assertIn('TimeFromFilename', report['heuristics']['filename'])

    def test_sidecar_compare_diff(self):
        live = build_tiff_ifd0([(0x010F, 'NewCam')])
        orig = build_tiff_ifd0([(0x010F, 'OldCam'), (0x0110, 'Kept')])
        path = self._write('shot.jpg', wrap_jpeg_app1(live))
        self._write('shot_original.jpg', wrap_jpeg_app1(orig))
        # analyze then manual compare like CLI does
        a = tool.analyze_image(str(self.root / 'shot_original.jpg'))
        b = tool.analyze_image(path)
        diff = tool.diff_reports(a, b)
        self.assertIn('Make', diff['changed'])
        self.assertEqual(diff['changed']['Make']['a'], 'OldCam')
        self.assertEqual(diff['changed']['Make']['b'], 'NewCam')
        self.assertEqual(diff['only_in_first']['Model'], 'Kept')
        # auto sidecar finder
        self.assertEqual(
            tool.find_sidecar_original(path),
            str(self.root / 'shot_original.jpg'),
        )

    def test_corrupt_and_empty_do_not_crash(self):
        junk = self._write('junk.jpg', b'\xff\xd8\x00\x01\x02\xff\xd9')
        empty = self._write('empty.jpg', b'')
        not_img = self._write('note.txt', b'hello')
        for path in (junk, empty, not_img):
            report = tool.analyze_image(path)
            self.assertIn('summary', report)
            self.assertIn('file_info', report)

    def test_missing_file(self):
        report = tool.analyze_image(str(self.root / 'nope.jpg'))
        self.assertIn('error', report)

    def test_cli_json_and_quiet(self):
        tiff = build_tiff_ifd0([(0x010F, 'CliCam')])
        path = self._write('cli.jpg', wrap_jpeg_app1(tiff))
        buf = io.StringIO()
        err = io.StringIO()
        with mock.patch('sys.stdout', buf), mock.patch('sys.stderr', err):
            code = tool.main([path, '-j'])
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn('CliCam', out)
        self.assertIn('Make', out)
        self.assertIn('Rhino EXIF Recovery', err.getvalue())

        buf2 = io.StringIO()
        with mock.patch('sys.stdout', buf2), mock.patch('sys.stderr', io.StringIO()):
            code = tool.main([path, '-q'])
        self.assertEqual(code, 0)
        self.assertIn('cli.jpg:', buf2.getvalue())
        self.assertIn('live EXIF', buf2.getvalue())

    def test_cli_output_file(self):
        tiff = build_tiff_ifd0([(0x010F, 'OutCam')])
        path = self._write('out.jpg', wrap_jpeg_app1(tiff))
        dest = str(self.root / 'report.json')
        with mock.patch('sys.stdout', io.StringIO()), mock.patch('sys.stderr', io.StringIO()):
            code = tool.main([path, '-o', dest])
        self.assertEqual(code, 0)
        text = Path(dest).read_text(encoding='utf-8')
        self.assertIn('OutCam', text)

    def test_list_images_recursive(self):
        sub = self.root / 'a' / 'b'
        sub.mkdir(parents=True)
        (sub / 'nested.jpg').write_bytes(wrap_jpeg_app1(build_tiff_ifd0([(0x010F, 'X')])))
        (self.root / 'top.png').write_bytes(png_with_text('k', 'v'))
        found = tool.list_images(str(self.root), recursive=True)
        names = {Path(p).name for p in found}
        self.assertIn('nested.jpg', names)
        self.assertIn('top.png', names)

    def test_gps_helpers(self):
        self.assertAlmostEqual(tool.gps_to_decimal([10, 30, 0], 'N'), 10.5, places=6)
        self.assertAlmostEqual(tool.gps_to_decimal([10, 30, 0], 'S'), -10.5, places=6)
        self.assertIsNone(tool.gps_to_decimal(None, 'N'))
        self.assertIsNone(tool._rational_to_float(1, 0))


if __name__ == '__main__':
    unittest.main()
