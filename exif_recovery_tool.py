#!/usr/bin/env python3
# Rhino EXIF Recovery Tool
# by 1rhino2 (github.com/1rhino2)
#
# Stdlib only. Digs EXIF out of JPEGs (and friends) even when someone
# stripped it but left APP1 junk, XMP, or a half-wiped block behind.
# Guesses from filenames/brand bytes are labeled as guesses. Dont confuse them.

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import math
import os
import re
import struct
import sys
import urllib.error
import urllib.request
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

CREDITS = 'Tool by 1rhino2 (github.com/1rhino2)'
VERSION = '2.0.0'
IMAGE_EXTS = ('.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp', '.gif', '.webp')

# TIFF type -> bytes per element
TIFF_TYPE_SIZE = {
    1: 1,   # BYTE
    2: 1,   # ASCII
    3: 2,   # SHORT
    4: 4,   # LONG
    5: 8,   # RATIONAL
    6: 1,   # SBYTE
    7: 1,   # UNDEFINED
    8: 2,   # SSHORT
    9: 4,   # SLONG
    10: 8,  # SRATIONAL
    11: 4,  # FLOAT
    12: 8,  # DOUBLE
}

# Tags we actually bother naming in the report
TAG_NAMES = {
    0x010E: 'ImageDescription',
    0x010F: 'Make',
    0x0110: 'Model',
    0x0112: 'Orientation',
    0x011A: 'XResolution',
    0x011B: 'YResolution',
    0x0128: 'ResolutionUnit',
    0x0131: 'Software',
    0x0132: 'DateTime',
    0x013B: 'Artist',
    0x0213: 'YCbCrPositioning',
    0x8298: 'Copyright',
    0x8769: 'ExifIFDPointer',
    0x8825: 'GPSInfoIFDPointer',
    0xA005: 'InteroperabilityIFDPointer',
    0x0100: 'ImageWidth',
    0x0101: 'ImageLength',
    0x0103: 'Compression',
    0x0111: 'StripOffsets',
    0x0117: 'StripByteCounts',
    0x0201: 'JPEGInterchangeFormat',
    0x0202: 'JPEGInterchangeFormatLength',
    0x829A: 'ExposureTime',
    0x829D: 'FNumber',
    0x8822: 'ExposureProgram',
    0x8827: 'ISOSpeedRatings',
    0x8830: 'SensitivityType',
    0x9000: 'ExifVersion',
    0x9003: 'DateTimeOriginal',
    0x9004: 'DateTimeDigitized',
    0x9101: 'ComponentsConfiguration',
    0x9102: 'CompressedBitsPerPixel',
    0x9201: 'ShutterSpeedValue',
    0x9202: 'ApertureValue',
    0x9204: 'ExposureBiasValue',
    0x9205: 'MaxApertureValue',
    0x9207: 'MeteringMode',
    0x9208: 'LightSource',
    0x9209: 'Flash',
    0x920A: 'FocalLength',
    0x927C: 'MakerNote',
    0x9286: 'UserComment',
    0xA001: 'ColorSpace',
    0xA002: 'PixelXDimension',
    0xA003: 'PixelYDimension',
    0xA402: 'ExposureMode',
    0xA403: 'WhiteBalance',
    0xA405: 'FocalLengthIn35mmFilm',
    0xA406: 'SceneCaptureType',
    0xA431: 'BodySerialNumber',
    0xA433: 'LensMake',
    0xA434: 'LensModel',
    0x0000: 'GPSVersionID',
    0x0001: 'GPSLatitudeRef',
    0x0002: 'GPSLatitude',
    0x0003: 'GPSLongitudeRef',
    0x0004: 'GPSLongitude',
    0x0005: 'GPSAltitudeRef',
    0x0006: 'GPSAltitude',
    0x0007: 'GPSTimeStamp',
    0x001D: 'GPSDateStamp',
}


def _safe_decode(blob: bytes) -> str:
    # EXIF ASCII is usually NUL-padded junk at the end
    return blob.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()


def _rational_to_float(num: int, den: int) -> Optional[float]:
    if den == 0:
        return None
    return num / den


def gps_to_decimal(dms: Any, ref: Any) -> Optional[float]:
    if not dms or not ref:
        return None
    try:
        parts = list(dms)
        if len(parts) != 3:
            return None
        d, m, s = (float(x) for x in parts)
        sign = -1.0 if str(ref).upper() in ('S', 'W') else 1.0
        return sign * (d + m / 60.0 + s / 3600.0)
    except (TypeError, ValueError):
        return None


def reverse_geocode(lat: float, lon: float, timeout: float = 5.0) -> Optional[str]:
    # Nominatim gets cranky without a UA. Fail quiet if offline.
    url = (
        'https://nominatim.openstreetmap.org/reverse'
        f'?format=json&lat={lat}&lon={lon}&zoom=12&addressdetails=0'
    )
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': f'RhinoExifRecovery/{VERSION} (github.com/1rhino2)',
            'Accept': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='replace'))
        return payload.get('display_name')
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError):
        return None


class TiffIfdReader:
    # Reads TIFF IFDs sitting inside APP1 Exif or a plain .tif

    def __init__(self, blob: bytes, tiff_start: int = 0):
        self.blob = blob
        self.tiff_start = tiff_start
        endian = blob[tiff_start:tiff_start + 2]
        if endian == b'II':
            self.endian = '<'
        elif endian == b'MM':
            self.endian = '>'
        else:
            raise ValueError('Not a TIFF header')
        magic = struct.unpack(self.endian + 'H', blob[tiff_start + 2:tiff_start + 4])[0]
        if magic != 42:
            raise ValueError('Bad TIFF magic')
        self.ifd0_offset = struct.unpack(
            self.endian + 'I', blob[tiff_start + 4:tiff_start + 8]
        )[0]

    def _u16(self, off: int) -> int:
        return struct.unpack(self.endian + 'H', self.blob[off:off + 2])[0]

    def _u32(self, off: int) -> int:
        return struct.unpack(self.endian + 'I', self.blob[off:off + 4])[0]

    def _i32(self, off: int) -> int:
        return struct.unpack(self.endian + 'i', self.blob[off:off + 4])[0]

    def _abs(self, rel: int) -> int:
        return self.tiff_start + rel

    def read_value(self, dtype: int, count: int, value_field: bytes) -> Any:
        size = TIFF_TYPE_SIZE.get(dtype)
        if size is None:
            return None
        total = size * count
        if total <= 4:
            raw = value_field[:total]
        else:
            offset = struct.unpack(self.endian + 'I', value_field)[0]
            start = self._abs(offset)
            raw = self.blob[start:start + total]
            if len(raw) < total:
                return None

        if dtype == 2:
            return _safe_decode(raw)
        if dtype == 7:
            # UserComment likes to start with a charset header
            if raw.startswith(b'ASCII\x00\x00\x00'):
                return _safe_decode(raw[8:])
            if raw.startswith(b'UNICODE\x00'):
                return raw[8:].decode('utf-16', errors='replace').strip('\x00')
            return raw.hex() if len(raw) <= 64 else f'<undefined {len(raw)} bytes>'
        if dtype in (1, 6):
            vals = list(raw)
            return vals[0] if count == 1 else vals
        if dtype == 3:
            fmt = self.endian + 'H' * count
            vals = list(struct.unpack(fmt, raw[:2 * count]))
            return vals[0] if count == 1 else vals
        if dtype == 4:
            fmt = self.endian + 'I' * count
            vals = list(struct.unpack(fmt, raw[:4 * count]))
            return vals[0] if count == 1 else vals
        if dtype == 8:
            fmt = self.endian + 'h' * count
            vals = list(struct.unpack(fmt, raw[:2 * count]))
            return vals[0] if count == 1 else vals
        if dtype == 9:
            fmt = self.endian + 'i' * count
            vals = list(struct.unpack(fmt, raw[:4 * count]))
            return vals[0] if count == 1 else vals
        if dtype == 5:
            out = []
            for i in range(count):
                chunk = raw[i * 8:(i + 1) * 8]
                if len(chunk) < 8:
                    break
                num, den = struct.unpack(self.endian + 'II', chunk)
                out.append(_rational_to_float(num, den))
            return out[0] if count == 1 else out
        if dtype == 10:
            out = []
            for i in range(count):
                chunk = raw[i * 8:(i + 1) * 8]
                if len(chunk) < 8:
                    break
                num, den = struct.unpack(self.endian + 'ii', chunk)
                out.append(_rational_to_float(num, den))
            return out[0] if count == 1 else out
        return None

    def walk_ifd(self, relative_offset: int, depth: int = 0) -> Dict[str, Any]:
        # Stop if pointers loop or look cursed
        if depth > 6 or relative_offset <= 0:
            return {}
        start = self._abs(relative_offset)
        if start + 2 > len(self.blob):
            return {}
        try:
            n = self._u16(start)
        except struct.error:
            return {}
        # 512 tags in one IFD = we landed in random bytes
        if n > 512:
            return {}

        tags: Dict[str, Any] = {}
        pointer_keys = {
            0x8769: 'Exif',
            0x8825: 'GPS',
            0xA005: 'Interop',
        }

        for i in range(n):
            entry = start + 2 + i * 12
            if entry + 12 > len(self.blob):
                break
            try:
                tag = self._u16(entry)
                dtype = self._u16(entry + 2)
                count = self._u32(entry + 4)
                value_field = self.blob[entry + 8:entry + 12]
            except struct.error:
                break

            name = TAG_NAMES.get(tag, f'Tag_0x{tag:04X}')
            if tag in pointer_keys:
                try:
                    ptr = struct.unpack(self.endian + 'I', value_field)[0]
                except struct.error:
                    continue
                nested = self.walk_ifd(ptr, depth + 1)
                if nested:
                    tags[pointer_keys[tag]] = nested
                continue

            # MakerNote can be huge; just say how big it is
            if tag == 0x927C and count > 256:
                tags[name] = f'<MakerNote {count} bytes>'
                continue

            try:
                value = self.read_value(dtype, count, value_field)
            except (struct.error, ValueError):
                continue
            if value is not None:
                tags[name] = value

        # Next IFD pointer (thumbnail usually hangs off IFD1)
        next_off_pos = start + 2 + n * 12
        if next_off_pos + 4 <= len(self.blob):
            try:
                next_rel = self._u32(next_off_pos)
            except struct.error:
                next_rel = 0
            if next_rel and next_rel != relative_offset:
                thumb = self.walk_ifd(next_rel, depth + 1)
                if thumb:
                    tags['ThumbnailIFD'] = thumb
        return tags

    def parse(self) -> Dict[str, Any]:
        return self.walk_ifd(self.ifd0_offset)


def find_jpeg_segments(data: bytes) -> List[Dict[str, Any]]:
    # Walk JPEG markers until SOS. APP* payloads live here.
    segments: List[Dict[str, Any]] = []
    if not data.startswith(b'\xff\xd8'):
        return segments
    i = 2
    length = len(data)
    while i < length - 3:
        if data[i] != 0xFF:
            i += 1
            continue
        while i < length and data[i] == 0xFF:
            i += 1
        if i >= length:
            break
        marker = data[i]
        i += 1
        # Standalone markers, no length field
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xDA:
            # compressed image data after this; orphan hunt covers the rest
            break
        if i + 2 > length:
            break
        seg_len = struct.unpack('>H', data[i:i + 2])[0]
        if seg_len < 2 or i + seg_len > length:
            break
        payload = data[i + 2:i + seg_len]
        entry = {
            'marker': f'APP{marker - 0xE0}' if 0xE0 <= marker <= 0xEF else f'0xFF{marker:02X}',
            'offset': i - 1,
            'length': seg_len,
        }
        if payload.startswith(b'Exif\x00\x00'):
            entry['kind'] = 'exif'
            entry['tiff_offset'] = (i + 2) + 6
        elif payload.startswith(b'http://ns.adobe.com/xap/1.0/\x00') or payload.startswith(b'XMP'):
            entry['kind'] = 'xmp'
        elif payload.startswith(b'JFIF'):
            entry['kind'] = 'jfif'
        elif payload.startswith(b'ICC_PROFILE'):
            entry['kind'] = 'icc'
        elif b'Photoshop 3.0' in payload[:32]:
            entry['kind'] = 'photoshop_iptc'
        else:
            entry['kind'] = 'other'
        entry['payload'] = payload
        segments.append(entry)
        i += seg_len
    return segments


def parse_exif_from_tiff_blob(blob: bytes, tiff_start: int = 0) -> Dict[str, Any]:
    try:
        return TiffIfdReader(blob, tiff_start).parse()
    except (ValueError, struct.error):
        return {}


def extract_xmp(data: bytes) -> Optional[Dict[str, Any]]:
    start = data.find(b'<x:xmpmeta')
    if start == -1:
        start = data.find(b'<xmpmeta')
    if start == -1:
        return None
    end_tag = b'</x:xmpmeta>'
    end = data.find(end_tag, start)
    if end == -1:
        end_tag = b'</xmpmeta>'
        end = data.find(end_tag, start)
    if end == -1:
        return None
    end += len(end_tag)
    xml = data[start:end].decode('utf-8', errors='replace')
    fields: Dict[str, str] = {}
    patterns = {
        'creator': r'(?:dc:creator|photoshop:Credit)[^>]*>([^<]+)',
        'title': r'(?:dc:title|photoshop:Headline)[^>]*>([^<]+)',
        'description': r'(?:dc:description|photoshop:Caption)[^>]*>([^<]+)',
        'CreateDate': r'(?:xmp:CreateDate|photoshop:DateCreated)[^>]*>([^<]+)',
        'ModifyDate': r'xmp:ModifyDate[^>]*>([^<]+)',
        'CreatorTool': r'xmp:CreatorTool[^>]*>([^<]+)',
        'Rating': r'xmp:Rating[^>]*>([^<]+)',
    }
    for key, pat in patterns.items():
        m = re.search(pat, xml, re.I)
        if m:
            fields[key] = m.group(1).strip()
    # attribute form uses quotes in the XML; build regex with chr so we stay on single quotes
    q = chr(34)
    for key, name in (
        ('CreateDate', 'xmp:CreateDate'),
        ('ModifyDate', 'xmp:ModifyDate'),
        ('CreatorTool', 'xmp:CreatorTool'),
    ):
        if key in fields:
            continue
        m = re.search(name + '=' + q + '([^' + q + ']+)' + q, xml)
        if m:
            fields[key] = m.group(1).strip()
    return {'raw_length': len(xml), 'fields': fields or None}


def extract_jpeg_comment(data: bytes) -> Optional[str]:
    idx = 0
    comments = []
    while True:
        idx = data.find(b'\xff\xfe', idx)
        if idx == -1 or idx + 4 > len(data):
            break
        length = struct.unpack('>H', data[idx + 2:idx + 4])[0]
        if length < 2 or idx + 2 + length > len(data):
            break
        comments.append(_safe_decode(data[idx + 4:idx + 2 + length]))
        idx += 2 + length
    if not comments:
        return None
    return ' | '.join(c for c in comments if c)


def parse_png_text(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return out
    i = 8
    texts = {}
    while i + 12 <= len(data):
        length = struct.unpack('>I', data[i:i + 4])[0]
        ctype = data[i + 4:i + 8]
        chunk = data[i + 8:i + 8 + length]
        i += 12 + length
        if ctype == b'IEND':
            break
        if ctype == b'tEXt':
            if b'\x00' in chunk:
                key, val = chunk.split(b'\x00', 1)
                texts[_safe_decode(key)] = _safe_decode(val)
        elif ctype == b'iTXt':
            parts = chunk.split(b'\x00')
            if parts:
                texts[_safe_decode(parts[0])] = _safe_decode(parts[-1]) if len(parts) > 1 else ''
        elif ctype == b'eXIf':
            out['Exif'] = parse_exif_from_tiff_blob(chunk, 0)
        elif ctype == b'time':
            if len(chunk) >= 7:
                y, mo, d, h, mi, s = struct.unpack('>HBBBBB', chunk[:7])
                out['ModificationTime'] = f'{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}'
    if texts:
        out['TextChunks'] = texts
    return out


def parse_webp_exif(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if data[:4] != b'RIFF' or data[8:12] != b'WEBP':
        return out
    i = 12
    while i + 8 <= len(data):
        fourcc = data[i:i + 4]
        size = struct.unpack('<I', data[i + 4:i + 8])[0]
        payload = data[i + 8:i + 8 + size]
        if fourcc == b'EXIF':
            # some writers stick Exif\0\0 in front, some just dump TIFF
            if payload.startswith(b'Exif\x00\x00'):
                out['Exif'] = parse_exif_from_tiff_blob(payload, 6)
            else:
                out['Exif'] = parse_exif_from_tiff_blob(payload, 0)
        elif fourcc == b'XMP ':
            xmp = extract_xmp(payload)
            if xmp:
                out['XMP'] = xmp
        i += 8 + size + (size & 1)
    return out


def filename_hints(name: str) -> Dict[str, Any]:
    hints: Dict[str, Any] = {}
    date_match = re.search(
        r'(20\d{2}|19\d{2})[\-_.]?(0[1-9]|1[0-2])[\-_.]?(0[1-9]|[12]\d|3[01])',
        name,
    )
    # IMG_20240101_153045.jpg style; allow end or file extension after the time
    time_match = re.search(
        r'(?:^|[\-_])([01]\d|2[0-3])([0-5]\d)([0-5]\d)(?:[\-_.]|$)',
        name,
    )
    if date_match:
        hints['DateFromFilename'] = date_match.group(0)
    if time_match:
        hints['TimeFromFilename'] = ''.join(time_match.groups())
    # phone-roll names: IMG_1234, DSC01234, PXL_20240101
    cam = re.search(r'\b(IMG|DSC|PXL|MVIMG|VID|Screenshot)[_\-]?\d+', name, re.I)
    if cam:
        hints['NamePattern'] = cam.group(0)
    return hints


def brand_byte_scan(data: bytes) -> Optional[str]:
    brands = (
        'Canon', 'Nikon', 'SONY', 'Sony', 'OLYMPUS', 'Olympus', 'FUJIFILM',
        'Panasonic', 'LEICA', 'PENTAX', 'SAMSUNG', 'GoPro', 'Hasselblad',
        'Apple', 'Google', 'Xiaomi', 'OnePlus', 'HUAWEI', 'DJI',
    )
    for brand in brands:
        if brand.encode('ascii') in data:
            return brand
    return None


def image_entropy(data: bytes, sample: int = 65536) -> float:
    chunk = data if len(data) <= sample else data[:sample]
    counts = Counter(chunk)
    total = len(chunk) or 1
    return round(
        -sum((c / total) * math.log2(c / total) for c in counts.values() if c),
        4,
    )


def find_sidecar_original(filepath: str) -> Optional[str]:
    base, ext = os.path.splitext(filepath)
    for suffix in ('_original', '_og', '-original', '-og', '.original', '.backup', '.bak'):
        candidate = base + suffix + ext
        if os.path.isfile(candidate):
            return candidate
    # phone dumps sometimes keep an Originals/ folder next door
    parent = os.path.dirname(filepath)
    alt = os.path.join(parent, 'Originals', os.path.basename(filepath))
    if os.path.isfile(alt):
        return alt
    return None


def flatten_exif(exif: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, val in exif.items():
        path = f'{prefix}.{key}' if prefix else key
        if isinstance(val, dict):
            flat.update(flatten_exif(val, path))
        else:
            flat[path] = val
    return flat


def analyze_image(filepath: str, geocode: bool = False) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        'file': os.path.abspath(filepath),
        'tool': f'Rhino EXIF Recovery {VERSION}',
        'credits': CREDITS,
    }
    try:
        with open(filepath, 'rb') as fh:
            data = fh.read()
    except OSError as exc:
        report['error'] = str(exc)
        return report

    stat = os.stat(filepath)
    report['file_info'] = {
        'name': os.path.basename(filepath),
        'size_bytes': stat.st_size,
        'created': dt.datetime.fromtimestamp(stat.st_ctime).isoformat(timespec='seconds'),
        'modified': dt.datetime.fromtimestamp(stat.st_mtime).isoformat(timespec='seconds'),
        'sha256': hashlib.sha256(data).hexdigest(),
        'entropy': image_entropy(data),
        'header_hex': data[:16].hex(),
    }

    recovered: Dict[str, Any] = {
        'exif_blocks': [],
        'primary_exif': None,
        'xmp': None,
        'jpeg_comment': None,
        'png': None,
        'webp': None,
        'segments_summary': [],
    }
    heuristics: Dict[str, Any] = {}
    confidence = {
        'live_exif': False,
        'orphaned_exif': False,
        'xmp': False,
        'container_meta': False,
        'filename_only': False,
    }

    ext = os.path.splitext(filepath)[1].lower()

    # --- JPEG ---
    if data.startswith(b'\xff\xd8') or ext in ('.jpg', '.jpeg'):
        segments = find_jpeg_segments(data)
        # after SOS, stripped files sometimes still have Exif\0\0 floating around
        orphan_hits = []
        search_from = 0
        while True:
            hit = data.find(b'Exif\x00\x00', search_from)
            if hit == -1:
                break
            orphan_hits.append(hit)
            search_from = hit + 1

        for seg in segments:
            recovered['segments_summary'].append({
                'marker': seg['marker'],
                'kind': seg['kind'],
                'offset': seg['offset'],
                'length': seg['length'],
            })
            if seg['kind'] == 'exif':
                parsed = parse_exif_from_tiff_blob(data, seg['tiff_offset'])
                block = {
                    'offset': seg['offset'],
                    'source': 'jpeg_segment',
                    'tags': parsed,
                }
                recovered['exif_blocks'].append(block)
                if recovered['primary_exif'] is None and parsed:
                    recovered['primary_exif'] = parsed
                    confidence['live_exif'] = True

        # orphans the marker walk already missed
        for hit in orphan_hits:
            # intact APP1 looks like FF E1 len Exif\0\0 ...
            approx_seg = hit - 4
            already = any(abs(b['offset'] - approx_seg) < 8 for b in recovered['exif_blocks'])
            if already:
                continue
            tiff_at = hit + 6
            if tiff_at + 8 > len(data):
                continue
            parsed = parse_exif_from_tiff_blob(data, tiff_at)
            if not parsed:
                continue
            recovered['exif_blocks'].append({
                'offset': hit,
                'source': 'orphaned_signature',
                'tags': parsed,
            })
            confidence['orphaned_exif'] = True
            if recovered['primary_exif'] is None:
                recovered['primary_exif'] = parsed

        recovered['jpeg_comment'] = extract_jpeg_comment(data)
        recovered['xmp'] = extract_xmp(data)
        if recovered['xmp'] and recovered['xmp'].get('fields'):
            confidence['xmp'] = True

        # DQT count is a weak hint at best
        qt_count = 0
        idx = 0
        while True:
            idx = data.find(b'\xff\xdb', idx)
            if idx == -1:
                break
            qt_count += 1
            idx += 2
        if qt_count:
            heuristics['jpeg_quant_tables'] = qt_count

    # --- PNG ---
    if data.startswith(b'\x89PNG') or ext == '.png':
        png = parse_png_text(data)
        if png:
            recovered['png'] = png
            confidence['container_meta'] = True
            if png.get('Exif') and recovered['primary_exif'] is None:
                recovered['primary_exif'] = png['Exif']
                confidence['live_exif'] = True

    # --- WebP ---
    if data[8:12] == b'WEBP' or ext == '.webp':
        webp = parse_webp_exif(data)
        if webp:
            recovered['webp'] = webp
            confidence['container_meta'] = True
            if webp.get('Exif') and recovered['primary_exif'] is None:
                recovered['primary_exif'] = webp['Exif']
                confidence['live_exif'] = True

    # --- TIFF ---
    if data[:2] in (b'II', b'MM') and ext in ('.tif', '.tiff'):
        parsed = parse_exif_from_tiff_blob(data, 0)
        if parsed:
            recovered['primary_exif'] = parsed
            recovered['exif_blocks'].append({
                'offset': 0,
                'source': 'tiff_file',
                'tags': parsed,
            })
            confidence['live_exif'] = True

    # heuristics only. never sell these as recovered EXIF
    brand = brand_byte_scan(data)
    if brand:
        heuristics['brand_bytes_in_file'] = brand
    hints = filename_hints(os.path.basename(filepath))
    if hints:
        heuristics['filename'] = hints
        confidence['filename_only'] = not (
            confidence['live_exif'] or confidence['orphaned_exif'] or confidence['xmp']
        )

    # GPS decimal + optional geocode
    primary = recovered.get('primary_exif') or {}
    gps = primary.get('GPS') if isinstance(primary, dict) else None
    if isinstance(gps, dict):
        lat = gps_to_decimal(gps.get('GPSLatitude'), gps.get('GPSLatitudeRef'))
        lon = gps_to_decimal(gps.get('GPSLongitude'), gps.get('GPSLongitudeRef'))
        if lat is not None and lon is not None:
            recovered['gps_decimal'] = {'lat': lat, 'lon': lon}
            if geocode:
                place = reverse_geocode(lat, lon)
                if place:
                    recovered['gps_decimal']['place'] = place

    report['confidence'] = confidence
    report['recovered'] = recovered
    report['heuristics'] = heuristics or None
    report['summary'] = _build_summary(confidence, recovered, heuristics)
    return report


def _build_summary(
    confidence: Dict[str, bool],
    recovered: Dict[str, Any],
    heuristics: Dict[str, Any],
) -> str:
    bits = []
    if confidence.get('live_exif'):
        bits.append('live EXIF')
    if confidence.get('orphaned_exif'):
        bits.append('orphaned EXIF residue')
    if confidence.get('xmp'):
        bits.append('XMP packet')
    if confidence.get('container_meta'):
        bits.append('container meta')
    if not bits and heuristics:
        bits.append('no EXIF, just filename/byte guesses')
    if not bits:
        bits.append('nothing useful found')
    n_blocks = len(recovered.get('exif_blocks') or [])
    if n_blocks:
        bits.append(f'{n_blocks} EXIF block(s)')
    return '; '.join(bits)


def diff_reports(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    fa = flatten_exif((a.get('recovered') or {}).get('primary_exif') or {})
    fb = flatten_exif((b.get('recovered') or {}).get('primary_exif') or {})
    only_a = {k: fa[k] for k in fa.keys() - fb.keys()}
    only_b = {k: fb[k] for k in fb.keys() - fa.keys()}
    changed = {
        k: {'a': fa[k], 'b': fb[k]}
        for k in fa.keys() & fb.keys()
        if fa[k] != fb[k]
    }
    return {
        'only_in_first': only_a or None,
        'only_in_second': only_b or None,
        'changed': changed or None,
    }


def list_images(directory: str, recursive: bool = False) -> List[str]:
    directory = os.path.abspath(directory)
    found: List[str] = []
    if recursive:
        for root, _dirs, files in os.walk(directory):
            for name in files:
                if name.lower().endswith(IMAGE_EXTS):
                    found.append(os.path.join(root, name))
    else:
        for ext in IMAGE_EXTS:
            found.extend(glob.glob(os.path.join(directory, f'*{ext}')))
            found.extend(glob.glob(os.path.join(directory, f'*{ext.upper()}')))
    return sorted(set(found))


def print_report(report: Dict[str, Any], verbose: bool = False) -> None:
    info = report.get('file_info') or {}
    name = info.get('name', report.get('file'))
    sha = (info.get('sha256') or '')[:16]
    print()
    print('=' * 60)
    print(f'File: {name}')
    summary = report.get('summary')
    print(f'Summary: {summary}')
    print('-' * 60)
    if report.get('error'):
        err = report.get('error')
        print(f'Error: {err}')
        return

    size = info.get('size_bytes')
    entropy = info.get('entropy')
    created = info.get('created')
    modified = info.get('modified')
    print(f'Size: {size}  SHA256: {sha}...  Entropy: {entropy}')
    print(f'Created: {created}  Modified: {modified}')

    recovered = report.get('recovered') or {}
    primary = recovered.get('primary_exif')
    if primary:
        print()
        print('Primary EXIF')
        _print_dict(primary, indent=2)
    elif verbose:
        print()
        print('Primary EXIF: (none)')

    if recovered.get('gps_decimal'):
        gps = recovered['gps_decimal']
        lat = gps.get('lat')
        lon = gps.get('lon')
        line = f'GPS: {lat}, {lon}'
        if gps.get('place'):
            place = gps.get('place')
            line += f'  ({place})'
        print()
        print(line)

    if recovered.get('xmp'):
        print()
        print('XMP')
        _print_dict(recovered['xmp'], indent=2)

    if recovered.get('jpeg_comment'):
        print()
        comment = recovered.get('jpeg_comment')
        print(f'JPEG comment: {comment}')

    if recovered.get('png'):
        print()
        print('PNG metadata')
        _print_dict(recovered['png'], indent=2)

    if recovered.get('webp'):
        print()
        print('WebP metadata')
        _print_dict(recovered['webp'], indent=2)

    blocks = recovered.get('exif_blocks') or []
    if verbose and len(blocks) > 1:
        print()
        print(f'All EXIF blocks ({len(blocks)})')
        for i, block in enumerate(blocks):
            off = block.get('offset')
            src = block.get('source')
            print(f'  [{i}] offset={off} source={src}')
            _print_dict(block.get('tags') or {}, indent=4)

    if report.get('heuristics'):
        print()
        print('Heuristics (guesses, not proven EXIF)')
        _print_dict(report['heuristics'], indent=2)

    conf = report.get('confidence') or {}
    print()
    print('Flags: ' + ', '.join(f'{k}={v}' for k, v in conf.items()))


def _print_dict(obj: Any, indent: int = 0) -> None:
    pad = ' ' * indent
    if not isinstance(obj, dict):
        print(f'{pad}{obj}')
        return
    for key, val in obj.items():
        if isinstance(val, dict):
            print(f'{pad}{key}:')
            _print_dict(val, indent + 2)
        else:
            text = repr(val)
            if len(text) > 120:
                text = text[:117] + '...'
            print(f'{pad}{key}: {text}')


def interactive_pick(images: List[str]) -> Optional[str]:
    print('Found these images:')
    for idx, path in enumerate(images):
        print(f'[{idx}] {os.path.basename(path)}')
    while True:
        raw = input(f'Select an image by number (0-{len(images) - 1}), or q to quit: ').strip()
        if raw.lower() in ('q', 'quit', 'exit'):
            return None
        try:
            choice = int(raw)
        except ValueError:
            print('Enter a number.')
            continue
        if 0 <= choice < len(images):
            return images[choice]
        print('Out of range.')


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='exif_recovery_tool.py',
        description=(
            'Pull EXIF / XMP / container meta out of images. '
            'Works on live tags and leftover junk after a sloppy strip. Stdlib only.'
        ),
    )
    p.add_argument('paths', nargs='*', help='file(s) or folder(s)')
    p.add_argument('-r', '--recursive', action='store_true', help='walk folders')
    p.add_argument('-j', '--json', action='store_true', help='dump JSON to stdout')
    p.add_argument('-o', '--output', metavar='FILE', help='write JSON to FILE')
    p.add_argument('-v', '--verbose', action='store_true', help='show every EXIF block')
    p.add_argument('-q', '--quiet', action='store_true', help='one summary line per file')
    p.add_argument(
        '-g',
        '--geocode',
        action='store_true',
        help='lookup GPS via OpenStreetMap (needs net)',
    )
    p.add_argument(
        '-c',
        '--compare',
        metavar='ORIGINAL',
        help='diff against another image / sidecar',
    )
    p.add_argument(
        '-i',
        '--interactive',
        action='store_true',
        help='pick a file from the current folder',
    )
    p.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    return p


def collect_targets(paths: Iterable[str], recursive: bool) -> List[str]:
    targets: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            targets.extend(list_images(path, recursive=recursive))
        elif os.path.isfile(path):
            targets.append(os.path.abspath(path))
        else:
            print(f'[!] Not found: {path}', file=sys.stderr)
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # banner on stderr so `... -j | jq` stays clean
    print(f'--- Rhino EXIF Recovery Tool v{VERSION} ---', file=sys.stderr)
    print(CREDITS, file=sys.stderr)

    targets: List[str] = []
    if args.interactive or not args.paths:
        cwd_images = list_images(os.getcwd(), recursive=False)
        if not cwd_images and not args.paths:
            print('[!] No images in the current directory. Pass a path or use -i after cd.')
            return 1
        if args.interactive or not args.paths:
            if not cwd_images:
                print('[!] No images to pick.')
                return 1
            picked = interactive_pick(cwd_images)
            if not picked:
                return 0
            targets = [picked]
        else:
            targets = collect_targets(args.paths, args.recursive)
    else:
        targets = collect_targets(args.paths, args.recursive)

    if not targets:
        print('[!] No images found.')
        return 1

    reports = []
    for path in targets:
        report = analyze_image(path, geocode=args.geocode)
        # auto-diff against a sidecar if one is sitting next to it
        if args.compare:
            other = analyze_image(args.compare, geocode=False)
            report['compare'] = {
                'against': os.path.abspath(args.compare),
                'diff': diff_reports(other, report),
            }
        else:
            sidecar = find_sidecar_original(path)
            if sidecar:
                other = analyze_image(sidecar, geocode=False)
                report['compare'] = {
                    'against': sidecar,
                    'diff': diff_reports(other, report),
                    'note': 'auto-detected sidecar original',
                }
        reports.append(report)

        if args.quiet:
            info = report.get('file_info') or {}
            quiet_name = info.get('name')
            quiet_summary = report.get('summary')
            print(f'{quiet_name}: {quiet_summary}')
        elif args.json:
            pass  # printed once below
        else:
            print_report(report, verbose=args.verbose)
            if report.get('compare'):
                print()
                against = report['compare'].get('against')
                print(f'Compare vs {against}')
                _print_dict(report['compare'].get('diff') or {}, indent=2)

    payload = reports[0] if len(reports) == 1 else reports
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=2, default=str)
        print(f'[+] Wrote {args.output}')

    print()
    print(CREDITS, file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
